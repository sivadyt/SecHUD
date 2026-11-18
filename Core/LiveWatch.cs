using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;

namespace SecHUD
{
    /// <summary>
    /// The live watch. A normal scan looks at everything every couple of minutes. This sits
    /// between scans and lets Windows say the moment something on this PC changes, so the
    /// check runs within a second or two.
    ///
    ///   registry      Windows signals when a Run key, the service list, the task list, a
    ///                 firewall profile, Defender's settings or the DNS settings change
    ///   startup       the two Startup folders are watched for new or changed files
    ///   event logs    the logs the detection rules read wake it when a matching event is written
    ///   ports         the listening ports are compared every two seconds
    ///   accounts      the local accounts and administrators are compared every two seconds
    ///
    /// It only notices that something changed. Working out what changed, and whether it
    /// deserves an alert, is still the scanner's job.
    /// </summary>
    public sealed class LiveWatch : IDisposable
    {
        private const int QuietGapMs = 400;   // wait this long for a burst of changes to finish
        private const int MaxWaitMs = 2000;   // but never hold a change back longer than this
        private const int PollMs = 2000;

        private readonly object gate = new object();
        private readonly List<FileSystemWatcher> folders = new List<FileSystemWatcher>();
        private readonly List<EventLogWatcher> logs = new List<EventLogWatcher>();
        private readonly List<string> pendingReasons = new List<string>();
        private ManualResetEvent stop;
        private Thread registryThread;
        private Thread pollThread;
        private Timer flushTimer;
        private DateTime firstPendingUtc;
        private bool running;
        private int registryKeys;

        /// <summary>Raised on a background thread with a short description of what moved.</summary>
        public event Action<string> Changed;

        public bool IsRunning { get { lock (gate) return running; } }

        /// <summary>What is being watched, for the status line.</summary>
        public string Summary
        {
            get
            {
                lock (gate)
                {
                    if (!running) return "off";
                    return registryKeys + " registry keys, " + folders.Count + " startup folders, "
                        + logs.Count + " event logs, ports, accounts";
                }
            }
        }

        private class KeySpec
        {
            public RegistryHive Hive; public RegistryView View; public string Path; public bool Subtree; public int Filter; public string Reason;
        }

        private static readonly KeySpec[] KeySpecs = BuildKeySpecs();

        private static KeySpec[] BuildKeySpecs()
        {
            const string run = @"Software\Microsoft\Windows\CurrentVersion\Run";
            const string runOnce = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
            const string firewall = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            const int values = Native.RegNotifyChangeLastSet | Native.RegNotifyChangeName;
            const int names = Native.RegNotifyChangeName;
            RegistryHive user = RegistryHive.CurrentUser, machine = RegistryHive.LocalMachine;
            RegistryView std = RegistryView.Default, v64 = RegistryView.Registry64, v32 = RegistryView.Registry32;

            return new[]
            {
                new KeySpec { Hive = user, View = std, Path = run, Filter = values, Reason = "run key" },
                new KeySpec { Hive = user, View = std, Path = runOnce, Filter = values, Reason = "run key" },
                new KeySpec { Hive = machine, View = v64, Path = run, Filter = values, Reason = "run key" },
                new KeySpec { Hive = machine, View = v64, Path = runOnce, Filter = values, Reason = "run key" },
                new KeySpec { Hive = machine, View = v32, Path = run, Filter = values, Reason = "run key" },
                // Only names: a service being added or removed. Watching every value under here would never be quiet.
                new KeySpec { Hive = machine, View = v64, Path = @"SYSTEM\CurrentControlSet\Services", Filter = names, Reason = "service list" },
                new KeySpec { Hive = machine, View = v64, Path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", Subtree = true, Filter = names, Reason = "scheduled tasks" },
                new KeySpec { Hive = machine, View = v64, Path = firewall + "StandardProfile", Filter = values, Reason = "firewall" },
                new KeySpec { Hive = machine, View = v64, Path = firewall + "PublicProfile", Filter = values, Reason = "firewall" },
                new KeySpec { Hive = machine, View = v64, Path = firewall + "DomainProfile", Filter = values, Reason = "firewall" },
                new KeySpec { Hive = machine, View = v64, Path = @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", Filter = values, Reason = "antivirus" },
                new KeySpec { Hive = machine, View = v64, Path = @"SOFTWARE\Policies\Microsoft\Windows Defender", Subtree = true, Filter = values, Reason = "antivirus" },
                new KeySpec { Hive = machine, View = v64, Path = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", Subtree = true, Filter = values, Reason = "network settings" }
            };
        }

        public void Start(AppConfig config)
        {
            lock (gate)
            {
                if (running) return;
                running = true;
                stop = new ManualResetEvent(false);
                registryKeys = 0;

                int ignoreAbove = config == null ? 49151 : config.IgnorePortsAbove;
                bool watchAutoruns = config == null || config.WatchAutoruns;
                bool watchEvents = config == null || config.WatchEvents;

                ManualResetEvent stopEvent = stop;
                registryThread = new Thread(() => RegistryLoop(stopEvent)) { IsBackground = true, Name = "SecHUD live registry" };
                registryThread.Start();
                pollThread = new Thread(() => PollLoop(stopEvent, ignoreAbove, watchEvents)) { IsBackground = true, Name = "SecHUD live poll" };
                pollThread.Start();

                if (watchAutoruns)
                {
                    WatchFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
                    WatchFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
                }
                if (watchEvents) WatchLogs();

                try { NetworkChange.NetworkAddressChanged += OnNetworkChanged; } catch { }
            }
        }

        public void Stop()
        {
            Thread registry, poll;
            List<FileSystemWatcher> oldFolders;
            List<EventLogWatcher> oldLogs;
            lock (gate)
            {
                if (!running) return;
                running = false;
                try { NetworkChange.NetworkAddressChanged -= OnNetworkChanged; } catch { }
                try { stop.Set(); } catch { }
                oldFolders = new List<FileSystemWatcher>(folders);
                oldLogs = new List<EventLogWatcher>(logs);
                folders.Clear();
                logs.Clear();
                if (flushTimer != null) { flushTimer.Dispose(); flushTimer = null; }
                pendingReasons.Clear();
                registry = registryThread;
                poll = pollThread;
                registryThread = null;
                pollThread = null;
            }

            // Everything below happens outside the lock. Closing a watcher can wait for a callback
            // that is in flight, and that callback needs the lock to find out it should do nothing.
            foreach (FileSystemWatcher watcher in oldFolders) { try { watcher.EnableRaisingEvents = false; watcher.Dispose(); } catch { } }
            foreach (EventLogWatcher watcher in oldLogs) { try { watcher.Enabled = false; watcher.Dispose(); } catch { } }
            if (registry != null) registry.Join(3000);
            if (poll != null) poll.Join(3000);
        }

        public void Dispose()
        {
            Stop();
        }

        // ---------------------------------------------------------- registry ---

        private void RegistryLoop(ManualResetEvent stopEvent)
        {
            var keys = new List<RegistryKey>();
            var events = new List<AutoResetEvent>();
            var specs = new List<KeySpec>();
            try
            {
                foreach (KeySpec spec in KeySpecs)
                {
                    try
                    {
                        RegistryKey key;
                        using (RegistryKey root = RegistryKey.OpenBaseKey(spec.Hive, spec.View))
                        {
                            key = root.OpenSubKey(spec.Path, false);
                        }
                        if (key == null) continue; // not present on this PC (Defender replaced, no policy key...)

                        var signal = new AutoResetEvent(false);
                        if (Native.RegNotifyChangeKeyValue(key.Handle, spec.Subtree, spec.Filter, signal.SafeWaitHandle, true) != 0)
                        {
                            key.Dispose();
                            signal.Dispose();
                            continue;
                        }
                        keys.Add(key);
                        events.Add(signal);
                        specs.Add(spec);
                    }
                    catch
                    {
                        // No permission for this key: the regular scan still covers it.
                    }
                }
                lock (gate) registryKeys = keys.Count;
                if (keys.Count == 0) return;

                var handles = new WaitHandle[events.Count + 1];
                handles[0] = stopEvent;
                for (int i = 0; i < events.Count; i++) handles[i + 1] = events[i];

                while (true)
                {
                    int index = WaitHandle.WaitAny(handles);
                    if (index == 0) return;
                    int which = index - 1;
                    Raise(specs[which].Reason);

                    // The notification fires once. Ask again, and stop listening to a key that has gone away.
                    try
                    {
                        Native.RegNotifyChangeKeyValue(keys[which].Handle, specs[which].Subtree, specs[which].Filter,
                            events[which].SafeWaitHandle, true);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Store.LogError("live registry", ex);
            }
            finally
            {
                foreach (RegistryKey key in keys) { try { key.Dispose(); } catch { } }
                foreach (AutoResetEvent signal in events) { try { signal.Dispose(); } catch { } }
            }
        }

        // ----------------------------------------------------- startup folders ---

        private void WatchFolder(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) return;
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    IncludeSubdirectories = false
                };
                watcher.Created += (s, e) => Raise("startup folder");
                watcher.Deleted += (s, e) => Raise("startup folder");
                watcher.Changed += (s, e) => Raise("startup folder");
                watcher.Renamed += (s, e) => Raise("startup folder");
                watcher.EnableRaisingEvents = true;
                folders.Add(watcher);
            }
            catch
            {
                // The regular scan still reads the folder.
            }
        }

        // ---------------------------------------------------------- event logs ---

        private void WatchLogs()
        {
            var wanted = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
            Action<string, int> want = (log, id) =>
            {
                if (string.IsNullOrEmpty(log) || id <= 0) return;
                HashSet<int> ids;
                if (!wanted.TryGetValue(log, out ids)) wanted[log] = ids = new HashSet<int>();
                ids.Add(id);
            };

            foreach (DetectionRule rule in Detector.Rules) want(rule.Log, rule.Id);
            try { foreach (DetectionRule rule in Detector.LoadCustomRules()) want(rule.Log, rule.Id); } catch { }
            want(Detector.Security, 4625); // failed logons, for the failed-login count

            foreach (KeyValuePair<string, HashSet<int>> pair in wanted)
            {
                try
                {
                    var query = new EventLogQuery(pair.Key, PathType.LogName, BuildQuery(pair.Value));
                    var watcher = new EventLogWatcher(query);
                    watcher.EventRecordWritten += OnEventWritten;
                    watcher.Enabled = true; // throws when this account may not read the log
                    logs.Add(watcher);
                }
                catch
                {
                    // Usually the Security log without Event Log Readers. The account and port checks do not need it.
                }
            }
        }

        /// <summary>The event-log filter for a set of event ids.</summary>
        public static string BuildQuery(IEnumerable<int> ids)
        {
            return "*[System[(" + string.Join(" or ", ids.OrderBy(i => i).Select(i => "EventID=" + i)) + ")]]";
        }

        private void OnEventWritten(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e != null && e.EventRecord != null) e.EventRecord.Dispose();
            }
            catch { }
            Raise("event log");
        }

        private void OnNetworkChanged(object sender, EventArgs e)
        {
            Raise("network settings");
        }

        // ----------------------------------------------------- ports, accounts ---

        private void PollLoop(ManualResetEvent stopEvent, int ignoreAbove, bool watchAccounts)
        {
            string adminGroup = "";
            try
            {
                // The Administrators group has a translated name on non-English Windows, so it is found by its fixed id.
                string full = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value;
                adminGroup = full.Substring(full.LastIndexOf('\\') + 1);
            }
            catch { }

            string lastPorts = null;
            string lastAccounts = null;
            int slowTick = 0;

            while (!stopEvent.WaitOne(PollMs))
            {
                try
                {
                    string ports = ReadPorts(ignoreAbove);
                    if (ports != null)
                    {
                        if (lastPorts != null && ports != lastPorts) Raise("listening ports");
                        lastPorts = ports;
                    }

                    if (!watchAccounts) continue;
                    List<string> accounts = null;
                    try { accounts = Native.QuickAccountList(adminGroup); } catch { accounts = null; }
                    if (accounts == null)
                    {
                        // No quick answer from Windows: fall back to the slower query, less often.
                        if (++slowTick % 5 != 0) continue;
                        try { accounts = Accounts.Query(); } catch { accounts = null; }
                    }
                    if (accounts == null || accounts.Count == 0) continue;

                    string signature = Signature(accounts);
                    if (lastAccounts != null && signature != lastAccounts) Raise("local accounts");
                    lastAccounts = signature;
                }
                catch (Exception ex)
                {
                    Store.LogError("live poll", ex);
                }
            }
        }

        private static string ReadPorts(int ignoreAbove)
        {
            try
            {
                return PortSignature(IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                    .Where(e => !IPAddress.IsLoopback(e.Address))
                    .Select(e => e.Port), ignoreAbove);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// The listening ports as one comparable string. Ports above the cutoff are left out:
        /// those are short-lived Windows ports that open and close all day.
        /// </summary>
        public static string PortSignature(IEnumerable<int> ports, int ignoreAbove)
        {
            return string.Join(",", (ports ?? new int[0]).Where(p => p <= ignoreAbove).Distinct().OrderBy(p => p));
        }

        /// <summary>A list as one comparable string, whatever order it arrived in.</summary>
        public static string Signature(IEnumerable<string> items)
        {
            return string.Join("\n", (items ?? new string[0]).Select(i => (i ?? "").ToLowerInvariant()).Distinct().OrderBy(i => i, StringComparer.Ordinal));
        }

        // ------------------------------------------------------------ batching ---

        /// <summary>
        /// One change usually arrives as a burst (an installer writes several keys). The burst is
        /// passed on as a single signal shortly after it goes quiet, and never later than two seconds.
        /// </summary>
        private void Raise(string reason)
        {
            lock (gate)
            {
                if (!running) return;
                if (pendingReasons.Count == 0) firstPendingUtc = DateTime.UtcNow;
                if (!pendingReasons.Contains(reason)) pendingReasons.Add(reason);

                double waited = (DateTime.UtcNow - firstPendingUtc).TotalMilliseconds;
                int due = (int)Math.Max(0, Math.Min(QuietGapMs, MaxWaitMs - waited));
                if (flushTimer == null) flushTimer = new Timer(Flush, null, due, Timeout.Infinite);
                else flushTimer.Change(due, Timeout.Infinite);
            }
        }

        private void Flush(object state)
        {
            string reasons;
            lock (gate)
            {
                if (!running || pendingReasons.Count == 0) return;
                reasons = string.Join(", ", pendingReasons);
                pendingReasons.Clear();
            }
            Action<string> handler = Changed;
            if (handler == null) return;
            try { handler(reasons); }
            catch (Exception ex) { Store.LogError("live watch", ex); }
        }
    }
}
