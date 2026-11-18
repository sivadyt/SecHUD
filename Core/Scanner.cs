using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SecHUD
{
    /// <summary>
    /// The engine. One call to Run does a full pass:
    ///   1. this PC      - antivirus, firewall, failed logins, listening ports, autoruns, accounts, detections
    ///   2. the LAN      - an ARP sweep of the local subnet, compared with the device baseline
    ///   3. watched hosts - TCP reachability and TLS certificate expiry
    /// and logs an event for anything that changed since the previous pass.
    ///
    /// RunQuick is the live-watch pass: it repeats step 1 only (plus the DNS setting, which is
    /// free to read) and carries the network rows over from the last full pass. It takes about
    /// a second, so it can run the moment Windows reports a change.
    ///
    /// The only traffic it sends is ARP requests on your own private subnet and a TCP connect
    /// to the hosts listed in config.json. It never needs admin rights.
    /// </summary>
    public class Scanner
    {
        private const int MaxHostRows = 8;

        /// <summary>Held while the baselines and state are read, compared and written.</summary>
        private readonly object runLock = new object();

        /// <summary>One full pass at a time. The slow network part runs under this lock only,
        /// so a live-watch pass never has to wait for an ARP sweep to finish.</summary>
        private readonly object fullLock = new object();

        private ScanResult lastFull;
        private int pendingHighEvents;
        private long sequence;

        /// <summary>What the network part of a full pass found, before it is compared with anything.</summary>
        private class NetFacts
        {
            public AppConfig Config;
            public LanInfo Lan;
            public Dictionary<string, string> Found;
            public WifiScan Wifi;
            public bool WifiFailed;
            public RouterSnapshot Router;
            public List<CheckRow> HostRows = new List<CheckRow>();
            public ProxmoxSnapshot Proxmox;
            public string Pinned;
        }

        public ScanResult Run(bool approve)
        {
            lock (fullLock)
            {
                NetFacts facts = Gather(approve);
                lock (runLock)
                {
                    return RunCore(approve, facts);
                }
            }
        }

        /// <summary>The live-watch pass. Returns null until the first full pass has finished.</summary>
        public ScanResult RunQuick()
        {
            lock (runLock)
            {
                if (lastFull == null) return null;
                return RunCore(false, null);
            }
        }

        /// <summary>Everything slow: the sweep, the Wi-Fi survey, the router, the watched hosts, Proxmox.</summary>
        private NetFacts Gather(bool approve)
        {
            var facts = new NetFacts();
            AppConfig config = Store.LoadConfig();
            facts.Config = config;
            AppState state;
            lock (runLock)
            {
                // Read under the lock so a half-written file can never make the Proxmox pin look empty.
                state = Store.Load<AppState>(Store.StatePath) ?? AppState.CreateDefault();
            }
            state.Normalize();
            DateTime now = DateTime.Now;

            if (config.ScanLan)
            {
                try { facts.Lan = FindLan(); } catch { facts.Lan = null; }
                if (facts.Lan != null) facts.Found = Sweep(facts.Lan);
            }
            string gatewayIp = facts.Lan != null && facts.Lan.Gateway != null ? facts.Lan.Gateway.ToString() : null;

            if (config.WatchWifi)
            {
                try { facts.Wifi = Wifi.Scan(); } catch { facts.WifiFailed = true; }
            }

            if (config.WatchRouter)
            {
                try { facts.Router = Upnp.Query(gatewayIp); }
                catch { facts.Router = new RouterSnapshot { Note = "could not query the router" }; }
            }

            foreach (WatchedHost host in config.WatchedHosts)
            {
                if (host == null || string.IsNullOrWhiteSpace(host.Host)) continue;
                if (facts.HostRows.Count >= MaxHostRows) break;
                facts.HostRows.Add(CheckHost(host, config, now));
            }

            // Approving accepts a changed Proxmox certificate: forget the old one so the next one is remembered.
            facts.Pinned = approve && state.ProxmoxCertChanged ? "" : state.ProxmoxThumbprint;
            try { facts.Proxmox = Proxmox.Fetch(config, facts.Pinned); }
            catch { facts.Proxmox = new ProxmoxSnapshot { Configured = true, Error = "error" }; }
            return facts;
        }

        private ScanResult RunCore(bool approve, NetFacts facts)
        {
            bool quick = facts == null;
            DateTime now = DateTime.Now;
            string stamp = now.ToString("HH:mm");
            AppConfig config = quick ? Store.LoadConfig() : facts.Config;
            AppState state = Store.Load<AppState>(Store.StatePath) ?? AppState.CreateDefault();
            state.Normalize();

            var events = new List<EventEntry>();
            var result = new ScanResult { Time = now, Config = config, IsQuick = quick, Sequence = ++sequence };

            // ---- this PC ----
            CheckRow antivirus = CheckAntivirus(config, now);
            CheckRow firewall = CheckFirewall();
            CheckRow logins = CheckFailedLogins(config);

            List<PortInfo> ports;
            CheckRow portRow = CheckPorts(config, approve, events, now, out ports);

            List<AutorunItem> autoruns;
            CheckRow autorunRow = CheckAutoruns(config, approve, events, now, state, out autoruns);

            List<EventEntry> openItems = approve ? new List<EventEntry>() : state.OpenItems;
            string eventsSince;
            int customRules;
            CheckRow detectionRow = CheckDetections(config, events, now, state.EventsSinceUtc, state.LogMarkers, openItems, out eventsSince, out customRules);

            // Accounts are compared directly, so this works even when the Security log cannot be read.
            int openBefore = openItems.Count;
            CheckRow accountRow = CheckAccounts(config, events, now, openItems);
            if (openItems.Count != openBefore)
            {
                bool partial = detectionRow.Value.EndsWith("partial", StringComparison.Ordinal);
                detectionRow = new CheckRow("DETECTIONS", openItems.Count + " open" + (partial ? " | partial" : ""), true, false);
            }

            if (state.DefenderOk && !antivirus.Ok) AddEvent(events, now, "antivirus", "high", "no antivirus is actively protecting this PC", "T1562.001");
            if (!state.DefenderOk && antivirus.Ok) AddEvent(events, now, "antivirus", "info", "antivirus protection is active again");
            if (state.FirewallOk && !firewall.Ok) AddEvent(events, now, "firewall", "high", "firewall profile disabled (" + firewall.Value + ")", "T1562.004");
            if (!state.FirewallOk && firewall.Ok) AddEvent(events, now, "firewall", "info", "all firewall profiles back on");

            bool loginsOver = logins.IsAlert;
            if (loginsOver && !state.LoginsOver) AddEvent(events, now, "logins", "high", logins.Value + " failed logins in 24h", "T1110");

            foreach (PortInfo p in ports.Where(x => x.IsNew))
            {
                if (!state.NewPorts.Contains(p.Port))
                    AddEvent(events, now, "new-port", "high", "new listening port " + p.Port + " (" + p.Process + ")");
            }

            var pcRows = new List<CheckRow> { antivirus, firewall, logins, portRow, autorunRow, accountRow, detectionRow };

            // ---- the network ----
            List<CheckRow> netRows;
            List<DeviceRecord> devices;
            ProxmoxSnapshot proxmox;
            RouterSnapshot router;
            List<string> trustedDns = state.TrustedDns;
            bool dnsChanged;

            if (quick)
            {
                // Reading the DNS setting costs nothing, so a hijack is caught live as well.
                string dnsNow = null;
                try
                {
                    LanInfo lan = config.ScanLan ? FindLan() : null;
                    if (lan != null) dnsNow = lan.Dns;
                }
                catch { }
                CheckRow dnsRow = CheckDns(dnsNow, false, events, now, state.DnsChanged, trustedDns, out dnsChanged);
                if (string.IsNullOrEmpty(dnsNow))
                {
                    // Nothing could be read this instant: keep the row from the last full pass.
                    dnsRow = lastFull.NetRows.FirstOrDefault(r => r.Label == dnsRow.Label) ?? dnsRow;
                }
                netRows = lastFull.NetRows.Select(r => r.Label == dnsRow.Label ? dnsRow : r).ToList();
                devices = lastFull.Devices;
                proxmox = lastFull.Proxmox;
                router = lastFull.Router;
            }
            else
            {
                string gatewayIp = facts.Lan != null && facts.Lan.Gateway != null ? facts.Lan.Gateway.ToString() : null;
                string ownIp = facts.Lan != null ? facts.Lan.Ip.ToString() : null;
                string dnsServers = facts.Lan != null ? facts.Lan.Dns : null;
                string gatewayMac = null;
                if (facts.Found != null && gatewayIp != null)
                    gatewayMac = facts.Found.Where(p => p.Value == gatewayIp).Select(p => p.Key).FirstOrDefault();

                CheckRow lanRow = EvaluateLan(config, facts.Found, ownIp, gatewayIp, approve, events, now, out devices);

                string trustedGateway = state.GatewayMac;
                bool gatewayChanged;
                CheckRow gatewayRow = CheckGateway(gatewayMac, approve, events, now, state.GatewayChanged, ref trustedGateway, out gatewayChanged);
                CheckRow dnsRow = CheckDns(dnsServers, approve, events, now, state.DnsChanged, trustedDns, out dnsChanged);

                List<string> newAccessPoints;
                CheckRow wifiRow = CheckWifi(config, facts, approve, events, now, state, out newAccessPoints);

                router = facts.Router ?? new RouterSnapshot { Note = "turned off in settings" };
                CheckRow routerRow = CheckRouter(config, router, approve, events, now, state);

                List<CheckRow> hostRows = facts.HostRows.ToList();
                string pinned = facts.Pinned ?? "";
                proxmox = facts.Proxmox ?? new ProxmoxSnapshot();
                bool proxmoxCertChanged = false;
                if (proxmox.Configured)
                {
                    if (proxmox.CertChanged)
                    {
                        proxmoxCertChanged = true;
                        if (!state.ProxmoxCertChanged)
                            AddEvent(events, now, "proxmox", "high", "Proxmox certificate changed (possible interception)", "T1557");
                        hostRows.Add(new CheckRow("PROXMOX API", "CERT CHANGED", true, true));
                    }
                    else if (proxmox.Ok)
                    {
                        if (pinned.Length == 0) pinned = proxmox.Thumbprint;
                        int running = proxmox.Guests.Count(g => g.Running);
                        hostRows.Add(new CheckRow("PROXMOX API", running + "/" + proxmox.Guests.Count + " running", false, true));
                    }
                    else
                    {
                        hostRows.Add(new CheckRow("PROXMOX API", proxmox.Error.Length > 0 ? proxmox.Error : "DOWN", true, false));
                    }
                }

                List<string> downNow = hostRows.Where(h => !h.Ok).Select(h => h.Label).ToList();
                foreach (string name in downNow)
                {
                    if (!state.HostsDown.Contains(name)) AddEvent(events, now, "host", "high", name + " is DOWN");
                }
                foreach (string name in state.HostsDown)
                {
                    if (!downNow.Contains(name) && hostRows.Any(h => h.Label == name))
                        AddEvent(events, now, "host", "info", name + " is back up");
                }

                netRows = new List<CheckRow> { lanRow, gatewayRow, dnsRow, wifiRow, routerRow };
                netRows.AddRange(hostRows);

                state.HostsDown = downNow;
                state.GatewayMac = trustedGateway ?? "";
                state.GatewayChanged = gatewayChanged;
                state.ProxmoxThumbprint = pinned ?? "";
                state.ProxmoxCertChanged = proxmoxCertChanged;
                state.NewForwards = router.Forwards.Where(f => f.IsNew).Select(f => f.Key).ToList();
                state.NewAccessPoints = newAccessPoints;
            }

            // ---- overall level ----
            bool elevated = pcRows.Any(r => r.IsAlert) || netRows.Any(r => r.IsAlert);
            string level = elevated ? "ELEVATED" : "NOMINAL";
            if (level != state.Level) AddEvent(events, now, "level", "info", "status changed " + state.Level + " -> " + level);

            string lastAlert = state.LastAlert ?? "";
            EventEntry newestHigh = events.LastOrDefault(e => e.Severity == "high");
            if (newestHigh != null) lastAlert = stamp + " " + newestHigh.Msg;

            string ticker;
            if (elevated && lastAlert.Length > 0) ticker = lastAlert;
            else if (elevated) ticker = stamp + " see the flagged rows";
            else ticker = stamp + " scan complete, no changes";

            state.Level = level;
            state.DefenderOk = antivirus.Ok;
            state.FirewallOk = firewall.Ok;
            state.LoginsOver = loginsOver;
            state.NewPorts = ports.Where(p => p.IsNew).Select(p => p.Port).ToList();
            state.LastAlert = elevated ? lastAlert : "";
            state.EventsSinceUtc = eventsSince;
            state.OpenDetections = openItems.Count;
            state.OpenItems = openItems;
            state.NewAutoruns = autoruns.Where(a => a.IsNew).Select(a => a.Key).ToList();
            state.TrustedDns = trustedDns;
            state.DnsChanged = dnsChanged;
            Store.Save(Store.StatePath, state);
            Store.AppendEvents(events);

            int highNow = events.Count(e => e.Severity == "high");
            if (quick)
            {
                // History has one line per full pass. Alerts raised in between are added to the next one.
                pendingHighEvents += highNow;
            }
            else
            {
                var point = new HistoryPoint
                {
                    Time = now,
                    Online = devices.Count(d => d.Online),
                    Unknown = devices.Count(d => !d.Approved),
                    Elevated = elevated,
                    HighEvents = highNow + pendingHighEvents
                };
                pendingHighEvents = 0;
                foreach (CheckRow host in netRows.Skip(5)) point.Hosts[host.Label] = host.Ok;
                History.Append(point);
            }

            result.Level = level;
            result.Elevated = elevated;
            result.Ticker = ticker;
            result.PcRows = pcRows;
            result.NetRows = netRows;
            result.Devices = devices;
            result.Ports = ports;
            result.Autoruns = autoruns;
            result.Proxmox = proxmox;
            result.OpenDetections = openItems.ToList();
            result.Router = router;
            result.CustomRuleCount = customRules;
            result.NewEvents = events;
            if (!quick) lastFull = result;
            return result;
        }

        private static void AddEvent(List<EventEntry> events, DateTime now, string type, string severity, string msg, string technique = null)
        {
            events.Add(new EventEntry { Ts = now.ToString("s"), Type = type, Severity = severity, Msg = msg, Technique = technique });
        }

        // ------------------------------------------------------------ this PC ---

        /// <summary>Whichever antivirus Windows says is active. Falls back to asking Defender directly.</summary>
        private static CheckRow CheckAntivirus(AppConfig config, DateTime now)
        {
            try
            {
                List<AvProduct> products = Antivirus.Query();
                if (products.Count > 0)
                {
                    CheckRow row = Antivirus.ToRow(products);
                    AvProduct onlyDefender = products.Count(p => p.Enabled) == 1
                        ? products.FirstOrDefault(p => p.Enabled && p.Name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0)
                        : null;
                    if (onlyDefender == null) return row;
                    // Defender is the one on duty, so its own detail (signature age) is worth showing.
                    CheckRow detail = CheckDefender(config, now);
                    return detail.Value == "n/a" ? row : detail;
                }
            }
            catch
            {
                // Security Center is not available on Windows Server editions.
            }
            return CheckDefender(config, now);
        }

        private static CheckRow CheckDefender(AppConfig config, DateTime now)
        {
            const string label = "ANTIVIRUS";
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT RealTimeProtectionEnabled, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus"))
                {
                    foreach (ManagementBaseObject status in searcher.Get())
                    {
                        bool realTime = Convert.ToBoolean(status["RealTimeProtectionEnabled"]);
                        string text = realTime ? "Defender | on" : "Defender | OFF";
                        bool stale = false;

                        string updated = status["AntivirusSignatureLastUpdated"] as string;
                        if (!string.IsNullOrEmpty(updated))
                        {
                            DateTime when = ManagementDateTimeConverter.ToDateTime(updated);
                            int hours = Math.Max(0, (int)Math.Floor((now - when).TotalHours));
                            stale = hours > config.SignatureMaxAgeHours;
                            if (realTime) text = "Defender | sigs " + FormatAge(hours);
                        }
                        return new CheckRow(label, text, !realTime || stale, realTime);
                    }
                }
            }
            catch
            {
                // Defender's WMI provider is missing when another antivirus has replaced it.
            }
            return new CheckRow(label, "n/a", false, true);
        }

        private static string FormatAge(int hours)
        {
            return hours < 48 ? hours + "h" : (hours / 24) + "d";
        }

        private static CheckRow CheckFirewall()
        {
            const string label = "FIREWALL";
            object policy = null;
            try
            {
                // The firewall's own COM object reports the effective state, group policy included.
                Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (type == null) return new CheckRow(label, "n/a", false, true);
                policy = Activator.CreateInstance(type);

                int on = 0;
                int[] profiles = { 1, 2, 4 }; // domain, private, public
                foreach (int profile in profiles)
                {
                    object enabled = type.InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null,
                        policy, new object[] { profile });
                    if (Convert.ToBoolean(enabled)) on++;
                }
                bool ok = on == profiles.Length;
                return new CheckRow(label, on + "/" + profiles.Length + " profiles", !ok, ok);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
            finally
            {
                if (policy != null)
                {
                    try { Marshal.ReleaseComObject(policy); } catch { }
                }
            }
        }

        private static CheckRow CheckFailedLogins(AppConfig config)
        {
            const string label = "FAILED LOGINS 24H";
            const int cap = 2000;
            try
            {
                // Event 4625 = an account failed to log on. Reading the Security log needs
                // membership in "Event Log Readers" (or an elevated session).
                var query = new EventLogQuery("Security", PathType.LogName,
                    "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
                int count = 0;
                using (var reader = new EventLogReader(query))
                {
                    EventRecord record;
                    while (count < cap && (record = reader.ReadEvent()) != null)
                    {
                        count++;
                        record.Dispose();
                    }
                }
                bool over = count >= config.FailedLoginThreshold;
                return new CheckRow(label, count >= cap ? cap + "+" : count.ToString(), over, !over);
            }
            catch (UnauthorizedAccessException)
            {
                return new CheckRow(label, "no access", false, true);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
        }

        private static CheckRow CheckPorts(AppConfig config, bool approve, List<EventEntry> events,
            DateTime now, out List<PortInfo> ports)
        {
            const string label = "LISTENING PORTS";
            ports = new List<PortInfo>();
            try
            {
                List<int> all = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                    .Where(e => !IPAddress.IsLoopback(e.Address))
                    .Select(e => e.Port)
                    .Distinct()
                    .OrderBy(p => p)
                    .ToList();

                List<int> known = Store.Load<List<int>>(Store.PortsPath);
                if (known == null)
                {
                    known = new List<int>(all);
                    Store.Save(Store.PortsPath, known);
                    AddEvent(events, now, "baseline", "info", "port baseline created with " + all.Count + " listening ports");
                }

                // Ports above the cutoff are short-lived Windows RPC ports that change every boot.
                List<int> fresh = all.Where(p => p <= config.IgnorePortsAbove && !known.Contains(p)).ToList();
                if (approve && fresh.Count > 0)
                {
                    known = known.Union(all).OrderBy(p => p).ToList();
                    Store.Save(Store.PortsPath, known);
                    AddEvent(events, now, "approve", "info", "approved port(s) " + string.Join(", ", fresh));
                    fresh.Clear();
                }

                Dictionary<int, int> pids = Native.GetListenerPids();
                foreach (int port in all)
                {
                    string process = "";
                    int pid;
                    if (pids.TryGetValue(port, out pid))
                    {
                        try { process = Process.GetProcessById(pid).ProcessName; } catch { process = "pid " + pid; }
                    }
                    ports.Add(new PortInfo { Port = port, Process = process, IsNew = fresh.Contains(port) });
                }

                return new CheckRow(label, all.Count + " | " + fresh.Count + " new", fresh.Count > 0, fresh.Count == 0);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
        }

        private static CheckRow CheckAutoruns(AppConfig config, bool approve, List<EventEntry> events,
            DateTime now, AppState state, out List<AutorunItem> autoruns)
        {
            const string label = "AUTORUNS";
            autoruns = new List<AutorunItem>();
            if (!config.WatchAutoruns) return new CheckRow(label, "off", false, true);
            try
            {
                autoruns = Autoruns.Collect();
                if (autoruns.Count == 0) return new CheckRow(label, "n/a", false, true);

                List<string> known = Store.Load<List<string>>(Store.AutorunsPath);
                if (known == null)
                {
                    known = autoruns.Select(a => a.Key).ToList();
                    Store.Save(Store.AutorunsPath, known);
                    AddEvent(events, now, "baseline", "info", "autorun baseline created with " + known.Count + " entries");
                }

                List<AutorunItem> fresh = Autoruns.MarkNew(autoruns, known);
                if (approve && fresh.Count > 0)
                {
                    known = known.Union(autoruns.Select(a => a.Key), StringComparer.OrdinalIgnoreCase).ToList();
                    Store.Save(Store.AutorunsPath, known);
                    AddEvent(events, now, "approve", "info", "approved " + fresh.Count + " autorun(s)");
                    foreach (AutorunItem item in fresh) item.IsNew = false;
                    fresh.Clear();
                }

                foreach (AutorunItem item in fresh)
                {
                    if (!state.NewAutoruns.Contains(item.Key, StringComparer.OrdinalIgnoreCase))
                        AddEvent(events, now, "new-autorun", "high", "new " + item.Kind + " autorun: " + item.Name, item.Technique);
                }
                return new CheckRow(label, autoruns.Count + " | " + fresh.Count + " new", fresh.Count > 0, fresh.Count == 0);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
        }

        /// <summary>
        /// Runs the Windows event rules over everything logged since each log was last read.
        /// A log that cannot be read keeps its place, so once access is granted the events
        /// that were missed in the meantime are still reported (up to two days back).
        /// </summary>
        private CheckRow CheckDetections(AppConfig config, List<EventEntry> events, DateTime now,
            string watchStartText, List<LogMarker> markers, List<EventEntry> open, out string watchStartOut, out int customRuleCount)
        {
            const string label = "DETECTIONS";
            watchStartOut = watchStartText ?? "";
            customRuleCount = 0;
            if (!config.WatchEvents) return new CheckRow(label, "off", false, true);

            List<DetectionRule> custom;
            try { custom = Detector.LoadCustomRules(); } catch { custom = new List<DetectionRule>(); }
            customRuleCount = custom.Count;

            DateTime queryTime = DateTime.UtcNow;
            string queryText = queryTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            DateTime watchStart;
            if (!TryParseUtc(watchStartText, out watchStart))
            {
                // The very first scan starts the clock; it does not dig through old history.
                watchStartOut = queryText;
                return new CheckRow(label, open.Count + " open", open.Count > 0, open.Count == 0);
            }

            DateTime oldest = queryTime.AddDays(-2);
            Func<string, DateTime> sinceFor = log =>
            {
                DateTime since = watchStart;
                LogMarker marker = markers.FirstOrDefault(m => m != null && string.Equals(m.Log, log, StringComparison.OrdinalIgnoreCase));
                DateTime parsed;
                if (marker != null && TryParseUtc(marker.SinceUtc, out parsed)) since = parsed;
                return since < oldest ? oldest : since;
            };

            var readLogs = new List<string>();
            int denied;
            List<EventEntry> found;
            try
            {
                found = Detector.Run(EventSource, sinceFor, custom, readLogs, out denied);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }

            foreach (string log in readLogs)
            {
                LogMarker marker = markers.FirstOrDefault(m => m != null && string.Equals(m.Log, log, StringComparison.OrdinalIgnoreCase));
                if (marker == null) markers.Add(new LogMarker { Log = log, SinceUtc = queryText });
                else marker.SinceUtc = queryText;
            }

            foreach (EventEntry e in found)
            {
                if (Accounts.IsRepeat(e, open)) continue; // the account watch already raised this one
                events.Add(e);
                if (e.Severity == "high") open.Add(e);
            }
            if (open.Count > 100) open.RemoveRange(0, open.Count - 100);
            string value = open.Count + " open" + (denied > 0 ? " | partial" : "");
            return new CheckRow(label, value, open.Count > 0, open.Count == 0);
        }

        private static bool TryParseUtc(string text, out DateTime value)
        {
            return DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out value);
        }

        /// <summary>Replaceable so tests can supply their own account list.</summary>
        public Func<List<string>> AccountSource = Accounts.Query;

        /// <summary>New local accounts and new administrators, found by comparing with the previous scan.</summary>
        private CheckRow CheckAccounts(AppConfig config, List<EventEntry> events, DateTime now, List<EventEntry> open)
        {
            const string label = "LOCAL ACCOUNTS";
            if (!config.WatchEvents) return new CheckRow(label, "off", false, true);
            try
            {
                List<string> current = AccountSource();
                if (current == null || current.Count == 0) return new CheckRow(label, "n/a", false, true);

                List<string> known = Store.Load<List<string>>(Store.AccountsPath);
                if (known == null)
                {
                    Store.Save(Store.AccountsPath, current);
                    AddEvent(events, now, "baseline", "info", "account baseline created with " + current.Count + " entries");
                }
                else
                {
                    List<EventEntry> changes = Accounts.Diff(current, known, now);
                    foreach (EventEntry change in changes)
                    {
                        if (Accounts.IsRepeat(change, events) || Accounts.IsRepeat(change, open)) continue; // the Security log already raised it
                        events.Add(change);
                        if (change.Severity == "high") open.Add(change);
                    }
                    if (changes.Count > 0) Store.Save(Store.AccountsPath, current);
                }

                int users = current.Count(k => k.StartsWith("user|", StringComparison.OrdinalIgnoreCase));
                int admins = current.Count(k => k.StartsWith("admin|", StringComparison.OrdinalIgnoreCase));
                return new CheckRow(label, users + " users | " + admins + " admins", false, true);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
        }

        /// <summary>Replaceable so tests can feed their own events.</summary>
        public IEventSource EventSource = new WindowsEventSource();

        /// <summary>
        /// The router's hardware address should never change. If it does, another device may be
        /// answering in its place, which is how ARP spoofing redirects traffic.
        /// </summary>
        private static CheckRow CheckGateway(string currentMac, bool approve, List<EventEntry> events, DateTime now,
            bool wasChanged, ref string trustedMac, out bool changed)
        {
            const string label = "GATEWAY";
            changed = wasChanged;
            if (string.IsNullOrEmpty(currentMac))
            {
                // Not seen this scan: keep whatever we knew.
                return new CheckRow(label, wasChanged ? "MAC CHANGED" : "not seen", wasChanged, !wasChanged);
            }

            if (string.IsNullOrEmpty(trustedMac) || approve)
            {
                trustedMac = currentMac;
                changed = false;
                return new CheckRow(label, "mac ok", false, true);
            }

            if (string.Equals(trustedMac, currentMac, StringComparison.OrdinalIgnoreCase))
            {
                if (wasChanged) AddEvent(events, now, "gateway", "info", "gateway MAC is back to " + trustedMac);
                changed = false;
                return new CheckRow(label, "mac ok", false, true);
            }

            if (!wasChanged)
                AddEvent(events, now, "gateway", "high", "gateway MAC changed from " + trustedMac + " to " + currentMac + " (possible ARP spoofing)", "T1557.002");
            changed = true;
            return new CheckRow(label, "MAC CHANGED", true, false);
        }

        /// <summary>
        /// The DNS servers this PC uses decide where every name it looks up really goes. A change
        /// nobody made is how DNS hijacking shows up. Several settings can be trusted, so switching
        /// a VPN on and off does not alert twice.
        /// </summary>
        private static CheckRow CheckDns(string current, bool approve, List<EventEntry> events, DateTime now,
            bool wasChanged, List<string> trusted, out bool changed)
        {
            const string label = "DNS SERVERS";
            changed = wasChanged;
            if (string.IsNullOrEmpty(current))
                return new CheckRow(label, wasChanged ? "CHANGED" : "not seen", wasChanged, !wasChanged);

            string first = current.Split(',')[0].Trim();
            int extra = current.Split(',').Length - 1;
            string shown = first + (extra > 0 ? " +" + extra : "");

            bool known = trusted.Contains(current, StringComparer.OrdinalIgnoreCase);
            if (trusted.Count == 0 || approve || known)
            {
                if (!known) trusted.Add(current);
                if (wasChanged && known && !approve) AddEvent(events, now, "dns", "info", "DNS servers are back to a trusted setting (" + current + ")");
                changed = false;
                return new CheckRow(label, shown, false, true);
            }

            if (!wasChanged)
                AddEvent(events, now, "dns", "high", "DNS servers changed to " + current + " (possible DNS hijack)", "T1557");
            changed = true;
            return new CheckRow(label, "CHANGED", true, false);
        }

        /// <summary>Flags an access point that starts broadcasting the home Wi-Fi name (an "evil twin").</summary>
        private static CheckRow CheckWifi(AppConfig config, NetFacts facts, bool approve, List<EventEntry> events, DateTime now,
            AppState state, out List<string> stillNew)
        {
            const string label = "WI-FI TWIN CHECK";
            stillNew = new List<string>();
            if (!config.WatchWifi) return new CheckRow(label, "off", false, true);
            if (facts.WifiFailed || facts.Wifi == null) return new CheckRow(label, "n/a", false, true);
            try
            {
                WifiScan scan = facts.Wifi;
                if (!scan.Available) return new CheckRow(label, "no wi-fi", false, true);
                if (scan.NeedsLocation) return new CheckRow(label, "needs location", false, true);
                return EvaluateWifi(config.HomeWifiName, scan, approve, events, now, state.NewAccessPoints, out stillNew);
            }
            catch
            {
                return new CheckRow(label, "n/a", false, true);
            }
        }

        /// <summary>The decision part of the Wi-Fi check, separate from running netsh so it can be tested.</summary>
        public static CheckRow EvaluateWifi(string homeName, WifiScan scan, bool approve, List<EventEntry> events, DateTime now,
            List<string> alreadyReported, out List<string> stillNew)
        {
            const string label = "WI-FI TWIN CHECK";
            stillNew = new List<string>();
            string name = string.IsNullOrWhiteSpace(homeName) ? scan.ConnectedName : homeName.Trim();
            if (string.IsNullOrEmpty(name)) return new CheckRow(label, "set name", false, true);

            List<string> seen;
            if (!scan.Networks.TryGetValue(name, out seen) || seen.Count == 0)
                return new CheckRow(label, "not in range", false, true);

            List<string> known = Store.Load<List<string>>(Store.BssidsPath) ?? new List<string>();
            string prefix = name + "|";
            bool firstTime = !known.Any(k => k.StartsWith(prefix, StringComparison.Ordinal));
            List<string> keys = seen.Select(mac => prefix + mac).ToList();
            List<string> fresh = keys.Where(k => !known.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();

            if (firstTime || approve)
            {
                if (fresh.Count > 0)
                {
                    known.AddRange(fresh);
                    Store.Save(Store.BssidsPath, known);
                    AddEvent(events, now, firstTime ? "baseline" : "approve", "info",
                        (firstTime ? "Wi-Fi baseline for '" : "approved access point(s) for '") + name + "': " + fresh.Count);
                }
                fresh = new List<string>();
            }

            foreach (string key in fresh)
            {
                if (!alreadyReported.Contains(key, StringComparer.OrdinalIgnoreCase))
                    AddEvent(events, now, "wifi", "high", "new access point using your Wi-Fi name '" + name + "': " + key.Substring(prefix.Length) + " (possible evil twin)", "T1557.004");
            }
            stillNew = fresh;
            int total = known.Count(k => k.StartsWith(prefix, StringComparison.Ordinal));
            return new CheckRow(label, total + " known | " + fresh.Count + " new", fresh.Count > 0, fresh.Count == 0);
        }

        private static CheckRow CheckRouter(AppConfig config, RouterSnapshot router, bool approve, List<EventEntry> events,
            DateTime now, AppState state)
        {
            const string label = "ROUTER FORWARDS";
            if (!config.WatchRouter) return new CheckRow(label, "off", false, true);
            if (!router.Found) return new CheckRow(label, "no upnp", false, true);
            return EvaluateForwards(router, approve, events, now, state.NewForwards);
        }

        public static CheckRow EvaluateForwards(RouterSnapshot router, bool approve, List<EventEntry> events, DateTime now, List<string> alreadyReported)
        {
            const string label = "ROUTER FORWARDS";
            List<string> known = Store.Load<List<string>>(Store.ForwardsPath);
            if (known == null)
            {
                known = router.Forwards.Select(f => f.Key).ToList();
                Store.Save(Store.ForwardsPath, known);
                AddEvent(events, now, "baseline", "info", "router baseline created with " + known.Count + " port forward(s)");
            }

            List<ForwardInfo> fresh = router.Forwards.Where(f => !known.Contains(f.Key, StringComparer.OrdinalIgnoreCase)).ToList();
            if (approve && fresh.Count > 0)
            {
                known.AddRange(fresh.Select(f => f.Key));
                Store.Save(Store.ForwardsPath, known);
                AddEvent(events, now, "approve", "info", "approved " + fresh.Count + " port forward(s)");
                fresh.Clear();
            }

            foreach (ForwardInfo forward in fresh)
            {
                forward.IsNew = true;
                if (!alreadyReported.Contains(forward.Key, StringComparer.OrdinalIgnoreCase))
                    AddEvent(events, now, "router", "high", "new port forward on the router: " + forward.Summary);
            }
            return new CheckRow(label, router.Forwards.Count + " | " + fresh.Count + " new", fresh.Count > 0, fresh.Count == 0);
        }

        // ---------------------------------------------- single-item approvals ---
        // These take the same lock as a scan, so they can never collide with one.

        public void ApprovePort(int port)
        {
            lock (runLock)
            {
                List<int> known = Store.Load<List<int>>(Store.PortsPath) ?? new List<int>();
                if (known.Contains(port)) return;
                known.Add(port);
                known.Sort();
                Store.Save(Store.PortsPath, known);
            }
        }

        public void ApproveAutorun(string key)
        {
            AddToBaseline(Store.AutorunsPath, key);
        }

        public void ApproveForward(string key)
        {
            AddToBaseline(Store.ForwardsPath, key);
        }

        private void AddToBaseline(string path, string key)
        {
            if (string.IsNullOrEmpty(key)) return;
            lock (runLock)
            {
                List<string> known = Store.Load<List<string>>(path) ?? new List<string>();
                if (known.Contains(key, StringComparer.OrdinalIgnoreCase)) return;
                known.Add(key);
                Store.Save(path, known);
            }
        }

        /// <summary>Marks one open detection as dealt with.</summary>
        public bool DismissDetection(string ts, string msg)
        {
            lock (runLock)
            {
                AppState state = Store.Load<AppState>(Store.StatePath);
                if (state == null) return false;
                state.Normalize();
                int index = state.OpenItems.FindIndex(e => e != null && e.Ts == ts && e.Msg == msg);
                if (index < 0) return false;
                state.OpenItems.RemoveAt(index);
                state.OpenDetections = state.OpenItems.Count;
                Store.Save(Store.StatePath, state);
                return true;
            }
        }

        // ---------------------------------------------------------------- LAN ---

        private class LanInfo
        {
            public IPAddress Ip;
            public uint IpNumber;
            public int Prefix;
            public IPAddress Gateway;
            public string Mac;
            public string Dns;
        }

        /// <summary>Replaceable so tests do not wait on real name lookups.</summary>
        public static Func<string, string> NameResolver = ResolveName;

        /// <summary>
        /// Compares what a sweep found with the stored device list: new devices, approvals, and
        /// watched devices that have stopped answering. "found" maps MAC to IP, or is null when
        /// no sweep could be done (then nothing is marked offline).
        /// </summary>
        public static CheckRow EvaluateLan(AppConfig config, Dictionary<string, string> found, string ownIp, string gatewayIp,
            bool approve, List<EventEntry> events, DateTime now, out List<DeviceRecord> devices)
        {
            const string label = "LAN DEVICES";
            devices = new List<DeviceRecord>();
            string today = now.ToString("s");

            lock (Store.DevicesLock)
            {
                List<DeviceRecord> stored = Store.Load<List<DeviceRecord>>(Store.DevicesPath);
                bool firstRun = stored == null;
                var byMac = new Dictionary<string, DeviceRecord>(StringComparer.OrdinalIgnoreCase);
                if (stored != null)
                {
                    foreach (DeviceRecord d in stored)
                    {
                        if (d == null) continue;
                        string mac = NormalizeMac(d.Mac);
                        if (mac == null || byMac.ContainsKey(mac)) continue;
                        d.Mac = mac;
                        d.Online = false;
                        if (d.Name == null) d.Name = "";
                        if (d.Ip == null) d.Ip = "";
                        devices.Add(d);
                        byMac[mac] = d;
                    }
                }

                if (found != null)
                {
                    foreach (KeyValuePair<string, string> pair in found)
                    {
                        DeviceRecord known;
                        if (byMac.TryGetValue(pair.Key, out known))
                        {
                            known.Ip = pair.Value;
                            known.LastSeen = today;
                            known.Online = true;
                            continue;
                        }

                        string name;
                        if (pair.Value == ownIp) name = Environment.MachineName;
                        else if (gatewayIp != null && pair.Value == gatewayIp) name = "gateway";
                        else name = NameResolver(pair.Value) ?? "";

                        var device = new DeviceRecord
                        {
                            Mac = pair.Key,
                            Ip = pair.Value,
                            Name = name,
                            Approved = firstRun, // the first scan becomes the baseline
                            FirstSeen = today,
                            LastSeen = today,
                            Online = true
                        };
                        devices.Add(device);
                        byMac[pair.Key] = device;
                        if (!firstRun)
                        {
                            string who = name.Length > 0 ? pair.Value + " (" + name + ")" : pair.Value;
                            AddEvent(events, now, "new-device", "high", "new device " + who + " " + pair.Key + MakerNote(pair.Key));
                        }
                    }

                    if (firstRun)
                        AddEvent(events, now, "baseline", "info", "device baseline created with " + devices.Count + " devices");

                    // Watched devices: one missed sweep is normal (a busy device can skip a reply), so it
                    // takes a few in a row before the alert, and it is raised once, not on every scan.
                    foreach (DeviceRecord d in devices)
                    {
                        if (d.Online)
                        {
                            if (d.Down && d.Watched) AddEvent(events, now, "device-watch", "info", "watched device " + Describe(d) + " is back online");
                            d.Down = false;
                            d.Missed = 0;
                            continue;
                        }
                        if (d.Missed < 1000) d.Missed++;
                        if (!d.Watched) { d.Down = false; continue; }
                        if (!d.Down && d.Missed >= config.WatchMisses)
                        {
                            d.Down = true;
                            AddEvent(events, now, "device-watch", "high", "watched device " + Describe(d) + " went offline");
                        }
                    }
                }

                int approvedNow = 0;
                if (approve)
                {
                    foreach (DeviceRecord d in devices)
                    {
                        if (!d.Approved) { d.Approved = true; approvedNow++; }
                    }
                    if (approvedNow > 0) AddEvent(events, now, "approve", "info", "approved " + approvedNow + " device(s)");
                }

                // With no sweep there is nothing new to record, and an empty file must not become the baseline.
                if (found != null || approvedNow > 0) Store.Save(Store.DevicesPath, devices);
            }

            int unknown = devices.Count(d => !d.Approved);
            int down = devices.Count(d => d.Watched && d.Down);
            string tail = down > 0 ? " | " + down + " down" : "";
            bool alert = unknown > 0 || down > 0;
            if (found == null)
            {
                string why = config.ScanLan ? "no lan" : "off";
                if (unknown > 0) why += " | " + unknown + " unknown";
                return new CheckRow(label, why + tail, alert, !alert);
            }

            int online = devices.Count(d => d.Online);
            return new CheckRow(label, online + " | " + unknown + " unknown" + tail, alert, !alert);
        }

        private static string Describe(DeviceRecord d)
        {
            return string.IsNullOrEmpty(d.Name) ? d.Ip + " " + d.Mac : d.Name + " (" + d.Ip + ")";
        }

        /// <summary>Who made the device, added to the alert so an unknown one is easier to place.</summary>
        private static string MakerNote(string mac)
        {
            string maker = Vendors.Lookup(mac);
            if (maker.Length == 0) return "";
            return maker == Vendors.PrivateLabel ? ", private address (often a phone or tablet)" : ", made by " + maker;
        }

        /// <summary>The physical adapter that is actually on the home network (never a VPN or VM adapter).</summary>
        private static LanInfo FindLan()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet
                    && nic.NetworkInterfaceType != NetworkInterfaceType.GigabitEthernet
                    && nic.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) continue;
                if (LooksVirtual(nic.Description) || LooksVirtual(nic.Name)) continue;

                IPInterfaceProperties props = nic.GetIPProperties();
                IPAddress gateway = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                if (gateway == null) continue;

                foreach (UnicastIPAddressInformation address in props.UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (!IsPrivate(address.Address)) continue; // never sweep a public range

                    int prefix = address.IPv4Mask == null ? 24 : PrefixLength(address.IPv4Mask);
                    return new LanInfo
                    {
                        Ip = address.Address,
                        IpNumber = ToNumber(address.Address),
                        Prefix = prefix,
                        Gateway = gateway,
                        Mac = FormatMac(nic.GetPhysicalAddress().GetAddressBytes()),
                        Dns = string.Join(", ", props.DnsAddresses
                            .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                            .Select(a => a.ToString())
                            .OrderBy(a => a, StringComparer.Ordinal))
                    };
                }
            }
            return null;
        }

        private static bool LooksVirtual(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            string t = text.ToLowerInvariant();
            string[] hints = { "virtual", "vmware", "hyper-v", "vethernet", "vpn", "tap-", "wireguard", "wintun", "tunnel", "loopback", "bluetooth" };
            return hints.Any(h => t.Contains(h));
        }

        /// <summary>ARP every address on the subnet. A device can ignore pings, but it has to answer ARP to be on the network at all.</summary>
        private static Dictionary<string, string> Sweep(LanInfo lan)
        {
            int prefix = lan.Prefix;
            if (prefix < 22 || prefix > 30) prefix = 24; // never sweep more than 1022 addresses
            uint size = 1u << (32 - prefix);
            uint network = lan.IpNumber & ~(size - 1);
            uint first = network + 1;
            uint last = network + size - 2;

            var targets = new ConcurrentQueue<uint>();
            for (uint n = first; n <= last; n++)
            {
                if (n != lan.IpNumber) targets.Enqueue(n);
            }

            var found = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var workers = new List<Thread>();
            for (int i = 0; i < 64; i++)
            {
                var worker = new Thread(() =>
                {
                    uint target;
                    while (targets.TryDequeue(out target))
                    {
                        try
                        {
                            IPAddress address = FromNumber(target);
                            byte[] mac = new byte[6];
                            int length = mac.Length;
                            uint destination = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
                            if (Native.SendARP(destination, 0, mac, ref length) == 0 && length == 6)
                            {
                                string text = FormatMac(mac);
                                if (text != null) found[text] = address.ToString();
                            }
                        }
                        catch { }
                    }
                }, 256 * 1024);
                worker.IsBackground = true;
                worker.Start();
                workers.Add(worker);
            }
            foreach (Thread worker in workers) worker.Join(30000);

            var result = new Dictionary<string, string>(found, StringComparer.OrdinalIgnoreCase);
            if (lan.Mac != null) result[lan.Mac] = lan.Ip.ToString(); // this PC never answers its own ARP
            return result;
        }

        private static string ResolveName(string ip)
        {
            try
            {
                var lookup = Dns.GetHostEntryAsync(ip);
                if (lookup.Wait(1500) && lookup.Result != null)
                {
                    string name = lookup.Result.HostName;
                    if (!string.IsNullOrEmpty(name) && name != ip) return name;
                }
            }
            catch { }
            return "";
        }

        // ------------------------------------------------------ watched hosts ---

        private static CheckRow CheckHost(WatchedHost host, AppConfig config, DateTime now)
        {
            string label = string.IsNullOrWhiteSpace(host.Name) ? host.Host : host.Name;
            int port = host.Port > 0 && host.Port < 65536 ? host.Port : 443;
            try
            {
                using (var client = new TcpClient())
                {
                    Stopwatch timer = Stopwatch.StartNew();
                    var connect = client.ConnectAsync(host.Host, port);
                    if (!connect.Wait(2500)) return new CheckRow(label, "DOWN", true, false);
                    timer.Stop();

                    if (!host.Tls) return new CheckRow(label, "up | " + timer.ElapsedMilliseconds + "ms", false, true);

                    // Any certificate is accepted because only its expiry date is read (a Proxmox box
                    // normally has a self-signed one). Nothing is sent over the connection.
                    using (var ssl = new SslStream(client.GetStream(), false, (sender, cert, chain, errors) => true))
                    {
                        try
                        {
                            ssl.AuthenticateAsClient(host.Host);
                            var certificate = new X509Certificate2(ssl.RemoteCertificate);
                            int days = (int)Math.Floor((certificate.NotAfter - now).TotalDays);
                            return new CheckRow(label, "up | cert " + days + "d", days < config.CertWarnDays, true);
                        }
                        catch
                        {
                            return new CheckRow(label, "up | tls error", true, true);
                        }
                    }
                }
            }
            catch
            {
                return new CheckRow(label, "DOWN", true, false);
            }
        }

        // ------------------------------------------------------------ helpers ---

        private static uint ToNumber(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress FromNumber(uint value)
        {
            return new IPAddress(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });
        }

        private static int PrefixLength(IPAddress mask)
        {
            uint m = ToNumber(mask);
            int bits = 0;
            while ((m & 0x80000000u) != 0) { bits++; m <<= 1; }
            return bits;
        }

        private static bool IsPrivate(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 10 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31);
        }

        /// <summary>AA-BB-CC-DD-EE-FF, or null for an empty or broadcast address.</summary>
        private static string FormatMac(byte[] mac)
        {
            if (mac == null || mac.Length != 6) return null;
            if (mac.All(x => x == 0) || mac.All(x => x == 0xFF)) return null;
            return BitConverter.ToString(mac);
        }

        public static string NormalizeMac(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            string hex = new string(text.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (hex.Length != 12 || hex == "000000000000" || hex == "FFFFFFFFFFFF") return null;
            return string.Join("-", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
        }
    }
}
