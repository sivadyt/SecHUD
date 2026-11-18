using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace SecHUD
{
    /// <summary>
    /// Lists the places software uses to start itself: Run keys, startup folders, services and
    /// scheduled tasks. Compared with a baseline, anything new is how persistence shows up.
    /// </summary>
    public static class Autoruns
    {
        private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunOncePath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";

        public static List<AutorunItem> Collect()
        {
            var items = new List<AutorunItem>();
            Guard(() => ReadRunKey(items, RegistryHive.CurrentUser, RegistryView.Default, RunPath, "HKCU"));
            Guard(() => ReadRunKey(items, RegistryHive.CurrentUser, RegistryView.Default, RunOncePath, "HKCU once"));
            Guard(() => ReadRunKey(items, RegistryHive.LocalMachine, RegistryView.Registry64, RunPath, "HKLM"));
            Guard(() => ReadRunKey(items, RegistryHive.LocalMachine, RegistryView.Registry64, RunOncePath, "HKLM once"));
            Guard(() => ReadRunKey(items, RegistryHive.LocalMachine, RegistryView.Registry32, RunPath, "HKLM 32"));
            Guard(() => ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.Startup)));
            Guard(() => ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)));
            Guard(() => ReadServices(items));
            Guard(() => ReadTasks(items));

            // One entry per key, so a duplicate registry view cannot double-count.
            return items.GroupBy(i => i.Key, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        }

        /// <summary>Marks what is not in the baseline and returns those items.</summary>
        public static List<AutorunItem> MarkNew(List<AutorunItem> current, IEnumerable<string> known)
        {
            var baseline = new HashSet<string>(known ?? new string[0], StringComparer.OrdinalIgnoreCase);
            var fresh = new List<AutorunItem>();
            foreach (AutorunItem item in current)
            {
                item.IsNew = !baseline.Contains(item.Key);
                if (item.IsNew) fresh.Add(item);
            }
            return fresh;
        }

        // ------------------------------------------------------------ removal ---

        /// <summary>Which registry key a Run entry such as "HKCU once\Name" lives in.</summary>
        public static bool ParseRunName(string name, out RegistryHive hive, out RegistryView view, out string path, out string valueName)
        {
            hive = RegistryHive.CurrentUser;
            view = RegistryView.Default;
            path = RunPath;
            valueName = "";
            int slash = (name ?? "").IndexOf('\\');
            if (slash <= 0 || slash == name.Length - 1) return false;

            valueName = name.Substring(slash + 1);
            switch (name.Substring(0, slash))
            {
                case "HKCU": return true;
                case "HKCU once": path = RunOncePath; return true;
                case "HKLM": hive = RegistryHive.LocalMachine; view = RegistryView.Registry64; return true;
                case "HKLM once": hive = RegistryHive.LocalMachine; view = RegistryView.Registry64; path = RunOncePath; return true;
                case "HKLM 32": hive = RegistryHive.LocalMachine; view = RegistryView.Registry32; return true;
                default: return false;
            }
        }

        /// <summary>
        /// Takes a startup item out of Windows. A record of what it was is kept in the
        /// removed-autoruns folder first, so nothing is lost: Run entries are logged with their
        /// command, startup files are moved there, and scheduled tasks are exported as XML.
        /// </summary>
        public static bool Remove(AutorunItem item, out string message)
        {
            message = "";
            if (item == null) { message = "nothing selected"; return false; }
            try
            {
                Directory.CreateDirectory(Store.QuarantineDir);
                string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");

                switch (item.Kind)
                {
                    case "run":
                        RegistryHive hive; RegistryView view; string path, valueName;
                        if (!ParseRunName(item.Name, out hive, out view, out path, out valueName))
                        {
                            message = "could not work out where this entry lives";
                            return false;
                        }
                        string raw, valueKind;
                        bool existed = ReadRegistryValue(hive, view, path, valueName, out raw, out valueKind);
                        if (!existed || !DeleteRegistryValue(hive, view, path, valueName))
                        {
                            message = "it was already gone";
                            return true;
                        }
                        Record(item, stamp, "", raw, valueKind);
                        LogRemoval(item, "registry value deleted");
                        message = "removed the Run entry";
                        return true;

                    case "startup":
                        if (!File.Exists(item.Command))
                        {
                            message = "it was already gone";
                            return true;
                        }
                        string target = Path.Combine(Store.QuarantineDir, stamp + "-" + Path.GetFileName(item.Command));
                        File.Move(item.Command, target);
                        Record(item, stamp, target, "", "");
                        LogRemoval(item, "file moved to " + target);
                        message = "moved the startup file out";
                        return true;

                    case "task":
                        return RemoveTask(item, stamp, out message);

                    case "service":
                        message = "Services can only be changed by an administrator. Open services.msc as administrator, or run: sc config \"" + item.Name + "\" start= disabled";
                        return false;

                    default:
                        message = "this kind of item cannot be removed from here";
                        return false;
                }
            }
            catch (UnauthorizedAccessException)
            {
                message = "Windows refused: this one needs administrator rights. Close SecHUD from the tray, then start SecHUD.exe with Run as administrator and try again.";
                return false;
            }
            catch (System.Security.SecurityException)
            {
                message = "Windows refused: this one needs administrator rights. Close SecHUD from the tray, then start SecHUD.exe with Run as administrator and try again.";
                return false;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        /// <summary>True when the value existed and was deleted.</summary>
        public static bool DeleteRegistryValue(RegistryHive hive, RegistryView view, string path, string valueName)
        {
            using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view))
            using (RegistryKey key = root.OpenSubKey(path, true))
            {
                if (key == null || key.GetValue(valueName) == null) return false;
                key.DeleteValue(valueName, false);
                return true;
            }
        }

        private static bool RemoveTask(AutorunItem item, string stamp, out string message)
        {
            Type type = Type.GetTypeFromProgID("Schedule.Service");
            if (type == null) { message = "the Task Scheduler is not available"; return false; }
            dynamic scheduler = Activator.CreateInstance(type);
            scheduler.Connect();

            string full = item.Name ?? "";
            int slash = full.LastIndexOf('\\');
            string folderPath = slash <= 0 ? "\\" : full.Substring(0, slash);
            string taskName = slash < 0 ? full : full.Substring(slash + 1);

            dynamic folder = scheduler.GetFolder(folderPath);
            dynamic task = folder.GetTask(taskName);

            // Keep the full definition. It can be put back with: schtasks /create /tn "name" /xml "file"
            string safe = new string(taskName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray());
            string backup = Path.Combine(Store.QuarantineDir, stamp + "-task-" + safe + ".xml");
            File.WriteAllText(backup, Convert.ToString(task.Xml) ?? "");

            folder.DeleteTask(taskName, 0);
            Record(item, stamp, backup, "", "");
            LogRemoval(item, "task deleted, definition saved to " + backup);
            message = "deleted the scheduled task";
            return true;
        }

        /// <summary>The raw (unexpanded) text of a registry value and its kind. False when it does not exist.</summary>
        public static bool ReadRegistryValue(RegistryHive hive, RegistryView view, string path, string valueName, out string raw, out string kind)
        {
            raw = "";
            kind = "";
            using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view))
            using (RegistryKey key = root.OpenSubKey(path))
            {
                if (key == null) return false;
                object value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (value == null) return false;
                raw = Convert.ToString(value) ?? "";
                kind = key.GetValueKind(valueName).ToString();
                return true;
            }
        }

        // ------------------------------------------------------------ restore ---

        private static readonly object RemovedLock = new object();

        /// <summary>Everything that has been denied, oldest first. Items denied by an older version are read from its log.</summary>
        public static List<RemovedRecord> LoadRemoved()
        {
            lock (RemovedLock)
            {
                List<RemovedRecord> records = Store.Load<List<RemovedRecord>>(Store.RemovedPath);
                if (records != null) return records.Where(r => r != null).ToList();

                records = new List<RemovedRecord>();
                try
                {
                    if (File.Exists(Store.RemovedLogPath))
                    {
                        foreach (string line in File.ReadAllLines(Store.RemovedLogPath))
                        {
                            RemovedRecord parsed = ParseLogLine(line);
                            if (parsed != null) records.Add(parsed);
                        }
                    }
                }
                catch { }
                return records;
            }
        }

        /// <summary>One line of the older removed.log: time, kind, name, command, what was done.</summary>
        public static RemovedRecord ParseLogLine(string line)
        {
            string[] parts = (line ?? "").Split('\t');
            if (parts.Length < 5 || parts[1].Length == 0 || parts[2].Length == 0) return null;
            if (parts[4] == "restored") return null;
            string backup = "";
            foreach (string marker in new[] { "file moved to ", "definition saved to " })
            {
                int at = parts[4].IndexOf(marker, StringComparison.Ordinal);
                if (at >= 0) backup = parts[4].Substring(at + marker.Length).Trim();
            }
            return new RemovedRecord { Id = parts[0] + "|" + parts[1] + "|" + parts[2], Ts = parts[0], Kind = parts[1], Name = parts[2], Command = parts[3], Backup = backup, ValueKind = "" };
        }

        /// <summary>Saved before the log line is written, so the log import can never count the same item twice.</summary>
        private static void Record(AutorunItem item, string stamp, string backup, string raw, string valueKind)
        {
            try
            {
                lock (RemovedLock)
                {
                    List<RemovedRecord> records = LoadRemoved();
                    records.Add(new RemovedRecord
                    {
                        Id = stamp + "|" + item.Kind + "|" + item.Name,
                        Ts = DateTime.Now.ToString("s"),
                        Kind = item.Kind,
                        Name = item.Name,
                        // A Run entry is put back exactly as it was written, variables and all.
                        Command = item.Kind == "run" && !string.IsNullOrEmpty(raw) ? raw : (item.Command ?? ""),
                        Backup = backup ?? "",
                        ValueKind = valueKind ?? ""
                    });
                    if (records.Count > 200) records.RemoveRange(0, records.Count - 200);
                    Store.Save(Store.RemovedPath, records);
                }
            }
            catch { }
        }

        /// <summary>
        /// Puts a denied startup item back where it was. Nothing existing is overwritten: if
        /// something with the same name is already there, the restore is refused.
        /// </summary>
        public static bool Restore(RemovedRecord record, out string message)
        {
            message = "";
            if (record == null) { message = "nothing selected"; return false; }
            try
            {
                switch (record.Kind)
                {
                    case "run":
                        RegistryHive hive; RegistryView view; string path, valueName;
                        if (!ParseRunName(record.Name, out hive, out view, out path, out valueName))
                        {
                            message = "could not work out where this entry lived";
                            return false;
                        }
                        using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view))
                        using (RegistryKey key = root.CreateSubKey(path))
                        {
                            if (key == null) { message = "could not open the Run key"; return false; }
                            if (key.GetValue(valueName) != null) { message = "an entry with that name already exists"; return false; }
                            bool expand = string.Equals(record.ValueKind, "ExpandString", StringComparison.OrdinalIgnoreCase);
                            key.SetValue(valueName, record.Command ?? "", expand ? RegistryValueKind.ExpandString : RegistryValueKind.String);
                        }
                        message = "put the Run entry back";
                        break;

                    case "startup":
                        if (string.IsNullOrEmpty(record.Backup) || !File.Exists(record.Backup))
                        {
                            message = "the saved copy is no longer in the removed-autoruns folder";
                            return false;
                        }
                        if (File.Exists(record.Command)) { message = "a file with that name is already in the startup folder"; return false; }
                        File.Move(record.Backup, record.Command);
                        message = "moved the startup file back";
                        break;

                    case "task":
                        if (!RestoreTask(record, out message)) return false;
                        break;

                    default:
                        message = "this kind of item cannot be put back from here";
                        return false;
                }
                MarkRestored(record);
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                message = "Windows refused: this one needs administrator rights. Close SecHUD from the tray, then start SecHUD.exe with Run as administrator and try again.";
                return false;
            }
            catch (System.Security.SecurityException)
            {
                message = "Windows refused: this one needs administrator rights. Close SecHUD from the tray, then start SecHUD.exe with Run as administrator and try again.";
                return false;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        /// <summary>The baseline key the item will have once it is back, so it is not flagged as new again.</summary>
        public static string KeyAfterRestore(RemovedRecord record)
        {
            if (record == null) return "";
            if (record.Kind != "run") return record.Kind + "|" + record.Name;
            string command = record.Command ?? "";
            // The scanner reads Run values with their variables filled in, so the key has to match that.
            if (string.Equals(record.ValueKind, "ExpandString", StringComparison.OrdinalIgnoreCase))
                command = Environment.ExpandEnvironmentVariables(command);
            return "run|" + record.Name + "|" + command;
        }

        private static bool RestoreTask(RemovedRecord record, out string message)
        {
            if (string.IsNullOrEmpty(record.Backup) || !File.Exists(record.Backup))
            {
                message = "the saved task definition is no longer in the removed-autoruns folder";
                return false;
            }
            string name = record.Name ?? "";
            if (name.Length == 0 || name.IndexOf('"') >= 0 || record.Backup.IndexOf('"') >= 0)
            {
                message = "the task name cannot be used safely";
                return false;
            }

            // schtasks is part of Windows. Without /f it refuses to overwrite a task that already exists.
            var start = new ProcessStartInfo("schtasks.exe", "/create /tn \"" + name + "\" /xml \"" + record.Backup + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true
            };
            using (Process process = Process.Start(start))
            {
                string error = process.StandardError.ReadToEnd();
                process.StandardOutput.ReadToEnd();
                if (!process.WaitForExit(20000))
                {
                    try { process.Kill(); } catch { }
                    message = "the Task Scheduler did not answer";
                    return false;
                }
                if (process.ExitCode != 0)
                {
                    message = error.Trim().Length > 0 ? error.Trim() : "the Task Scheduler refused (exit code " + process.ExitCode + ")";
                    return false;
                }
            }
            message = "created the scheduled task again";
            return true;
        }

        private static void MarkRestored(RemovedRecord record)
        {
            lock (RemovedLock)
            {
                List<RemovedRecord> records = LoadRemoved();
                RemovedRecord match = records.FirstOrDefault(r => r.Id == record.Id);
                if (match == null) { record.Restored = true; records.Add(record); }
                else match.Restored = true;
                record.Restored = true;
                Store.Save(Store.RemovedPath, records);
            }
            Store.AppendLine(Store.RemovedLogPath,
                DateTime.Now.ToString("s") + "\t" + record.Kind + "\t" + record.Name + "\t" + record.Command + "\trestored",
                5L * 1024 * 1024);
        }

        private static void LogRemoval(AutorunItem item, string action)
        {
            Store.AppendLine(Store.RemovedLogPath,
                DateTime.Now.ToString("s") + "\t" + item.Kind + "\t" + item.Name + "\t" + item.Command + "\t" + action,
                5L * 1024 * 1024);
        }

        private static void Guard(Action action)
        {
            try { action(); } catch { }
        }

        private static void ReadRunKey(List<AutorunItem> items, RegistryHive hive, RegistryView view, string path, string label)
        {
            using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view))
            using (RegistryKey key = root.OpenSubKey(path))
            {
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    string command = Convert.ToString(key.GetValue(name)) ?? "";
                    items.Add(new AutorunItem { Kind = "run", Name = label + "\\" + name, Command = command, Technique = "T1547.001" });
                }
            }
        }

        private static void ReadStartupFolder(List<AutorunItem> items, string folder)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            foreach (string file in Directory.GetFiles(folder))
            {
                string name = Path.GetFileName(file);
                if (string.Equals(name, "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                items.Add(new AutorunItem { Kind = "startup", Name = name, Command = file, Technique = "T1547.001" });
            }
        }

        private static void ReadServices(List<AutorunItem> items)
        {
            using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey services = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
            {
                if (services == null) return;
                foreach (string name in services.GetSubKeyNames())
                {
                    try
                    {
                        using (RegistryKey service = services.OpenSubKey(name))
                        {
                            if (service == null) continue;
                            int type = Convert.ToInt32(service.GetValue("Type", 0));
                            int start = Convert.ToInt32(service.GetValue("Start", 4));
                            if ((type & 0x30) == 0) continue;  // kernel and file system drivers
                            if ((type & 0x80) != 0) continue;  // per-user service copies, renamed at every logon
                            if (start == 4) continue;          // disabled
                            string image = Convert.ToString(service.GetValue("ImagePath")) ?? "";
                            items.Add(new AutorunItem { Kind = "service", Name = name, Command = image, Technique = "T1543.003" });
                        }
                    }
                    catch { }
                }
            }
        }

        private static void ReadTasks(List<AutorunItem> items)
        {
            // The Task Scheduler's own COM interface lists every task this account may see, no admin needed.
            Type type = Type.GetTypeFromProgID("Schedule.Service");
            if (type == null) return;
            dynamic scheduler = Activator.CreateInstance(type);
            scheduler.Connect();
            WalkTaskFolder(scheduler.GetFolder("\\"), items, 0);
        }

        private static void WalkTaskFolder(dynamic folder, List<AutorunItem> items, int depth)
        {
            if (depth > 8) return;
            try
            {
                foreach (dynamic task in folder.GetTasks(1)) // 1 = include hidden tasks
                {
                    string path = Convert.ToString(task.Path) ?? "";
                    // Windows creates and removes its own tasks under this folder all the time.
                    if (path.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase)) continue;
                    items.Add(new AutorunItem { Kind = "task", Name = path, Command = "", Technique = "T1053.005" });
                }
            }
            catch { }
            try
            {
                foreach (dynamic sub in folder.GetFolders(0))
                {
                    WalkTaskFolder(sub, items, depth + 1);
                }
            }
            catch { }
        }
    }
}
