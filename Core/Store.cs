using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;

namespace SecHUD
{
    /// <summary>
    /// File storage. Everything lives as plain JSON under %LOCALAPPDATA%\SecHUD so it can be
    /// read, edited, or thrown away without the app.
    /// </summary>
    public static class Store
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        /// <summary>Held while devices.json is read, changed and written, so a rename can't be lost to a scan.</summary>
        public static readonly object DevicesLock = new object();

        private static string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecHUD");

        public static string Dir { get { return dir; } }

        /// <summary>Points storage somewhere else. The tests use this so they never touch real data.</summary>
        public static void UseDirectory(string path)
        {
            dir = path;
        }

        public static string ConfigPath { get { return Path.Combine(Dir, "config.json"); } }
        public static string DevicesPath { get { return Path.Combine(Dir, "devices.json"); } }
        public static string PortsPath { get { return Path.Combine(Dir, "known-ports.json"); } }
        public static string StatePath { get { return Path.Combine(Dir, "state.json"); } }
        public static string EventsPath { get { return Path.Combine(Dir, "events.log"); } }
        public static string ErrorPath { get { return Path.Combine(Dir, "error.log"); } }
        public static string AutorunsPath { get { return Path.Combine(Dir, "known-autoruns.json"); } }
        public static string HistoryPath { get { return Path.Combine(Dir, "history.csv"); } }
        public static string SyslogPath { get { return Path.Combine(Dir, "syslog.log"); } }
        public static string RulesPath { get { return Path.Combine(Dir, "rules.json"); } }
        public static string AccountsPath { get { return Path.Combine(Dir, "known-accounts.json"); } }
        public static string ForwardsPath { get { return Path.Combine(Dir, "known-forwards.json"); } }
        public static string BssidsPath { get { return Path.Combine(Dir, "known-access-points.json"); } }

        /// <summary>Where denied startup items are kept so they can be put back.</summary>
        public static string QuarantineDir { get { return Path.Combine(Dir, "removed-autoruns"); } }
        public static string RemovedLogPath { get { return Path.Combine(QuarantineDir, "removed.log"); } }
        public static string RemovedPath { get { return Path.Combine(QuarantineDir, "removed.json"); } }
        public static string WindowPath { get { return Path.Combine(Dir, "window.json"); } }
        public static string SummaryPath { get { return Path.Combine(Dir, "summary.json"); } }

        public static void EnsureDir()
        {
            Directory.CreateDirectory(Dir);
        }

        public static T Load<T>(string path) where T : class
        {
            try
            {
                if (!File.Exists(path)) return null;
                string text = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(text)) return null;
                return FromJson<T>(text);
            }
            catch
            {
                return null;
            }
        }

        public static void Save<T>(string path, T value)
        {
            EnsureDir();
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder)) Directory.CreateDirectory(folder);
            WriteAtomic(path, Pretty(ToJson(value)) + Environment.NewLine);
        }

        public static AppConfig LoadConfig()
        {
            AppConfig config = Load<AppConfig>(ConfigPath);
            if (config == null)
            {
                config = AppConfig.CreateDefault();
                if (!File.Exists(ConfigPath))
                {
                    try { Save(ConfigPath, config); } catch { }
                }
            }
            config.Normalize();
            return config;
        }

        public static void AppendEvents(IList<EventEntry> events)
        {
            if (events == null || events.Count == 0) return;
            try
            {
                EnsureDir();
                var info = new FileInfo(EventsPath);
                if (info.Exists && info.Length > 5 * 1024 * 1024)
                {
                    string old = EventsPath + ".old";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(EventsPath, old);
                }
                var sb = new StringBuilder();
                foreach (EventEntry e in events) sb.Append(ToJson(e)).Append(Environment.NewLine);
                File.AppendAllText(EventsPath, sb.ToString(), Utf8NoBom);
            }
            catch
            {
                // The log is a convenience. A failed write must never stop a scan.
            }
        }

        /// <summary>Newest first.</summary>
        public static List<EventEntry> ReadRecentEvents(int max)
        {
            var result = new List<EventEntry>();
            try
            {
                if (!File.Exists(EventsPath)) return result;
                string[] lines = File.ReadAllLines(EventsPath);
                for (int i = lines.Length - 1; i >= 0 && result.Count < max; i--)
                {
                    if (string.IsNullOrWhiteSpace(lines[i])) continue;
                    try
                    {
                        EventEntry e = FromJson<EventEntry>(lines[i]);
                        if (e != null) result.Add(e);
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        public static void LogError(string where, Exception ex)
        {
            try
            {
                EnsureDir();
                File.AppendAllText(ErrorPath,
                    DateTime.Now.ToString("s") + " " + where + ": " + ex + Environment.NewLine, Utf8NoBom);
            }
            catch { }
        }

        public static string ToJson<T>(T value)
        {
            var serializer = new DataContractJsonSerializer(typeof(T));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, value);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static T FromJson<T>(string json) where T : class
        {
            var serializer = new DataContractJsonSerializer(typeof(T));
            using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                return serializer.ReadObject(ms) as T;
            }
        }

        /// <summary>Appends one line, rolling the file over to .old once it passes maxBytes.</summary>
        public static void AppendLine(string path, string line, long maxBytes)
        {
            try
            {
                EnsureDir();
                var info = new FileInfo(path);
                if (info.Exists && info.Length > maxBytes)
                {
                    string old = path + ".old";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(path, old);
                }
                File.AppendAllText(path, line + Environment.NewLine, Utf8NoBom);
            }
            catch { }
        }

        private static void WriteAtomic(string path, string text)
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, text, Utf8NoBom);
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                    return;
                }
                catch (IOException)
                {
                    if (attempt >= 5) throw;
                    Thread.Sleep(150);
                }
            }
        }

        /// <summary>Indents compact JSON so the files are comfortable to read and edit by hand.</summary>
        public static string Pretty(string json)
        {
            var sb = new StringBuilder(json.Length * 2);
            int indent = 0;
            bool inString = false;
            bool escaped = false;

            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inString)
                {
                    sb.Append(c);
                    if (escaped) escaped = false;
                    else if (c == '\\') escaped = true;
                    else if (c == '"') inString = false;
                    continue;
                }

                switch (c)
                {
                    case '"':
                        inString = true;
                        sb.Append(c);
                        break;
                    case '{':
                    case '[':
                        int next = i + 1;
                        while (next < json.Length && char.IsWhiteSpace(json[next])) next++;
                        if (next < json.Length && (json[next] == '}' || json[next] == ']'))
                        {
                            sb.Append(c).Append(json[next]);
                            i = next;
                        }
                        else
                        {
                            sb.Append(c);
                            indent++;
                            NewLine(sb, indent);
                        }
                        break;
                    case '}':
                    case ']':
                        indent--;
                        NewLine(sb, indent);
                        sb.Append(c);
                        break;
                    case ',':
                        sb.Append(c);
                        NewLine(sb, indent);
                        break;
                    case ':':
                        sb.Append(": ");
                        break;
                    default:
                        if (!char.IsWhiteSpace(c)) sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        private static void NewLine(StringBuilder sb, int indent)
        {
            sb.Append(Environment.NewLine);
            sb.Append(' ', Math.Max(0, indent) * 2);
        }
    }
}
