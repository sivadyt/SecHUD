using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace SecHUD
{
    /// <summary>A Windows event reduced to what the rules need.</summary>
    public class RawEvent
    {
        public string Log { get; set; }
        public int Id { get; set; }
        public DateTime TimeUtc { get; set; }
        public List<string> Props { get; set; }

        public RawEvent()
        {
            Props = new List<string>();
        }

        /// <summary>Property by position, or "" when the event has fewer.</summary>
        public string P(int index)
        {
            return index >= 0 && index < Props.Count ? (Props[index] ?? "") : "";
        }
    }

    /// <summary>Where events come from. The real one reads the Windows event log; tests feed fakes.</summary>
    public interface IEventSource
    {
        List<RawEvent> Read(string log, int[] ids, DateTime sinceUtc, int max);
    }

    public class WindowsEventSource : IEventSource
    {
        public List<RawEvent> Read(string log, int[] ids, DateTime sinceUtc, int max)
        {
            var list = new List<RawEvent>();
            string idFilter = string.Join(" or ", ids.Select(i => "EventID=" + i));
            string since = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            string xpath = "*[System[(" + idFilter + ") and TimeCreated[@SystemTime>='" + since + "']]]";

            var query = new EventLogQuery(log, PathType.LogName, xpath);
            using (var reader = new EventLogReader(query))
            {
                EventRecord record;
                while (list.Count < max && (record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        var raw = new RawEvent { Log = log, Id = record.Id };
                        raw.TimeUtc = (record.TimeCreated ?? DateTime.Now).ToUniversalTime();
                        try
                        {
                            foreach (EventProperty property in record.Properties)
                                raw.Props.Add(property.Value == null ? "" : property.Value.ToString());
                        }
                        catch { }
                        list.Add(raw);
                    }
                }
            }
            return list;
        }
    }

    /// <summary>One detection: which event, how serious, which ATT&amp;CK technique, and how to word it.</summary>
    public class DetectionRule
    {
        public string Log { get; set; }
        public int Id { get; set; }
        public string Technique { get; set; }
        public string Severity { get; set; }
        /// <summary>Returns the message, or null when this particular event should be ignored.</summary>
        public Func<RawEvent, string> Describe { get; set; }
    }

    /// <summary>
    /// Detection rules over Windows events. Each rule is one event id mapped to the attacker
    /// behaviour it usually means, tagged with its MITRE ATT&amp;CK technique.
    /// </summary>
    public static class Detector
    {
        public const string Security = "Security";
        public const string SystemLog = "System";
        public const string Defender = "Microsoft-Windows-Windows Defender/Operational";
        private const string AdministratorsSid = "S-1-5-32-544";

        public static readonly DetectionRule[] Rules =
        {
            new DetectionRule { Log = Security, Id = 4720, Technique = "T1136.001", Severity = "high",
                Describe = e => "new local user account created: " + Name(e.P(0)) },

            new DetectionRule { Log = Security, Id = 4732, Technique = "T1098", Severity = "high",
                Describe = e => e.Props.Any(p => p == AdministratorsSid)
                    ? "account added to the Administrators group: " + Name(e.P(0) == "-" || e.P(0).Length == 0 ? e.P(1) : e.P(0))
                    : null },

            new DetectionRule { Log = Security, Id = 1102, Technique = "T1070.001", Severity = "high",
                Describe = e => "the Security event log was cleared" },

            new DetectionRule { Log = SystemLog, Id = 104, Technique = "T1070.001", Severity = "high",
                Describe = e => "an event log was cleared: " + Name(e.P(2)) },

            new DetectionRule { Log = Security, Id = 4698, Technique = "T1053.005", Severity = "medium",
                Describe = e => "scheduled task created: " + Name(e.P(4)) },

            new DetectionRule { Log = SystemLog, Id = 7045, Technique = "T1543.003", Severity = "medium",
                Describe = e => "new service installed: " + Name(e.P(0)) + " (" + Trim(e.P(1), 80) + ")" },

            new DetectionRule { Log = Security, Id = 4624, Technique = "T1021.001", Severity = "info",
                Describe = e => e.P(8) == "10"
                    ? "remote desktop logon by " + Name(e.P(5)) + " from " + Name(e.P(18))
                    : null },

            new DetectionRule { Log = Defender, Id = 1116, Technique = "", Severity = "high",
                Describe = e => "Defender detected malware: " + Name(e.P(7)) },

            new DetectionRule { Log = Defender, Id = 5001, Technique = "T1562.001", Severity = "high",
                Describe = e => "Defender real-time protection was disabled" }
        };

        /// <summary>Applies the rules (built-in ones when none are given) to a batch of events.</summary>
        public static List<EventEntry> Evaluate(IEnumerable<RawEvent> events, IList<DetectionRule> rules = null)
        {
            if (rules == null) rules = Rules;
            var found = new List<EventEntry>();
            foreach (RawEvent e in events.OrderBy(x => x.TimeUtc))
            {
                foreach (DetectionRule rule in rules.Where(r => string.Equals(r.Log, e.Log, StringComparison.OrdinalIgnoreCase) && r.Id == e.Id))
                {
                    string message;
                    try { message = rule.Describe(e); } catch { message = null; }
                    if (message == null) continue;

                    found.Add(new EventEntry
                    {
                        Ts = e.TimeUtc.ToLocalTime().ToString("s"),
                        Type = "detection",
                        Severity = rule.Severity,
                        Msg = message,
                        Technique = string.IsNullOrEmpty(rule.Technique) ? null : rule.Technique
                    });
                }
            }
            return found;
        }

        /// <summary>
        /// Reads rules.json and turns each enabled entry into a rule. On first use it writes the
        /// file with two disabled examples, so there is something to copy from.
        /// </summary>
        public static List<DetectionRule> LoadCustomRules()
        {
            var result = new List<DetectionRule>();
            List<CustomRule> custom = Store.Load<List<CustomRule>>(Store.RulesPath);
            if (custom == null)
            {
                if (!System.IO.File.Exists(Store.RulesPath))
                {
                    try { Store.Save(Store.RulesPath, SampleRules()); } catch { }
                }
                return result;
            }

            foreach (CustomRule c in custom)
            {
                DetectionRule rule = FromCustom(c);
                if (rule != null) result.Add(rule);
            }
            return result;
        }

        /// <summary>Null when the entry is disabled or incomplete.</summary>
        public static DetectionRule FromCustom(CustomRule c)
        {
            if (c == null || !c.Enabled || c.Id <= 0 || string.IsNullOrWhiteSpace(c.Log) || string.IsNullOrWhiteSpace(c.Message)) return null;

            string severity = (c.Severity ?? "").Trim().ToLowerInvariant();
            if (severity != "high" && severity != "medium" && severity != "info") severity = "medium";
            string contains = (c.Contains ?? "").Trim();
            string message = c.Message.Trim();

            return new DetectionRule
            {
                Log = c.Log.Trim(),
                Id = c.Id,
                Technique = (c.Technique ?? "").Trim(),
                Severity = severity,
                Describe = e =>
                {
                    if (contains.Length > 0 && !e.Props.Any(p => p != null && p.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0))
                        return null;
                    string detail = string.Join(", ", e.Props.Where(p => !string.IsNullOrWhiteSpace(p) && p != "-").Take(3));
                    return detail.Length == 0 ? message : message + ": " + Trim(detail, 90);
                }
            };
        }

        private static List<CustomRule> SampleRules()
        {
            return new List<CustomRule>
            {
                new CustomRule { Enabled = false, Log = Security, Id = 4728, Contains = "", Technique = "T1098", Severity = "high",
                    Message = "member added to a global security group" },
                new CustomRule { Enabled = false, Log = SystemLog, Id = 7040, Contains = "disabled", Technique = "T1562.001", Severity = "medium",
                    Message = "a service start type was changed" }
            };
        }

        /// <summary>Reads every log the rules need since the given time. Logs that cannot be read are counted, not fatal.</summary>
        public static List<EventEntry> Run(IEventSource source, DateTime sinceUtc, IList<DetectionRule> extraRules, out int logsRead, out int logsDenied)
        {
            var read = new List<string>();
            List<EventEntry> found = Run(source, log => sinceUtc, extraRules, read, out logsDenied);
            logsRead = read.Count;
            return found;
        }

        /// <summary>
        /// Same, with a separate starting point per log. "logsRead" receives the logs that were
        /// read successfully, so the caller only moves those forward.
        /// </summary>
        public static List<EventEntry> Run(IEventSource source, Func<string, DateTime> sinceFor, IList<DetectionRule> extraRules, List<string> logsRead, out int logsDenied)
        {
            logsDenied = 0;
            var rules = new List<DetectionRule>(Rules);
            if (extraRules != null) rules.AddRange(extraRules);

            var raw = new List<RawEvent>();
            foreach (IGrouping<string, DetectionRule> group in rules.GroupBy(r => r.Log, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    raw.AddRange(source.Read(group.Key, group.Select(r => r.Id).Distinct().ToArray(), sinceFor(group.Key), 500));
                    logsRead.Add(group.Key);
                }
                catch (UnauthorizedAccessException)
                {
                    logsDenied++;
                }
                catch
                {
                    // A log that does not exist on this edition of Windows is simply skipped.
                }
            }
            return Evaluate(raw, rules);
        }

        private static string Name(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "(unknown)" : Trim(value, 60);
        }

        private static string Trim(string value, int max)
        {
            if (value == null) return "";
            value = value.Replace("\r", " ").Replace("\n", " ").Trim();
            return value.Length <= max ? value : value.Substring(0, max) + "...";
        }
    }
}
