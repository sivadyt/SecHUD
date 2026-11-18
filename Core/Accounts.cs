using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;

namespace SecHUD
{
    /// <summary>
    /// Watches the local user accounts and who is in the Administrators group by comparing
    /// them with the last scan. Unlike the event-log rules this needs no special permission,
    /// so a new account is caught even when the Security log cannot be read.
    /// </summary>
    public static class Accounts
    {
        private static readonly Regex Member = new Regex("Domain=\"([^\"]*)\",Name=\"([^\"]*)\"", RegexOptions.Compiled);

        /// <summary>Keys of the form "user|name" and "admin|domain\name". Empty when Windows gives no answer.</summary>
        public static List<string> Query()
        {
            var keys = new List<string>();
            using (var searcher = new ManagementObjectSearcher(@"root\cimv2",
                "SELECT Name FROM Win32_UserAccount WHERE LocalAccount = True"))
            {
                foreach (ManagementBaseObject user in searcher.Get())
                {
                    string name = user["Name"] as string;
                    if (!string.IsNullOrEmpty(name)) keys.Add("user|" + name);
                }
            }

            // The Administrators group is found by its fixed id, because its name is translated on non-English Windows.
            string group = null, domain = null;
            using (var searcher = new ManagementObjectSearcher(@"root\cimv2",
                "SELECT Name, Domain FROM Win32_Group WHERE SID = 'S-1-5-32-544' AND LocalAccount = True"))
            {
                foreach (ManagementBaseObject item in searcher.Get())
                {
                    group = item["Name"] as string;
                    domain = item["Domain"] as string;
                }
            }
            if (string.IsNullOrEmpty(group) || string.IsNullOrEmpty(domain)) return keys;

            string query = "SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='"
                + domain.Replace("'", "") + "',Name='" + group.Replace("'", "") + "'\"";
            using (var searcher = new ManagementObjectSearcher(@"root\cimv2", query))
            {
                foreach (ManagementBaseObject item in searcher.Get())
                {
                    string member = ParseMemberName(item["PartComponent"] as string);
                    if (member.Length > 0) keys.Add("admin|" + member);
                }
            }
            return keys;
        }

        /// <summary>Pulls PC\name out of a WMI path such as ...Win32_UserAccount.Domain="PC",Name="name".</summary>
        public static string ParseMemberName(string partComponent)
        {
            Match m = Member.Match(partComponent ?? "");
            return m.Success ? m.Groups[1].Value + "\\" + m.Groups[2].Value : "";
        }

        /// <summary>What changed between two scans, as events. Additions are high, removals are informational.</summary>
        public static List<EventEntry> Diff(IList<string> current, IList<string> known, DateTime now)
        {
            var events = new List<EventEntry>();
            var before = new HashSet<string>(known ?? new string[0], StringComparer.OrdinalIgnoreCase);
            var after = new HashSet<string>(current ?? new string[0], StringComparer.OrdinalIgnoreCase);

            foreach (string key in after.Where(k => !before.Contains(k)).OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            {
                bool admin = key.StartsWith("admin|", StringComparison.OrdinalIgnoreCase);
                events.Add(new EventEntry
                {
                    Ts = now.ToString("s"),
                    Type = "detection",
                    Severity = "high",
                    Technique = admin ? "T1098" : "T1136.001",
                    Msg = (admin ? "account added to Administrators: " : "new local user account: ") + NameOf(key)
                });
            }
            foreach (string key in before.Where(k => !after.Contains(k)).OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
            {
                bool admin = key.StartsWith("admin|", StringComparison.OrdinalIgnoreCase);
                events.Add(new EventEntry
                {
                    Ts = now.ToString("s"),
                    Type = "accounts",
                    Severity = "info",
                    Msg = (admin ? "account removed from Administrators: " : "local user account removed: ") + NameOf(key)
                });
            }
            return events;
        }

        /// <summary>
        /// True when "candidate" reports the same account event as something already in "existing"
        /// (the account watch and the Security log can both notice one new account).
        /// </summary>
        public static bool IsRepeat(EventEntry candidate, IEnumerable<EventEntry> existing)
        {
            if (candidate == null || (candidate.Technique != "T1136.001" && candidate.Technique != "T1098")) return false;
            string subject = Subject(candidate.Msg);
            if (subject.Length == 0) return false;
            return existing.Any(e => e != null && e != candidate && e.Technique == candidate.Technique
                && (e.Msg ?? "").IndexOf(subject, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>The account name at the end of a message, without any PC\ prefix.</summary>
        private static string Subject(string message)
        {
            int colon = (message ?? "").LastIndexOf(": ", StringComparison.Ordinal);
            if (colon < 0) return "";
            string name = message.Substring(colon + 2).Trim();
            int slash = name.LastIndexOf('\\');
            return slash >= 0 ? name.Substring(slash + 1) : name;
        }

        private static string NameOf(string key)
        {
            int bar = key.IndexOf('|');
            return bar < 0 ? key : key.Substring(bar + 1);
        }
    }
}
