using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace SecHUD
{
    /// <summary>
    /// The weekly Discord message. A monitor that is working well says nothing for days, which
    /// looks exactly like a monitor that has stopped. One short message a week settles that.
    /// </summary>
    public static class Summary
    {
        public const int Days = 7;

        private static readonly string[][] Groups =
        {
            new[] { "new-device", "new device", "new devices" },
            new[] { "new-autorun", "new startup item", "new startup items" },
            new[] { "new-port", "new listening port", "new listening ports" },
            new[] { "detection", "detection", "detections" },
            new[] { "device-watch", "watched device offline", "watched devices offline" },
            new[] { "host", "host down", "hosts down" },
            new[] { "antivirus", "antivirus alert", "antivirus alerts" },
            new[] { "firewall", "firewall alert", "firewall alerts" },
            new[] { "gateway", "gateway change", "gateway changes" },
            new[] { "dns", "DNS change", "DNS changes" },
            new[] { "wifi", "copycat Wi-Fi alert", "copycat Wi-Fi alerts" },
            new[] { "router", "new port forward", "new port forwards" },
            new[] { "logins", "failed-login alert", "failed-login alerts" },
            new[] { "syslog", "syslog alert", "syslog alerts" }
        };

        /// <summary>True when a week or more has passed since the last one. A missing or unreadable time counts as never.</summary>
        public static bool IsDue(string lastSentUtc, DateTime nowUtc)
        {
            DateTime last;
            if (!DateTime.TryParse(lastSentUtc, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out last)) return true;
            return (nowUtc - last).TotalDays >= Days;
        }

        /// <summary>Builds the message from the event log and the latest scan.</summary>
        public static string Build(IEnumerable<EventEntry> events, IList<DeviceRecord> devices, string level,
            int openDetections, DateTime now, string machine, string version)
        {
            DateTime from = now.AddDays(-Days);
            var week = new List<EventEntry>();
            foreach (EventEntry e in events ?? new EventEntry[0])
            {
                DateTime when;
                if (e == null || !DateTime.TryParse(e.Ts, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out when)) continue;
                if (when >= from && when <= now.AddMinutes(5)) week.Add(e);
            }

            List<EventEntry> alerts = week.Where(e => e.Severity == "high").ToList();
            var parts = new List<string>();
            int counted = 0;
            foreach (string[] group in Groups)
            {
                int n = alerts.Count(e => string.Equals(e.Type, group[0], StringComparison.OrdinalIgnoreCase));
                if (n == 0) continue;
                counted += n;
                parts.Add(n + " " + (n == 1 ? group[1] : group[2]));
            }
            if (alerts.Count > counted) parts.Add((alerts.Count - counted) + " other");

            devices = devices ?? new List<DeviceRecord>();
            int known = devices.Count(d => d.Approved);
            int unknown = devices.Count(d => !d.Approved && !d.Guest);
            int seen = devices.Count(d =>
            {
                DateTime last;
                return DateTime.TryParse(d.LastSeen, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out last) && last >= from;
            });

            var sb = new StringBuilder();
            sb.Append("SecHUD weekly summary for ").Append(machine)
              .Append(" (").Append(from.ToString("MMM d", CultureInfo.InvariantCulture)).Append(" to ")
              .Append(now.ToString("MMM d", CultureInfo.InvariantCulture)).Append(")");
            sb.Append("\nStatus now: ").Append(string.IsNullOrEmpty(level) ? "unknown" : level);
            sb.Append("\nAlerts this week: ").Append(alerts.Count);
            if (parts.Count > 0) sb.Append(" (").Append(string.Join(", ", parts)).Append(")");

            var waiting = new List<string>();
            if (openDetections > 0) waiting.Add(openDetections + (openDetections == 1 ? " open detection" : " open detections"));
            if (unknown > 0) waiting.Add(unknown + (unknown == 1 ? " unknown device" : " unknown devices"));
            sb.Append("\nWaiting for you: ").Append(waiting.Count > 0 ? string.Join(", ", waiting) : "nothing");

            sb.Append("\nDevices: ").Append(known).Append(" known, ").Append(seen).Append(" seen this week");
            if (alerts.Count == 0) sb.Append("\nA quiet week. Nothing new showed up.");
            sb.Append("\nSecHUD ").Append(version).Append(" is running and watching.");
            return sb.ToString();
        }
    }
}
