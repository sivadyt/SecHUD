using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace SecHUD
{
    /// <summary>
    /// Quiet hours for Discord. While they are on, ordinary alerts are held and sent as one
    /// summary afterwards. Alerts that mean protection was switched off or someone is tampering
    /// still go out straight away.
    /// </summary>
    public static class Quiet
    {
        private static readonly string[] UrgentTypes = { "antivirus", "firewall", "gateway", "dns", "wifi", "proxmox" };
        private static readonly string[] UrgentTechniques = { "T1136.001", "T1098", "T1562.001", "T1070.001" };

        /// <summary>Reads "23:00", "7:30" or just "7" as minutes after midnight.</summary>
        public static bool TryParseTime(string text, out int minutes)
        {
            minutes = 0;
            string[] parts = (text ?? "").Trim().Split(':');
            if (parts.Length < 1 || parts.Length > 2) return false;
            int hour, minute = 0;
            if (!int.TryParse(parts[0].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out hour)) return false;
            if (parts.Length == 2 && !int.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out minute)) return false;
            if (hour > 23 || minute > 59) return false;
            minutes = hour * 60 + minute;
            return true;
        }

        public static string FormatTime(int minutes)
        {
            return (minutes / 60).ToString("00") + ":" + (minutes % 60).ToString("00");
        }

        /// <summary>True inside the window. A window such as 23:00 to 07:00 runs past midnight.</summary>
        public static bool InWindow(int start, int end, int now)
        {
            if (start == end) return false;
            return start < end ? now >= start && now < end : now >= start || now < end;
        }

        public static bool IsQuiet(AppConfig config, DateTime now)
        {
            if (config == null || !config.QuietHours) return false;
            int start, end;
            if (!TryParseTime(config.QuietStart, out start) || !TryParseTime(config.QuietEnd, out end)) return false;
            return InWindow(start, end, now.Hour * 60 + now.Minute);
        }

        /// <summary>Alerts that are sent even during quiet hours.</summary>
        public static bool IsUrgent(EventEntry e)
        {
            if (e == null) return false;
            if (UrgentTypes.Contains(e.Type ?? "", StringComparer.OrdinalIgnoreCase)) return true;
            if (UrgentTechniques.Contains(e.Technique ?? "", StringComparer.OrdinalIgnoreCase)) return true;
            return (e.Msg ?? "").IndexOf("malware", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>The one message sent when quiet hours end.</summary>
        public static string Digest(IList<string> held, string machine)
        {
            var sb = new StringBuilder();
            sb.Append("SecHUD on ").Append(machine).Append(": ").Append(held.Count)
              .Append(held.Count == 1 ? " alert was" : " alerts were").Append(" held during quiet hours:");
            const int shown = 12;
            foreach (string line in held.Take(shown)) sb.Append("\n- ").Append(line);
            if (held.Count > shown) sb.Append("\n(and ").Append(held.Count - shown).Append(" more, see the Events tab)");
            return sb.ToString();
        }
    }
}
