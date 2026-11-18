using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace SecHUD
{
    /// <summary>Writes a self-contained HTML report of the current state, ready to attach to a writeup.</summary>
    public static class Report
    {
        public static string Folder
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SecHUD Reports");
            }
        }

        public static string Save(ScanResult result, IList<EventEntry> recentEvents)
        {
            Directory.CreateDirectory(Folder);
            string path = Path.Combine(Folder, "sechud-report-" + result.Time.ToString("yyyyMMdd-HHmmss") + ".html");
            File.WriteAllText(path, Build(result, recentEvents), new UTF8Encoding(false));
            return path;
        }

        public static string Build(ScanResult result, IList<EventEntry> recentEvents)
        {
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
            sb.Append("<title>SecHUD report ").Append(E(result.Time.ToString("yyyy-MM-dd HH:mm"))).Append("</title>\n");
            sb.Append("<style>\n");
            sb.Append("body{background:#0a080e;color:#ececf2;font-family:Segoe UI,Arial,sans-serif;margin:32px;}\n");
            sb.Append("h1{color:#ff003c;font-size:22px;margin:0 0 4px;}\n");
            sb.Append("h2{color:#ff003c;font-size:15px;margin:28px 0 8px;border-bottom:1px solid #5a0018;padding-bottom:4px;}\n");
            sb.Append("table{border-collapse:collapse;width:100%;font-size:13px;}\n");
            sb.Append("th{text-align:left;color:#aaaab9;font-weight:600;padding:6px 10px 6px 0;}\n");
            sb.Append("td{padding:6px 10px 6px 0;border-top:1px solid #2a1320;vertical-align:top;}\n");
            sb.Append(".ok{color:#00f0ff;}.bad{color:#fcee0a;font-weight:600;}.muted{color:#aaaab9;}\n");
            sb.Append(".level{font-size:34px;font-weight:700;margin:6px 0;}\n");
            sb.Append("a{color:#00f0ff;}\n</style></head><body>\n");

            sb.Append("<h1>SecHUD report</h1>\n");
            sb.Append("<div class=\"muted\">").Append(E(Environment.MachineName)).Append(" &middot; ")
              .Append(E(result.Time.ToString("yyyy-MM-dd HH:mm:ss"))).Append("</div>\n");
            sb.Append("<div class=\"level ").Append(result.Elevated ? "bad" : "ok").Append("\">").Append(E(result.Level)).Append("</div>\n");
            sb.Append("<div class=\"").Append(result.Elevated ? "bad" : "muted").Append("\">").Append(E(result.Ticker)).Append("</div>\n");

            sb.Append("<h2>Checks</h2>\n<table><tr><th>Check</th><th>Result</th></tr>\n");
            foreach (CheckRow row in result.PcRows.Concat(result.NetRows))
            {
                sb.Append("<tr><td>").Append(E(row.Label)).Append("</td><td class=\"").Append(row.IsAlert ? "bad" : "ok").Append("\">")
                  .Append(E(row.Value)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");

            sb.Append("<h2>Devices on the network (").Append(result.Devices.Count).Append(")</h2>\n");
            sb.Append("<table><tr><th>Status</th><th>Name</th><th>Address</th><th>MAC</th><th>First seen</th><th>Last seen</th></tr>\n");
            foreach (DeviceRecord d in result.Devices.OrderBy(x => x.Approved).ThenBy(x => x.Ip, StringComparer.Ordinal))
            {
                string status = !d.Approved ? "UNKNOWN" : (d.Online ? "online" : "offline");
                sb.Append("<tr><td class=\"").Append(!d.Approved ? "bad" : (d.Online ? "ok" : "muted")).Append("\">").Append(status).Append("</td><td>")
                  .Append(E(d.Name)).Append("</td><td>").Append(E(d.Ip)).Append("</td><td class=\"muted\">").Append(E(d.Mac))
                  .Append("</td><td class=\"muted\">").Append(E(d.FirstSeen)).Append("</td><td class=\"muted\">").Append(E(d.LastSeen)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");

            sb.Append("<h2>Listening ports (").Append(result.Ports.Count).Append(")</h2>\n");
            sb.Append("<table><tr><th>Port</th><th>Process</th><th></th></tr>\n");
            foreach (PortInfo p in result.Ports)
            {
                sb.Append("<tr><td>").Append(p.Port).Append("</td><td>").Append(E(p.Process)).Append("</td><td class=\"bad\">")
                  .Append(p.IsNew ? "NEW" : "").Append("</td></tr>\n");
            }
            sb.Append("</table>\n");

            List<AutorunItem> fresh = result.Autoruns.Where(a => a.IsNew).ToList();
            sb.Append("<h2>Autoruns (").Append(result.Autoruns.Count).Append(" tracked, ").Append(fresh.Count).Append(" new)</h2>\n");
            if (fresh.Count == 0)
            {
                sb.Append("<div class=\"muted\">Nothing new since the baseline.</div>\n");
            }
            else
            {
                sb.Append("<table><tr><th>Kind</th><th>Name</th><th>Command</th><th>ATT&amp;CK</th></tr>\n");
                foreach (AutorunItem a in fresh)
                {
                    sb.Append("<tr><td class=\"bad\">").Append(E(a.Kind)).Append("</td><td>").Append(E(a.Name)).Append("</td><td class=\"muted\">")
                      .Append(E(a.Command)).Append("</td><td>").Append(TechniqueLink(a.Technique)).Append("</td></tr>\n");
                }
                sb.Append("</table>\n");
            }

            sb.Append("<h2>Recent events</h2>\n<table><tr><th>Time</th><th>Level</th><th>ATT&amp;CK</th><th>Event</th></tr>\n");
            foreach (EventEntry e in (recentEvents ?? new List<EventEntry>()).Take(100))
            {
                bool high = e.Severity == "high";
                sb.Append("<tr><td class=\"muted\">").Append(E(e.Ts)).Append("</td><td class=\"").Append(high ? "bad" : "muted").Append("\">")
                  .Append(E(e.Severity)).Append("</td><td>").Append(TechniqueLink(e.Technique)).Append("</td><td>").Append(E(e.Msg)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");

            sb.Append("<p class=\"muted\" style=\"margin-top:28px\">Generated by SecHUD.</p>\n</body></html>\n");
            return sb.ToString();
        }

        /// <summary>T1136.001 becomes a link to attack.mitre.org/techniques/T1136/001/.</summary>
        public static string TechniqueLink(string technique)
        {
            if (string.IsNullOrWhiteSpace(technique)) return "";
            string safe = new string(technique.Where(c => char.IsLetterOrDigit(c) || c == '.').ToArray());
            if (safe.Length == 0) return "";
            return "<a href=\"https://attack.mitre.org/techniques/" + safe.Replace(".", "/") + "/\">" + safe + "</a>";
        }

        private static string E(string text)
        {
            return WebUtility.HtmlEncode(text ?? "");
        }
    }
}
