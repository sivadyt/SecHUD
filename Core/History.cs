using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace SecHUD
{
    /// <summary>One line per scan in history.csv, and the sums the History tab draws.</summary>
    public static class History
    {
        private const int MaxLines = 15000;   // about three weeks at one scan every two minutes
        private const int KeepLines = 10000;

        public static string ToLine(HistoryPoint point)
        {
            string hosts = string.Join(";", point.Hosts.Select(h => h.Key.Replace(",", " ").Replace(";", " ").Replace("=", " ") + "=" + (h.Value ? "1" : "0")));
            return string.Join(",", new[]
            {
                point.Time.ToString("s"),
                point.Online.ToString(CultureInfo.InvariantCulture),
                point.Unknown.ToString(CultureInfo.InvariantCulture),
                point.Elevated ? "1" : "0",
                point.HighEvents.ToString(CultureInfo.InvariantCulture),
                hosts
            });
        }

        public static HistoryPoint FromLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            string[] parts = line.Split(new[] { ',' }, 6);
            if (parts.Length < 5) return null;

            DateTime time;
            int online, unknown, high;
            if (!DateTime.TryParse(parts[0], CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out time)) return null;
            if (!int.TryParse(parts[1], out online) || !int.TryParse(parts[2], out unknown) || !int.TryParse(parts[4], out high)) return null;

            var point = new HistoryPoint { Time = time, Online = online, Unknown = unknown, Elevated = parts[3] == "1", HighEvents = high };
            if (parts.Length == 6)
            {
                foreach (string pair in parts[5].Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = pair.LastIndexOf('=');
                    if (eq > 0) point.Hosts[pair.Substring(0, eq)] = pair.Substring(eq + 1) == "1";
                }
            }
            return point;
        }

        public static void Append(HistoryPoint point)
        {
            try
            {
                Store.EnsureDir();
                File.AppendAllText(Store.HistoryPath, ToLine(point) + Environment.NewLine);
            }
            catch { }
        }

        /// <summary>Loads the points from the last given number of hours, trimming the file when it has grown large.</summary>
        public static List<HistoryPoint> Load(DateTime now, int hours)
        {
            var points = new List<HistoryPoint>();
            try
            {
                if (!File.Exists(Store.HistoryPath)) return points;
                string[] lines = File.ReadAllLines(Store.HistoryPath);
                if (lines.Length > MaxLines)
                {
                    lines = lines.Skip(lines.Length - KeepLines).ToArray();
                    File.WriteAllLines(Store.HistoryPath, lines);
                }
                DateTime from = now.AddHours(-hours);
                foreach (string line in lines)
                {
                    HistoryPoint p = FromLine(line);
                    if (p != null && p.Time >= from && p.Time <= now.AddMinutes(1)) points.Add(p);
                }
            }
            catch { }
            return points;
        }

        /// <summary>
        /// Splits the last "hours" hours into one bucket per hour, oldest first. Each bucket holds
        /// the largest value seen in that hour (useSum false) or the total (useSum true).
        /// A bucket with no scans is -1 so the chart can leave a gap.
        /// </summary>
        public static double[] Hourly(IEnumerable<HistoryPoint> points, DateTime now, int hours, Func<HistoryPoint, double> value, bool useSum)
        {
            var buckets = new double[hours];
            for (int i = 0; i < hours; i++) buckets[i] = -1;

            foreach (HistoryPoint p in points)
            {
                double age = (now - p.Time).TotalHours;
                if (age < 0 || age >= hours) continue;
                int index = hours - 1 - (int)Math.Floor(age);
                double v = value(p);
                if (buckets[index] < 0) buckets[index] = v;
                else buckets[index] = useSum ? buckets[index] + v : Math.Max(buckets[index], v);
            }
            return buckets;
        }

        /// <summary>Percent of scans in which each watched host answered.</summary>
        public static Dictionary<string, int> Uptime(IEnumerable<HistoryPoint> points)
        {
            var seen = new Dictionary<string, int>();
            var up = new Dictionary<string, int>();
            foreach (HistoryPoint p in points)
            {
                foreach (KeyValuePair<string, bool> host in p.Hosts)
                {
                    int count;
                    seen.TryGetValue(host.Key, out count);
                    seen[host.Key] = count + 1;
                    up.TryGetValue(host.Key, out count);
                    up[host.Key] = count + (host.Value ? 1 : 0);
                }
            }
            return seen.ToDictionary(s => s.Key, s => (int)Math.Round(100.0 * up[s.Key] / s.Value));
        }
    }
}
