using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace SecHUD
{
    /// <summary>
    /// Works out who made a device from the first half of its MAC address. The table is the
    /// public IEEE registry of address blocks, packed inside the exe (Data\oui.gz), so nothing
    /// is looked up online.
    /// </summary>
    public static class Vendors
    {
        public const string PrivateLabel = "Private address";
        private const string ResourceName = "SecHUD.oui.gz";

        private static readonly object Gate = new object();
        private static Dictionary<int, string> table;

        /// <summary>The maker's name, "Private address" for a randomized one, or "" when unknown.</summary>
        public static string Lookup(string mac)
        {
            string hex = new string((mac ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (hex.Length < 6) return "";
            if (IsRandomized(hex)) return PrivateLabel;

            int prefix;
            if (!int.TryParse(hex.Substring(0, 6), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out prefix)) return "";
            string name;
            return Table.TryGetValue(prefix, out name) ? name : "";
        }

        /// <summary>
        /// Phones, tablets and laptops often invent a different address for each network to make
        /// tracking harder. Those have the "locally administered" bit set, so no maker owns them.
        /// </summary>
        public static bool IsRandomized(string mac)
        {
            string hex = new string((mac ?? "").Where(Uri.IsHexDigit).ToArray());
            if (hex.Length < 2) return false;
            int second;
            if (!int.TryParse(hex.Substring(1, 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out second)) return false;
            return (second & 2) != 0;
        }

        /// <summary>How many address blocks the table knows. Zero means the table could not be loaded.</summary>
        public static int Count { get { return Table.Count; } }

        private static Dictionary<int, string> Table
        {
            get
            {
                lock (Gate)
                {
                    if (table == null) table = Load();
                    return table;
                }
            }
        }

        private static Dictionary<int, string> Load()
        {
            var result = new Dictionary<int, string>();
            try
            {
                using (Stream raw = typeof(Vendors).Assembly.GetManifestResourceStream(ResourceName))
                {
                    if (raw == null) return result;
                    using (var unzip = new GZipStream(raw, CompressionMode.Decompress))
                    using (var reader = new StreamReader(unzip, Encoding.UTF8))
                    {
                        Parse(reader, result);
                    }
                }
            }
            catch
            {
                // Maker names are a convenience. Without the table the column is simply empty.
            }
            return result;
        }

        /// <summary>One block per line: six hex digits, a tab, the name.</summary>
        public static void Parse(TextReader reader, Dictionary<int, string> into)
        {
            var names = new Dictionary<string, string>(StringComparer.Ordinal); // share one string per maker
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                int tab = line.IndexOf('\t');
                if (tab != 6 || line.Length < 8) continue;
                int prefix;
                if (!int.TryParse(line.Substring(0, 6), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out prefix)) continue;
                string name = line.Substring(7).Trim();
                if (name.Length == 0) continue;
                string shared;
                if (!names.TryGetValue(name, out shared)) { names[name] = name; shared = name; }
                into[prefix] = shared;
            }
        }
    }
}
