using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace SecHUD
{
    public class AvProduct
    {
        public string Name { get; set; }
        public bool Enabled { get; set; }
        public bool UpToDate { get; set; }
    }

    /// <summary>
    /// Asks Windows Security Center which antivirus is actually protecting this PC. That is the
    /// right question when a third-party product is installed, because Defender then stands down
    /// on purpose.
    /// </summary>
    public static class Antivirus
    {
        /// <summary>
        /// Security Center packs the state into one number. Read as hex 0xAABBCC:
        /// BB is 0x10 or 0x11 when real-time protection is on, CC is 0x00 when definitions are current.
        /// </summary>
        public static AvProduct Decode(string name, uint productState)
        {
            uint scanner = (productState >> 8) & 0xFF;
            uint definitions = productState & 0xFF;
            return new AvProduct
            {
                Name = string.IsNullOrWhiteSpace(name) ? "antivirus" : name.Trim(),
                Enabled = scanner == 0x10 || scanner == 0x11,
                UpToDate = definitions == 0x00
            };
        }

        public static List<AvProduct> Query()
        {
            var products = new List<AvProduct>();
            using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                "SELECT displayName, productState FROM AntiVirusProduct"))
            {
                foreach (ManagementBaseObject item in searcher.Get())
                {
                    products.Add(Decode(item["displayName"] as string, Convert.ToUInt32(item["productState"])));
                }
            }
            return products;
        }

        /// <summary>Turns the product list into the overview row.</summary>
        public static CheckRow ToRow(List<AvProduct> products)
        {
            const string label = "ANTIVIRUS";
            if (products == null || products.Count == 0) return new CheckRow(label, "none found", true, false);

            List<AvProduct> active = products.Where(p => p.Enabled).ToList();
            if (active.Count == 0) return new CheckRow(label, "NONE ACTIVE", true, false);

            // If Defender and another product are both listed, the other one is the one doing the work.
            AvProduct main = active.FirstOrDefault(p => p.Name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0) ?? active[0];
            string name = Shorten(main.Name);
            if (!main.UpToDate) return new CheckRow(label, name + " | OUT OF DATE", true, true);
            return new CheckRow(label, name + " | on", false, true);
        }

        private static string Shorten(string name)
        {
            name = name.Replace("Microsoft Defender Antivirus", "Defender").Replace("Windows Defender", "Defender");
            return name.Length <= 20 ? name : name.Substring(0, 20);
        }
    }
}
