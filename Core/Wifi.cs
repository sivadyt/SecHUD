using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

namespace SecHUD
{
    public class WifiScan
    {
        /// <summary>False when this PC has no Wi-Fi adapter (or the WLAN service is off).</summary>
        public bool Available { get; set; }
        /// <summary>True when Windows refused because location permission is off.</summary>
        public bool NeedsLocation { get; set; }
        public string ConnectedName { get; set; }
        /// <summary>Network name to the hardware addresses (BSSIDs) broadcasting it.</summary>
        public Dictionary<string, List<string>> Networks { get; set; }

        public WifiScan()
        {
            ConnectedName = "";
            Networks = new Dictionary<string, List<string>>();
        }
    }

    /// <summary>
    /// Lists the access points broadcasting each Wi-Fi name, using Windows' own "netsh wlan".
    /// An unfamiliar access point using your network's name is what an evil twin looks like.
    /// </summary>
    public static class Wifi
    {
        private static readonly Regex SsidLine = new Regex(@"^SSID\s+\d+\s*:\s?(.*)$", RegexOptions.Compiled);
        private static readonly Regex BssidLine = new Regex(@"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", RegexOptions.Compiled);
        private static readonly Regex ConnectedLine = new Regex(@"^SSID\s*:\s?(.*)$", RegexOptions.Compiled);

        public static WifiScan Scan()
        {
            var scan = new WifiScan();
            string interfaces = Run("wlan show interfaces");
            if (interfaces == null) return scan;
            // No adapter: netsh prints a one-line message and no "SSID" or "State" fields at all.
            scan.Available = interfaces.IndexOf(" : ", StringComparison.Ordinal) >= 0;
            if (!scan.Available) return scan;
            scan.ConnectedName = ParseConnectedName(interfaces);

            string networks = Run("wlan show networks mode=bssid") ?? "";
            scan.Networks = ParseNetworks(networks);
            scan.NeedsLocation = scan.Networks.Count == 0 && networks.IndexOf("location", StringComparison.OrdinalIgnoreCase) >= 0;
            return scan;
        }

        /// <summary>The name of the network this PC is connected to, from "netsh wlan show interfaces".</summary>
        public static string ParseConnectedName(string output)
        {
            foreach (string raw in (output ?? "").Split('\n'))
            {
                Match m = ConnectedLine.Match(raw.Trim());
                if (m.Success) return m.Groups[1].Value.Trim();
            }
            return "";
        }

        /// <summary>Parses "netsh wlan show networks mode=bssid". The words SSID and BSSID are the same in every language.</summary>
        public static Dictionary<string, List<string>> ParseNetworks(string output)
        {
            var networks = new Dictionary<string, List<string>>();
            string current = null;
            foreach (string raw in (output ?? "").Split('\n'))
            {
                string line = raw.Trim();
                Match ssid = SsidLine.Match(line);
                if (ssid.Success)
                {
                    current = ssid.Groups[1].Value.Trim();
                    if (!networks.ContainsKey(current)) networks[current] = new List<string>();
                    continue;
                }
                Match bssid = BssidLine.Match(line);
                if (bssid.Success && current != null)
                {
                    string mac = bssid.Groups[1].Value.ToUpperInvariant().Replace(':', '-');
                    if (!networks[current].Contains(mac)) networks[current].Add(mac);
                }
            }
            return networks;
        }

        private static string Run(string arguments)
        {
            try
            {
                var info = new ProcessStartInfo("netsh.exe", arguments)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using (Process process = Process.Start(info))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(5000);
                    return output;
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
