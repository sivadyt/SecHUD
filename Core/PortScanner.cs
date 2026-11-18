using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SecHUD
{
    /// <summary>
    /// Checks which common services one device on your own network is offering. It only runs
    /// when you click Scan on a device, and it refuses any address outside the private ranges.
    /// </summary>
    public static class PortScanner
    {
        public static readonly Dictionary<int, string> CommonPorts = new Dictionary<int, string>
        {
            { 21, "FTP" }, { 22, "SSH" }, { 23, "TELNET" }, { 25, "SMTP" }, { 53, "DNS" }, { 80, "HTTP" },
            { 135, "RPC" }, { 139, "NETBIOS" }, { 443, "HTTPS" }, { 445, "SMB" }, { 515, "LPD" }, { 554, "RTSP" },
            { 631, "IPP" }, { 1433, "MSSQL" }, { 1883, "MQTT" }, { 3306, "MYSQL" }, { 3389, "RDP" },
            { 5000, "UPNP" }, { 5357, "WSD" }, { 5432, "POSTGRES" }, { 5900, "VNC" }, { 7000, "AIRPLAY" },
            { 8006, "PROXMOX" }, { 8008, "CAST" }, { 8009, "CAST" }, { 8080, "HTTP-ALT" }, { 8443, "HTTPS-ALT" },
            { 8883, "MQTT-TLS" }, { 9000, "HTTP-ALT" }, { 9100, "PRINTER" }, { 32400, "PLEX" }, { 62078, "IPHONE" }
        };

        public static bool IsPrivateAddress(string ip)
        {
            IPAddress address;
            if (!IPAddress.TryParse(ip, out address) || address.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = address.GetAddressBytes();
            return b[0] == 10 || (b[0] == 192 && b[1] == 168) || (b[0] == 172 && b[1] >= 16 && b[1] <= 31);
        }

        public static async Task<List<PortHit>> ScanAsync(string ip, int timeoutMs)
        {
            if (!IsPrivateAddress(ip)) throw new InvalidOperationException("only private LAN addresses can be scanned");

            List<Task<PortHit>> probes = CommonPorts.Select(pair => ProbeAsync(ip, pair.Key, pair.Value, timeoutMs)).ToList();
            PortHit[] results = await Task.WhenAll(probes);
            return results.Where(r => r != null).OrderBy(r => r.Port).ToList();
        }

        private static async Task<PortHit> ProbeAsync(string ip, int port, string service, int timeoutMs)
        {
            using (var client = new TcpClient())
            {
                try
                {
                    Task connect = client.ConnectAsync(ip, port);
                    Task finished = await Task.WhenAny(connect, Task.Delay(timeoutMs));
                    if (finished != connect)
                    {
                        // Let the abandoned attempt fail quietly once the socket is disposed.
                        var ignored = connect.ContinueWith(t => { var e = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                        return null;
                    }
                    await connect;
                    return new PortHit { Port = port, Service = service };
                }
                catch
                {
                    return null;
                }
            }
        }

        public static string Describe(List<PortHit> hits)
        {
            if (hits == null || hits.Count == 0) return "no common ports open";
            return "open: " + string.Join(", ", hits.Select(h => h.Port + " " + h.Service));
        }
    }
}
