using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;

namespace SecHUD
{
    [DataContract]
    internal class PveNodeList
    {
        [DataMember(Name = "data")] public List<PveNode> Data { get; set; }
    }

    [DataContract]
    internal class PveNode
    {
        [DataMember(Name = "node")] public string Node { get; set; }
        [DataMember(Name = "status")] public string Status { get; set; }
        [DataMember(Name = "cpu")] public double Cpu { get; set; }
        [DataMember(Name = "mem")] public double Mem { get; set; }
        [DataMember(Name = "maxmem")] public double MaxMem { get; set; }
    }

    [DataContract]
    internal class PveResourceList
    {
        [DataMember(Name = "data")] public List<PveResource> Data { get; set; }
    }

    [DataContract]
    internal class PveResource
    {
        [DataMember(Name = "vmid")] public long VmId { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "type")] public string Type { get; set; }
        [DataMember(Name = "status")] public string Status { get; set; }
        [DataMember(Name = "cpu")] public double Cpu { get; set; }
        [DataMember(Name = "mem")] public double Mem { get; set; }
        [DataMember(Name = "maxmem")] public double MaxMem { get; set; }
    }

    /// <summary>
    /// Read-only Proxmox API client. Uses an API token (give it the PVEAuditor role, which can
    /// look but not change anything).
    ///
    /// A Proxmox box normally has a self-signed certificate, so instead of trusting any
    /// certificate the app remembers the first one it sees and refuses a different one later.
    /// A changed certificate is reported as a possible interception.
    /// </summary>
    public static class Proxmox
    {
        public static ProxmoxSnapshot Fetch(AppConfig config, string pinnedThumbprint)
        {
            var snapshot = new ProxmoxSnapshot();
            string secret = Secrets.Unprotect(config.ProxmoxSecretProtected);
            if (string.IsNullOrWhiteSpace(config.ProxmoxHost) || string.IsNullOrWhiteSpace(config.ProxmoxTokenId) || secret.Length == 0)
                return snapshot;

            snapshot.Configured = true;
            string baseUrl = "https://" + config.ProxmoxHost.Trim() + ":" + config.ProxmoxPort + "/api2/json";
            string authorization = "PVEAPIToken=" + config.ProxmoxTokenId.Trim() + "=" + secret;
            string seen = "";
            bool rejected = false;

            RemoteCertificateValidationCallback validate = (sender, certificate, chain, errors) =>
            {
                if (certificate == null) return false;
                seen = new X509Certificate2(certificate).Thumbprint ?? "";
                if (errors == SslPolicyErrors.None) return true;          // publicly trusted
                if (string.IsNullOrEmpty(pinnedThumbprint)) return true;   // first contact: remember it
                bool same = string.Equals(pinnedThumbprint, seen, StringComparison.OrdinalIgnoreCase);
                if (!same) rejected = true;
                return same;
            };

            try
            {
                string nodesJson = Get(baseUrl + "/nodes", authorization, validate);
                string resourcesJson = Get(baseUrl + "/cluster/resources?type=vm", authorization, validate);
                Parse(snapshot, nodesJson, resourcesJson);
                snapshot.Ok = true;
            }
            catch (Exception ex)
            {
                snapshot.Ok = false;
                snapshot.Error = rejected ? "certificate changed" : Describe(ex);
            }
            snapshot.Thumbprint = seen;
            snapshot.CertChanged = rejected;
            return snapshot;
        }

        /// <summary>Turns the two API answers into what the window shows.</summary>
        public static void Parse(ProxmoxSnapshot snapshot, string nodesJson, string resourcesJson)
        {
            PveNodeList nodes = Store.FromJson<PveNodeList>(nodesJson);
            PveResourceList resources = Store.FromJson<PveResourceList>(resourcesJson);

            var parts = new List<string>();
            if (nodes != null && nodes.Data != null)
            {
                foreach (PveNode node in nodes.Data)
                {
                    int memory = node.MaxMem > 0 ? (int)Math.Round(node.Mem / node.MaxMem * 100) : 0;
                    parts.Add((node.Node ?? "node") + " " + (node.Status ?? "?")
                        + " cpu " + (int)Math.Round(node.Cpu * 100) + "% mem " + memory + "%");
                }
            }

            if (resources != null && resources.Data != null)
            {
                foreach (PveResource r in resources.Data.OrderBy(x => x.VmId))
                {
                    bool running = string.Equals(r.Status, "running", StringComparison.OrdinalIgnoreCase);
                    snapshot.Guests.Add(new ProxmoxGuest
                    {
                        Id = r.VmId.ToString(),
                        Name = r.Name ?? "",
                        Kind = r.Type == "lxc" ? "CT" : "VM",
                        Status = r.Status ?? "?",
                        Running = running,
                        Cpu = running ? (int)Math.Round(r.Cpu * 100) + "%" : "",
                        Memory = running && r.MaxMem > 0 ? (int)Math.Round(r.Mem / r.MaxMem * 100) + "%" : ""
                    });
                }
            }
            snapshot.Summary = string.Join(" | ", parts);
        }

        private static string Get(string url, string authorization, RemoteCertificateValidationCallback validate)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 5000;
            request.ReadWriteTimeout = 5000;
            request.Headers["Authorization"] = authorization;
            request.ServerCertificateValidationCallback = validate;
            using (var response = (HttpWebResponse)request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
            {
                return reader.ReadToEnd();
            }
        }

        private static string Describe(Exception ex)
        {
            var web = ex as WebException;
            if (web != null)
            {
                var response = web.Response as HttpWebResponse;
                if (response != null)
                {
                    if (response.StatusCode == HttpStatusCode.Unauthorized) return "token rejected";
                    if (response.StatusCode == HttpStatusCode.Forbidden) return "token lacks permission";
                    return "http " + (int)response.StatusCode;
                }
                if (web.Status == WebExceptionStatus.Timeout) return "timeout";
                return "unreachable";
            }
            return "bad response";
        }
    }
}
