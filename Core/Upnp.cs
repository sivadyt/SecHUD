using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;

namespace SecHUD
{
    /// <summary>
    /// Asks the router, over UPnP, which ports it forwards from the internet to devices inside.
    /// Any program on the network can ask a UPnP router to open a port, so this list is worth
    /// watching. Read-only: it never adds or removes a forward.
    /// </summary>
    public static class Upnp
    {
        private const string SearchTarget = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
        private const int MaxEntries = 64;
        private const int MaxBytes = 256 * 1024;

        private static string cachedControlUrl;
        private static string cachedServiceType;

        public static RouterSnapshot Query(string gatewayIp)
        {
            var snapshot = new RouterSnapshot();
            try
            {
                if (cachedControlUrl == null)
                {
                    string location = Discover(gatewayIp, 2500);
                    if (location == null)
                    {
                        snapshot.Note = "the router did not answer UPnP (it is probably switched off there)";
                        return snapshot;
                    }
                    string description = HttpGet(location);
                    string control, service;
                    if (!ParseDescription(description, location, out control, out service))
                    {
                        snapshot.Note = "the router answered but offers no port mapping service";
                        return snapshot;
                    }
                    cachedControlUrl = control;
                    cachedServiceType = service;
                }

                snapshot.Found = true;
                try { snapshot.ExternalIp = ParseValue(Soap("GetExternalIPAddress", ""), "NewExternalIPAddress"); } catch { }

                for (int index = 0; index < MaxEntries; index++)
                {
                    string response;
                    try
                    {
                        response = Soap("GetGenericPortMappingEntry", "<NewPortMappingIndex>" + index + "</NewPortMappingIndex>");
                    }
                    catch (WebException)
                    {
                        break; // the router answers with an error once the index runs past the last entry
                    }
                    ForwardInfo forward = ParseMapping(response);
                    if (forward == null) break;
                    snapshot.Forwards.Add(forward);
                }
            }
            catch
            {
                cachedControlUrl = null; // rediscover next time
                snapshot.Found = false;
                snapshot.Note = "could not read the router's port mappings";
            }
            return snapshot;
        }

        /// <summary>Broadcasts the standard UPnP search and returns the description address of the router that answers.</summary>
        private static string Discover(string gatewayIp, int timeoutMs)
        {
            string request = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + SearchTarget + "\r\n\r\n";
            byte[] data = Encoding.ASCII.GetBytes(request);
            string fallback = null;

            using (var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0)))
            {
                udp.Send(data, data.Length, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
                DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                while (true)
                {
                    int remaining = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                    if (remaining <= 0) break;
                    udp.Client.ReceiveTimeout = remaining;
                    try
                    {
                        var remote = new IPEndPoint(IPAddress.Any, 0);
                        string reply = Encoding.ASCII.GetString(udp.Receive(ref remote));
                        string location = ParseLocation(reply);
                        if (location == null) continue;
                        string host = new Uri(location).Host;
                        if (!PortScanner.IsPrivateAddress(host)) continue;          // only ever talk to the local network
                        if (gatewayIp != null && host == gatewayIp) return location;  // the gateway itself is the best answer
                        if (fallback == null) fallback = location;
                    }
                    catch (SocketException)
                    {
                        break; // timed out
                    }
                    catch (UriFormatException)
                    {
                    }
                }
            }
            return fallback;
        }

        public static string ParseLocation(string ssdpReply)
        {
            foreach (string line in (ssdpReply ?? "").Split('\n'))
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (line.Substring(0, colon).Trim().Equals("LOCATION", StringComparison.OrdinalIgnoreCase))
                {
                    string value = line.Substring(colon + 1).Trim();
                    Uri uri;
                    if (Uri.TryCreate(value, UriKind.Absolute, out uri) && uri.Scheme == Uri.UriSchemeHttp) return value;
                }
            }
            return null;
        }

        /// <summary>Finds the WAN connection service in the router's description and its control address.</summary>
        public static bool ParseDescription(string xml, string location, out string controlUrl, out string serviceType)
        {
            controlUrl = null;
            serviceType = null;
            XDocument doc = XDocument.Parse(xml);

            string baseText = doc.Descendants().Where(e => e.Name.LocalName == "URLBase").Select(e => e.Value.Trim()).FirstOrDefault();
            Uri baseUri = new Uri(string.IsNullOrEmpty(baseText) ? location : baseText);

            foreach (XElement service in doc.Descendants().Where(e => e.Name.LocalName == "service"))
            {
                string type = Child(service, "serviceType");
                if (type.IndexOf("WANIPConnection", StringComparison.OrdinalIgnoreCase) < 0
                    && type.IndexOf("WANPPPConnection", StringComparison.OrdinalIgnoreCase) < 0) continue;

                string control = Child(service, "controlURL");
                if (control.Length == 0) continue;
                var resolved = new Uri(baseUri, control);
                if (!PortScanner.IsPrivateAddress(resolved.Host)) continue;

                controlUrl = resolved.ToString();
                serviceType = type;
                return true;
            }
            return false;
        }

        /// <summary>One answer to GetGenericPortMappingEntry. Null when it holds no mapping.</summary>
        public static ForwardInfo ParseMapping(string soapXml)
        {
            int external, inner;
            if (!int.TryParse(ParseValue(soapXml, "NewExternalPort"), out external)) return null;
            int.TryParse(ParseValue(soapXml, "NewInternalPort"), out inner);
            return new ForwardInfo
            {
                ExternalPort = external,
                InternalPort = inner,
                Protocol = ParseValue(soapXml, "NewProtocol").ToUpperInvariant(),
                InternalClient = ParseValue(soapXml, "NewInternalClient"),
                Description = Clean(ParseValue(soapXml, "NewPortMappingDescription"))
            };
        }

        public static string ParseValue(string soapXml, string name)
        {
            try
            {
                XDocument doc = XDocument.Parse(soapXml);
                XElement element = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == name);
                return element == null ? "" : element.Value.Trim();
            }
            catch
            {
                return "";
            }
        }

        private static string Child(XElement parent, string name)
        {
            XElement element = parent.Elements().FirstOrDefault(e => e.Name.LocalName == name);
            return element == null ? "" : element.Value.Trim();
        }

        private static string Clean(string text)
        {
            var sb = new StringBuilder();
            foreach (char c in text ?? "")
            {
                sb.Append(char.IsControl(c) ? ' ' : c);
                if (sb.Length >= 60) break;
            }
            return sb.ToString().Trim();
        }

        private static string Soap(string action, string arguments)
        {
            string body = "<?xml version=\"1.0\"?>"
                + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                + "<s:Body><u:" + action + " xmlns:u=\"" + cachedServiceType + "\">" + arguments + "</u:" + action + "></s:Body></s:Envelope>";
            byte[] data = Encoding.UTF8.GetBytes(body);

            var request = (HttpWebRequest)WebRequest.Create(cachedControlUrl);
            request.Method = "POST";
            request.Timeout = 3000;
            request.ReadWriteTimeout = 3000;
            request.ContentType = "text/xml; charset=\"utf-8\"";
            request.Headers["SOAPAction"] = "\"" + cachedServiceType + "#" + action + "\"";
            request.ContentLength = data.Length;
            request.Proxy = null;
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }
            using (var response = (HttpWebResponse)request.GetResponse())
            {
                return ReadLimited(response.GetResponseStream());
            }
        }

        private static string HttpGet(string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = 3000;
            request.ReadWriteTimeout = 3000;
            request.Proxy = null;
            using (var response = (HttpWebResponse)request.GetResponse())
            {
                return ReadLimited(response.GetResponseStream());
            }
        }

        private static string ReadLimited(Stream stream)
        {
            using (var memory = new MemoryStream())
            {
                var buffer = new byte[8192];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memory.Write(buffer, 0, read);
                    if (memory.Length > MaxBytes) throw new InvalidDataException("response too large");
                }
                return Encoding.UTF8.GetString(memory.ToArray());
            }
        }
    }
}
