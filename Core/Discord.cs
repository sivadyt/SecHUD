using System;
using System.IO;
using System.Net;
using System.Text;

namespace SecHUD
{
    /// <summary>Sends alerts to a Discord channel through a webhook, so they reach your phone.</summary>
    public static class Discord
    {
        /// <summary>Only real Discord webhook addresses are accepted, so an alert can never be sent anywhere else.</summary>
        public static bool IsValidWebhook(string url)
        {
            Uri uri;
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out uri)) return false;
            if (uri.Scheme != Uri.UriSchemeHttps) return false;
            string host = uri.Host.ToLowerInvariant();
            bool discordHost = host == "discord.com" || host == "discordapp.com"
                || host.EndsWith(".discord.com") || host.EndsWith(".discordapp.com");
            return discordHost && uri.AbsolutePath.StartsWith("/api/webhooks/", StringComparison.OrdinalIgnoreCase);
        }

        public static bool Send(string webhookUrl, string content, out string error)
        {
            error = "";
            if (!IsValidWebhook(webhookUrl))
            {
                error = "not a Discord webhook address";
                return false;
            }
            try
            {
                if (content.Length > 1800) content = content.Substring(0, 1800);
                byte[] body = Encoding.UTF8.GetBytes("{\"content\":\"" + JsonEscape(content) + "\"}");

                var request = (HttpWebRequest)WebRequest.Create(webhookUrl.Trim());
                request.Method = "POST";
                request.ContentType = "application/json";
                request.Timeout = 6000;
                request.UserAgent = "SecHUD";
                request.ContentLength = body.Length;
                using (Stream stream = request.GetRequestStream())
                {
                    stream.Write(body, 0, body.Length);
                }
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    return (int)response.StatusCode < 300;
                }
            }
            catch (WebException ex)
            {
                var response = ex.Response as HttpWebResponse;
                error = response != null ? "Discord answered " + (int)response.StatusCode : "could not reach Discord";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public static string JsonEscape(string text)
        {
            var sb = new StringBuilder(text.Length + 16);
            foreach (char c in text)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': break;
                    case '\t': sb.Append(' '); break;
                    default:
                        if (c < 0x20) sb.Append(' ');
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
