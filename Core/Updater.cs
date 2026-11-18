using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;

namespace SecHUD
{
    [DataContract]
    internal class GithubRelease
    {
        [DataMember(Name = "tag_name")] public string TagName { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "html_url")] public string HtmlUrl { get; set; }
        [DataMember(Name = "body")] public string Body { get; set; }
        [DataMember(Name = "draft")] public bool Draft { get; set; }
        [DataMember(Name = "prerelease")] public bool Prerelease { get; set; }
    }

    public class UpdateInfo
    {
        public string Version { get; set; }
        public string Notes { get; set; }
        public string Url { get; set; }
    }

    /// <summary>
    /// Looks for a newer release on the project's GitHub page. It only ever tells you and opens
    /// the download page in your browser: it never downloads or installs anything by itself,
    /// and it sends nothing about you or your network.
    /// </summary>
    public static class Updater
    {
        /// <summary>The GitHub account and repository releases are published from.</summary>
        public const string Repo = "sivadyt/SecHUD";

        public static string ReleasesPage { get { return "https://github.com/" + Repo + "/releases/latest"; } }
        private static string ApiUrl { get { return "https://api.github.com/repos/" + Repo + "/releases/latest"; } }

        /// <summary>The version of the running program, as major.minor.patch.</summary>
        public static Version CurrentVersion
        {
            get
            {
                Assembly assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
                return Normalize(assembly.GetName().Version);
            }
        }

        /// <summary>Asks GitHub for the latest release. Null when there is nothing newer; "error" says why a check failed.</summary>
        public static UpdateInfo Check(Version current, out string error)
        {
            error = "";
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(ApiUrl);
                request.Method = "GET";
                request.Timeout = 8000;
                request.ReadWriteTimeout = 8000;
                request.UserAgent = "SecHUD-update-check"; // GitHub requires one
                request.Accept = "application/vnd.github+json";
                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                {
                    return ParseRelease(reader.ReadToEnd(), current);
                }
            }
            catch (WebException ex)
            {
                var response = ex.Response as HttpWebResponse;
                if (response != null && response.StatusCode == HttpStatusCode.NotFound) return null; // no release published yet
                error = response != null ? "GitHub answered " + (int)response.StatusCode : "could not reach GitHub";
                return null;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return null;
            }
        }

        /// <summary>Reads GitHub's answer. Null unless it describes a published release newer than "current".</summary>
        public static UpdateInfo ParseRelease(string json, Version current)
        {
            GithubRelease release = Store.FromJson<GithubRelease>(json);
            if (release == null || release.Draft || release.Prerelease) return null;

            Version latest;
            if (!TryParseVersion(release.TagName, out latest)) return null;
            if (latest <= Normalize(current)) return null;

            return new UpdateInfo
            {
                Version = latest.ToString(3),
                Notes = Shorten(release.Body, 700),
                Url = SafeUrl(release.HtmlUrl)
            };
        }

        /// <summary>Accepts "v0.7.0", "0.7" or "V1.2.3-beta" and reads the numbers at the front.</summary>
        public static bool TryParseVersion(string tag, out Version version)
        {
            version = new Version(0, 0, 0);
            string text = (tag ?? "").Trim().TrimStart('v', 'V');
            string numbers = new string(text.TakeWhile(c => char.IsDigit(c) || c == '.').ToArray()).Trim('.');
            if (numbers.Length == 0) return false;
            if (!numbers.Contains(".")) numbers += ".0";

            Version parsed;
            if (!Version.TryParse(numbers, out parsed)) return false;
            version = Normalize(parsed);
            return true;
        }

        /// <summary>Three parts exactly, so 0.6 and 0.6.0.0 compare as equal.</summary>
        public static Version Normalize(Version v)
        {
            if (v == null) return new Version(0, 0, 0);
            return new Version(v.Major, v.Minor, Math.Max(0, v.Build));
        }

        /// <summary>The button may only ever open a page inside this project on github.com.</summary>
        public static string SafeUrl(string url)
        {
            Uri uri;
            if (Uri.TryCreate(url ?? "", UriKind.Absolute, out uri)
                && uri.Scheme == Uri.UriSchemeHttps
                && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
                && uri.AbsolutePath.StartsWith("/" + Repo + "/", StringComparison.OrdinalIgnoreCase))
            {
                return uri.ToString();
            }
            return ReleasesPage;
        }

        private static string Shorten(string text, int max)
        {
            text = (text ?? "").Replace("\r", "").Trim();
            if (text.Length == 0) return "No release notes were written for this version.";
            return text.Length <= max ? text : text.Substring(0, max) + "...";
        }
    }
}
