using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography;
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
        [DataMember(Name = "assets")] public List<GithubAsset> Assets { get; set; }
    }

    /// <summary>One file attached to a release.</summary>
    [DataContract]
    internal class GithubAsset
    {
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "browser_download_url")] public string DownloadUrl { get; set; }
        [DataMember(Name = "size")] public long Size { get; set; }
        /// <summary>GitHub's own checksum of the file, as "sha256:hex".</summary>
        [DataMember(Name = "digest")] public string Digest { get; set; }
    }

    public class UpdateInfo
    {
        public string Version { get; set; }
        public string Notes { get; set; }
        public string Url { get; set; }

        /// <summary>Where the release zip is, or "" when the release has none this program can install.</summary>
        public string ZipUrl { get; set; }
        /// <summary>The published checksum file for the zip, or "".</summary>
        public string HashUrl { get; set; }
        /// <summary>GitHub's own SHA-256 of the zip (64 hex digits), or "".</summary>
        public string Digest { get; set; }

        /// <summary>True when the program can install this release by itself: a zip, and a checksum to check it against.</summary>
        public bool CanInstall
        {
            get { return !string.IsNullOrEmpty(ZipUrl) && (!string.IsNullOrEmpty(HashUrl) || !string.IsNullOrEmpty(Digest)); }
        }

        public UpdateInfo()
        {
            ZipUrl = "";
            HashUrl = "";
            Digest = "";
        }
    }

    /// <summary>
    /// Looks for a newer release on the project's GitHub page and, when you press the update
    /// button, installs it: download, check, swap the program files, start again.
    ///
    /// Nothing is installed unless you ask. The download only ever comes from this project's
    /// releases on github.com over HTTPS, and it is only used if its SHA-256 matches the
    /// checksum published with the release. The check itself sends nothing about you or
    /// your network.
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

        /// <summary>
        /// Set by the "--test-update" start option. The latest release is then offered even when
        /// this copy is the same version or newer, so the update button can be tried out at any
        /// time. The release is still downloaded and checked exactly as usual.
        /// </summary>
        public static bool OfferAnyRelease;

        /// <summary>Asks GitHub for the latest release. Null when there is nothing newer; "error" says why a check failed.</summary>
        public static UpdateInfo Check(Version current, out string error)
        {
            error = "";
            if (OfferAnyRelease) current = new Version(0, 0, 0);
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
                Url = SafeUrl(release.HtmlUrl),
                ZipUrl = AssetUrl(release, "SecHUD-v" + latest.ToString(3) + ".zip"),
                HashUrl = AssetUrl(release, "SecHUD-v" + latest.ToString(3) + ".sha256.txt"),
                Digest = AssetDigest(release, "SecHUD-v" + latest.ToString(3) + ".zip")
            };
        }

        private static GithubAsset FindAsset(GithubRelease release, string name)
        {
            if (release.Assets == null) return null;
            return release.Assets.FirstOrDefault(a => a != null && string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        private static string AssetUrl(GithubRelease release, string name)
        {
            GithubAsset asset = FindAsset(release, name);
            return asset == null ? "" : SafeDownloadUrl(asset.DownloadUrl);
        }

        private static string AssetDigest(GithubRelease release, string name)
        {
            GithubAsset asset = FindAsset(release, name);
            string digest = asset == null ? "" : (asset.Digest ?? "");
            const string prefix = "sha256:";
            return digest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ? ParseHash(digest.Substring(prefix.Length)) : "";
        }

        /// <summary>A file may only be downloaded from this project's releases on github.com. Anything else gives "".</summary>
        public static string SafeDownloadUrl(string url)
        {
            Uri uri;
            if (Uri.TryCreate(url ?? "", UriKind.Absolute, out uri)
                && uri.Scheme == Uri.UriSchemeHttps
                && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
                && uri.IsDefaultPort
                && uri.Query.Length == 0 && uri.Fragment.Length == 0 && uri.UserInfo.Length == 0
                && uri.AbsolutePath.StartsWith("/" + Repo + "/releases/download/", StringComparison.OrdinalIgnoreCase)
                && uri.AbsolutePath.IndexOf("..", StringComparison.Ordinal) < 0)
            {
                return uri.ToString();
            }
            return "";
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

        // ------------------------------------------------------------ install ---

        /// <summary>The only files an update may put in the program folder. The exe goes last.</summary>
        public static readonly string[] ProgramFiles = { "SecHUD.exe.config", "README.md", "LICENSE", "SecHUD.exe" };
        public const string ExeName = "SecHUD.exe";
        private const long MaxZipBytes = 60L * 1024 * 1024;
        private const long MaxUnpackedBytes = 200L * 1024 * 1024;

        /// <summary>Tests point this at a scratch folder so an install never lands next to the real program.</summary>
        public static string AppDirOverride;

        /// <summary>The folder the running program lives in.</summary>
        public static string AppDir
        {
            get
            {
                if (!string.IsNullOrEmpty(AppDirOverride)) return AppDirOverride;
                Assembly assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
                return Path.GetDirectoryName(assembly.Location) ?? "";
            }
        }

        /// <summary>Scratch space for a download. Emptied before and after every update.</summary>
        public static string WorkDir { get { return Path.Combine(Store.Dir, "update"); } }

        /// <summary>Replaceable so tests can check the version rule without a real program file.</summary>
        public static Func<string, string> VersionReader = path => FileVersionInfo.GetVersionInfo(path).FileVersion;

        /// <summary>Replaceable so tests can supply a download without touching the network.</summary>
        public static Func<string, string, long, Action<int>, string> Downloader = DownloadFile;

        /// <summary>
        /// Downloads the release, checks it, and unpacks it into a staging folder. Nothing in the
        /// program folder is touched yet. Returns false with the reason in "error".
        /// </summary>
        public static bool Prepare(UpdateInfo info, Action<string> status, out string stagedDir, out string error)
        {
            stagedDir = "";
            error = "";
            if (info == null || !info.CanInstall || SafeDownloadUrl(info.ZipUrl).Length == 0)
            {
                error = "this release has no download the program can install by itself";
                return false;
            }
            Action<string> say = status ?? (text => { });
            try
            {
                if (Directory.Exists(WorkDir)) Directory.Delete(WorkDir, true);
                Directory.CreateDirectory(WorkDir);
                string zipPath = Path.Combine(WorkDir, "update.zip");

                say("DOWNLOADING UPDATE...");
                error = Downloader(info.ZipUrl, zipPath, MaxZipBytes, percent => say("DOWNLOADING UPDATE " + percent + "%"));
                if (error.Length > 0) return false;

                say("CHECKING THE DOWNLOAD...");
                var expected = new List<string>();
                if (!string.IsNullOrEmpty(info.Digest)) expected.Add(ParseHash(info.Digest));
                if (SafeDownloadUrl(info.HashUrl).Length > 0)
                {
                    string hashPath = Path.Combine(WorkDir, "update.sha256.txt");
                    error = Downloader(info.HashUrl, hashPath, 4096, null);
                    if (error.Length > 0) return false;
                    expected.Add(ParseHash(File.ReadAllText(hashPath)));
                }
                if (expected.Count == 0 || expected.Any(h => h.Length == 0))
                {
                    error = "the release's checksum could not be read";
                    return false;
                }
                string actual = Sha256File(zipPath);
                if (expected.Any(h => !string.Equals(h, actual, StringComparison.OrdinalIgnoreCase)))
                {
                    error = "the download does not match the checksum published with the release, so it was thrown away";
                    return false;
                }

                say("UNPACKING...");
                string target = Path.Combine(WorkDir, "files");
                if (!Unpack(zipPath, target, out error)) return false;
                if (!VerifyExe(Path.Combine(target, ExeName), info.Version, out error)) return false;

                stagedDir = target;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        /// <summary>Fetches one file from this project's releases. Returns "" on success, otherwise why it failed.</summary>
        public static string DownloadFile(string url, string path, long maxBytes, Action<int> progress)
        {
            string safe = SafeDownloadUrl(url);
            if (safe.Length == 0) return "the download address is not this project's release page";
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(safe);
                request.Method = "GET";
                request.Timeout = 20000;
                request.ReadWriteTimeout = 30000;
                request.UserAgent = "SecHUD-update";
                request.AllowAutoRedirect = true; // GitHub hands the file over from its own storage servers
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    if (response.ResponseUri == null || response.ResponseUri.Scheme != Uri.UriSchemeHttps)
                        return "the download left the secure connection";
                    long length = response.ContentLength;
                    if (length > maxBytes) return "the download is larger than expected";

                    using (Stream input = response.GetResponseStream())
                    using (var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        var buffer = new byte[64 * 1024];
                        long total = 0;
                        int lastPercent = -1;
                        int read;
                        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            total += read;
                            if (total > maxBytes) return "the download is larger than expected";
                            output.Write(buffer, 0, read);
                            if (progress != null && length > 0)
                            {
                                int percent = (int)(total * 100 / length);
                                if (percent != lastPercent) { lastPercent = percent; progress(percent); }
                            }
                        }
                        if (length > 0 && total != length) return "the download stopped part way";
                    }
                }
                return "";
            }
            catch (WebException ex)
            {
                var response = ex.Response as HttpWebResponse;
                return response != null ? "GitHub answered " + (int)response.StatusCode : "could not reach GitHub";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        /// <summary>The 64 hex digits at the start of a checksum file ("hash  name"), in lower case. "" when there are none.</summary>
        public static string ParseHash(string text)
        {
            string first = (text ?? "").Trim('\uFEFF', ' ', '\t', '\r', '\n').Split(new[] { ' ', '\t', '\r', '\n', '*' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            return first.Length == 64 && first.All(Uri.IsHexDigit) ? first.ToLowerInvariant() : "";
        }

        public static string Sha256File(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                return string.Concat(sha.ComputeHash(stream).Select(b => b.ToString("x2")));
            }
        }

        /// <summary>
        /// Unpacks the release zip. Only the program's own files are taken, by exact name, from
        /// the top level of the zip. Anything else in it is ignored.
        /// </summary>
        public static bool Unpack(string zipPath, string targetDir, out string error)
        {
            error = "";
            try
            {
                if (Directory.Exists(targetDir)) Directory.Delete(targetDir, true);
                Directory.CreateDirectory(targetDir);
                long total = 0;
                var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                using (FileStream stream = File.OpenRead(zipPath))
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Read))
                {
                    foreach (ZipArchiveEntry entry in zip.Entries)
                    {
                        string name = ProgramFiles.FirstOrDefault(f => string.Equals(f, entry.FullName, StringComparison.OrdinalIgnoreCase));
                        if (name == null || !taken.Add(name)) continue;

                        total += entry.Length;
                        if (total > MaxUnpackedBytes) { error = "the update unpacks to more than expected"; return false; }

                        using (Stream input = entry.Open())
                        using (var output = new FileStream(Path.Combine(targetDir, name), FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            var buffer = new byte[64 * 1024];
                            long written = 0;
                            int read;
                            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                written += read;
                                if (written > MaxUnpackedBytes) { error = "the update unpacks to more than expected"; return false; }
                                output.Write(buffer, 0, read);
                            }
                        }
                    }
                }

                if (!taken.Contains(ExeName)) { error = "the update does not contain " + ExeName; return false; }
                return true;
            }
            catch (Exception ex)
            {
                error = "the update could not be unpacked: " + ex.Message;
                return false;
            }
        }

        /// <summary>The new program file has to be a Windows program, and exactly the version the release says it is.</summary>
        public static bool VerifyExe(string exePath, string expectedVersion, out string error)
        {
            error = "";
            try
            {
                using (FileStream stream = File.OpenRead(exePath))
                {
                    if (stream.Length < 1024 || stream.ReadByte() != 'M' || stream.ReadByte() != 'Z')
                    {
                        error = "the downloaded file is not a Windows program";
                        return false;
                    }
                }
                Version found, expected;
                if (!TryParseVersion(VersionReader(exePath), out found) || !TryParseVersion(expectedVersion, out expected) || found != expected)
                {
                    error = "the downloaded program is not version " + expectedVersion;
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Swaps the program files. Windows will not let a running program be overwritten, but
        /// it can be renamed, so each current file is set aside as name.old and the new one takes
        /// its place. If anything fails part way, every file is put back as it was.
        /// </summary>
        public static bool Install(string stagedDir, string appDir, out string error)
        {
            error = "";
            var done = new List<string>(); // targets already swapped, for undoing
            try
            {
                if (!File.Exists(Path.Combine(stagedDir, ExeName))) { error = "the update is incomplete"; return false; }

                foreach (string name in ProgramFiles)
                {
                    string staged = Path.Combine(stagedDir, name);
                    if (!File.Exists(staged)) continue;
                    string target = Path.Combine(appDir, name);
                    string old = target + ".old";

                    if (File.Exists(old)) File.Delete(old);
                    bool hadTarget = File.Exists(target);
                    if (hadTarget) File.Move(target, old);
                    try
                    {
                        File.Copy(staged, target, false);
                    }
                    catch
                    {
                        // Put this one file back before the rest are undone below.
                        try { if (File.Exists(target)) File.Delete(target); } catch { }
                        if (hadTarget && !File.Exists(target)) File.Move(old, target);
                        throw;
                    }
                    done.Add(target);
                }
                return true;
            }
            catch (Exception ex)
            {
                foreach (string target in Enumerable.Reverse(done))
                {
                    try
                    {
                        File.Delete(target);
                        if (File.Exists(target + ".old")) File.Move(target + ".old", target);
                    }
                    catch { }
                }
                error = ex is UnauthorizedAccessException
                    ? "SecHUD is not allowed to change the files in its own folder (" + appDir + ")"
                    : ex.Message;
                return false;
            }
        }

        /// <summary>Removes what an update left behind: the set-aside files and the download. Safe to call at any start.</summary>
        public static void CleanupAfterUpdate(string appDir)
        {
            foreach (string name in ProgramFiles)
            {
                try
                {
                    string old = Path.Combine(appDir ?? "", name + ".old");
                    if (File.Exists(old)) File.Delete(old);
                }
                catch { }
            }
            try
            {
                if (Directory.Exists(WorkDir)) Directory.Delete(WorkDir, true);
            }
            catch { }
        }

        private static string Shorten(string text, int max)
        {
            text = (text ?? "").Replace("\r", "").Trim();
            if (text.Length == 0) return "No release notes were written for this version.";
            return text.Length <= max ? text : text.Substring(0, max) + "...";
        }
    }
}
