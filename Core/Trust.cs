using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace SecHUD
{
    /// <summary>
    /// Answers "should I trust this?" for a new startup item, in words anyone can read.
    ///
    /// It looks at the program the item starts: is it signed, by whom, does Windows trust that
    /// signature, and where does the file live. A signature is not proof a program is good, and
    /// plenty of harmless hobby programs are not signed. But "signed by a company you know, in
    /// Program Files" and "not signed, in a temp folder" are very different starting points.
    ///
    /// One trap is handled on purpose: tools such as PowerShell are signed by Microsoft, yet they
    /// run whatever the rest of the command says. Those are never reported as simply "signed".
    /// </summary>
    public static class Trust
    {
        private static readonly string[] ProgramExtensions = { ".exe", ".dll", ".com", ".scr", ".sys", ".cpl", ".msi", ".ocx" };
        private static readonly string[] ScriptExtensions = { ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".url", ".pif" };

        /// <summary>Windows tools that run whatever they are handed. Signed by Microsoft, so the signature says nothing.</summary>
        private static readonly string[] ScriptHosts =
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
            "regsvr32.exe", "msiexec.exe", "wmic.exe", "bitsadmin.exe", "certutil.exe", "forfiles.exe", "schtasks.exe",
            "conhost.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "curl.exe", "bash.exe", "wsl.exe"
        };

        /// <summary>Asks Windows about a file's signature. Tests swap this.</summary>
        public static Func<string, SignatureInfo> SignatureReader = ReadSignature;
        /// <summary>Where a shortcut points, as "target arguments". Tests swap this.</summary>
        public static Func<string, string> ShortcutResolver = ResolveShortcut;
        /// <summary>The DLL a service hosted by svchost really runs. Tests swap this.</summary>
        public static Func<string, string> ServiceDllReader = ReadServiceDll;
        /// <summary>What a scheduled task runs, as "program arguments". Tests swap this.</summary>
        public static Func<string, string> TaskActionReader = ReadTaskAction;
        public static Func<string, bool> FileExists = File.Exists;

        private static readonly object CacheLock = new object();
        private static readonly Dictionary<string, TrustNote> Cache = new Dictionary<string, TrustNote>(StringComparer.OrdinalIgnoreCase);

        /// <summary>The note for one startup item, or null when nothing useful can be said. Results are remembered.</summary>
        public static TrustNote Describe(AutorunItem item)
        {
            if (item == null) return null;
            string cacheKey = (item.Key ?? "") + "|" + (item.Command ?? "");
            lock (CacheLock)
            {
                TrustNote cached;
                if (Cache.TryGetValue(cacheKey, out cached)) return cached;
            }

            TrustNote note = null;
            try
            {
                switch (item.Kind)
                {
                    case "run":
                        note = DescribeCommand(item.Command);
                        break;
                    case "startup":
                        note = DescribeStartupFile(item.Command);
                        break;
                    case "service":
                        note = DescribeService(item.Name, item.Command);
                        break;
                    case "task":
                        string action = TaskActionReader(item.Name);
                        note = string.IsNullOrWhiteSpace(action) ? null : DescribeCommand(action);
                        break;
                }
            }
            catch
            {
                note = null; // a note is a help, never a reason for a scan to fail
            }

            lock (CacheLock)
            {
                if (Cache.Count > 500) Cache.Clear();
                Cache[cacheKey] = note;
            }
            return note;
        }

        /// <summary>Forgets remembered notes (tests, and after a file may have changed).</summary>
        public static void ClearCache()
        {
            lock (CacheLock) Cache.Clear();
        }

        private static TrustNote DescribeStartupFile(string file)
        {
            if (string.IsNullOrEmpty(file)) return null;
            string extension = (System.IO.Path.GetExtension(file) ?? "").ToLowerInvariant();
            if (extension == ".lnk")
            {
                string target = ShortcutResolver(file);
                return string.IsNullOrWhiteSpace(target)
                    ? Note(TrustNote.Caution, "A shortcut whose target could not be read.", "a shortcut that could not be read", file)
                    : DescribeCommand(target);
            }
            return DescribeCommand("\"" + file + "\"");
        }

        private static TrustNote DescribeService(string name, string imagePath)
        {
            string arguments;
            string path = ExtractPath(imagePath, out arguments);
            if (FileNameOf(path).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            {
                // Many Windows services share svchost.exe. The code that matters is the DLL it loads.
                string dll = ServiceDllReader(name);
                if (!string.IsNullOrWhiteSpace(dll))
                {
                    TrustNote inner = DescribeCommand("\"" + dll + "\"");
                    if (inner != null)
                    {
                        inner.Text = "Runs inside the Windows service host. Its own file: " + Lower(inner.Text);
                        return inner;
                    }
                }
                return Note(TrustNote.Caution, "Runs inside the Windows service host, and the file it loads could not be read.", "runs inside the Windows service host", path);
            }
            return DescribeCommand(imagePath);
        }

        /// <summary>The note for a command line such as a Run key value.</summary>
        public static TrustNote DescribeCommand(string command)
        {
            string arguments;
            string path = ExtractPath(command, out arguments);
            if (string.IsNullOrEmpty(path)) return null;

            string resolved = Resolve(path);
            string fileName = FileNameOf(resolved);
            string extension = (System.IO.Path.GetExtension(resolved) ?? "").ToLowerInvariant();

            if (!FileExists(resolved))
                return Note(TrustNote.Caution, "The file it points to is not there: " + resolved + ". It may be left over from something that was removed.", "its file is missing", resolved);

            string where = LocationWarning(resolved);

            if (ScriptExtensions.Contains(extension))
            {
                return Note(where.Length > 0 ? TrustNote.Warn : TrustNote.Caution,
                    "A script, not a program, so it cannot be signed. Open it in Notepad to see what it does."
                        + (where.Length > 0 ? " It sits in " + where + ", which is an unusual place for something that starts by itself." : ""),
                    "a script" + (where.Length > 0 ? " in " + where : ""), resolved);
            }

            SignatureInfo signature = SignatureReader(resolved) ?? new SignatureInfo();
            string signer = string.IsNullOrWhiteSpace(signature.Signer) ? "an unnamed signer" : signature.Signer.Trim();

            if (signature.State == SignatureInfo.Broken)
                return Note(TrustNote.Warn, "The signature is broken: this file was changed after " + signer + " signed it. Treat it as untrusted.", "its signature is broken", resolved);

            if (signature.State == SignatureInfo.Trusted && ScriptHosts.Contains(fileName, StringComparer.OrdinalIgnoreCase))
            {
                // Signed by Microsoft, but only a messenger: what matters is what it was told to run.
                bool hasOrders = !string.IsNullOrWhiteSpace(arguments);
                return Note(TrustNote.Caution,
                    "Starts " + fileName + ", a Windows tool that runs whatever the rest of the command tells it to. "
                        + (hasOrders ? "Read the command itself: that is the part to judge." : "It is given nothing to run."),
                    "runs a command through " + fileName, resolved);
            }

            if (signature.State == SignatureInfo.Trusted)
            {
                return where.Length > 0
                    ? Note(TrustNote.Caution, "Signed by " + signer + ", and Windows trusts the signature. It runs from " + where + ", which is unusual for an installed program.", "signed by " + signer + ", in " + where, resolved)
                    : Note(TrustNote.Ok, "Signed by " + signer + ", and Windows trusts the signature.", "signed by " + signer, resolved);
            }

            if (signature.State == SignatureInfo.Untrusted)
                return Note(TrustNote.Warn, "Signed by " + signer + ", but Windows does not trust that signature." + (where.Length > 0 ? " It runs from " + where + "." : ""), "signature not trusted", resolved);

            return where.Length > 0
                ? Note(TrustNote.Warn, "Not signed, and it runs from " + where + ". Programs you installed on purpose rarely look like this.", "not signed, in " + where, resolved)
                : Note(TrustNote.Caution, "Not signed, so there is no proof of who made it. Many small programs are not. Approve it only if you know what it is.", "not signed", resolved);
        }

        private static TrustNote Note(string level, string text, string brief, string path)
        {
            return new TrustNote { Level = level, Text = text, Short = brief, Path = path };
        }

        /// <summary>The last part of a Windows path, whichever way its slashes lean.</summary>
        private static string FileNameOf(string path)
        {
            string text = path ?? "";
            int cut = Math.Max(text.LastIndexOf('\\'), text.LastIndexOf('/'));
            return cut < 0 ? text : text.Substring(cut + 1);
        }

        private static string Lower(string text)
        {
            return string.IsNullOrEmpty(text) ? "" : char.ToLowerInvariant(text[0]) + text.Substring(1);
        }

        // ------------------------------------------------------------- paths ---

        /// <summary>
        /// The program a command line starts, and the rest of the line. Handles quotes, paths with
        /// spaces written without quotes, %VARIABLES% and the path styles services use.
        /// </summary>
        public static string ExtractPath(string command, out string arguments)
        {
            arguments = "";
            string text = Environment.ExpandEnvironmentVariables((command ?? "").Trim());
            if (text.Length == 0) return "";

            string path;
            if (text[0] == '"')
            {
                int close = text.IndexOf('"', 1);
                if (close < 0) { path = text.Substring(1); }
                else
                {
                    path = text.Substring(1, close - 1);
                    arguments = text.Substring(close + 1).Trim();
                }
            }
            else
            {
                // No quotes: the path runs up to the first known extension that ends a word.
                int end = -1;
                foreach (string extension in ProgramExtensions.Concat(ScriptExtensions))
                {
                    int from = 0;
                    while (true)
                    {
                        int at = text.IndexOf(extension, from, StringComparison.OrdinalIgnoreCase);
                        if (at < 0) break;
                        int after = at + extension.Length;
                        if (after == text.Length || text[after] == ' ' || text[after] == ',')
                        {
                            if (end < 0 || after < end) end = after;
                            break;
                        }
                        from = after;
                    }
                }
                if (end < 0)
                {
                    int space = text.IndexOf(' ');
                    end = space < 0 ? text.Length : space;
                }
                path = text.Substring(0, end);
                arguments = text.Substring(end).Trim().TrimStart(',').Trim();
            }

            path = path.Trim();
            // Services write paths in the kernel's style.
            if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path.Substring(4);
            string windows = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = windows + path.Substring(11);
            else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase)) path = windows + "\\" + path;
            return path;
        }

        /// <summary>A bare name such as notepad.exe is looked for where Windows would look.</summary>
        private static string Resolve(string path)
        {
            try
            {
                if (path.IndexOf('\\') >= 0 || path.IndexOf('/') >= 0 || path.IndexOf(':') >= 0) return path;
                string name = System.IO.Path.HasExtension(path) ? path : path + ".exe";
                var folders = new List<string>
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                };
                folders.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'));
                foreach (string folder in folders)
                {
                    if (string.IsNullOrWhiteSpace(folder)) continue;
                    string candidate = System.IO.Path.Combine(folder.Trim(), name);
                    if (FileExists(candidate)) return candidate;
                }
                return name;
            }
            catch
            {
                return path;
            }
        }

        /// <summary>Names the folder when it is one that installed programs do not normally live in. "" otherwise.</summary>
        public static string LocationWarning(string path)
        {
            string p = "\\" + (path ?? "").Replace('/', '\\').ToLowerInvariant();
            if (p.Contains("\\appdata\\local\\temp\\") || p.Contains("\\windows\\temp\\") || p.Contains("\\temp\\") || p.Contains("\\tmp\\")) return "a temp folder";
            if (p.Contains("\\downloads\\")) return "the Downloads folder";
            if (p.Contains("\\$recycle.bin\\")) return "the Recycle Bin";
            if (p.Contains("\\users\\public\\")) return "the Public folder";
            if (p.Contains("\\desktop\\")) return "the Desktop";
            if (p.Contains("\\documents\\") || p.Contains("\\pictures\\") || p.Contains("\\music\\") || p.Contains("\\videos\\")) return "a personal folder";
            return "";
        }

        // ---------------------------------------------------- asking Windows ---

        private static SignatureInfo ReadSignature(string path)
        {
            var info = new SignatureInfo();
            int result = Native.VerifyFileSignature(path);

            if (result == 0)
            {
                info.State = SignatureInfo.Trusted;
                info.Signer = SignerOf(path);
                return info;
            }

            const int noSignature = unchecked((int)0x800B0100);
            const int formUnknown = unchecked((int)0x800B0003);
            const int providerUnknown = unchecked((int)0x800B0001);
            const int badDigest = unchecked((int)0x80096010);

            if (result == noSignature || result == formUnknown || result == providerUnknown)
            {
                // Most of Windows itself is signed through a catalog: the signature lives in a
                // separate file that lists the hashes of the files it covers.
                string catalog = Native.FindCatalogFor(path);
                if (!string.IsNullOrEmpty(catalog))
                {
                    info.Signer = SignerOf(catalog);
                    info.State = Native.VerifyFileSignature(catalog) == 0 ? SignatureInfo.Trusted : SignatureInfo.Untrusted;
                }
                return info;
            }

            info.Signer = SignerOf(path);
            info.State = result == badDigest ? SignatureInfo.Broken : SignatureInfo.Untrusted;
            return info;
        }

        private static string SignerOf(string path)
        {
            try
            {
                using (var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                {
                    return certificate.GetNameInfo(X509NameType.SimpleName, false) ?? "";
                }
            }
            catch
            {
                return "";
            }
        }

        private static string ResolveShortcut(string linkPath)
        {
            Type type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) return "";
            dynamic shell = Activator.CreateInstance(type);
            dynamic link = shell.CreateShortcut(linkPath);
            string target = Convert.ToString(link.TargetPath) ?? "";
            string arguments = Convert.ToString(link.Arguments) ?? "";
            return target.Length == 0 ? "" : "\"" + target + "\" " + arguments;
        }

        private static string ReadServiceDll(string serviceName)
        {
            using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey key = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName + @"\Parameters"))
            {
                return key == null ? "" : (Convert.ToString(key.GetValue("ServiceDll")) ?? "");
            }
        }

        private static string ReadTaskAction(string taskPath)
        {
            Type type = Type.GetTypeFromProgID("Schedule.Service");
            if (type == null) return "";
            dynamic scheduler = Activator.CreateInstance(type);
            scheduler.Connect();

            string full = taskPath ?? "";
            int slash = full.LastIndexOf('\\');
            string folderPath = slash <= 0 ? "\\" : full.Substring(0, slash);
            string taskName = slash < 0 ? full : full.Substring(slash + 1);
            dynamic task = scheduler.GetFolder(folderPath).GetTask(taskName);
            foreach (dynamic action in task.Definition.Actions)
            {
                if (Convert.ToInt32(action.Type) != 0) continue; // 0 = start a program
                string program = Convert.ToString(action.Path) ?? "";
                string arguments = Convert.ToString(action.Arguments) ?? "";
                if (program.Length > 0) return "\"" + program.Trim('"') + "\" " + arguments;
            }
            return "";
        }
    }
}
