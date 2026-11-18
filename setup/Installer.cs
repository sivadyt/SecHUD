using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace SecHUD.Setup
{
    /// <summary>What the setup program was asked to do on its command line.</summary>
    public class SetupOptions
    {
        /// <summary>Remove SecHUD instead of installing it.</summary>
        public bool Uninstall { get; set; }
        /// <summary>No window: do the job and report through the exit code. Used by the automated test.</summary>
        public bool Silent { get; set; }
        public bool NoLaunch { get; set; }
        public bool NoDesktopShortcut { get; set; }
        /// <summary>With Uninstall: also delete settings, baselines and history.</summary>
        public bool RemoveData { get; set; }
        /// <summary>Where to install. Empty means the usual per-user place.</summary>
        public string Dir { get; set; }

        public SetupOptions()
        {
            Dir = "";
        }
    }

    /// <summary>The parts of setup that touch Windows itself, kept behind one interface so the logic can be tested.</summary>
    public interface ISetupSystem
    {
        void StopRunningApp();
        void MakeShortcut(string linkPath, string targetExe, string workingDir);
        void RemoveShortcut(string linkPath);
        void RegisterUninstall(string installDir, string version);
        void UnregisterUninstall();
        /// <summary>If "Start with Windows" was switched on in an older copy, point it at the new one.</summary>
        void FixStartupEntry(string exePath);
        void RemoveStartupEntry();
        void Launch(string exePath);
        /// <summary>Where a previous setup put SecHUD, or "" when it has never been installed.</summary>
        string InstalledDir();
    }

    /// <summary>
    /// Installs SecHUD for the current user: finds the newest release on GitHub, downloads and
    /// checks it exactly the way the app's own update button does, puts it in place, and adds
    /// shortcuts and an entry under "Installed apps". No administrator rights are needed, and
    /// nothing outside this user's own folders and registry is touched.
    /// </summary>
    public static class Installer
    {
        public const string UninstallerName = "Uninstall.exe";
        public const string ShortcutName = "SecHUD.lnk";

        /// <summary>The Windows side. Tests swap in a recorder.</summary>
        public static ISetupSystem Windows = new WindowsSetupSystem();

        /// <summary>Finds the newest release. Tests swap this so nothing touches the network.</summary>
        public static Func<UpdateInfo> ReleaseFinder = FindLatestRelease;

        /// <summary>Why the last ReleaseFinder call came back empty.</summary>
        public static string FindError = "";

        public static string DefaultDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "SecHUD"); }
        }

        public static string StartMenuShortcut
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), ShortcutName); }
        }

        public static string DesktopShortcut
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), ShortcutName); }
        }

        public static SetupOptions ParseArgs(string[] args)
        {
            var options = new SetupOptions();
            args = args ?? new string[0];
            for (int i = 0; i < args.Length; i++)
            {
                switch ((args[i] ?? "").ToLowerInvariant())
                {
                    case "--uninstall": options.Uninstall = true; break;
                    case "--silent": options.Silent = true; break;
                    case "--no-launch": options.NoLaunch = true; break;
                    case "--no-desktop": options.NoDesktopShortcut = true; break;
                    case "--remove-data": options.RemoveData = true; break;
                    case "--dir":
                        if (i + 1 < args.Length) options.Dir = (args[++i] ?? "").Trim().Trim('"');
                        break;
                }
            }
            return options;
        }

        /// <summary>Where this run installs to (or removes from).</summary>
        public static string TargetDir(SetupOptions options)
        {
            if (options != null && !string.IsNullOrWhiteSpace(options.Dir)) return Path.GetFullPath(options.Dir);
            if (options != null && options.Uninstall)
            {
                string installed = "";
                try { installed = Windows.InstalledDir() ?? ""; } catch { }
                if (installed.Length > 0) return installed;
            }
            return DefaultDir;
        }

        private static UpdateInfo FindLatestRelease()
        {
            string error;
            UpdateInfo info = Updater.Check(new Version(0, 0, 0), out error);
            FindError = error ?? "";
            return info;
        }

        /// <summary>
        /// The whole install. "selfPath" is the running setup program, which is copied in as the
        /// uninstaller. Returns false with the reason in "error", and in that case the program
        /// folder is left exactly as it was.
        /// </summary>
        public static bool Install(SetupOptions options, string selfPath, Action<string> status, out string version, out string error)
        {
            version = "";
            error = "";
            Action<string> say = text => { if (status != null) status((text ?? "").Replace("DOWNLOADING UPDATE", "DOWNLOADING SECHUD")); };
            try
            {
                string dir = TargetDir(options);

                say("LOOKING FOR THE NEWEST VERSION...");
                FindError = "";
                UpdateInfo info = ReleaseFinder();
                if (info == null)
                {
                    error = FindError.Length > 0 ? FindError : "no version of SecHUD has been published yet";
                    return false;
                }
                if (!info.CanInstall)
                {
                    error = "the newest release has no download that setup can check";
                    return false;
                }

                string staged;
                if (!Updater.Prepare(info, say, out staged, out error)) return false;

                say("INSTALLING...");
                Windows.StopRunningApp(); // only one copy may run, and it has to be the new one
                Directory.CreateDirectory(dir);
                if (!Updater.Install(staged, dir, out error)) return false;
                Updater.CleanupAfterUpdate(dir);
                version = info.Version;

                // From here on SecHUD itself is in place. The extras are worth having but none of
                // them is a reason to call the install a failure.
                string exe = Path.Combine(dir, Updater.ExeName);
                Quietly(() => CopyUninstaller(selfPath, dir));
                Quietly(() => Windows.MakeShortcut(StartMenuShortcut, exe, dir));
                if (options == null || !options.NoDesktopShortcut) Quietly(() => Windows.MakeShortcut(DesktopShortcut, exe, dir));
                string installedVersion = version;
                Quietly(() => Windows.RegisterUninstall(dir, installedVersion));
                Quietly(() => Windows.FixStartupEntry(exe));

                if (options == null || !options.NoLaunch)
                {
                    say("STARTING SECHUD...");
                    Quietly(() => Windows.Launch(exe));
                }
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                error = "Windows would not let setup write to the install folder";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static void CopyUninstaller(string selfPath, string dir)
        {
            if (string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath)) return;
            string target = Path.Combine(dir, UninstallerName);
            if (string.Equals(Path.GetFullPath(selfPath), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase)) return;
            File.Copy(selfPath, target, true);
        }

        /// <summary>
        /// Removes SecHUD. Only the files setup put there are deleted, by name, so a folder that
        /// holds anything else is never emptied. Settings and history are kept unless asked.
        /// </summary>
        public static bool Uninstall(SetupOptions options, Action<string> status, out string error)
        {
            error = "";
            try
            {
                string dir = TargetDir(options);
                if (status != null) status("REMOVING SECHUD...");

                Windows.StopRunningApp();
                Quietly(() => Windows.RemoveStartupEntry());
                Quietly(() => Windows.RemoveShortcut(StartMenuShortcut));
                Quietly(() => Windows.RemoveShortcut(DesktopShortcut));
                Quietly(() => Windows.UnregisterUninstall());

                var names = new List<string>(Updater.ProgramFiles);
                names.AddRange(Updater.ProgramFiles.Select(n => n + ".old"));
                names.Add(UninstallerName);
                foreach (string name in names) DeleteWithRetry(Path.Combine(dir, name));
                // Gone only if nothing else lives there.
                Quietly(() => { if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any()) Directory.Delete(dir); });

                if (options != null && options.RemoveData)
                    Quietly(() => { if (Directory.Exists(Store.Dir)) Directory.Delete(Store.Dir, true); });

                if (File.Exists(Path.Combine(dir, Updater.ExeName)))
                {
                    error = "SecHUD is still running or its files are in use. Close it from the tray icon and try again.";
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
        /// A program that has just been closed can keep its file locked for a moment longer, so a
        /// delete that fails is tried again for a few seconds before giving up.
        /// </summary>
        private static void DeleteWithRetry(string path)
        {
            for (int attempt = 0; attempt < 24; attempt++)
            {
                try
                {
                    if (!File.Exists(path)) return;
                    File.Delete(path);
                    return;
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                System.Threading.Thread.Sleep(250);
            }
        }

        private static void Quietly(Action action)
        {
            try { action(); }
            catch (Exception ex) { Store.LogError("setup", ex); }
        }
    }

    /// <summary>The real thing: processes, shortcuts and the current user's registry.</summary>
    public class WindowsSetupSystem : ISetupSystem
    {
        private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\SecHUD";
        private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunValue = "SecHUD";

        public void StopRunningApp()
        {
            foreach (Process process in Process.GetProcessesByName("SecHUD"))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit(8000);
                }
                catch
                {
                    // Already gone, or another user's copy. Either way there is nothing to do.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        public void MakeShortcut(string linkPath, string targetExe, string workingDir)
        {
            // The Windows Script Host ships with Windows and is the standard way to write a .lnk file.
            Type type = Type.GetTypeFromProgID("WScript.Shell");
            if (type == null) throw new InvalidOperationException("Windows Script Host is not available");
            string folder = Path.GetDirectoryName(linkPath);
            if (!string.IsNullOrEmpty(folder)) Directory.CreateDirectory(folder);

            dynamic shell = Activator.CreateInstance(type);
            dynamic link = shell.CreateShortcut(linkPath);
            link.TargetPath = targetExe;
            link.WorkingDirectory = workingDir;
            link.Description = "SecHUD home network security monitor";
            link.IconLocation = targetExe + ",0";
            link.Save();
        }

        public void RemoveShortcut(string linkPath)
        {
            if (File.Exists(linkPath)) File.Delete(linkPath);
        }

        public void RegisterUninstall(string installDir, string version)
        {
            string exe = Path.Combine(installDir, Updater.ExeName);
            string uninstaller = Path.Combine(installDir, Installer.UninstallerName);
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                if (key == null) return;
                key.SetValue("DisplayName", "SecHUD");
                key.SetValue("DisplayVersion", version ?? "");
                key.SetValue("Publisher", "sivadyt");
                key.SetValue("InstallLocation", installDir);
                key.SetValue("DisplayIcon", exe);
                key.SetValue("UninstallString", "\"" + uninstaller + "\" --uninstall");
                key.SetValue("URLInfoAbout", "https://github.com/" + Updater.Repo);
                key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                try
                {
                    long bytes = new DirectoryInfo(installDir).GetFiles().Sum(f => f.Length);
                    key.SetValue("EstimatedSize", (int)Math.Max(1, bytes / 1024), RegistryValueKind.DWord);
                }
                catch { }
            }
        }

        public void UnregisterUninstall()
        {
            Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
        }

        public string InstalledDir()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(UninstallKey))
            {
                return key == null ? "" : (Convert.ToString(key.GetValue("InstallLocation")) ?? "");
            }
        }

        public void FixStartupEntry(string exePath)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunPath, true))
            {
                if (key == null || key.GetValue(RunValue) == null) return;
                key.SetValue(RunValue, "\"" + exePath + "\" --tray");
            }
        }

        public void RemoveStartupEntry()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunPath, true))
            {
                if (key != null && key.GetValue(RunValue) != null) key.DeleteValue(RunValue, false);
            }
        }

        public void Launch(string exePath)
        {
            Process.Start(new ProcessStartInfo(exePath)
            {
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? ""
            });
        }
    }
}
