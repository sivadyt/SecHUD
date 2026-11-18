using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;

namespace SecHUD.Setup
{
    /// <summary>
    /// SecHUD-Setup.exe. Run it with no options and a small window installs SecHUD. The same
    /// program, copied into the install folder as Uninstall.exe, removes it again.
    ///
    ///   --uninstall      remove SecHUD
    ///   --remove-data    with --uninstall: also delete settings and history
    ///   --silent         no window; the exit code is 0 for success
    ///   --no-launch      do not start SecHUD afterwards
    ///   --no-desktop     no desktop shortcut
    ///   --dir "path"     install somewhere other than the usual place
    /// </summary>
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            SetupOptions options = Installer.ParseArgs(args);
            string self = Assembly.GetExecutingAssembly().Location;

            try
            {
                // A program cannot delete the folder it is running from. So the uninstaller first
                // steps outside: it copies itself to the temp folder and carries on from there.
                if (options.Uninstall && IsInside(self, Installer.TargetDir(options)))
                {
                    string dir = Installer.TargetDir(options);
                    string copy = Path.Combine(Path.GetTempPath(), "SecHUD-Uninstall-" + Process.GetCurrentProcess().Id + ".exe");
                    File.Copy(self, copy, true);
                    string arguments = "--uninstall --dir \"" + dir + "\""
                        + (options.Silent ? " --silent" : "") + (options.RemoveData ? " --remove-data" : "");
                    Process.Start(new ProcessStartInfo(copy, arguments) { UseShellExecute = false });
                    return 0;
                }

                if (options.Silent) return RunSilently(options, self);
            }
            catch (Exception ex)
            {
                Store.LogError("setup", ex);
                if (options.Silent) return 1;
            }

            var app = new Application();
            app.Run(new SetupWindow(options, self));
            return 0;
        }

        private static int RunSilently(SetupOptions options, string self)
        {
            string error, version;
            bool ok = options.Uninstall
                ? Installer.Uninstall(options, null, out error)
                : Installer.Install(options, self, null, out version, out error);
            if (!ok) Store.LogError("setup", new Exception(error));
            return ok ? 0 : 1;
        }

        private static bool IsInside(string file, string folder)
        {
            try
            {
                string parent = Path.GetFullPath(Path.GetDirectoryName(file) ?? "").TrimEnd('\\', '/');
                return string.Equals(parent, Path.GetFullPath(folder).TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
