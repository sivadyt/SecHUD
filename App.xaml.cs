using System;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace SecHUD
{
    public partial class App : Application
    {
        private Mutex instanceLock;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // One copy at a time: two scanners would fight over the same data files.
            bool isFirst;
            instanceLock = new Mutex(true, @"Local\SecHUD.App", out isFirst);
            if (!isFirst)
            {
                MessageBox.Show("SecHUD is already running. Look for its icon in the system tray.",
                    "SecHUD", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }

            DispatcherUnhandledException += OnUnhandledException;
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var window = new MainWindow();
            MainWindow = window;

            // "--tray" is how the Start with Windows entry launches it: watching, but out of the way.
            bool startHidden = e.Args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));
            if (!startHidden) window.Show();
        }

        private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Store.LogError("ui", e.Exception);
            MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message
                + "\n\nDetails were saved to:\n" + Store.ErrorPath,
                "SecHUD", MessageBoxButton.OK, MessageBoxImage.Warning);
            e.Handled = true;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (instanceLock != null)
            {
                try { instanceLock.ReleaseMutex(); } catch { }
                instanceLock.Dispose();
            }
            base.OnExit(e);
        }
    }
}
