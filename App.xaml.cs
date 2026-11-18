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

            // "--after-update" is how a copy that has just updated itself starts the new version.
            bool afterUpdate = e.Args.Any(a => string.Equals(a, "--after-update", StringComparison.OrdinalIgnoreCase));

            // "--test-update" offers the latest release whatever version this copy is, to try the update button.
            if (e.Args.Any(a => string.Equals(a, "--test-update", StringComparison.OrdinalIgnoreCase))) Updater.OfferAnyRelease = true;

            // One copy at a time: two scanners would fight over the same data files. After an
            // update the old copy is still closing, so the new one waits for it to let go.
            bool isFirst = false;
            DateTime giveUp = DateTime.UtcNow.AddSeconds(afterUpdate ? 30 : 0);
            while (true)
            {
                instanceLock = new Mutex(true, @"Local\SecHUD.App", out isFirst);
                if (isFirst || DateTime.UtcNow >= giveUp) break;
                instanceLock.Dispose();
                instanceLock = null;
                Thread.Sleep(300);
            }
            if (!isFirst)
            {
                MessageBox.Show("SecHUD is already running. Look for its icon in the system tray.",
                    "SecHUD", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }

            // Clears away what the last update set aside. Does nothing when there is nothing to clear.
            Updater.CleanupAfterUpdate(Updater.AppDir);

            DispatcherUnhandledException += OnUnhandledException;
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var window = new MainWindow();
            MainWindow = window;

            // "--tray" is how the Start with Windows entry launches it: watching, but out of the way.
            bool startHidden = e.Args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));
            if (afterUpdate) window.AnnounceUpdated();
            if (!startHidden || afterUpdate) window.Show();
        }

        private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Store.LogError("ui", e.Exception);
            MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message
                + "\n\nDetails were saved to:\n" + Store.ErrorPath,
                "SecHUD", MessageBoxButton.OK, MessageBoxImage.Warning);
            e.Handled = true;
        }

        /// <summary>
        /// Lets go of the one-copy lock early. Called just before an update starts the new
        /// version, so the new copy is never told that SecHUD is already running.
        /// </summary>
        public void ReleaseInstanceLock()
        {
            if (instanceLock == null) return;
            try { instanceLock.ReleaseMutex(); } catch { }
            instanceLock.Dispose();
            instanceLock = null;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            ReleaseInstanceLock();
            base.OnExit(e);
        }
    }
}
