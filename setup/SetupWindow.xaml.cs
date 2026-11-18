using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;

namespace SecHUD.Setup
{
    /// <summary>The one window of the setup program. It has a few states: ready, working, done, failed.</summary>
    public partial class SetupWindow : Window
    {
        private static readonly Regex Percent = new Regex(@"(\d{1,3})%", RegexOptions.Compiled);

        private readonly SetupOptions options;
        private readonly string selfPath;
        private bool busy;
        private bool finished;
        private bool failed;

        public SetupWindow(SetupOptions options, string selfPath)
        {
            this.options = options ?? new SetupOptions();
            this.selfPath = selfPath;
            InitializeComponent();
            ShowReady();
        }

        private void ShowReady()
        {
            failed = false;
            finished = false;
            StatusText.Text = "";
            Bar.Visibility = Visibility.Hidden;
            OptionBox.Visibility = Visibility.Visible;
            SecondButton.Visibility = Visibility.Visible;
            SecondButton.Content = "CANCEL";
            MainButton.IsEnabled = true;
            SecondButton.IsEnabled = true;

            if (options.Uninstall)
            {
                Title = "Remove SecHUD";
                TitleText.Text = "REMOVE SECHUD";
                BodyText.Text = "This takes SecHUD off this PC: the program, its shortcuts, and its Start with Windows entry.";
                OptionBox.Content = "Also delete my settings, device list and history";
                OptionBox.IsChecked = options.RemoveData;
                FootText.Text = "Leave the box empty if you might install SecHUD again. It will pick up where it left off.";
                MainButton.Content = "REMOVE";
            }
            else
            {
                TitleText.Text = "INSTALL SECHUD";
                BodyText.Text = "SecHUD watches this PC and your home network and tells you when something changes. "
                    + "Press Install and setup downloads the newest version, puts it in place, and starts it. There is nothing else to do.";
                OptionBox.Content = "Put a shortcut on my desktop";
                OptionBox.IsChecked = !options.NoDesktopShortcut;
                FootText.Text = "Installs for you only, in " + Installer.TargetDir(options) + ". No administrator password is needed. "
                    + "The download comes from github.com/" + Updater.Repo + " and is checked before it is used. "
                    + "If SecHUD is already here, this updates it and keeps your settings.";
                MainButton.Content = "INSTALL";
            }
        }

        private async void Main_Click(object sender, RoutedEventArgs e)
        {
            if (busy) return;
            if (finished && !failed)
            {
                Close();
                return;
            }

            busy = true;
            failed = false;
            MainButton.IsEnabled = false;
            SecondButton.IsEnabled = false;
            OptionBox.Visibility = Visibility.Collapsed;
            Bar.Visibility = Visibility.Visible;
            Bar.IsIndeterminate = true;

            string error = "";
            string version = "";
            bool ok;
            if (options.Uninstall)
            {
                options.RemoveData = OptionBox.IsChecked == true;
                ok = await Task.Run(() => Installer.Uninstall(options, Report, out error));
            }
            else
            {
                options.NoDesktopShortcut = OptionBox.IsChecked != true;
                ok = await Task.Run(() => Installer.Install(options, selfPath, Report, out version, out error));
            }

            busy = false;
            finished = true;
            Bar.IsIndeterminate = false;
            Bar.Visibility = Visibility.Hidden;
            MainButton.IsEnabled = true;
            SecondButton.IsEnabled = true;

            if (ok) ShowDone(version);
            else ShowFailed(error);
        }

        private void ShowDone(string version)
        {
            StatusText.Text = "";
            SecondButton.Visibility = Visibility.Collapsed;
            MainButton.Content = "CLOSE";
            if (options.Uninstall)
            {
                TitleText.Text = "SECHUD HAS BEEN REMOVED";
                BodyText.Text = options.RemoveData
                    ? "The program and everything it stored are gone."
                    : "The program is gone. Your settings and history were kept in case you install it again.";
                FootText.Text = "";
            }
            else
            {
                TitleText.Text = "SECHUD IS INSTALLED";
                BodyText.Text = "Version " + version + " is ready" + (options.NoLaunch ? "." : " and has been started. Look for its window, or its icon near the clock.")
                    + " You can open it any time from the Start menu: type SecHUD.";
                FootText.Text = "From now on SecHUD updates itself: when a new version is out, a yellow button appears at the top of its window. "
                    + "To remove it, use Installed apps in Windows Settings.";
            }
        }

        private void ShowFailed(string error)
        {
            failed = true;
            StatusText.Text = "";
            TitleText.Text = "THAT DID NOT WORK";
            BodyText.Text = (options.Uninstall ? "SecHUD could not be removed: " : "SecHUD could not be installed: ") + error + ".";
            FootText.Text = options.Uninstall
                ? ""
                : "Check that this PC is online, then try again. If it keeps failing, the download page has the files to install by hand.";
            MainButton.Content = "TRY AGAIN";
            SecondButton.Visibility = Visibility.Visible;
            SecondButton.Content = options.Uninstall ? "CLOSE" : "OPEN DOWNLOAD PAGE";
        }

        private void Second_Click(object sender, RoutedEventArgs e)
        {
            if (busy) return;
            if (failed && !options.Uninstall)
            {
                try { Process.Start(Updater.ReleasesPage); } catch { }
                return;
            }
            Close();
        }

        /// <summary>Progress from the worker thread, shown on the window.</summary>
        private void Report(string text)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                StatusText.Text = text ?? "";
                Match match = Percent.Match(text ?? "");
                int percent;
                if (match.Success && int.TryParse(match.Groups[1].Value, out percent))
                {
                    Bar.IsIndeterminate = false;
                    Bar.Value = Math.Max(0, Math.Min(100, percent));
                }
                else
                {
                    Bar.IsIndeterminate = true;
                }
            }));
        }

        /// <summary>The window stays open while files are being changed, so nothing is left half done.</summary>
        protected override void OnClosing(CancelEventArgs e)
        {
            if (busy) e.Cancel = true;
            base.OnClosing(e);
        }
    }
}
