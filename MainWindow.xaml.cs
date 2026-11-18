using System;
using System.ComponentModel;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace SecHUD
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel viewModel = new MainViewModel();
        private System.Windows.Forms.NotifyIcon tray;
        private bool exiting;
        private bool trayHintShown;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = viewModel;
            viewModel.AlertRaised += OnAlert;
            viewModel.UpdateFound += OnUpdateFound;
            viewModel.Confirm = AskYesNo;
            viewModel.ShowMessage = ShowInfo;
            SetupTray();

            // Started here, not on Loaded, so monitoring also runs when the app starts hidden in the tray.
            viewModel.Start();
        }

        // ---- window chrome ----

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed) DragMove();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        /// <summary>Closing the window keeps the monitor running in the tray. Exit is in the tray menu.</summary>
        protected override void OnClosing(CancelEventArgs e)
        {
            if (!exiting)
            {
                e.Cancel = true;
                Hide();
                if (!trayHintShown && tray != null)
                {
                    trayHintShown = true;
                    tray.ShowBalloonTip(4000, "SecHUD is still watching",
                        "Right-click the tray icon and choose Exit to stop it.",
                        System.Windows.Forms.ToolTipIcon.Info);
                }
            }
            base.OnClosing(e);
        }

        // ---- questions and messages from the view model ----

        private bool AskYesNo(string question)
        {
            return MessageBox.Show(this, question, "SecHUD", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
                   == MessageBoxResult.Yes;
        }

        private void ShowInfo(string text)
        {
            MessageBox.Show(this, text, "SecHUD", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        // ---- device name box: Enter saves, Escape cancels ----

        private void NameBox_KeyDown(object sender, KeyEventArgs e)
        {
            var box = sender as TextBox;
            if (box == null) return;

            if (e.Key == Key.Enter)
            {
                var binding = box.GetBindingExpression(TextBox.TextProperty);
                if (binding != null) binding.UpdateSource();
                Keyboard.ClearFocus();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                var binding = box.GetBindingExpression(TextBox.TextProperty);
                if (binding != null) binding.UpdateTarget();
                Keyboard.ClearFocus();
                e.Handled = true;
            }
        }

        // ---- tray icon ----

        private void SetupTray()
        {
            System.Drawing.Icon icon = null;
            try
            {
                icon = System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            }
            catch { }

            tray = new System.Windows.Forms.NotifyIcon();
            tray.Icon = icon ?? System.Drawing.SystemIcons.Shield;
            tray.Text = "SecHUD";
            tray.Visible = true;
            tray.DoubleClick += OnTrayOpen;

            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Open SecHUD", null, OnTrayOpen);
            menu.Items.Add("Scan now", null, OnTrayScan);
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            menu.Items.Add("Exit", null, OnTrayExit);
            tray.ContextMenuStrip = menu;
        }

        private void OnTrayOpen(object sender, EventArgs e)
        {
            Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
        }

        private void OnTrayScan(object sender, EventArgs e)
        {
            viewModel.ScanCommand.Execute(null);
        }

        private void OnTrayExit(object sender, EventArgs e)
        {
            exiting = true;
            viewModel.Shutdown();
            if (tray != null)
            {
                tray.Visible = false;
                tray.Dispose();
                tray = null;
            }
            Application.Current.Shutdown();
        }

        private void OnUpdateFound(string message)
        {
            if (tray == null) return;
            tray.ShowBalloonTip(8000, "SecHUD update", message, System.Windows.Forms.ToolTipIcon.Info);
        }

        private void OnAlert(string message)
        {
            if (tray == null) return;
            tray.ShowBalloonTip(6000, "SecHUD alert", message, System.Windows.Forms.ToolTipIcon.Warning);
        }
    }
}
