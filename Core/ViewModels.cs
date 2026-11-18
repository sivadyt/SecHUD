using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace SecHUD
{
    public abstract class Observable : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected void Raise([CallerMemberName] string name = null)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null) handler(this, new PropertyChangedEventArgs(name));
        }

        protected bool Set<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            Raise(name);
            return true;
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly Action<object> execute;

        public RelayCommand(Action<object> execute)
        {
            this.execute = execute;
        }

        public event EventHandler CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object parameter) { return true; }
        public void Execute(object parameter) { execute(parameter); }
    }

    /// <summary>One label/value line on the overview.</summary>
    public class RowViewModel : Observable
    {
        private string label;
        private string text;
        private bool isAlert;

        public string Label { get { return label; } set { Set(ref label, value); } }
        public string Value { get { return text; } set { Set(ref text, value); } }
        public bool IsAlert { get { return isAlert; } set { Set(ref isAlert, value); } }
    }

    public class DeviceViewModel : Observable
    {
        private readonly MainViewModel owner;
        private string ip;
        private string name;
        private bool approved;
        private bool online;
        private string lastSeen;
        private string openPorts = "";

        public DeviceViewModel(MainViewModel owner, DeviceRecord record)
        {
            this.owner = owner;
            Mac = record.Mac;
            name = record.Name ?? "";
            ApproveCommand = new RelayCommand(o => owner.ApproveDevice(this));
            ScanPortsCommand = new RelayCommand(o => owner.ScanDevicePorts(this));
            Update(record);
        }

        public string Mac { get; private set; }
        public ICommand ApproveCommand { get; private set; }
        public ICommand ScanPortsCommand { get; private set; }

        public string Ip { get { return ip; } private set { Set(ref ip, value); } }
        public string LastSeen { get { return lastSeen; } private set { Set(ref lastSeen, value); } }

        /// <summary>Editable in the device list. The new name is written to devices.json.</summary>
        public string Name
        {
            get { return name; }
            set
            {
                string cleaned = (value ?? "").Trim();
                if (Set(ref name, cleaned)) owner.RenameDevice(Mac, cleaned);
            }
        }

        public bool Approved
        {
            get { return approved; }
            set
            {
                if (Set(ref approved, value))
                {
                    Raise("IsUnknown");
                    Raise("Status");
                }
            }
        }

        public bool Online
        {
            get { return online; }
            private set
            {
                if (Set(ref online, value)) Raise("Status");
            }
        }

        /// <summary>Result of the last on-demand port scan, shown under the device.</summary>
        public string OpenPorts
        {
            get { return openPorts; }
            set
            {
                if (Set(ref openPorts, value ?? "")) Raise("HasOpenPorts");
            }
        }

        public bool HasOpenPorts { get { return openPorts.Length > 0; } }
        public bool IsUnknown { get { return !approved; } }
        public string Status { get { return !approved ? "UNKNOWN" : (online ? "ONLINE" : "OFFLINE"); } }

        /// <summary>Sort key: unknown devices first, then by address.</summary>
        public long SortKey
        {
            get
            {
                long number = 0;
                foreach (string part in (ip ?? "").Split('.'))
                {
                    int octet;
                    number = number * 256 + (int.TryParse(part, out octet) ? octet : 0);
                }
                return (approved ? 1L << 40 : 0) + number;
            }
        }

        public void Update(DeviceRecord record)
        {
            Ip = record.Ip ?? "";
            Approved = record.Approved;
            Online = record.Online;
            LastSeen = MainViewModel.ShortTime(record.LastSeen);
            // The name is left alone once shown, so a scan never overwrites what is being typed.
        }
    }

    /// <summary>Base for list rows that can be flagged NEW and approved one at a time.</summary>
    public abstract class FlaggedViewModel : Observable
    {
        private bool isNew;

        public bool IsNew
        {
            get { return isNew; }
            set { if (Set(ref isNew, value)) Raise("Flag"); }
        }

        public string Flag { get { return isNew ? "NEW" : ""; } }
        public ICommand ApproveCommand { get; protected set; }
    }

    public class PortViewModel : FlaggedViewModel
    {
        public PortViewModel(MainViewModel owner)
        {
            ApproveCommand = new RelayCommand(o => owner.ApprovePort(this));
        }

        public int Port { get; set; }
        public string Process { get; set; }
    }

    public class AutorunViewModel : FlaggedViewModel
    {
        public AutorunViewModel(MainViewModel owner)
        {
            ApproveCommand = new RelayCommand(o => owner.ApproveAutorun(this));
            DenyCommand = new RelayCommand(o => owner.DenyAutorun(this));
        }

        /// <summary>Removes the item from Windows (after asking).</summary>
        public ICommand DenyCommand { get; private set; }

        /// <summary>The kind exactly as the engine names it (run, startup, service, task).</summary>
        public string RawKind { get; set; }
        public string Key { get; set; }
        public string Kind { get; set; }
        public string Name { get; set; }
        public string Command { get; set; }
    }

    public class ForwardViewModel : FlaggedViewModel
    {
        public ForwardViewModel(MainViewModel owner)
        {
            ApproveCommand = new RelayCommand(o => owner.ApproveForward(this));
        }

        public string Key { get; set; }
        public string Port { get; set; }
        public string Target { get; set; }
        public string Description { get; set; }
    }

    public class EventViewModel : Observable
    {
        private bool isOpen;

        public EventViewModel(MainViewModel owner)
        {
            DismissCommand = new RelayCommand(o => owner.DismissDetection(this));
        }

        /// <summary>Timestamp and message exactly as logged, used to match an open detection.</summary>
        public string Ts { get; set; }
        public string RawMessage { get; set; }

        public string Time { get; set; }
        public string Severity { get; set; }
        public string Technique { get; set; }
        public string Message { get; set; }
        public bool IsHigh { get; set; }
        public ICommand DismissCommand { get; private set; }

        /// <summary>True while this detection is still keeping the status elevated.</summary>
        public bool IsOpen { get { return isOpen; } set { Set(ref isOpen, value); } }
    }

    public class GuestViewModel
    {
        public string Id { get; set; }
        public string Kind { get; set; }
        public string Name { get; set; }
        public string Status { get; set; }
        public string Cpu { get; set; }
        public string Memory { get; set; }
        /// <summary>Stopped guests are drawn muted, not as alerts.</summary>
        public bool IsRunning { get; set; }
    }

    public class LogViewModel
    {
        public string Time { get; set; }
        public string Source { get; set; }
        public string Text { get; set; }
        /// <summary>Syslog severity 0-3 (emergency to error).</summary>
        public bool IsHigh { get; set; }
    }

    /// <summary>One bar of a history chart.</summary>
    public class BarViewModel
    {
        public double Height { get; set; }
        public bool IsAlert { get; set; }
        public string Tip { get; set; }
    }

    /// <summary>Everything the window shows. It owns the scan loop and talks to the engine.</summary>
    public class MainViewModel : Observable
    {
        private const int MaxShown = 300;
        private const int MaxLogsKept = 2000;
        private const double ChartHeight = 70;

        private readonly Scanner scanner = new Scanner();
        private readonly SyslogServer syslog = new SyslogServer();
        private readonly SyslogAuthRule syslogRule = new SyslogAuthRule();
        private readonly ConcurrentQueue<SyslogMessage> pendingLogs = new ConcurrentQueue<SyslogMessage>();
        private readonly ConcurrentQueue<EventEntry> pendingEvents = new ConcurrentQueue<EventEntry>();
        private readonly Dictionary<string, DeviceViewModel> deviceIndex =
            new Dictionary<string, DeviceViewModel>(StringComparer.OrdinalIgnoreCase);
        private readonly List<EventViewModel> allEvents = new List<EventViewModel>();
        private readonly List<LogViewModel> allLogs = new List<LogViewModel>();

        private AppConfig config = new AppConfig();
        private ScanResult lastResult;
        private string level = "STARTING";
        private bool isElevated;
        private bool isScanning;
        private string ticker = "FIRST SCAN IN PROGRESS";
        private string lastScan = "LAST SCAN --:--:--";
        private string deviceSummary = "DEVICES";
        private string portSummary = "PORTS";
        private string autorunSummary = "AUTORUNS";
        private string eventSummary = "EVENTS";
        private string logSummary = "LOGS";
        private string proxmoxStatus = "NOT SET UP. ADD THE HOST AND AN API TOKEN IN SETTINGS.";
        private string routerStatus = "WAITING FOR THE FIRST SCAN";
        private string rulesInfo = "";
        private bool rescanRequested;
        private bool updateAvailable;
        private string updateLabel = "";
        private string updateNotes = "";
        private string updateUrl = Updater.ReleasesPage;
        private string announcedVersion = "";
        private bool setCheckUpdates = true;
        private string syslogStatus = "SYSLOG INTAKE IS OFF. TURN IT ON IN SETTINGS.";
        private string eventFilter = "";
        private string logFilter = "";
        private string footerNote = "";
        private string autorunSignature = "";
        private bool started;

        // settings form
        private string setScanSeconds = "120";
        private string setLoginThreshold = "5";
        private bool setScanLan = true;
        private bool setNotify = true;
        private bool setWatchEvents = true;
        private bool setWatchAutoruns = true;
        private bool setStartWithWindows;
        private bool setSyslogEnabled;
        private string setSyslogPort = "514";
        private string setDiscordWebhook = "";
        private string setProxmoxHost = "";
        private string setProxmoxTokenId = "";
        private string setProxmoxSecret = "";
        private string setWatchedHosts = "";
        private string setHomeWifiName = "";
        private bool setWatchWifi = true;
        private bool setWatchRouter = true;
        private string settingsStatus = "";
        private string discordState = "NOT SET";
        private string proxmoxSecretState = "NOT SET";

        public MainViewModel()
        {
            PcRows = new ObservableCollection<RowViewModel>();
            NetRows = new ObservableCollection<RowViewModel>();
            Devices = new ObservableCollection<DeviceViewModel>();
            Ports = new ObservableCollection<PortViewModel>();
            Autoruns = new ObservableCollection<AutorunViewModel>();
            Guests = new ObservableCollection<GuestViewModel>();
            Forwards = new ObservableCollection<ForwardViewModel>();
            Events = new ObservableCollection<EventViewModel>();
            Logs = new ObservableCollection<LogViewModel>();
            DeviceBars = new ObservableCollection<BarViewModel>();
            AlertBars = new ObservableCollection<BarViewModel>();
            StatusBars = new ObservableCollection<BarViewModel>();
            UptimeRows = new ObservableCollection<RowViewModel>();

            ScanCommand = new RelayCommand(o => { var ignored = ScanAsync(false); });
            ApproveAllCommand = new RelayCommand(o => { var ignored = ScanAsync(true); });
            OpenConfigCommand = new RelayCommand(o => OpenConfig());
            OpenFolderCommand = new RelayCommand(o => { Store.EnsureDir(); Launch("explorer.exe", "\"" + Store.Dir + "\""); });
            ExportReportCommand = new RelayCommand(o => ExportReport());
            SaveSettingsCommand = new RelayCommand(o => SaveSettings());
            TestDiscordCommand = new RelayCommand(o => TestDiscord());
            OpenRulesCommand = new RelayCommand(o => OpenRules());
            OpenUpdateCommand = new RelayCommand(o => Launch(updateUrl, ""));
            CheckUpdatesCommand = new RelayCommand(o => { var ignored = CheckForUpdateAsync(true); });

            syslog.Received += OnSyslogReceived;
        }

        public ObservableCollection<RowViewModel> PcRows { get; private set; }
        public ObservableCollection<RowViewModel> NetRows { get; private set; }
        public ObservableCollection<DeviceViewModel> Devices { get; private set; }
        public ObservableCollection<PortViewModel> Ports { get; private set; }
        public ObservableCollection<AutorunViewModel> Autoruns { get; private set; }
        public ObservableCollection<GuestViewModel> Guests { get; private set; }
        public ObservableCollection<ForwardViewModel> Forwards { get; private set; }
        public ObservableCollection<EventViewModel> Events { get; private set; }
        public ObservableCollection<LogViewModel> Logs { get; private set; }
        public ObservableCollection<BarViewModel> DeviceBars { get; private set; }
        public ObservableCollection<BarViewModel> AlertBars { get; private set; }
        public ObservableCollection<BarViewModel> StatusBars { get; private set; }
        public ObservableCollection<RowViewModel> UptimeRows { get; private set; }

        public ICommand ScanCommand { get; private set; }
        public ICommand ApproveAllCommand { get; private set; }
        public ICommand OpenConfigCommand { get; private set; }
        public ICommand OpenFolderCommand { get; private set; }
        public ICommand ExportReportCommand { get; private set; }
        public ICommand SaveSettingsCommand { get; private set; }
        public ICommand TestDiscordCommand { get; private set; }
        public ICommand OpenRulesCommand { get; private set; }
        public ICommand OpenUpdateCommand { get; private set; }
        public ICommand CheckUpdatesCommand { get; private set; }

        /// <summary>Raised once per new version, with a short message for the tray.</summary>
        public event Action<string> UpdateFound;

        public bool UpdateAvailable { get { return updateAvailable; } private set { Set(ref updateAvailable, value); } }
        public string UpdateLabel { get { return updateLabel; } private set { Set(ref updateLabel, value); } }
        public string UpdateNotes { get { return updateNotes; } private set { Set(ref updateNotes, value); } }
        public string VersionText { get { return "THIS IS VERSION " + Updater.CurrentVersion.ToString(3); } }
        public bool SetCheckUpdates { get { return setCheckUpdates; } set { Set(ref setCheckUpdates, value); } }

        /// <summary>Raised with a short message when something new needs a look.</summary>
        public event Action<string> AlertRaised;

        /// <summary>Set by the window: asks a yes/no question. Nothing destructive happens without a yes.</summary>
        public Func<string, bool> Confirm { get; set; }

        /// <summary>Set by the window: shows a message that needs to be read.</summary>
        public Action<string> ShowMessage { get; set; }

        public string Level { get { return level; } private set { Set(ref level, value); } }
        public bool IsElevated { get { return isElevated; } private set { Set(ref isElevated, value); } }
        public bool IsScanning { get { return isScanning; } private set { if (Set(ref isScanning, value)) Raise("ScanLabel"); } }
        public string ScanLabel { get { return isScanning ? "SCANNING..." : "SCAN NOW"; } }
        public string Ticker { get { return ticker; } private set { Set(ref ticker, value); } }
        public string LastScan { get { return lastScan; } private set { Set(ref lastScan, value); } }
        public string DeviceSummary { get { return deviceSummary; } private set { Set(ref deviceSummary, value); } }
        public string PortSummary { get { return portSummary; } private set { Set(ref portSummary, value); } }
        public string AutorunSummary { get { return autorunSummary; } private set { Set(ref autorunSummary, value); } }
        public string EventSummary { get { return eventSummary; } private set { Set(ref eventSummary, value); } }
        public string LogSummary { get { return logSummary; } private set { Set(ref logSummary, value); } }
        public string ProxmoxStatus { get { return proxmoxStatus; } private set { Set(ref proxmoxStatus, value); } }
        public string RouterStatus { get { return routerStatus; } private set { Set(ref routerStatus, value); } }
        public string RulesInfo { get { return rulesInfo; } private set { Set(ref rulesInfo, value); } }
        public string SyslogStatus { get { return syslogStatus; } private set { Set(ref syslogStatus, value); } }
        public string FooterNote { get { return footerNote; } private set { Set(ref footerNote, value); } }
        public string DataFolder { get { return Store.Dir.ToUpperInvariant(); } }

        public string EventFilter
        {
            get { return eventFilter; }
            set { if (Set(ref eventFilter, value ?? "")) RefreshEvents(); }
        }

        public string LogFilter
        {
            get { return logFilter; }
            set { if (Set(ref logFilter, value ?? "")) RefreshLogs(); }
        }

        // ---- settings form ----
        public string SetScanSeconds { get { return setScanSeconds; } set { Set(ref setScanSeconds, value); } }
        public string SetLoginThreshold { get { return setLoginThreshold; } set { Set(ref setLoginThreshold, value); } }
        public bool SetScanLan { get { return setScanLan; } set { Set(ref setScanLan, value); } }
        public bool SetNotify { get { return setNotify; } set { Set(ref setNotify, value); } }
        public bool SetWatchEvents { get { return setWatchEvents; } set { Set(ref setWatchEvents, value); } }
        public bool SetWatchAutoruns { get { return setWatchAutoruns; } set { Set(ref setWatchAutoruns, value); } }
        public bool SetStartWithWindows { get { return setStartWithWindows; } set { Set(ref setStartWithWindows, value); } }
        public bool SetSyslogEnabled { get { return setSyslogEnabled; } set { Set(ref setSyslogEnabled, value); } }
        public string SetSyslogPort { get { return setSyslogPort; } set { Set(ref setSyslogPort, value); } }
        public string SetDiscordWebhook { get { return setDiscordWebhook; } set { Set(ref setDiscordWebhook, value); } }
        public string SetProxmoxHost { get { return setProxmoxHost; } set { Set(ref setProxmoxHost, value); } }
        public string SetProxmoxTokenId { get { return setProxmoxTokenId; } set { Set(ref setProxmoxTokenId, value); } }
        public string SetProxmoxSecret { get { return setProxmoxSecret; } set { Set(ref setProxmoxSecret, value); } }
        public string SetWatchedHosts { get { return setWatchedHosts; } set { Set(ref setWatchedHosts, value); } }
        public string SetHomeWifiName { get { return setHomeWifiName; } set { Set(ref setHomeWifiName, value); } }
        public bool SetWatchWifi { get { return setWatchWifi; } set { Set(ref setWatchWifi, value); } }
        public bool SetWatchRouter { get { return setWatchRouter; } set { Set(ref setWatchRouter, value); } }
        public string SettingsStatus { get { return settingsStatus; } private set { Set(ref settingsStatus, value); } }
        public string DiscordState { get { return discordState; } private set { Set(ref discordState, value); } }
        public string ProxmoxSecretState { get { return proxmoxSecretState; } private set { Set(ref proxmoxSecretState, value); } }

        /// <summary>Call once, from the UI thread, when the window has been created.</summary>
        public void Start()
        {
            if (started) return;
            started = true;

            config = Store.LoadConfig();
            LoadSettingsForm();
            ApplySyslogSetting();

            foreach (EventEntry e in Store.ReadRecentEvents(MaxShown)) allEvents.Add(ToViewModel(e));
            RefreshEvents();
            RefreshHistory(DateTime.Now);

            var scans = RunLoopAsync();
            var pump = PumpLoopAsync();
            var updates = UpdateLoopAsync();
        }

        /// <summary>Looks for a newer release shortly after start, then once a day.</summary>
        private async Task UpdateLoopAsync()
        {
            await Task.Delay(TimeSpan.FromSeconds(20));
            while (true)
            {
                if (config.CheckUpdates) await CheckForUpdateAsync(false);
                await Task.Delay(TimeSpan.FromHours(24));
            }
        }

        /// <summary>"manual" is the Check now button: it reports the result even when there is nothing new.</summary>
        public async Task CheckForUpdateAsync(bool manual)
        {
            try
            {
                if (manual) SettingsStatus = "CHECKING GITHUB...";
                string error = "";
                Version current = Updater.CurrentVersion;
                UpdateInfo info = await Task.Run(() => Updater.Check(current, out error));
                ApplyUpdate(info);

                if (manual)
                {
                    if (info != null) SettingsStatus = "VERSION " + info.Version + " IS AVAILABLE. USE THE BUTTON AT THE TOP.";
                    else if (error.Length > 0) SettingsStatus = ("UPDATE CHECK FAILED: " + error).ToUpperInvariant();
                    else SettingsStatus = "YOU HAVE THE LATEST VERSION (" + current.ToString(3) + ")";
                }
            }
            catch (Exception ex)
            {
                Store.LogError("update check", ex);
            }
        }

        /// <summary>Shows (or hides) the update button. Announces each new version once.</summary>
        public void ApplyUpdate(UpdateInfo info)
        {
            if (info == null)
            {
                UpdateAvailable = false;
                return;
            }
            updateUrl = info.Url;
            UpdateLabel = "UPDATE AVAILABLE: V" + info.Version;
            UpdateNotes = "What is new in " + info.Version + ":\n\n" + info.Notes + "\n\nClick to open the download page.";
            UpdateAvailable = true;

            if (announcedVersion != info.Version)
            {
                announcedVersion = info.Version;
                Action<string> handler = UpdateFound;
                if (handler != null) handler("SecHUD " + info.Version + " is available. Open SecHUD and click the update button to get it.");
            }
        }

        private async Task RunLoopAsync()
        {
            while (true)
            {
                await ScanAsync(false);
                await Task.Delay(TimeSpan.FromSeconds(config.ScanSeconds));
            }
        }

        /// <summary>Moves syslog lines and their alerts from the listener thread onto the UI, in batches.</summary>
        private async Task PumpLoopAsync()
        {
            while (true)
            {
                await Task.Delay(1500);
                try { DrainPending(); } catch (Exception ex) { Store.LogError("pump", ex); }
            }
        }

        public async Task ScanAsync(bool approve)
        {
            if (IsScanning) return;
            IsScanning = true;
            try
            {
                ScanResult result = await Task.Run(() => scanner.Run(approve));
                Apply(result);
            }
            catch (Exception ex)
            {
                Store.LogError("scan", ex);
                Level = "ERROR";
                IsElevated = true;
                Ticker = ("SCAN FAILED: " + ex.Message).ToUpperInvariant();
            }
            finally
            {
                IsScanning = false;
            }

            if (rescanRequested)
            {
                rescanRequested = false;
                await ScanAsync(false);
            }
        }

        /// <summary>Scans now, or right after the scan that is already running.</summary>
        private void RequestScan()
        {
            if (IsScanning) rescanRequested = true;
            else { var ignored = ScanAsync(false); }
        }

        private void Apply(ScanResult result)
        {
            lastResult = result;
            config = result.Config;
            Level = result.Level;
            IsElevated = result.Elevated;
            Ticker = (result.Ticker ?? "").ToUpperInvariant();
            LastScan = "LAST SCAN " + result.Time.ToString("HH:mm:ss");

            SyncRows(PcRows, result.PcRows);
            SyncRows(NetRows, result.NetRows);

            // Devices: update in place so a name being edited keeps its focus.
            foreach (DeviceRecord record in result.Devices)
            {
                DeviceViewModel existing;
                if (deviceIndex.TryGetValue(record.Mac, out existing))
                {
                    existing.Update(record);
                }
                else
                {
                    var created = new DeviceViewModel(this, record);
                    deviceIndex[record.Mac] = created;
                    Devices.Add(created);
                }
            }
            List<DeviceViewModel> ordered = Devices.OrderBy(d => d.SortKey).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                int current = Devices.IndexOf(ordered[i]);
                if (current != i) Devices.Move(current, i);
            }
            int unknown = Devices.Count(d => d.IsUnknown);
            DeviceSummary = "DEVICES (" + Devices.Count + ")" + (unknown > 0 ? " " + unknown + " UNKNOWN" : "");

            Ports.Clear();
            foreach (PortInfo p in result.Ports.OrderByDescending(x => x.IsNew).ThenBy(x => x.Port))
            {
                Ports.Add(new PortViewModel(this) { Port = p.Port, Process = (p.Process ?? "").ToUpperInvariant(), IsNew = p.IsNew });
            }
            int freshPorts = result.Ports.Count(p => p.IsNew);
            PortSummary = "PORTS (" + Ports.Count + ")" + (freshPorts > 0 ? " " + freshPorts + " NEW" : "");

            // The autorun list can hold hundreds of rows, so it is only rebuilt when something in it changed.
            int freshAutoruns = result.Autoruns.Count(a => a.IsNew);
            string signature = result.Autoruns.Count + "/" + freshAutoruns + "/"
                + result.Autoruns.Aggregate(17, (hash, a) => unchecked(hash * 31 + (a.Key ?? "").GetHashCode() + (a.IsNew ? 1 : 0)));
            if (signature != autorunSignature)
            {
                autorunSignature = signature;
                Autoruns.Clear();
                foreach (AutorunItem a in result.Autoruns.OrderByDescending(x => x.IsNew).ThenBy(x => x.Kind).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                {
                    Autoruns.Add(new AutorunViewModel(this) { Key = a.Key, RawKind = a.Kind ?? "", Kind = (a.Kind ?? "").ToUpperInvariant(), Name = a.Name ?? "", Command = a.Command ?? "", IsNew = a.IsNew });
                }
            }
            AutorunSummary = "AUTORUNS (" + Autoruns.Count + ")" + (freshAutoruns > 0 ? " " + freshAutoruns + " NEW" : "");

            ApplyProxmox(result.Proxmox);
            ApplyRouter(result.Router);
            RulesInfo = Detector.Rules.Length + " BUILT-IN RULES + " + result.CustomRuleCount + " OF YOUR OWN";

            string alert = null;
            foreach (EventEntry e in result.NewEvents)
            {
                allEvents.Insert(0, ToViewModel(e));
                if (e.Severity == "high") alert = Describe(e);
            }
            TrimEvents();

            var open = new HashSet<string>(result.OpenDetections.Select(e => e.Ts + "|" + e.Msg));
            foreach (EventViewModel e in allEvents) e.IsOpen = open.Contains(e.Ts + "|" + e.RawMessage);
            RefreshEvents();
            RefreshHistory(result.Time);

            if (alert != null) SendAlert(alert);
        }

        private void ApplyProxmox(ProxmoxSnapshot snapshot)
        {
            Guests.Clear();
            if (snapshot == null || !snapshot.Configured)
            {
                ProxmoxStatus = "NOT SET UP. ADD THE HOST AND AN API TOKEN IN SETTINGS.";
                return;
            }
            if (!snapshot.Ok)
            {
                ProxmoxStatus = ("PROXMOX API: " + (snapshot.CertChanged
                    ? "the certificate changed, so the connection was refused. Approve all if you replaced it yourself."
                    : snapshot.Error)).ToUpperInvariant();
                return;
            }
            ProxmoxStatus = snapshot.Summary.ToUpperInvariant();
            foreach (ProxmoxGuest g in snapshot.Guests)
            {
                Guests.Add(new GuestViewModel
                {
                    Id = g.Id,
                    Kind = g.Kind,
                    Name = g.Name,
                    Status = (g.Status ?? "").ToUpperInvariant(),
                    Cpu = g.Cpu,
                    Memory = g.Memory,
                    IsRunning = g.Running
                });
            }
        }

        private void ApplyRouter(RouterSnapshot router)
        {
            Forwards.Clear();
            if (router == null || !router.Found)
            {
                RouterStatus = ("ROUTER: " + (router == null || router.Note.Length == 0 ? "no answer" : router.Note)).ToUpperInvariant();
                return;
            }
            RouterStatus = ("EXTERNAL ADDRESS " + (router.ExternalIp.Length > 0 ? router.ExternalIp : "UNKNOWN")
                + "  |  " + router.Forwards.Count + " PORT FORWARD(S)").ToUpperInvariant();
            foreach (ForwardInfo f in router.Forwards.OrderByDescending(x => x.IsNew).ThenBy(x => x.ExternalPort))
            {
                Forwards.Add(new ForwardViewModel(this)
                {
                    Key = f.Key,
                    Port = f.Protocol + " " + f.ExternalPort,
                    Target = f.InternalClient + ":" + f.InternalPort,
                    Description = f.Description ?? "",
                    IsNew = f.IsNew
                });
            }
        }

        private static void SyncRows(ObservableCollection<RowViewModel> target, List<CheckRow> source)
        {
            while (target.Count > source.Count) target.RemoveAt(target.Count - 1);
            for (int i = 0; i < source.Count; i++)
            {
                if (i >= target.Count) target.Add(new RowViewModel());
                target[i].Label = (source[i].Label ?? "").ToUpperInvariant();
                target[i].Value = (source[i].Value ?? "").ToUpperInvariant();
                target[i].IsAlert = source[i].IsAlert;
            }
        }

        // ---- events ----

        private EventViewModel ToViewModel(EventEntry e)
        {
            return new EventViewModel(this)
            {
                Ts = e.Ts ?? "",
                RawMessage = e.Msg ?? "",
                Time = ShortTime(e.Ts),
                Severity = (e.Severity ?? "").ToUpperInvariant(),
                Technique = e.Technique ?? "",
                Message = (e.Msg ?? "").ToUpperInvariant(),
                IsHigh = e.Severity == "high"
            };
        }

        private static string Describe(EventEntry e)
        {
            return string.IsNullOrEmpty(e.Technique) ? e.Msg : e.Msg + " [" + e.Technique + "]";
        }

        private void TrimEvents()
        {
            if (allEvents.Count > MaxShown) allEvents.RemoveRange(MaxShown, allEvents.Count - MaxShown);
        }

        private void RefreshEvents()
        {
            string filter = eventFilter.Trim().ToUpperInvariant();
            Events.Clear();
            foreach (EventViewModel e in allEvents)
            {
                if (filter.Length == 0 || e.Message.Contains(filter) || e.Technique.ToUpperInvariant().Contains(filter) || e.Severity.Contains(filter))
                    Events.Add(e);
            }
            EventSummary = "EVENTS (" + allEvents.Count + ")";
        }

        /// <summary>"2026-11-18T03:41:07" becomes "11-18 03:41".</summary>
        public static string ShortTime(string iso)
        {
            DateTime when;
            if (DateTime.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out when))
                return when.ToString("MM-dd HH:mm");
            return iso ?? "";
        }

        private void SendAlert(string message)
        {
            if (config.Notify)
            {
                Action<string> handler = AlertRaised;
                if (handler != null) handler(message);
            }

            string webhook = Secrets.Unprotect(config.DiscordWebhookProtected);
            if (webhook.Length > 0)
            {
                string text = "SecHUD alert on " + Environment.MachineName + ": " + message;
                Task.Run(() =>
                {
                    string error;
                    if (!Discord.Send(webhook, text, out error)) Store.LogError("discord", new Exception(error));
                });
            }
        }

        // ---- syslog ----

        private void ApplySyslogSetting()
        {
            if (!config.SyslogEnabled)
            {
                syslog.Stop();
                SyslogStatus = "SYSLOG INTAKE IS OFF. TURN IT ON IN SETTINGS.";
                return;
            }
            if (syslog.IsRunning && syslog.Port == config.SyslogPort) return;

            string error;
            if (syslog.Start(config.SyslogPort, out error))
                SyslogStatus = "LISTENING ON UDP " + config.SyslogPort + ". POINT YOUR DEVICES' SYSLOG AT THIS PC.";
            else
                SyslogStatus = ("COULD NOT LISTEN ON UDP " + config.SyslogPort + ": " + error).ToUpperInvariant();
        }

        /// <summary>Listener thread: store the line and check it, but touch nothing on screen.</summary>
        private void OnSyslogReceived(SyslogMessage message)
        {
            Store.AppendLine(Store.SyslogPath,
                message.Time.ToString("s") + "\t" + message.Source + "\t" + message.Severity + "\t" + message.Text,
                10L * 1024 * 1024);
            pendingLogs.Enqueue(message);

            EventEntry alert = syslogRule.Check(message);
            if (alert != null) pendingEvents.Enqueue(alert);
        }

        /// <summary>UI thread: show what the listener has queued up.</summary>
        public void DrainPending()
        {
            bool logsChanged = false;
            SyslogMessage message;
            while (pendingLogs.TryDequeue(out message))
            {
                allLogs.Insert(0, new LogViewModel
                {
                    Time = message.Time.ToString("MM-dd HH:mm:ss"),
                    Source = message.Source,
                    Text = message.Text,
                    IsHigh = message.Severity <= 3
                });
                logsChanged = true;
            }
            if (logsChanged)
            {
                if (allLogs.Count > MaxLogsKept) allLogs.RemoveRange(MaxLogsKept, allLogs.Count - MaxLogsKept);
                RefreshLogs();
            }

            var fresh = new List<EventEntry>();
            EventEntry entry;
            while (pendingEvents.TryDequeue(out entry)) fresh.Add(entry);
            if (fresh.Count > 0) AddEvents(fresh);
        }

        private void AddEvents(List<EventEntry> entries)
        {
            Store.AppendEvents(entries);
            string alert = null;
            foreach (EventEntry e in entries)
            {
                allEvents.Insert(0, ToViewModel(e));
                if (e.Severity == "high") alert = Describe(e);
            }
            TrimEvents();
            RefreshEvents();
            if (alert != null) SendAlert(alert);
        }

        private void RefreshLogs()
        {
            string filter = logFilter.Trim();
            Logs.Clear();
            foreach (LogViewModel log in allLogs)
            {
                if (filter.Length == 0
                    || log.Text.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0
                    || log.Source.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Logs.Add(log);
                    if (Logs.Count >= MaxShown) break;
                }
            }
            LogSummary = "LOGS (" + allLogs.Count + ")";
        }

        // ---- history charts ----

        private void RefreshHistory(DateTime now)
        {
            const int hours = 24;
            List<HistoryPoint> points = History.Load(now, hours);

            double[] online = History.Hourly(points, now, hours, p => p.Online, false);
            double[] alerts = History.Hourly(points, now, hours, p => p.HighEvents, true);
            double[] elevated = History.Hourly(points, now, hours, p => p.Elevated ? 1 : 0, false);

            FillBars(DeviceBars, online, now, v => v + " online", v => false);
            FillBars(AlertBars, alerts, now, v => v + " alert(s)", v => v > 0);
            FillBars(StatusBars, elevated.Select(v => v < 0 ? -1.0 : 1.0).ToArray(), now, v => "", v => false);
            for (int i = 0; i < hours; i++)
            {
                StatusBars[i].Height = elevated[i] < 0 ? 2 : 14;
                StatusBars[i].IsAlert = elevated[i] > 0;
                StatusBars[i].Tip = HourLabel(now, hours, i) + (elevated[i] < 0 ? "  no data" : (elevated[i] > 0 ? "  elevated" : "  nominal"));
            }
            // Bars are replaced, not mutated, so swap the collection contents to refresh the bindings.
            var copy = StatusBars.ToList();
            StatusBars.Clear();
            foreach (BarViewModel bar in copy) StatusBars.Add(bar);

            var uptime = History.Uptime(points).OrderBy(u => u.Key, StringComparer.OrdinalIgnoreCase).ToList();
            while (UptimeRows.Count > uptime.Count) UptimeRows.RemoveAt(UptimeRows.Count - 1);
            for (int i = 0; i < uptime.Count; i++)
            {
                if (i >= UptimeRows.Count) UptimeRows.Add(new RowViewModel());
                UptimeRows[i].Label = uptime[i].Key.ToUpperInvariant();
                UptimeRows[i].Value = uptime[i].Value + "% UP";
                UptimeRows[i].IsAlert = uptime[i].Value < 99;
            }
        }

        private static void FillBars(ObservableCollection<BarViewModel> target, double[] values, DateTime now,
            Func<double, string> describe, Func<double, bool> isAlert)
        {
            double max = Math.Max(1, values.Where(v => v > 0).DefaultIfEmpty(1).Max());
            target.Clear();
            for (int i = 0; i < values.Length; i++)
            {
                double v = values[i];
                target.Add(new BarViewModel
                {
                    Height = v < 0 ? 0 : Math.Max(2, Math.Round(v / max * ChartHeight)),
                    IsAlert = v >= 0 && isAlert(v),
                    Tip = HourLabel(now, values.Length, i) + (v < 0 ? "  no data" : "  " + describe(v))
                });
            }
        }

        private static string HourLabel(DateTime now, int hours, int index)
        {
            return now.AddHours(-(hours - 1 - index)).ToString("HH") + ":00";
        }

        // ---- device actions (file and network work happens off the UI thread) ----

        public void RenameDevice(string mac, string name)
        {
            Task.Run(() =>
            {
                try
                {
                    lock (Store.DevicesLock)
                    {
                        List<DeviceRecord> devices = Store.Load<List<DeviceRecord>>(Store.DevicesPath);
                        if (devices == null) return;
                        DeviceRecord match = devices.FirstOrDefault(d => d != null
                            && string.Equals(Scanner.NormalizeMac(d.Mac), mac, StringComparison.OrdinalIgnoreCase));
                        if (match == null) return;
                        match.Name = name;
                        Store.Save(Store.DevicesPath, devices);
                    }
                }
                catch (Exception ex)
                {
                    Store.LogError("rename", ex);
                }
            });
        }

        public async void ApproveDevice(DeviceViewModel device)
        {
            if (device == null || !device.IsUnknown) return;
            device.Approved = true;
            string mac = device.Mac;
            string label = device.Ip + (device.Name.Length > 0 ? " (" + device.Name + ")" : "");
            try
            {
                await Task.Run(() =>
                {
                    lock (Store.DevicesLock)
                    {
                        List<DeviceRecord> devices = Store.Load<List<DeviceRecord>>(Store.DevicesPath);
                        if (devices == null) return;
                        foreach (DeviceRecord d in devices)
                        {
                            if (d != null && string.Equals(Scanner.NormalizeMac(d.Mac), mac, StringComparison.OrdinalIgnoreCase))
                                d.Approved = true;
                        }
                        Store.Save(Store.DevicesPath, devices);
                    }
                });
                AddEvents(new List<EventEntry>
                {
                    new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "approve", Severity = "info", Msg = "approved device " + label + " " + mac }
                });
                RequestScan(); // refresh the overall status
            }
            catch (Exception ex)
            {
                Store.LogError("approve", ex);
            }
        }

        public void ApprovePort(PortViewModel port)
        {
            if (port == null || !port.IsNew) return;
            port.IsNew = false;
            RunApproval(() => scanner.ApprovePort(port.Port), "approved listening port " + port.Port);
        }

        public void ApproveAutorun(AutorunViewModel item)
        {
            if (item == null || !item.IsNew) return;
            item.IsNew = false;
            autorunSignature = ""; // make the next scan redraw the list
            RunApproval(() => scanner.ApproveAutorun(item.Key), "approved autorun " + item.Name);
        }

        /// <summary>Deny: take the startup item out of Windows. Asks first, and keeps a copy.</summary>
        public async void DenyAutorun(AutorunViewModel item)
        {
            if (item == null || !item.IsNew) return;

            string question = "Remove this startup item from Windows?\n\n"
                + item.Kind + ":  " + item.Name + "\n"
                + (string.IsNullOrEmpty(item.Command) ? "" : item.Command + "\n")
                + "\nA record is kept in the data folder (removed-autoruns) so it can be put back.";
            if (Confirm == null || !Confirm(question)) return;

            var target = new AutorunItem { Kind = item.RawKind, Name = item.Name, Command = item.Command };
            try
            {
                string message = "";
                bool removed = await Task.Run(() => SecHUD.Autoruns.Remove(target, out message));
                if (!removed)
                {
                    FooterNote = "NOT REMOVED: " + item.Name.ToUpperInvariant();
                    if (ShowMessage != null) ShowMessage("Could not remove " + item.Name + ".\n\n" + message);
                    return;
                }

                item.IsNew = false;
                autorunSignature = ""; // make the next scan redraw the list
                FooterNote = ("DENIED: " + item.Name + " (" + message + ")").ToUpperInvariant();
                AddEvents(new List<EventEntry>
                {
                    new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "deny", Severity = "info",
                        Msg = "denied " + target.Kind + " autorun " + target.Name + ": " + message
                              + (string.IsNullOrEmpty(target.Command) ? "" : " (was: " + target.Command + ")") }
                });
                RequestScan();
            }
            catch (Exception ex)
            {
                Store.LogError("deny", ex);
                if (ShowMessage != null) ShowMessage("Could not remove " + item.Name + ".\n\n" + ex.Message);
            }
        }

        public void ApproveForward(ForwardViewModel forward)
        {
            if (forward == null || !forward.IsNew) return;
            forward.IsNew = false;
            RunApproval(() => scanner.ApproveForward(forward.Key), "approved router forward " + forward.Port + " -> " + forward.Target);
        }

        public void DismissDetection(EventViewModel item)
        {
            if (item == null || !item.IsOpen) return;
            item.IsOpen = false;
            RunApproval(() => scanner.DismissDetection(item.Ts, item.RawMessage), "dismissed detection: " + item.RawMessage);
        }

        /// <summary>Writes the change off the UI thread, logs it, then rescans so the status reflects it.</summary>
        private async void RunApproval(Action change, string logMessage)
        {
            try
            {
                await Task.Run(change);
                AddEvents(new List<EventEntry>
                {
                    new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "approve", Severity = "info", Msg = logMessage }
                });
                RequestScan();
            }
            catch (Exception ex)
            {
                Store.LogError("approve", ex);
            }
        }

        public async void ScanDevicePorts(DeviceViewModel device)
        {
            if (device == null || device.OpenPorts == "SCANNING...") return;
            string ip = device.Ip;
            device.OpenPorts = "SCANNING...";
            try
            {
                List<PortHit> hits = await PortScanner.ScanAsync(ip, 600);
                string summary = PortScanner.Describe(hits);
                device.OpenPorts = summary.ToUpperInvariant();
                AddEvents(new List<EventEntry>
                {
                    new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "port-scan", Severity = "info", Msg = "port check of " + ip + ": " + summary }
                });
            }
            catch (Exception ex)
            {
                device.OpenPorts = ("SCAN FAILED: " + ex.Message).ToUpperInvariant();
            }
        }

        // ---- report ----

        private void ExportReport()
        {
            if (lastResult == null)
            {
                FooterNote = "WAIT FOR THE FIRST SCAN TO FINISH";
                return;
            }
            try
            {
                string path = Report.Save(lastResult, Store.ReadRecentEvents(100));
                FooterNote = "REPORT SAVED: " + path.ToUpperInvariant();
                Process.Start(path);
            }
            catch (Exception ex)
            {
                Store.LogError("report", ex);
                FooterNote = ("REPORT FAILED: " + ex.Message).ToUpperInvariant();
            }
        }

        // ---- settings ----

        private void LoadSettingsForm()
        {
            SetScanSeconds = config.ScanSeconds.ToString();
            SetLoginThreshold = config.FailedLoginThreshold.ToString();
            SetScanLan = config.ScanLan;
            SetNotify = config.Notify;
            SetWatchEvents = config.WatchEvents;
            SetWatchAutoruns = config.WatchAutoruns;
            SetSyslogEnabled = config.SyslogEnabled;
            SetSyslogPort = config.SyslogPort.ToString();
            SetProxmoxHost = config.ProxmoxHost;
            SetProxmoxTokenId = config.ProxmoxTokenId;
            SetDiscordWebhook = "";
            SetProxmoxSecret = "";
            SetWatchedHosts = FormatHosts(config.WatchedHosts);
            SetHomeWifiName = config.HomeWifiName;
            SetWatchWifi = config.WatchWifi;
            SetWatchRouter = config.WatchRouter;
            SetCheckUpdates = config.CheckUpdates;
            DiscordState = config.DiscordWebhookProtected.Length > 0 ? "SAVED" : "NOT SET";
            ProxmoxSecretState = config.ProxmoxSecretProtected.Length > 0 ? "SAVED" : "NOT SET";
            try { SetStartWithWindows = StartupEntry.IsEnabled(); } catch { SetStartWithWindows = false; }
        }

        public static string FormatHosts(IEnumerable<WatchedHost> hosts)
        {
            var sb = new StringBuilder();
            foreach (WatchedHost h in hosts)
            {
                if (h == null || string.IsNullOrWhiteSpace(h.Host)) continue;
                sb.Append(h.Name).Append(", ").Append(h.Host).Append(", ").Append(h.Port).Append(", ").Append(h.Tls ? "tls" : "plain").Append(Environment.NewLine);
            }
            return sb.ToString();
        }

        /// <summary>One host per line: name, host, port, tls|plain. Only the host is required.</summary>
        public static List<WatchedHost> ParseHosts(string text)
        {
            var hosts = new List<WatchedHost>();
            foreach (string raw in (text ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = raw.Split(',').Select(p => p.Trim()).ToArray();
                if (parts.Length == 0 || parts.All(p => p.Length == 0)) continue;

                string name = parts[0];
                string host = parts.Length > 1 && parts[1].Length > 0 ? parts[1] : parts[0];
                int port = 443;
                if (parts.Length > 2) int.TryParse(parts[2], out port);
                if (port < 1 || port > 65535) port = 443;
                bool tls = !(parts.Length > 3 && parts[3].Equals("plain", StringComparison.OrdinalIgnoreCase));
                if (host.Length == 0) continue;
                hosts.Add(new WatchedHost { Name = name.Length > 0 ? name : host, Host = host, Port = port, Tls = tls });
            }
            return hosts;
        }

        private void SaveSettings()
        {
            try
            {
                AppConfig updated = Store.LoadConfig();

                int number;
                if (int.TryParse(SetScanSeconds, out number)) updated.ScanSeconds = number;
                if (int.TryParse(SetLoginThreshold, out number)) updated.FailedLoginThreshold = number;
                if (int.TryParse(SetSyslogPort, out number)) updated.SyslogPort = number;
                updated.ScanLan = SetScanLan;
                updated.Notify = SetNotify;
                updated.WatchEvents = SetWatchEvents;
                updated.WatchAutoruns = SetWatchAutoruns;
                updated.SyslogEnabled = SetSyslogEnabled;
                updated.ProxmoxHost = (SetProxmoxHost ?? "").Trim();
                updated.ProxmoxTokenId = (SetProxmoxTokenId ?? "").Trim();
                updated.WatchedHosts = ParseHosts(SetWatchedHosts);
                updated.HomeWifiName = (SetHomeWifiName ?? "").Trim();
                updated.WatchWifi = SetWatchWifi;
                updated.WatchRouter = SetWatchRouter;
                updated.CheckUpdates = SetCheckUpdates;

                // Secret boxes: blank keeps what is stored, NONE removes it, anything else replaces it.
                string webhook = (SetDiscordWebhook ?? "").Trim();
                if (webhook.Equals("NONE", StringComparison.OrdinalIgnoreCase)) updated.DiscordWebhookProtected = "";
                else if (webhook.Length > 0)
                {
                    if (!Discord.IsValidWebhook(webhook))
                    {
                        SettingsStatus = "NOT SAVED: THAT IS NOT A DISCORD WEBHOOK ADDRESS";
                        return;
                    }
                    updated.DiscordWebhookProtected = Secrets.Protect(webhook);
                }

                string secret = (SetProxmoxSecret ?? "").Trim();
                if (secret.Equals("NONE", StringComparison.OrdinalIgnoreCase)) updated.ProxmoxSecretProtected = "";
                else if (secret.Length > 0) updated.ProxmoxSecretProtected = Secrets.Protect(secret);

                updated.Normalize();
                Store.Save(Store.ConfigPath, updated);
                config = updated;

                bool wantStartup = SetStartWithWindows;
                if (wantStartup != StartupEntry.IsEnabled())
                {
                    StartupEntry.Set(wantStartup);
                    if (wantStartup) TrustOwnStartupEntry();
                }

                ApplySyslogSetting();
                LoadSettingsForm();
                SettingsStatus = "SAVED " + DateTime.Now.ToString("HH:mm:ss");
                RequestScan();
            }
            catch (Exception ex)
            {
                Store.LogError("settings", ex);
                SettingsStatus = ("NOT SAVED: " + ex.Message).ToUpperInvariant();
            }
        }

        /// <summary>The app's own startup entry goes straight into the autorun baseline so it never flags itself.</summary>
        private static void TrustOwnStartupEntry()
        {
            try
            {
                List<string> known = Store.Load<List<string>>(Store.AutorunsPath);
                if (known == null) return; // no baseline yet: the first scan will include it
                string key = StartupEntry.AutorunKey;
                if (!known.Contains(key, StringComparer.OrdinalIgnoreCase))
                {
                    known.Add(key);
                    Store.Save(Store.AutorunsPath, known);
                }
            }
            catch (Exception ex)
            {
                Store.LogError("startup baseline", ex);
            }
        }

        private async void TestDiscord()
        {
            string typed = (SetDiscordWebhook ?? "").Trim();
            string webhook = typed.Length > 0 && !typed.Equals("NONE", StringComparison.OrdinalIgnoreCase)
                ? typed
                : Secrets.Unprotect(config.DiscordWebhookProtected);
            if (webhook.Length == 0)
            {
                SettingsStatus = "PASTE A DISCORD WEBHOOK ADDRESS FIRST";
                return;
            }

            SettingsStatus = "SENDING TEST...";
            string error = "";
            bool ok = await Task.Run(() => Discord.Send(webhook, "SecHUD test message from " + Environment.MachineName + ". Alerts will arrive here.", out error));
            SettingsStatus = ok ? "TEST SENT. CHECK YOUR DISCORD CHANNEL." : ("TEST FAILED: " + error).ToUpperInvariant();
        }

        private static void OpenRules()
        {
            try { Detector.LoadCustomRules(); } catch { } // writes the example file on first use
            Launch("notepad.exe", "\"" + Store.RulesPath + "\"");
        }

        private static void OpenConfig()
        {
            Store.LoadConfig(); // writes the default file on first use
            Launch("notepad.exe", "\"" + Store.ConfigPath + "\"");
        }

        private static void Launch(string program, string argument)
        {
            try
            {
                if (string.IsNullOrEmpty(argument)) Process.Start(program);
                else Process.Start(program, argument);
            }
            catch (Exception ex)
            {
                Store.LogError("launch " + program, ex);
            }
        }

        public void Shutdown()
        {
            syslog.Stop();
        }
    }
}
