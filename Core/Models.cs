using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace SecHUD
{
    /// <summary>A host the app checks on every scan (reachability, and certificate expiry when Tls is on).</summary>
    [DataContract]
    public class WatchedHost
    {
        [DataMember(Name = "name", Order = 1)] public string Name { get; set; }
        [DataMember(Name = "host", Order = 2)] public string Host { get; set; }
        [DataMember(Name = "port", Order = 3)] public int Port { get; set; }
        [DataMember(Name = "tls", Order = 4)] public bool Tls { get; set; }
    }

    /// <summary>User settings, stored as config.json in the data folder.</summary>
    [DataContract]
    public class AppConfig
    {
        [DataMember(Name = "scanSeconds", Order = 1)] public int ScanSeconds { get; set; }
        [DataMember(Name = "scanLan", Order = 2)] public bool ScanLan { get; set; }
        [DataMember(Name = "notify", Order = 3)] public bool Notify { get; set; }
        [DataMember(Name = "failedLoginThreshold", Order = 4)] public int FailedLoginThreshold { get; set; }
        [DataMember(Name = "signatureMaxAgeHours", Order = 5)] public int SignatureMaxAgeHours { get; set; }
        [DataMember(Name = "certWarnDays", Order = 6)] public int CertWarnDays { get; set; }
        [DataMember(Name = "ignorePortsAbove", Order = 7)] public int IgnorePortsAbove { get; set; }
        [DataMember(Name = "watchedHosts", Order = 8)] public List<WatchedHost> WatchedHosts { get; set; }
        [DataMember(Name = "watchEvents", Order = 9)] public bool WatchEvents { get; set; }
        [DataMember(Name = "watchAutoruns", Order = 10)] public bool WatchAutoruns { get; set; }
        [DataMember(Name = "syslogEnabled", Order = 11)] public bool SyslogEnabled { get; set; }
        [DataMember(Name = "syslogPort", Order = 12)] public int SyslogPort { get; set; }
        [DataMember(Name = "proxmoxHost", Order = 13)] public string ProxmoxHost { get; set; }
        [DataMember(Name = "proxmoxPort", Order = 14)] public int ProxmoxPort { get; set; }
        [DataMember(Name = "proxmoxTokenId", Order = 15)] public string ProxmoxTokenId { get; set; }
        [DataMember(Name = "watchWifi", Order = 18)] public bool WatchWifi { get; set; }
        [DataMember(Name = "homeWifiName", Order = 19)] public string HomeWifiName { get; set; }
        [DataMember(Name = "watchRouter", Order = 20)] public bool WatchRouter { get; set; }
        [DataMember(Name = "checkUpdates", Order = 21)] public bool CheckUpdates { get; set; }

        /// <summary>Watch this PC continuously and react to a change within a second or two.</summary>
        [DataMember(Name = "liveWatch", Order = 22)] public bool LiveWatch { get; set; }

        /// <summary>How many sweeps in a row a watched device may miss before it counts as offline.</summary>
        [DataMember(Name = "watchMisses", Order = 23)] public int WatchMisses { get; set; }

        /// <summary>Quiet hours hold back non-urgent Discord alerts and send them as one summary afterwards.</summary>
        [DataMember(Name = "quietHours", Order = 24)] public bool QuietHours { get; set; }
        [DataMember(Name = "quietStart", Order = 25)] public string QuietStart { get; set; }
        [DataMember(Name = "quietEnd", Order = 26)] public string QuietEnd { get; set; }

        /// <summary>
        /// Devices using a made-up private address (most phones and tablets) are listed as guests
        /// and do not raise an alert. Off by default: an intruder's phone looks the same.
        /// </summary>
        [DataMember(Name = "guestPrivate", Order = 28)] public bool GuestPrivate { get; set; }

        /// <summary>How many days an unapproved guest stays in the list after it was last seen.</summary>
        [DataMember(Name = "guestDays", Order = 29)] public int GuestDays { get; set; }

        /// <summary>Send one Discord message a week with what happened, so a quiet app still shows it is working.</summary>
        [DataMember(Name = "weeklySummary", Order = 30)] public bool WeeklySummary { get; set; }

        /// <summary>
        /// Programs whose listening ports are never flagged, as full paths. For software such as a
        /// media server that opens different ports every time it runs. Only the exact file counts:
        /// a program with the same name somewhere else is still flagged.
        /// </summary>
        [DataMember(Name = "trustedPrograms", Order = 31)] public List<string> TrustedPrograms { get; set; }

        /// <summary>False until the first-run welcome has been answered.</summary>
        [DataMember(Name = "welcomed", Order = 27)] public bool Welcomed { get; set; }

        // Secrets are never stored as plain text. These hold DPAPI-encrypted values that only
        // this Windows account can decrypt (see Secrets.cs).
        [DataMember(Name = "proxmoxSecretProtected", Order = 16)] public string ProxmoxSecretProtected { get; set; }
        [DataMember(Name = "discordWebhookProtected", Order = 17)] public string DiscordWebhookProtected { get; set; }

        public AppConfig()
        {
            SetDefaults();
        }

        // The JSON serializer skips constructors, so defaults are applied here before members are read.
        [OnDeserializing]
        private void OnDeserializing(StreamingContext context)
        {
            SetDefaults();
        }

        private void SetDefaults()
        {
            ScanSeconds = 120;
            ScanLan = true;
            Notify = true;
            FailedLoginThreshold = 5;
            SignatureMaxAgeHours = 72;
            CertWarnDays = 14;
            IgnorePortsAbove = 49151;
            WatchedHosts = new List<WatchedHost>();
            WatchEvents = true;
            WatchAutoruns = true;
            SyslogEnabled = false;
            SyslogPort = 514;
            ProxmoxHost = "";
            ProxmoxPort = 8006;
            ProxmoxTokenId = "";
            ProxmoxSecretProtected = "";
            DiscordWebhookProtected = "";
            WatchWifi = true;
            HomeWifiName = "";
            WatchRouter = true;
            CheckUpdates = true;
            LiveWatch = true;
            WatchMisses = 2;
            QuietHours = false;
            QuietStart = "23:00";
            QuietEnd = "07:00";
            Welcomed = false;
            GuestPrivate = false;
            GuestDays = 7;
            WeeklySummary = true;
            TrustedPrograms = new List<string>();
        }

        public static AppConfig CreateDefault()
        {
            var config = new AppConfig();
            return config;
        }

        /// <summary>Keeps hand-edited values inside sane limits.</summary>
        public void Normalize()
        {
            if (ScanSeconds < 30) ScanSeconds = 30;
            if (ScanSeconds > 3600) ScanSeconds = 3600;
            if (FailedLoginThreshold < 1) FailedLoginThreshold = 1;
            if (SignatureMaxAgeHours < 1) SignatureMaxAgeHours = 72;
            if (CertWarnDays < 0) CertWarnDays = 0;
            if (IgnorePortsAbove < 1 || IgnorePortsAbove > 65535) IgnorePortsAbove = 49151;
            if (WatchedHosts == null) WatchedHosts = new List<WatchedHost>();
            if (SyslogPort < 1 || SyslogPort > 65535) SyslogPort = 514;
            if (ProxmoxPort < 1 || ProxmoxPort > 65535) ProxmoxPort = 8006;
            if (ProxmoxHost == null) ProxmoxHost = "";
            if (ProxmoxTokenId == null) ProxmoxTokenId = "";
            if (ProxmoxSecretProtected == null) ProxmoxSecretProtected = "";
            if (DiscordWebhookProtected == null) DiscordWebhookProtected = "";
            if (HomeWifiName == null) HomeWifiName = "";
            if (WatchMisses < 1 || WatchMisses > 20) WatchMisses = 2;
            if (GuestDays < 1 || GuestDays > 365) GuestDays = 7;
            if (TrustedPrograms == null) TrustedPrograms = new List<string>();
            TrustedPrograms = TrustedPrograms.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim().Trim('"'))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            int minutes;
            if (!Quiet.TryParseTime(QuietStart, out minutes)) QuietStart = "23:00";
            if (!Quiet.TryParseTime(QuietEnd, out minutes)) QuietEnd = "07:00";
        }
    }

    /// <summary>One device seen on the LAN, keyed by MAC address. Stored in devices.json.</summary>
    [DataContract]
    public class DeviceRecord
    {
        [DataMember(Name = "mac", Order = 1)] public string Mac { get; set; }
        [DataMember(Name = "ip", Order = 2)] public string Ip { get; set; }
        [DataMember(Name = "name", Order = 3)] public string Name { get; set; }
        [DataMember(Name = "approved", Order = 4)] public bool Approved { get; set; }
        [DataMember(Name = "firstSeen", Order = 5)] public string FirstSeen { get; set; }
        [DataMember(Name = "lastSeen", Order = 6)] public string LastSeen { get; set; }

        /// <summary>A watched device raises an alert when it stops answering.</summary>
        [DataMember(Name = "watched", Order = 7, EmitDefaultValue = false)] public bool Watched { get; set; }
        /// <summary>Sweeps in a row this device has not answered.</summary>
        [DataMember(Name = "missed", Order = 8, EmitDefaultValue = false)] public int Missed { get; set; }
        /// <summary>True once the offline alert for a watched device has been raised.</summary>
        [DataMember(Name = "down", Order = 9, EmitDefaultValue = false)] public bool Down { get; set; }

        /// <summary>True when the device answered during the latest scan. Not saved.</summary>
        [IgnoreDataMember] public bool Online { get; set; }

        /// <summary>True for an unapproved device with a private address while guest handling is on. Not saved.</summary>
        [IgnoreDataMember] public bool Guest { get; set; }
    }

    /// <summary>One line of events.log.</summary>
    [DataContract]
    public class EventEntry
    {
        [DataMember(Name = "ts", Order = 1)] public string Ts { get; set; }
        [DataMember(Name = "type", Order = 2)] public string Type { get; set; }
        [DataMember(Name = "severity", Order = 3)] public string Severity { get; set; }
        [DataMember(Name = "msg", Order = 4)] public string Msg { get; set; }

        /// <summary>MITRE ATT&amp;CK technique id (for example T1136.001) when the event maps to one.</summary>
        [DataMember(Name = "technique", Order = 5, EmitDefaultValue = false)] public string Technique { get; set; }
    }

    /// <summary>What the previous scan saw, so events are only logged when something changes.</summary>
    [DataContract]
    public class AppState
    {
        [DataMember(Name = "level", Order = 1)] public string Level { get; set; }
        [DataMember(Name = "defenderOk", Order = 2)] public bool DefenderOk { get; set; }
        [DataMember(Name = "firewallOk", Order = 3)] public bool FirewallOk { get; set; }
        [DataMember(Name = "loginsOver", Order = 4)] public bool LoginsOver { get; set; }
        [DataMember(Name = "hostsDown", Order = 5)] public List<string> HostsDown { get; set; }
        [DataMember(Name = "newPorts", Order = 6)] public List<int> NewPorts { get; set; }
        [DataMember(Name = "lastAlert", Order = 7)] public string LastAlert { get; set; }
        [DataMember(Name = "gatewayMac", Order = 8)] public string GatewayMac { get; set; }
        [DataMember(Name = "gatewayChanged", Order = 9)] public bool GatewayChanged { get; set; }
        [DataMember(Name = "proxmoxThumbprint", Order = 10)] public string ProxmoxThumbprint { get; set; }
        [DataMember(Name = "proxmoxCertChanged", Order = 11)] public bool ProxmoxCertChanged { get; set; }
        [DataMember(Name = "eventsSinceUtc", Order = 12)] public string EventsSinceUtc { get; set; }
        [DataMember(Name = "openDetections", Order = 13)] public int OpenDetections { get; set; }
        [DataMember(Name = "newAutoruns", Order = 14)] public List<string> NewAutoruns { get; set; }

        /// <summary>High detections nobody has dismissed yet. They keep the status elevated.</summary>
        [DataMember(Name = "openItems", Order = 15)] public List<EventEntry> OpenItems { get; set; }
        [DataMember(Name = "trustedDns", Order = 16)] public List<string> TrustedDns { get; set; }
        [DataMember(Name = "dnsChanged", Order = 17)] public bool DnsChanged { get; set; }
        [DataMember(Name = "newForwards", Order = 18)] public List<string> NewForwards { get; set; }
        [DataMember(Name = "newAccessPoints", Order = 19)] public List<string> NewAccessPoints { get; set; }

        /// <summary>How far each event log has been read. A log that could not be read keeps its place,
        /// so nothing is skipped once access is granted.</summary>
        [DataMember(Name = "logMarkers", Order = 20)] public List<LogMarker> LogMarkers { get; set; }

        /// <summary>Fills in anything an older state file did not have.</summary>
        public void Normalize()
        {
            if (Level == null) Level = "NOMINAL";
            if (HostsDown == null) HostsDown = new List<string>();
            if (NewPorts == null) NewPorts = new List<int>();
            if (NewAutoruns == null) NewAutoruns = new List<string>();
            if (LastAlert == null) LastAlert = "";
            if (GatewayMac == null) GatewayMac = "";
            if (ProxmoxThumbprint == null) ProxmoxThumbprint = "";
            if (EventsSinceUtc == null) EventsSinceUtc = "";
            if (OpenItems == null) OpenItems = new List<EventEntry>();
            if (TrustedDns == null) TrustedDns = new List<string>();
            if (NewForwards == null) NewForwards = new List<string>();
            if (NewAccessPoints == null) NewAccessPoints = new List<string>();
            if (LogMarkers == null) LogMarkers = new List<LogMarker>();
        }

        public static AppState CreateDefault()
        {
            return new AppState
            {
                Level = "NOMINAL",
                DefenderOk = true,
                FirewallOk = true,
                LoginsOver = false,
                HostsDown = new List<string>(),
                NewPorts = new List<int>(),
                LastAlert = "",
                NewAutoruns = new List<string>(),
                GatewayMac = "",
                ProxmoxThumbprint = "",
                EventsSinceUtc = "",
                OpenItems = new List<EventEntry>(),
                TrustedDns = new List<string>(),
                NewForwards = new List<string>(),
                NewAccessPoints = new List<string>(),
                LogMarkers = new List<LogMarker>()
            };
        }
    }

    /// <summary>One label/value line on the overview.</summary>
    public class CheckRow
    {
        public string Label { get; set; }
        public string Value { get; set; }
        public bool IsAlert { get; set; }
        /// <summary>For checks with a simple healthy/unhealthy meaning (Defender on, firewall on, host up).</summary>
        public bool Ok { get; set; }

        public CheckRow(string label, string value, bool isAlert, bool ok)
        {
            Label = label;
            Value = value;
            IsAlert = isAlert;
            Ok = ok;
        }
    }

    public class PortInfo
    {
        public int Port { get; set; }
        public string Process { get; set; }
        public bool IsNew { get; set; }

        /// <summary>Full path of the program that opened the port, when Windows will say.</summary>
        public string Path { get; set; }
        /// <summary>True when the port is not in the baseline but its program is on the trusted list.</summary>
        public bool Trusted { get; set; }
        /// <summary>For new ports: what is known about the program (signed, by whom, where it lives).</summary>
        public TrustNote Note { get; set; }
    }

    /// <summary>Everything one scan produced. Handed from the scanner to the window.</summary>
    public class ScanResult
    {
        public DateTime Time { get; set; }
        public AppConfig Config { get; set; }
        public string Level { get; set; }
        public bool Elevated { get; set; }
        public string Ticker { get; set; }
        public List<CheckRow> PcRows { get; set; }
        public List<CheckRow> NetRows { get; set; }
        public List<DeviceRecord> Devices { get; set; }
        public List<PortInfo> Ports { get; set; }
        public List<EventEntry> NewEvents { get; set; }
        public List<AutorunItem> Autoruns { get; set; }
        public ProxmoxSnapshot Proxmox { get; set; }
        public List<EventEntry> OpenDetections { get; set; }
        public RouterSnapshot Router { get; set; }
        public int CustomRuleCount { get; set; }

        /// <summary>True for a live-watch pass: this PC was re-checked, the network part is carried over.</summary>
        public bool IsQuick { get; set; }
        /// <summary>Counts up with every pass, so a late result can never overwrite a newer one.</summary>
        public long Sequence { get; set; }

        public ScanResult()
        {
            PcRows = new List<CheckRow>();
            NetRows = new List<CheckRow>();
            Devices = new List<DeviceRecord>();
            Ports = new List<PortInfo>();
            NewEvents = new List<EventEntry>();
            Autoruns = new List<AutorunItem>();
            OpenDetections = new List<EventEntry>();
            Router = new RouterSnapshot();
        }
    }

    /// <summary>One port the router forwards from the internet to a device inside (learned over UPnP).</summary>
    public class ForwardInfo
    {
        public int ExternalPort { get; set; }
        public string Protocol { get; set; }
        public string InternalClient { get; set; }
        public int InternalPort { get; set; }
        public string Description { get; set; }
        public bool IsNew { get; set; }

        public string Key
        {
            get { return (Protocol ?? "") + "|" + ExternalPort + "|" + (InternalClient ?? "") + "|" + InternalPort; }
        }

        public string Summary
        {
            get
            {
                string text = (Protocol ?? "") + " " + ExternalPort + " -> " + (InternalClient ?? "") + ":" + InternalPort;
                return string.IsNullOrWhiteSpace(Description) ? text : text + " (" + Description + ")";
            }
        }
    }

    public class RouterSnapshot
    {
        /// <summary>True when a router answered UPnP. Many have it switched off, which is fine.</summary>
        public bool Found { get; set; }
        public string ExternalIp { get; set; }
        public string Note { get; set; }
        public List<ForwardInfo> Forwards { get; set; }

        public RouterSnapshot()
        {
            Forwards = new List<ForwardInfo>();
            ExternalIp = "";
            Note = "";
        }
    }

    /// <summary>A startup item that was denied, kept so it can be put back. Stored in removed.json.</summary>
    [DataContract]
    public class RemovedRecord
    {
        [DataMember(Name = "id", Order = 1)] public string Id { get; set; }
        [DataMember(Name = "ts", Order = 2)] public string Ts { get; set; }
        [DataMember(Name = "kind", Order = 3)] public string Kind { get; set; }
        [DataMember(Name = "name", Order = 4)] public string Name { get; set; }
        [DataMember(Name = "command", Order = 5)] public string Command { get; set; }
        /// <summary>Where the moved startup file or the exported task definition was saved.</summary>
        [DataMember(Name = "backup", Order = 6)] public string Backup { get; set; }
        /// <summary>For Run entries: "ExpandString" when the value held %VARIABLES%.</summary>
        [DataMember(Name = "valueKind", Order = 7)] public string ValueKind { get; set; }
        [DataMember(Name = "restored", Order = 8)] public bool Restored { get; set; }
    }

    /// <summary>When the weekly Discord summary last went out. Stored in summary.json.</summary>
    [DataContract]
    public class SummaryState
    {
        [DataMember(Name = "lastSentUtc", Order = 1)] public string LastSentUtc { get; set; }
    }

    /// <summary>The window's size, remembered between runs. Stored in window.json.</summary>
    [DataContract]
    public class WindowPlacement
    {
        [DataMember(Name = "width", Order = 1)] public double Width { get; set; }
        [DataMember(Name = "height", Order = 2)] public double Height { get; set; }
        [DataMember(Name = "maximized", Order = 3)] public bool Maximized { get; set; }
    }

    [DataContract]
    public class LogMarker
    {
        [DataMember(Name = "log", Order = 1)] public string Log { get; set; }
        [DataMember(Name = "sinceUtc", Order = 2)] public string SinceUtc { get; set; }
    }

    /// <summary>A user-defined detection in rules.json.</summary>
    [DataContract]
    public class CustomRule
    {
        [DataMember(Name = "enabled", Order = 1)] public bool Enabled { get; set; }
        [DataMember(Name = "log", Order = 2)] public string Log { get; set; }
        [DataMember(Name = "id", Order = 3)] public int Id { get; set; }
        [DataMember(Name = "contains", Order = 4)] public string Contains { get; set; }
        [DataMember(Name = "technique", Order = 5)] public string Technique { get; set; }
        [DataMember(Name = "severity", Order = 6)] public string Severity { get; set; }
        [DataMember(Name = "message", Order = 7)] public string Message { get; set; }
    }

    /// <summary>What Windows says about the signature on one file.</summary>
    public class SignatureInfo
    {
        public const string Trusted = "trusted";      // signed, and Windows trusts the signature
        public const string Untrusted = "untrusted";  // signed, but the signature does not check out
        public const string Broken = "broken";        // the file was changed after it was signed
        public const string None = "none";            // no signature at all

        public string State { get; set; }
        public string Signer { get; set; }

        public SignatureInfo()
        {
            State = None;
            Signer = "";
        }
    }

    /// <summary>A plain-language note about a startup item, to help decide between Approve and Deny.</summary>
    public class TrustNote
    {
        public const string Ok = "ok";
        public const string Caution = "caution";
        public const string Warn = "warn";

        public string Level { get; set; }
        /// <summary>One or two short sentences for the window.</summary>
        public string Text { get; set; }
        /// <summary>A few words for the alert, such as "not signed, runs from a temp folder".</summary>
        public string Short { get; set; }
        public string Path { get; set; }
    }

    /// <summary>Something that starts by itself: a Run key entry, a startup shortcut, a service or a scheduled task.</summary>
    public class AutorunItem
    {
        public string Kind { get; set; }
        public string Name { get; set; }
        public string Command { get; set; }
        public string Technique { get; set; }
        public bool IsNew { get; set; }

        /// <summary>For new items: what is known about the program behind it (signed, by whom, where it lives).</summary>
        public TrustNote Note { get; set; }

        /// <summary>Identity used for the baseline. Services and tasks are keyed by name only because
        /// their paths change with ordinary updates. Run entries include the command.</summary>
        public string Key
        {
            get
            {
                return Kind == "run" ? Kind + "|" + Name + "|" + Command : Kind + "|" + Name;
            }
        }
    }

    public class ProxmoxGuest
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Kind { get; set; }
        public string Status { get; set; }
        public string Cpu { get; set; }
        public string Memory { get; set; }
        public bool Running { get; set; }
    }

    /// <summary>What the Proxmox API returned on one scan.</summary>
    public class ProxmoxSnapshot
    {
        public bool Configured { get; set; }
        public bool Ok { get; set; }
        public string Error { get; set; }
        public string Summary { get; set; }
        public string Thumbprint { get; set; }
        public bool CertChanged { get; set; }
        public List<ProxmoxGuest> Guests { get; set; }

        public ProxmoxSnapshot()
        {
            Guests = new List<ProxmoxGuest>();
            Error = "";
            Summary = "";
            Thumbprint = "";
        }
    }

    public class SyslogMessage
    {
        public DateTime Time { get; set; }
        public string Source { get; set; }
        public int Severity { get; set; }
        public string Text { get; set; }
    }

    public class PortHit
    {
        public int Port { get; set; }
        public string Service { get; set; }
    }

    /// <summary>One line of history.csv: what a single scan saw.</summary>
    public class HistoryPoint
    {
        public DateTime Time { get; set; }
        public int Online { get; set; }
        public int Unknown { get; set; }
        public bool Elevated { get; set; }
        public int HighEvents { get; set; }
        public Dictionary<string, bool> Hosts { get; set; }

        public HistoryPoint()
        {
            Hosts = new Dictionary<string, bool>();
        }
    }
}
