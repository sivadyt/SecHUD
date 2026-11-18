using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using SecHUD;
using SecHUD.Setup;

/// <summary>
/// SecHUD's tests. Run them with run-tests.cmd. Everything here works on a temporary data
/// folder and fake inputs, so it never touches your real baselines or sends anything.
/// </summary>
static partial class Tests
{
    static int passed;
    static int failed;

    static void Check(string name, bool ok)
    {
        Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name);
        if (ok) passed++; else failed++;
    }

    static RawEvent Ev(string log, int id, params string[] props)
    {
        return new RawEvent { Log = log, Id = id, TimeUtc = DateTime.UtcNow, Props = props.ToList() };
    }

    /// <summary>Hook for extra tests that only make sense on one platform.</summary>
    static partial void PlatformTests();

    static int Main()
    {
        string temp = Path.Combine(Path.GetTempPath(), "SecHUD-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        Store.UseDirectory(temp);
        try
        {
            ConfigAndStorage();
            SecretsAreEncrypted();
            AntivirusDecoding();
            DetectionRules();
            CustomRules();
            AccountWatch();
            AutorunBaseline();
            Syslog();
            DiscordSafety();
            PortScanGuard();
            ProxmoxParsing();
            HistoryMath();
            SettingsParsing();
            GatewayAndDns();
            WifiTwins();
            RouterForwards();
            SingleItemApprovals();
            DenyRemovesAutoruns();
            ReportExport();
            UpdateCheck();
            ViewModel();
            QuietHours();
            DeviceMakers();
            WatchedDevices();
            RestoreDenied();
            LiveWatchHelpers();
            LiveAndQuietInTheWindow();
            UpdateInstall();
            SetupProgram();
            TrustNotes();
            GuestDevices();
            WeeklySummary();
            PlatformTests();
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAIL  a test crashed: " + ex);
            failed++;
        }
        finally
        {
            try { Directory.Delete(temp, true); } catch { }
        }

        Console.WriteLine();
        Console.WriteLine(failed == 0 ? "ALL " + passed + " PASSED" : failed + " FAILED, " + passed + " passed");
        return failed;
    }

    // ------------------------------------------------------------------

    static void ConfigAndStorage()
    {
        var config = AppConfig.CreateDefault();
        config.WatchedHosts.Add(new WatchedHost { Name = "site", Host = "example.org", Port = 443, Tls = true });
        var back = Store.FromJson<AppConfig>(Store.Pretty(Store.ToJson(config)));
        Check("config survives a save and load", back.WatchedHosts.Count == 1 && back.ScanSeconds == 120 && back.SyslogPort == 514 && back.WatchEvents && back.WatchWifi && back.WatchRouter);

        var old = Store.FromJson<AppConfig>("{\"scanSeconds\": 300, \"watchedHosts\":[{\"name\":\"x\",\"host\":\"\",\"port\":8006,\"tls\":true}]}");
        old.Normalize();
        Check("a config file from an older version gets the new defaults", old.ScanSeconds == 300 && old.WatchAutoruns && !old.SyslogEnabled && old.ProxmoxPort == 8006 && old.HomeWifiName == "" && old.WatchRouter);

        var oldState = Store.FromJson<AppState>("{\"level\":\"NOMINAL\",\"defenderOk\":true,\"firewallOk\":true,\"loginsOver\":false,\"hostsDown\":[],\"newPorts\":[],\"lastAlert\":\"\"}");
        oldState.Normalize();
        Check("a state file from an older version still loads", oldState.GatewayMac == "" && oldState.OpenItems != null && oldState.TrustedDns != null && oldState.NewForwards != null);

        config.Normalize();
        config.ScanSeconds = 5; config.SyslogPort = 99999; config.Normalize();
        Check("out-of-range settings are pulled back into range", config.ScanSeconds == 30 && config.SyslogPort == 514);

        Check("json is indented, and text inside strings is left alone", Store.Pretty("{\"a\":[],\"c\":\"x,{y}:\\\"z\"}").Contains("\"a\": []") && Store.Pretty("{\"c\":\"x,{y}:\\\"z\"}").Contains("\"x,{y}:\\\"z\""));
        Check("MAC addresses are normalised", Scanner.NormalizeMac("aa:bb:cc:dd:ee:0f") == "AA-BB-CC-DD-EE-0F" && Scanner.NormalizeMac("AABBCCDDEE0F") == "AA-BB-CC-DD-EE-0F" && Scanner.NormalizeMac("00-00-00-00-00-00") == null && Scanner.NormalizeMac("junk") == null);

        Store.Save(Store.DevicesPath, new List<DeviceRecord> { new DeviceRecord { Mac = "AA-BB-CC-00-00-01", Ip = "192.168.1.20", Name = "tv", Approved = true } });
        Check("device list survives a save and load", Store.Load<List<DeviceRecord>>(Store.DevicesPath)[0].Name == "tv");
    }

    static void SecretsAreEncrypted()
    {
        string stored = Secrets.Protect("s3cret-token");
        Check("secrets are not stored as plain text and decrypt again", Secrets.Unprotect(stored) == "s3cret-token" && !stored.Contains("s3cret"));
        Check("a damaged or empty secret reads as empty, not a crash", Secrets.Unprotect("not base64!!") == "" && Secrets.Protect("") == "" && Secrets.Unprotect("") == "");
    }

    static void AntivirusDecoding()
    {
        Check("Defender on and current is read as active", Antivirus.Decode("Windows Defender", 397568).Enabled && Antivirus.Decode("Windows Defender", 397568).UpToDate);
        Check("Defender off is read as inactive", !Antivirus.Decode("Windows Defender", 393472).Enabled);
        Check("an out-of-date product is noticed", Antivirus.Decode("X", 266256).Enabled && !Antivirus.Decode("X", 266256).UpToDate);

        var covered = Antivirus.ToRow(new List<AvProduct> { Antivirus.Decode("Windows Defender", 393472), Antivirus.Decode("Other AV", 266240) });
        Check("another antivirus covering for Defender is not an alert", !covered.IsAlert && covered.Ok && covered.Value.StartsWith("Other AV"));
        var nothing = Antivirus.ToRow(new List<AvProduct> { Antivirus.Decode("Windows Defender", 393472) });
        Check("no active antivirus at all is an alert", nothing.IsAlert && !nothing.Ok);
    }

    static void DetectionRules()
    {
        var found = Detector.Evaluate(new[] {
            Ev(Detector.Security, 4720, "backdoor", "PC", "S-1-5-21-1-2-3-1009"),
            Ev(Detector.Security, 4732, "-", "S-1-5-21-1-2-3-1009", "Administrators", "Builtin", "S-1-5-32-544"),
            Ev(Detector.Security, 4732, "-", "S-1-5-21-1-2-3-1009", "Users", "Builtin", "S-1-5-32-545"),
            Ev(Detector.Security, 1102),
            Ev(Detector.SystemLog, 7045, "EvilSvc", "C:\\Temp\\evil.exe", "user mode service", "auto start", "LocalSystem"),
            Ev(Detector.Security, 4624, "", "", "", "", "", "ty", "", "", "10", "", "", "", "", "", "", "", "", "", "192.168.1.50"),
            Ev(Detector.Security, 4624, "", "", "", "", "", "ty", "", "", "2"),
            Ev(Detector.Defender, 1116, "", "", "", "", "", "", "", "Trojan:Win32/Test"),
            Ev(Detector.Defender, 5001),
            Ev(Detector.Security, 9999) });

        Check("7 of 10 sample events raise a detection", found.Count == 7);
        Check("new user account -> T1136.001, high", found.Any(e => e.Technique == "T1136.001" && e.Msg.Contains("backdoor") && e.Severity == "high"));
        Check("only an add to Administrators fires T1098", found.Count(e => e.Technique == "T1098") == 1);
        Check("new service -> T1543.003, medium", found.Any(e => e.Technique == "T1543.003" && e.Severity == "medium" && e.Msg.Contains("EvilSvc")));
        Check("remote desktop logon -> T1021.001, info, with the source address", found.Any(e => e.Technique == "T1021.001" && e.Severity == "info" && e.Msg.Contains("192.168.1.50")));
        Check("log cleared -> T1070.001 and protection disabled -> T1562.001", found.Any(e => e.Technique == "T1070.001") && found.Any(e => e.Technique == "T1562.001"));
        Check("a malware detection is reported with its name", found.Any(e => e.Msg.Contains("Trojan:Win32/Test") && e.Technique == null));

        int read, denied;
        var source = new FakeEvents { DenySecurity = true };
        source.Items.Add(Ev(Detector.SystemLog, 104, "ty", "PC", "Application"));
        var partial = Detector.Run(source, DateTime.UtcNow.AddMinutes(-5), null, out read, out denied);
        Check("an unreadable Security log does not stop the other logs", denied == 1 && read == 2 && partial.Count == 1);
    }

    static void CustomRules()
    {
        if (File.Exists(Store.RulesPath)) File.Delete(Store.RulesPath);
        var none = Detector.LoadCustomRules();
        Check("first use writes an example rules file with nothing enabled", none.Count == 0 && File.Exists(Store.RulesPath) && File.ReadAllText(Store.RulesPath).Contains("\"enabled\": false"));

        Store.Save(Store.RulesPath, new List<CustomRule> {
            new CustomRule { Enabled = true, Log = "Security", Id = 4728, Contains = "", Technique = "T1098", Severity = "high", Message = "member added to a global group" },
            new CustomRule { Enabled = true, Log = "System", Id = 7040, Contains = "disabled", Technique = "", Severity = "weird", Message = "service start type changed" },
            new CustomRule { Enabled = false, Log = "System", Id = 1, Message = "off" },
            new CustomRule { Enabled = true, Log = "", Id = 5, Message = "no log" },
            new CustomRule { Enabled = true, Log = "Security", Id = 4720, Severity = "info", Message = "second opinion on new accounts" } });
        var rules = Detector.LoadCustomRules();
        Check("only complete, enabled custom rules are loaded", rules.Count == 3);

        int read, denied;
        var source = new FakeEvents();
        source.Items.Add(Ev("Security", 4728, "bob", "S-1-5-21-9", "Domain Admins"));
        source.Items.Add(Ev("System", 7040, "Windows Update", "auto start", "disabled"));
        source.Items.Add(Ev("System", 7040, "Print Spooler", "demand start", "auto start"));
        source.Items.Add(Ev("Security", 4720, "newguy"));
        var found = Detector.Run(source, DateTime.UtcNow.AddMinutes(-5), rules, out read, out denied);
        Check("a custom rule fires with its own technique and severity", found.Any(e => e.Technique == "T1098" && e.Severity == "high" && e.Msg.StartsWith("member added to a global group: bob")));
        Check("the 'contains' filter keeps unrelated events out", found.Count(e => e.Msg.StartsWith("service start type changed")) == 1);
        Check("an unknown severity falls back to medium", found.First(e => e.Msg.StartsWith("service start type changed")).Severity == "medium");
        Check("built-in and custom rules can both match one event", found.Count(e => e.Msg.Contains("newguy")) == 2);
    }

    static void AccountWatch()
    {
        Check("an Administrators member is read out of the Windows path", Accounts.ParseMemberName("\\\\PC\\root\\cimv2:Win32_UserAccount.Domain=\"PC\",Name=\"ty\"") == "PC\\ty" && Accounts.ParseMemberName("junk") == "" && Accounts.ParseMemberName(null) == "");

        var before = new List<string> { "user|ty", "user|Guest", "admin|PC\\ty" };
        var after = new List<string> { "user|ty", "user|backdoor", "admin|PC\\ty", "admin|PC\\backdoor" };
        var changes = Accounts.Diff(after, before, DateTime.Now);
        Check("a new local account is a high detection tagged T1136.001", changes.Any(e => e.Severity == "high" && e.Technique == "T1136.001" && e.Msg == "new local user account: backdoor"));
        Check("a new Administrators member is a high detection tagged T1098", changes.Any(e => e.Severity == "high" && e.Technique == "T1098" && e.Msg == "account added to Administrators: PC\\backdoor"));
        Check("a removed account is logged quietly", changes.Count == 3 && changes.Any(e => e.Severity == "info" && e.Msg == "local user account removed: Guest"));
        Check("no change means no events, whatever the letter case", Accounts.Diff(new List<string> { "USER|TY" }, new List<string> { "user|ty" }, DateTime.Now).Count == 0);

        var fromLog = new EventEntry { Technique = "T1136.001", Severity = "high", Msg = "new local user account created: backdoor" };
        var fromWatch = changes.First(e => e.Technique == "T1136.001");
        Check("the same new account seen two ways is only reported once", Accounts.IsRepeat(fromWatch, new[] { fromLog }) && Accounts.IsRepeat(fromLog, new[] { fromWatch })
            && !Accounts.IsRepeat(fromWatch, new[] { new EventEntry { Technique = "T1136.001", Msg = "new local user account created: someoneelse" } })
            && !Accounts.IsRepeat(new EventEntry { Technique = "T1070.001", Msg = "x: backdoor" }, new[] { fromLog }));
    }

    static void AutorunBaseline()
    {
        var current = new List<AutorunItem> {
            new AutorunItem { Kind = "run", Name = "HKCU\\Chat", Command = "a.exe" },
            new AutorunItem { Kind = "run", Name = "HKCU\\Chat2", Command = "evil.exe" },
            new AutorunItem { Kind = "service", Name = "WinDefend", Command = "C:\\x\\4.18.2\\MsMpEng.exe" },
            new AutorunItem { Kind = "task", Name = "\\Updater", Command = "" } };
        var fresh = Autoruns.MarkNew(current, new[] { "run|HKCU\\Chat|a.exe", "service|windefend", "task|\\Updater" });
        Check("only the unknown Run entry is flagged; a service whose path changed is not", fresh.Count == 1 && fresh[0].Name == "HKCU\\Chat2");
        Check("a Run entry whose command changed is flagged", Autoruns.MarkNew(new List<AutorunItem> { new AutorunItem { Kind = "run", Name = "HKCU\\Chat", Command = "other.exe" } }, new[] { "run|HKCU\\Chat|a.exe" }).Count == 1);
    }

    static void Syslog()
    {
        var m = SyslogServer.Parse(Encoding.UTF8.GetBytes("<38>Nov 18 04:40:01 pve sshd[991]: Failed password for root from 10.0.0.9 port 4242 ssh2\n"), "192.168.1.9", DateTime.Now);
        Check("a syslog line is split into severity and text", m != null && m.Severity == 6 && m.Text.StartsWith("Nov 18") && m.Source == "192.168.1.9" && !m.Text.Contains("\n"));
        Check("lines without a priority, and empty packets, are handled", SyslogServer.Parse(Encoding.UTF8.GetBytes("plain line"), "h", DateTime.Now).Text == "plain line" && SyslogServer.Parse(new byte[0], "h", DateTime.Now) == null);

        var rule = new SyslogAuthRule();
        EventEntry hit = null; int alerts = 0; DateTime start = DateTime.Now;
        for (int i = 0; i < 12; i++)
        {
            var a = rule.Check(new SyslogMessage { Time = start.AddSeconds(i), Source = "pve", Text = "pam_unix(sshd:auth): authentication failure; rhost=10.0.0.9" });
            if (a != null) { alerts++; hit = a; }
        }
        Check("a burst of login failures raises exactly one T1110 alert", alerts == 1 && hit.Technique == "T1110" && hit.Severity == "high");
        Check("ordinary lines never alert", rule.Check(new SyslogMessage { Time = start, Source = "pve", Text = "session opened for user root" }) == null);

        var server = new SyslogServer(); string error; SyslogMessage got = null;
        server.Received += x => got = x;
        bool listening = server.Start(15514, true, out error);
        using (var udp = new System.Net.Sockets.UdpClient())
        {
            byte[] data = Encoding.UTF8.GetBytes("<11>test: error line");
            udp.Send(data, data.Length, "127.0.0.1", 15514);
        }
        for (int i = 0; i < 60 && got == null; i++) Thread.Sleep(50);
        server.Stop();
        Check("the listener receives a real UDP packet", listening && got != null && got.Severity == 3 && got.Text == "test: error line");
    }

    static void DiscordSafety()
    {
        Check("real Discord webhook addresses are accepted", Discord.IsValidWebhook("https://discord.com/api/webhooks/123/abc") && Discord.IsValidWebhook("https://ptb.discord.com/api/webhooks/1/x"));
        Check("look-alike and non-https addresses are refused", !Discord.IsValidWebhook("http://discord.com/api/webhooks/1/x") && !Discord.IsValidWebhook("https://evil.example/api/webhooks/1/x")
            && !Discord.IsValidWebhook("https://discord.com.evil.example/api/webhooks/1/x") && !Discord.IsValidWebhook("https://discord.com/other") && !Discord.IsValidWebhook(""));
        Check("alert text is escaped before it goes into JSON", Discord.JsonEscape("a\"b\\c\nd\te") == "a\\\"b\\\\c\\nd e");
        string error;
        Check("sending to a non-Discord address is refused before any network use", !Discord.Send("https://example.com/x", "hi", out error) && error.Length > 0);
    }

    static void PortScanGuard()
    {
        Check("private addresses are recognised", PortScanner.IsPrivateAddress("192.168.1.20") && PortScanner.IsPrivateAddress("10.1.2.3") && PortScanner.IsPrivateAddress("172.20.0.1"));
        Check("public addresses and names are not", !PortScanner.IsPrivateAddress("8.8.8.8") && !PortScanner.IsPrivateAddress("172.32.0.1") && !PortScanner.IsPrivateAddress("example.com"));
        bool refused = false;
        try { PortScanner.ScanAsync("8.8.8.8", 100).Wait(); } catch { refused = true; }
        Check("a port check of a public address is refused", refused);
        Check("results are worded for the device row", PortScanner.Describe(new List<PortHit> { new PortHit { Port = 22, Service = "SSH" }, new PortHit { Port = 443, Service = "HTTPS" } }) == "open: 22 SSH, 443 HTTPS" && PortScanner.Describe(new List<PortHit>()) == "no common ports open");
    }

    static ProxmoxSnapshot SampleProxmox()
    {
        var snapshot = new ProxmoxSnapshot();
        Proxmox.Parse(snapshot,
            "{\"data\":[{\"node\":\"pve\",\"status\":\"online\",\"cpu\":0.1234,\"maxcpu\":8,\"mem\":8589934592,\"maxmem\":34359738368,\"uptime\":123456}]}",
            "{\"data\":[{\"vmid\":101,\"name\":\"web\",\"type\":\"qemu\",\"status\":\"running\",\"cpu\":0.05,\"mem\":1073741824,\"maxmem\":4294967296,\"node\":\"pve\"},{\"vmid\":100,\"name\":\"lab\",\"type\":\"lxc\",\"status\":\"stopped\",\"cpu\":0,\"mem\":0,\"maxmem\":2147483648}]}");
        return snapshot;
    }

    static void ProxmoxParsing()
    {
        var snapshot = SampleProxmox();
        Check("node load is summarised", snapshot.Summary == "pve online cpu 12% mem 25%");
        Check("guests are listed in id order with type, state and load", snapshot.Guests.Count == 2 && snapshot.Guests[0].Id == "100" && snapshot.Guests[0].Kind == "CT" && !snapshot.Guests[0].Running && snapshot.Guests[1].Cpu == "5%" && snapshot.Guests[1].Memory == "25%");
        Check("with no host or token, nothing is contacted", !Proxmox.Fetch(new AppConfig(), "").Configured);
    }

    static void HistoryMath()
    {
        DateTime now = new DateTime(2026, 11, 18, 4, 40, 0);
        var point = new HistoryPoint { Time = now.AddMinutes(-5), Online = 8, Unknown = 1, Elevated = true, HighEvents = 2 };
        point.Hosts["example.org"] = true; point.Hosts["PROXMOX API"] = false;
        var back = History.FromLine(History.ToLine(point));
        Check("a history line survives a save and load", back != null && back.Online == 8 && back.Elevated && back.HighEvents == 2 && back.Hosts["example.org"] && !back.Hosts["PROXMOX API"]);
        Check("a damaged history line is skipped", History.FromLine("garbage") == null && History.FromLine("") == null);

        var points = new List<HistoryPoint> { point,
            new HistoryPoint { Time = now.AddMinutes(-20), Online = 9, HighEvents = 1 },
            new HistoryPoint { Time = now.AddHours(-3).AddMinutes(-1), Online = 5 },
            new HistoryPoint { Time = now.AddHours(-30), Online = 99 } };
        points[1].Hosts["example.org"] = true; points[2].Hosts["example.org"] = false;
        double[] online = History.Hourly(points, now, 24, p => p.Online, false);
        double[] alerts = History.Hourly(points, now, 24, p => p.HighEvents, true);
        Check("hourly buckets take the peak, add up alerts, leave gaps, and drop old data", online[23] == 9 && online[20] == 5 && online[22] == -1 && alerts[23] == 3 && !online.Contains(99));
        Check("uptime is the share of scans a host answered", History.Uptime(points.Take(3))["example.org"] == 67 && History.Uptime(points.Take(3))["PROXMOX API"] == 0);
    }

    static void SettingsParsing()
    {
        var hosts = MainViewModel.ParseHosts("site, example.org, 443, tls\r\nnas, 192.168.1.5, 22, plain\r\n\r\nexample.net\r\nbad, , 99999");
        Check("watched hosts are read one per line with sensible defaults", hosts.Count == 4 && hosts[1].Port == 22 && !hosts[1].Tls && hosts[2].Host == "example.net" && hosts[2].Tls && hosts[2].Port == 443 && hosts[3].Port == 443);
        Check("the hosts box shows what it will read back", MainViewModel.ParseHosts(MainViewModel.FormatHosts(hosts)).Count == 4);
        Check("timestamps are shortened for the lists", MainViewModel.ShortTime("2026-11-18T03:41:07") == "11-18 03:41");
    }

    static void GatewayAndDns()
    {
        var gateway = typeof(Scanner).GetMethod("CheckGateway", BindingFlags.NonPublic | BindingFlags.Static);
        var events = new List<EventEntry>();
        object[] a1 = { "AA-BB-CC-11-22-33", false, events, DateTime.Now, false, "", false }; var g1 = (CheckRow)gateway.Invoke(null, a1);
        object[] a2 = { "DE-AD-BE-EF-00-01", false, events, DateTime.Now, false, a1[5], false }; var g2 = (CheckRow)gateway.Invoke(null, a2);
        object[] a3 = { "DE-AD-BE-EF-00-01", false, events, DateTime.Now, true, a2[5], false }; var g3 = (CheckRow)gateway.Invoke(null, a3);
        object[] a4 = { "DE-AD-BE-EF-00-01", true, events, DateTime.Now, true, a3[5], false }; var g4 = (CheckRow)gateway.Invoke(null, a4);
        Check("the first gateway MAC seen is trusted", !g1.IsAlert && (string)a1[5] == "AA-BB-CC-11-22-33");
        Check("a changed gateway MAC alerts once, tagged T1557.002, and stays flagged", g2.IsAlert && (bool)a2[6] && g3.IsAlert && events.Count(e => e.Technique == "T1557.002") == 1);
        Check("approving trusts the new gateway MAC", !g4.IsAlert && (string)a4[5] == "DE-AD-BE-EF-00-01" && !(bool)a4[6]);

        var dns = typeof(Scanner).GetMethod("CheckDns", BindingFlags.NonPublic | BindingFlags.Static);
        var trusted = new List<string>(); var dnsEvents = new List<EventEntry>();
        object[] d1 = { "192.168.1.1", false, dnsEvents, DateTime.Now, false, trusted, false }; var r1 = (CheckRow)dns.Invoke(null, d1);
        int trustedAfterFirst = trusted.Count;
        object[] d2 = { "6.6.6.6, 7.7.7.7", false, dnsEvents, DateTime.Now, false, trusted, false }; var r2 = (CheckRow)dns.Invoke(null, d2);
        object[] d3 = { "6.6.6.6, 7.7.7.7", true, dnsEvents, DateTime.Now, true, trusted, false }; var r3 = (CheckRow)dns.Invoke(null, d3);
        object[] d4 = { "192.168.1.1", false, dnsEvents, DateTime.Now, false, trusted, false }; var r4 = (CheckRow)dns.Invoke(null, d4);
        Check("the first DNS setting seen is trusted", !r1.IsAlert && r1.Value == "192.168.1.1" && trustedAfterFirst == 1);
        Check("a changed DNS setting alerts, tagged T1557", r2.IsAlert && (bool)d2[6] && dnsEvents.Count(e => e.Technique == "T1557") == 1);
        Check("approving adds it as a second trusted setting, so switching back and forth is quiet", !r3.IsAlert && trusted.Count == 2 && !r4.IsAlert && r3.Value == "6.6.6.6 +1");
    }

    const string NetshNetworks = "\r\nInterface name : Wi-Fi \r\nThere are 3 networks currently visible.\r\n\r\nSSID 1 : HomeNet\r\n    Network type            : Infrastructure\r\n    Authentication          : WPA2-Personal\r\n    Encryption              : CCMP \r\n    BSSID 1                 : aa:bb:cc:dd:ee:01\r\n         Signal             : 80%  \r\n         Radio type         : 802.11ax\r\n         Channel            : 44 \r\n    BSSID 2                 : aa:bb:cc:dd:ee:02\r\n         Signal             : 62%  \r\n\r\nSSID 2 : Neighbour\r\n    Network type            : Infrastructure\r\n    BSSID 1                 : 11:22:33:44:55:66\r\n\r\nSSID 3 : \r\n    BSSID 1                 : 99:88:77:66:55:44\r\n";

    static void WifiTwins()
    {
        var networks = Wifi.ParseNetworks(NetshNetworks);
        Check("netsh output is read into names and access points", networks.Count == 3 && networks["HomeNet"].Count == 2 && networks["HomeNet"][0] == "AA-BB-CC-DD-EE-01" && networks["Neighbour"].Count == 1 && networks[""].Count == 1);
        Check("the connected network name is read (and not confused with BSSID)", Wifi.ParseConnectedName("    Name                   : Wi-Fi\r\n    State                  : connected\r\n    SSID                   : HomeNet\r\n    AP BSSID               : aa:bb:cc:dd:ee:01\r\n") == "HomeNet" && Wifi.ParseConnectedName("There is no wireless interface on the system.") == "");

        if (File.Exists(Store.BssidsPath)) File.Delete(Store.BssidsPath);
        var scan = new WifiScan { Available = true, ConnectedName = "HomeNet", Networks = networks };
        var events = new List<EventEntry>(); List<string> stillNew;
        var first = Scanner.EvaluateWifi("", scan, false, events, DateTime.Now, new List<string>(), out stillNew);
        Check("the access points seen first become the baseline", !first.IsAlert && first.Value == "2 known | 0 new" && events.Any(e => e.Type == "baseline"));

        networks["HomeNet"].Add("DE-AD-BE-EF-00-99");
        events.Clear();
        var twin = Scanner.EvaluateWifi("", scan, false, events, DateTime.Now, new List<string>(), out stillNew);
        Check("a new access point using the home name alerts, tagged T1557.004", twin.IsAlert && twin.Value == "2 known | 1 new" && events.Count(e => e.Technique == "T1557.004" && e.Msg.Contains("DE-AD-BE-EF-00-99")) == 1 && stillNew.Count == 1);

        events.Clear();
        var again = Scanner.EvaluateWifi("", scan, false, events, DateTime.Now, stillNew, out stillNew);
        Check("it stays flagged but is not reported twice", again.IsAlert && events.Count == 0);
        var approved = Scanner.EvaluateWifi("", scan, true, events, DateTime.Now, stillNew, out stillNew);
        Check("approving adds it to the known access points", !approved.IsAlert && approved.Value == "3 known | 0 new");
        Check("a neighbour's network never matters", !Scanner.EvaluateWifi("HomeNet", new WifiScan { Available = true, Networks = new Dictionary<string, List<string>> { { "Neighbour", new List<string> { "11-22-33-44-55-66" } } } }, false, events, DateTime.Now, new List<string>(), out stillNew).IsAlert);
    }

    static void RouterForwards()
    {
        const string description = "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>";
        string control, service;
        Check("the router's port-mapping service is found in its description", Upnp.ParseDescription(description, "http://192.168.1.1:5000/rootDesc.xml", out control, out service) && control == "http://192.168.1.1:5000/ctl/IPConn" && service.EndsWith("WANIPConnection:1"));
        Check("a description pointing outside the local network is refused", !Upnp.ParseDescription(description.Replace("/ctl/IPConn", "http://203.0.113.9/ctl"), "http://192.168.1.1:5000/rootDesc.xml", out control, out service));
        Check("only http LOCATION headers are accepted", Upnp.ParseLocation("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n") == "http://192.168.1.1:5000/rootDesc.xml" && Upnp.ParseLocation("HTTP/1.1 200 OK\r\nLOCATION: file:///c:/x\r\n") == null);

        const string mapping = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:GetGenericPortMappingEntryResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>25565</NewExternalPort><NewProtocol>tcp</NewProtocol><NewInternalPort>25565</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Game server</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>";
        var forward = Upnp.ParseMapping(mapping);
        Check("a port mapping is read", forward != null && forward.ExternalPort == 25565 && forward.Protocol == "TCP" && forward.InternalClient == "192.168.1.50" && forward.Summary == "TCP 25565 -> 192.168.1.50:25565 (Game server)");
        Check("an answer with no mapping ends the list", Upnp.ParseMapping("<x/>") == null && Upnp.ParseMapping("not xml") == null);

        if (File.Exists(Store.ForwardsPath)) File.Delete(Store.ForwardsPath);
        var router = new RouterSnapshot { Found = true };
        router.Forwards.Add(forward);
        var events = new List<EventEntry>();
        var first = Scanner.EvaluateForwards(router, false, events, DateTime.Now, new List<string>());
        Check("forwards present on first sight become the baseline", !first.IsAlert && first.Value == "1 | 0 new");

        router.Forwards.Add(new ForwardInfo { ExternalPort = 3389, InternalPort = 3389, Protocol = "TCP", InternalClient = "192.168.1.50", Description = "" });
        events.Clear();
        var opened = Scanner.EvaluateForwards(router, false, events, DateTime.Now, new List<string>());
        Check("a forward that appears later alerts and is marked new", opened.IsAlert && opened.Value == "2 | 1 new" && router.Forwards[1].IsNew && events.Any(e => e.Severity == "high" && e.Msg.Contains("TCP 3389 -> 192.168.1.50:3389")));
    }

    static void SingleItemApprovals()
    {
        var scanner = new Scanner();
        Store.Save(Store.PortsPath, new List<int> { 80, 443 });
        scanner.ApprovePort(8080); scanner.ApprovePort(8080);
        Check("approving one port adds it to the baseline once", Store.Load<List<int>>(Store.PortsPath).SequenceEqual(new[] { 80, 443, 8080 }));

        Store.Save(Store.AutorunsPath, new List<string> { "run|HKCU\\Chat|a.exe" });
        scanner.ApproveAutorun("task|\\Updater");
        Check("approving one autorun adds it to the baseline", Store.Load<List<string>>(Store.AutorunsPath).Count == 2);

        scanner.ApproveForward("TCP|3389|192.168.1.50|3389");
        Check("approving one router forward adds it to the baseline", Store.Load<List<string>>(Store.ForwardsPath).Contains("TCP|3389|192.168.1.50|3389"));

        var state = AppState.CreateDefault();
        state.OpenItems.Add(new EventEntry { Ts = "2026-11-18T04:00:00", Msg = "one", Severity = "high" });
        state.OpenItems.Add(new EventEntry { Ts = "2026-11-18T04:01:00", Msg = "two", Severity = "high" });
        Store.Save(Store.StatePath, state);
        bool dismissed = scanner.DismissDetection("2026-11-18T04:00:00", "one");
        bool missing = scanner.DismissDetection("2026-11-18T04:00:00", "one");
        var after = Store.Load<AppState>(Store.StatePath);
        Check("dismissing one detection leaves the others open", dismissed && !missing && after.OpenItems.Count == 1 && after.OpenItems[0].Msg == "two");
    }

    static void DenyRemovesAutoruns()
    {
        Microsoft.Win32.RegistryHive hive; Microsoft.Win32.RegistryView view; string path, valueName;
        Check("a Run entry's name says which registry key it lives in",
            Autoruns.ParseRunName("HKCU\\Chat", out hive, out view, out path, out valueName) && hive == Microsoft.Win32.RegistryHive.CurrentUser && valueName == "Chat" && path.EndsWith("\\Run")
            && Autoruns.ParseRunName("HKLM once\\Up\\date", out hive, out view, out path, out valueName) && hive == Microsoft.Win32.RegistryHive.LocalMachine && path.EndsWith("RunOnce") && valueName == "Up\\date"
            && Autoruns.ParseRunName("HKLM 32\\X", out hive, out view, out path, out valueName) && view == Microsoft.Win32.RegistryView.Registry32);
        Check("a name that is not a Run entry is refused", !Autoruns.ParseRunName("Nonsense", out hive, out view, out path, out valueName) && !Autoruns.ParseRunName("HKXX\\Y", out hive, out view, out path, out valueName) && !Autoruns.ParseRunName(null, out hive, out view, out path, out valueName));

        string startupFile = Path.Combine(Store.Dir, "evil-shortcut.lnk");
        File.WriteAllText(startupFile, "x");
        string message;
        bool removed = Autoruns.Remove(new AutorunItem { Kind = "startup", Name = "evil-shortcut.lnk", Command = startupFile }, out message);
        Check("denying a startup file moves it out and keeps a copy", removed && !File.Exists(startupFile)
            && Directory.GetFiles(Store.QuarantineDir, "*evil-shortcut.lnk").Length == 1 && File.ReadAllText(Store.RemovedLogPath).Contains("evil-shortcut.lnk"));
        Check("denying something already gone is not an error", Autoruns.Remove(new AutorunItem { Kind = "startup", Name = "gone.lnk", Command = Path.Combine(Store.Dir, "gone.lnk") }, out message) && message == "it was already gone");
        Check("services are not touched, and you are told how to do it as administrator", !Autoruns.Remove(new AutorunItem { Kind = "service", Name = "EvilSvc", Command = "x.exe" }, out message) && message.Contains("sc config \"EvilSvc\" start= disabled"));
        Check("an unknown kind is refused", !Autoruns.Remove(new AutorunItem { Kind = "mystery", Name = "x" }, out message) && !Autoruns.Remove(null, out message));

        if (Path.DirectorySeparatorChar == '\\')
        {
            // Windows only, on a scratch key of its own (never the real Run key).
            const string scratch = "Software\\SecHUD-Tests";
            using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(scratch)) key.SetValue("ToRemove", "notepad.exe");
            bool deleted = Autoruns.DeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Default, scratch, "ToRemove");
            bool again = Autoruns.DeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Default, scratch, "ToRemove");
            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(scratch, false);
            Check("a registry value is deleted once, and reported as gone the second time", deleted && !again);
        }

        var vm = new MainViewModel();
        string stillThere = Path.Combine(Store.Dir, "keep-me.lnk");
        File.WriteAllText(stillThere, "x");
        var row = new AutorunViewModel(vm) { RawKind = "startup", Kind = "STARTUP", Name = "keep-me.lnk", Command = stillThere, IsNew = true };
        vm.DenyAutorun(row);                 // no window attached, so nobody can say yes
        vm.Confirm = question => false;      // the user says no
        vm.DenyAutorun(row);
        Check("nothing is removed unless you answer yes", File.Exists(stillThere) && row.IsNew);
    }

    static ScanResult SampleResult()
    {
        var result = new ScanResult { Time = DateTime.Now, Config = new AppConfig(), Level = "ELEVATED", Elevated = true, Ticker = "04:40 new device 192.168.1.47" };
        result.PcRows.Add(new CheckRow("ANTIVIRUS", "Defender | sigs 3h", false, true));
        result.PcRows.Add(new CheckRow("DETECTIONS", "1 open", true, false));
        result.NetRows.Add(new CheckRow("LAN DEVICES", "3 | 1 unknown", true, false));
        result.Devices.Add(new DeviceRecord { Mac = "AA-BB-CC-00-00-01", Ip = "192.168.1.20", Name = "tv", Approved = true, Online = true, LastSeen = "2026-11-18T04:39:00" });
        result.Devices.Add(new DeviceRecord { Mac = "AA-BB-CC-00-00-03", Ip = "192.168.1.3", Name = "nas", Approved = true, Online = false, LastSeen = "2026-11-18T03:00:00" });
        result.Devices.Add(new DeviceRecord { Mac = "AA-BB-CC-00-00-02", Ip = "192.168.1.47", Name = "", Approved = false, Online = true, LastSeen = "2026-11-18T04:39:00" });
        result.Ports.Add(new PortInfo { Port = 445, Process = "System", IsNew = false });
        result.Ports.Add(new PortInfo { Port = 4444, Process = "nc", IsNew = true });
        result.Autoruns.Add(new AutorunItem { Kind = "run", Name = "HKCU\\<script>x", Command = "evil.exe \"&\"", Technique = "T1547.001", IsNew = true });
        result.Autoruns.Add(new AutorunItem { Kind = "service", Name = "Spooler", Command = "spoolsv.exe" });
        var detection = new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "detection", Severity = "high", Msg = "new local user account created: backdoor", Technique = "T1136.001" };
        result.NewEvents.Add(new EventEntry { Ts = DateTime.Now.ToString("s"), Type = "level", Severity = "info", Msg = "status changed NOMINAL -> ELEVATED" });
        result.NewEvents.Add(detection);
        result.OpenDetections.Add(detection);
        result.Proxmox = SampleProxmox(); result.Proxmox.Configured = true; result.Proxmox.Ok = true;
        result.Router = new RouterSnapshot { Found = true, ExternalIp = "203.0.113.7" };
        result.Router.Forwards.Add(new ForwardInfo { ExternalPort = 3389, InternalPort = 3389, Protocol = "TCP", InternalClient = "192.168.1.50", IsNew = true });
        result.CustomRuleCount = 2;
        return result;
    }

    static void ReportExport()
    {
        var result = SampleResult();
        string html = Report.Build(result, result.NewEvents);
        Check("the report shows status, devices and ATT&CK links", html.Contains("ELEVATED") && html.Contains("192.168.1.47") && html.Contains("attack.mitre.org/techniques/T1136/001/"));
        Check("text from the system is escaped in the report", html.Contains("&lt;script&gt;x") && !html.Contains("<script>x"));
        Check("the router's public address is left out of the report", !html.Contains("203.0.113.7"));
        Check("technique ids are cleaned before they go into a link", Report.TechniqueLink("T1547.001\"><b>") == "<a href=\"https://attack.mitre.org/techniques/T1547/001b/\">T1547.001b</a>" && Report.TechniqueLink("") == "");
    }

    static void UpdateCheck()
    {
        Version v;
        Check("release tags are read as versions", Updater.TryParseVersion("v0.7.0", out v) && v == new Version(0, 7, 0) && Updater.TryParseVersion("V1.2.3-beta", out v) && v == new Version(1, 2, 3) && Updater.TryParseVersion("2", out v) && v == new Version(2, 0, 0));
        Check("a tag with no numbers is not a version", !Updater.TryParseVersion("latest", out v) && !Updater.TryParseVersion("", out v) && !Updater.TryParseVersion(null, out v));
        Check("0.6 and 0.6.0.0 count as the same version", Updater.Normalize(new Version(0, 6)) == Updater.Normalize(new Version(0, 6, 0, 0)));

        var current = new Version(0, 6, 0, 0);
        const string page = "https://github.com/sivadyt/SecHUD/releases/tag/v0.7.0";
        string json = "{\"tag_name\":\"v0.7.0\",\"name\":\"0.7.0\",\"html_url\":\"" + page + "\",\"body\":\"Added the thing.\\r\\nFixed the other thing.\",\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"SecHUD-v0.7.0.zip\"}]}";
        UpdateInfo info = Updater.ParseRelease(json, current);
        Check("a newer release is offered with its notes and page", info != null && info.Version == "0.7.0" && info.Url == page && info.Notes.StartsWith("Added the thing."));
        Check("the same or an older release is not offered", Updater.ParseRelease(json.Replace("v0.7.0", "v0.6.0"), current) == null && Updater.ParseRelease(json.Replace("v0.7.0", "v0.5.9"), current) == null);
        Check("drafts and pre-releases are not offered", Updater.ParseRelease(json.Replace("\"draft\":false", "\"draft\":true"), current) == null && Updater.ParseRelease(json.Replace("\"prerelease\":false", "\"prerelease\":true"), current) == null);
        Check("the update button can only open this project's page on github.com", Updater.SafeUrl("https://evil.example/sivadyt/SecHUD/releases") == Updater.ReleasesPage && Updater.SafeUrl("https://github.com/someone-else/SecHUD/releases/tag/v9") == Updater.ReleasesPage
            && Updater.SafeUrl("http://github.com/sivadyt/SecHUD/releases") == Updater.ReleasesPage && Updater.SafeUrl(null) == Updater.ReleasesPage && Updater.SafeUrl(page) == page);

        var vm = new MainViewModel();
        int announced = 0; vm.UpdateFound += x => announced++;
        vm.ApplyUpdate(info); vm.ApplyUpdate(info);
        Check("the window shows the update button and announces a version once", vm.UpdateAvailable && vm.UpdateLabel == "UPDATE AVAILABLE: V0.7.0" && vm.UpdateNotes.Contains("Added the thing.") && announced == 1);
        vm.ApplyUpdate(null);
        Check("with nothing newer the button is hidden", !vm.UpdateAvailable);
    }

    static void ViewModel()
    {
        DateTime now = DateTime.Now;
        History.Append(new HistoryPoint { Time = now.AddMinutes(-3), Online = 3, Unknown = 1, Elevated = true, HighEvents = 1 });

        var vm = new MainViewModel();
        var apply = typeof(MainViewModel).GetMethod("Apply", BindingFlags.NonPublic | BindingFlags.Instance);
        string alert = null; vm.AlertRaised += x => alert = x;
        apply.Invoke(vm, new object[] { SampleResult() });

        Check("the window gets its rows and status", vm.Level == "ELEVATED" && vm.IsElevated && vm.PcRows.Count == 2 && vm.PcRows[0].Label == "ANTIVIRUS" && vm.NetRows.Count == 1);
        Check("unknown devices are listed first, then by address", vm.Devices[0].Ip == "192.168.1.47" && vm.Devices[1].Ip == "192.168.1.3" && vm.Devices[2].Ip == "192.168.1.20");
        Check("device states read UNKNOWN, OFFLINE, ONLINE", vm.Devices[0].Status == "UNKNOWN" && vm.Devices[1].Status == "OFFLINE" && vm.Devices[2].Status == "ONLINE" && vm.DeviceSummary == "DEVICES (3) 1 UNKNOWN");
        Check("new ports, autoruns and forwards are listed first and flagged", vm.Ports[0].Port == 4444 && vm.Ports[0].Flag == "NEW" && vm.Autoruns[0].IsNew && vm.Forwards.Count == 1 && vm.Forwards[0].Flag == "NEW" && vm.Forwards[0].Target == "192.168.1.50:3389");
        Check("Proxmox guests and router status are shown", vm.Guests.Count == 2 && vm.ProxmoxStatus == "PVE ONLINE CPU 12% MEM 25%" && vm.RouterStatus.Contains("203.0.113.7") && vm.RulesInfo.Contains("2 OF YOUR OWN"));
        Check("an alert carries its ATT&CK technique", alert != null && alert.Contains("[T1136.001]"));
        Check("the open detection is marked so it can be dismissed", vm.Events.Count == 2 && vm.Events.Count(e => e.IsOpen) == 1 && vm.Events.First(e => e.IsOpen).Technique == "T1136.001");

        vm.EventFilter = "t1136"; int narrowed = vm.Events.Count; vm.EventFilter = "";
        Check("event search narrows the list and clears again", narrowed == 1 && vm.Events.Count == 2);
        Check("history charts have 24 hourly bars with the latest hour filled in", vm.DeviceBars.Count == 24 && vm.AlertBars.Count == 24 && vm.StatusBars.Count == 24 && vm.StatusBars[23].IsAlert && vm.AlertBars[23].IsAlert && vm.DeviceBars[23].Height >= 2);

        var onSyslog = typeof(MainViewModel).GetMethod("OnSyslogReceived", BindingFlags.NonPublic | BindingFlags.Instance);
        alert = null;
        for (int i = 0; i < 6; i++) onSyslog.Invoke(vm, new object[] { new SyslogMessage { Time = DateTime.Now, Source = "192.168.1.9", Severity = 4, Text = "sshd: Failed password for root" } });
        vm.DrainPending();
        Check("syslog lines appear, and a burst raises an alert and an event", vm.Logs.Count == 6 && alert != null && alert.Contains("T1110") && vm.Events[0].Technique == "T1110");
        vm.LogFilter = "nomatch"; int none = vm.Logs.Count; vm.LogFilter = "FAILED";
        Check("log search works without caring about upper or lower case", none == 0 && vm.Logs.Count == 6);
    }
}

static partial class Tests
{
    static void QuietHours()
    {
        int minutes;
        Check("times are read as 24-hour clock times", Quiet.TryParseTime("23:00", out minutes) && minutes == 1380 && Quiet.TryParseTime(" 7:30 ", out minutes) && minutes == 450 && Quiet.TryParseTime("7", out minutes) && minutes == 420);
        Check("nonsense times are refused", !Quiet.TryParseTime("25:00", out minutes) && !Quiet.TryParseTime("7:99", out minutes) && !Quiet.TryParseTime("soon", out minutes) && !Quiet.TryParseTime("", out minutes) && !Quiet.TryParseTime(null, out minutes) && !Quiet.TryParseTime("-1:00", out minutes));
        Check("a quiet window can run past midnight", Quiet.InWindow(1380, 420, 30) && Quiet.InWindow(1380, 420, 1400) && !Quiet.InWindow(1380, 420, 720) && !Quiet.InWindow(1380, 420, 420));
        Check("a daytime window, and an empty one", Quiet.InWindow(540, 1020, 600) && !Quiet.InWindow(540, 1020, 1200) && !Quiet.InWindow(600, 600, 600));

        var config = AppConfig.CreateDefault();
        var night = new DateTime(2026, 11, 18, 2, 15, 0);
        bool offByDefault = !Quiet.IsQuiet(config, night);
        config.QuietHours = true;
        Check("quiet hours are off until switched on, then follow the clock", offByDefault && Quiet.IsQuiet(config, night) && !Quiet.IsQuiet(config, night.AddHours(10)));
        config.QuietStart = "banana"; config.Normalize();
        Check("a hand-edited time that makes no sense goes back to the default", config.QuietStart == "23:00" && config.QuietEnd == "07:00");

        Check("protection being switched off, new accounts and tampering are urgent",
            Quiet.IsUrgent(new EventEntry { Type = "antivirus" }) && Quiet.IsUrgent(new EventEntry { Type = "firewall" }) && Quiet.IsUrgent(new EventEntry { Type = "gateway" })
            && Quiet.IsUrgent(new EventEntry { Type = "dns" }) && Quiet.IsUrgent(new EventEntry { Type = "wifi" })
            && Quiet.IsUrgent(new EventEntry { Type = "detection", Technique = "T1136.001" }) && Quiet.IsUrgent(new EventEntry { Type = "detection", Technique = "T1070.001" })
            && Quiet.IsUrgent(new EventEntry { Type = "detection", Technique = "", Msg = "Defender detected malware: X" }));
        Check("a new device, port or startup item can wait until morning",
            !Quiet.IsUrgent(new EventEntry { Type = "new-device", Msg = "new device 192.168.1.9" }) && !Quiet.IsUrgent(new EventEntry { Type = "new-port" })
            && !Quiet.IsUrgent(new EventEntry { Type = "new-autorun", Technique = "T1547.001" }) && !Quiet.IsUrgent(new EventEntry { Type = "host" }) && !Quiet.IsUrgent(null));

        var held = Enumerable.Range(1, 15).Select(i => "alert " + i).ToList();
        string digest = Quiet.Digest(held, "PC");
        Check("the morning summary counts everything and lists the first dozen", digest.StartsWith("SecHUD on PC: 15 alerts were held") && digest.Contains("- alert 12") && !digest.Contains("- alert 13") && digest.Contains("and 3 more")
            && Quiet.Digest(new List<string> { "one" }, "PC").Contains("1 alert was held"));
    }

    static void DeviceMakers()
    {
        Check("the maker table is packed into the program", Vendors.Count > 30000);
        Check("well-known makers are recognised from the MAC address", Vendors.Lookup("B8-27-EB-12-34-56").StartsWith("Raspberry Pi") && Vendors.Lookup("00:0c:29:aa:bb:cc") == "VMware" && Vendors.Lookup("F0D2F1000001") == "Amazon");
        Check("an address a phone made up for privacy is labelled, not guessed at", Vendors.IsRandomized("DA-A1-19-00-00-01") && Vendors.Lookup("DA-A1-19-00-00-01") == Vendors.PrivateLabel && Vendors.IsRandomized("02:00:00:00:00:01") && !Vendors.IsRandomized("B8-27-EB-12-34-56") && !Vendors.IsRandomized("00-0C-29-AA-BB-CC"));
        Check("an unknown or broken address gives no maker", Vendors.Lookup("FC-FF-FD-00-00-01") == "" && Vendors.Lookup("junk") == "" && Vendors.Lookup(null) == "" && Vendors.Lookup("") == "");

        var table = new Dictionary<int, string>();
        Vendors.Parse(new StringReader("AABBCC\tAcme\nbad line\n112233\tAcme\nZZZZZZ\tNope\n445566\t\n"), table);
        Check("the maker table skips lines it cannot read", table.Count == 2 && table[0xAABBCC] == "Acme" && ReferenceEquals(table[0xAABBCC], table[0x112233]));
    }

    static Dictionary<string, string> Seen(params string[] macThenIp)
    {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i + 1 < macThenIp.Length; i += 2) found[macThenIp[i]] = macThenIp[i + 1];
        return found;
    }

    static void WatchedDevices()
    {
        const string cam = "B8-27-EB-00-00-01", tv = "AA-BB-CC-00-00-02", pc = "AA-BB-CC-00-00-03";
        Func<string, string> realResolver = Scanner.NameResolver;
        Scanner.NameResolver = ip => "";
        try
        {
            File.Delete(Store.DevicesPath);
            var config = AppConfig.CreateDefault();
            DateTime now = DateTime.Now;
            var events = new List<EventEntry>();
            List<DeviceRecord> devices;

            CheckRow first = Scanner.EvaluateLan(config, Seen(cam, "192.168.1.30", tv, "192.168.1.20", pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("the first sweep becomes the device baseline", first.Value == "3 | 0 unknown" && !first.IsAlert && devices.All(d => d.Approved) && events.Count == 1 && events[0].Type == "baseline" && devices.First(d => d.Mac == pc).Name == Environment.MachineName);

            // Watch the camera, the way the Watch button does.
            devices.First(d => d.Mac == cam).Watched = true;
            devices.First(d => d.Mac == cam).Name = "camera";
            Store.Save(Store.DevicesPath, devices);

            events.Clear();
            CheckRow missedOnce = Scanner.EvaluateLan(config, Seen(tv, "192.168.1.20", pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("one missed sweep is not an alert", !missedOnce.IsAlert && missedOnce.Value == "2 | 0 unknown" && events.Count == 0 && devices.First(d => d.Mac == cam).Missed == 1);

            CheckRow missedTwice = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("a watched device missing twice in a row raises the alert", missedTwice.IsAlert && missedTwice.Value == "1 | 0 unknown | 1 down" && events.Count == 1 && events[0].Severity == "high" && events[0].Type == "device-watch" && events[0].Msg == "watched device camera (192.168.1.30) went offline");
            Check("a device that is not watched can go offline quietly", !events.Any(e => e.Msg.Contains("192.168.1.20")) && devices.First(d => d.Mac == tv).Missed == 1 && !devices.First(d => d.Mac == tv).Down);

            events.Clear();
            CheckRow stillDown = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("the offline alert is raised once, and the row stays flagged", stillDown.IsAlert && events.Count == 0);

            CheckRow noSweep = Scanner.EvaluateLan(config, null, null, null, false, events, now, out devices);
            Check("when this PC is off the network, nothing is counted as missed", noSweep.Value == "no lan | 1 down" && noSweep.IsAlert && devices.First(d => d.Mac == cam).Missed == 3 && events.Count == 0);

            CheckRow back = Scanner.EvaluateLan(config, Seen(cam, "192.168.1.30", pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("when it answers again the row clears and it is logged quietly", !back.IsAlert && back.Value == "2 | 0 unknown" && events.Count == 1 && events[0].Severity == "info" && events[0].Msg == "watched device camera (192.168.1.30) is back online" && !devices.First(d => d.Mac == cam).Down);

            events.Clear();
            config.WatchMisses = 1;
            Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2", "DA-A1-19-00-00-09", "192.168.1.77", "00-0C-29-00-00-09", "192.168.1.78"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("the number of misses allowed is a setting", events.Any(e => e.Type == "device-watch" && e.Severity == "high"));
            Check("a new device alert says who made it", events.Any(e => e.Msg == "new device 192.168.1.78 00-0C-29-00-00-09, made by VMware") && events.Any(e => e.Msg == "new device 192.168.1.77 DA-A1-19-00-00-09, private address (often a phone or tablet)"));

            var reloaded = Store.Load<List<DeviceRecord>>(Store.DevicesPath);
            Check("watch flags are saved with the device list", reloaded.First(d => d.Mac == cam).Watched && reloaded.First(d => d.Mac == cam).Down && !reloaded.First(d => d.Mac == tv).Watched);
            var older = Store.FromJson<List<DeviceRecord>>("[{\"mac\":\"AA-BB-CC-00-00-01\",\"ip\":\"192.168.1.20\",\"name\":\"tv\",\"approved\":true}]");
            Check("a device list from an older version loads with nothing watched", older.Count == 1 && !older[0].Watched && older[0].Missed == 0 && !older[0].Down);
        }
        finally
        {
            Scanner.NameResolver = realResolver;
        }
    }

    static void RestoreDenied()
    {
        if (Directory.Exists(Store.QuarantineDir)) Directory.Delete(Store.QuarantineDir, true);
        Check("with nothing denied the list is empty", Autoruns.LoadRemoved().Count == 0);

        string startupFile = Path.Combine(Store.Dir, "chat-helper.lnk");
        File.WriteAllText(startupFile, "shortcut");
        string message;
        Autoruns.Remove(new AutorunItem { Kind = "startup", Name = "chat-helper.lnk", Command = startupFile }, out message);
        List<RemovedRecord> removed = Autoruns.LoadRemoved();
        Check("a denied item is recorded with where its copy was kept", removed.Count == 1 && removed[0].Kind == "startup" && removed[0].Command == startupFile && File.Exists(removed[0].Backup) && !removed[0].Restored);

        File.WriteAllText(startupFile, "something else took its place");
        bool refused = !Autoruns.Restore(removed[0], out message);
        Check("restore never overwrites a file that is already there", refused && message.Contains("already") && File.ReadAllText(startupFile).StartsWith("something else") && File.Exists(removed[0].Backup));
        File.Delete(startupFile);

        bool restored = Autoruns.Restore(removed[0], out message);
        Check("restore puts the startup file back where it was", restored && File.ReadAllText(startupFile) == "shortcut" && !File.Exists(removed[0].Backup) && message == "moved the startup file back");
        Check("a restored item is marked and its baseline key is known", Autoruns.LoadRemoved()[0].Restored && Autoruns.KeyAfterRestore(removed[0]) == "startup|chat-helper.lnk");
        Check("restoring twice fails cleanly", !Autoruns.Restore(removed[0], out message) && message.Contains("no longer"));
        File.Delete(startupFile);

        Check("a Run entry's key matches what the scanner will read back",
            Autoruns.KeyAfterRestore(new RemovedRecord { Kind = "run", Name = "HKCU\\Chat", Command = "C:\\chat.exe --tray", ValueKind = "String" }) == "run|HKCU\\Chat|C:\\chat.exe --tray"
            && Autoruns.KeyAfterRestore(new RemovedRecord { Kind = "task", Name = "\\Updater" }) == "task|\\Updater" && Autoruns.KeyAfterRestore(null) == "");
        Check("services and unknown kinds cannot be restored from here", !Autoruns.Restore(new RemovedRecord { Kind = "service", Name = "X" }, out message) && !Autoruns.Restore(null, out message)
            && !Autoruns.Restore(new RemovedRecord { Kind = "run", Name = "Nonsense", Command = "x" }, out message)
            && !Autoruns.Restore(new RemovedRecord { Kind = "task", Name = "\\Bad\"Name", Backup = startupFile }, out message));

        // Items denied by version 0.7 only exist as lines in removed.log.
        RemovedRecord fromLog = Autoruns.ParseLogLine("2026-11-18T05:20:11\tstartup\tevil.lnk\tC:\\Users\\x\\Startup\\evil.lnk\tfile moved to C:\\data\\removed-autoruns\\20261118-052011-evil.lnk");
        RemovedRecord runLine = Autoruns.ParseLogLine("2026-11-18T05:21:00\trun\tHKCU\\SecHUD-LiveTest\tnotepad.exe\tregistry value deleted");
        Check("items denied by the previous version are read from its log", fromLog != null && fromLog.Kind == "startup" && fromLog.Backup.EndsWith("20261118-052011-evil.lnk") && runLine != null && runLine.Name == "HKCU\\SecHUD-LiveTest" && runLine.Command == "notepad.exe" && runLine.Backup == ""
            && Autoruns.ParseLogLine("garbage") == null && Autoruns.ParseLogLine(null) == null && Autoruns.ParseLogLine("2026-11-18T05:21:00\trun\tHKCU\\X\tx\trestored") == null);

        if (Path.DirectorySeparatorChar == '\\')
        {
            const string scratch = "Software\\SecHUD-Tests";
            using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(scratch)) key.SetValue("Expanding", "%WINDIR%\\notepad.exe", Microsoft.Win32.RegistryValueKind.ExpandString);
            string raw, kind;
            bool read = Autoruns.ReadRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Default, scratch, "Expanding", out raw, out kind);
            bool missing = Autoruns.ReadRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Default, scratch, "NotThere", out raw, out kind);
            Autoruns.ReadRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Default, scratch, "Expanding", out raw, out kind);
            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(scratch, false);
            Check("a registry value is recorded exactly as written, variables included", read && !missing && raw == "%WINDIR%\\notepad.exe" && kind == "ExpandString");
        }

        var vm = new MainViewModel();
        File.WriteAllText(startupFile, "shortcut");
        Autoruns.Remove(new AutorunItem { Kind = "startup", Name = "chat-helper.lnk", Command = startupFile }, out message);
        vm.RefreshRemoved();
        bool listed = vm.HasRemoved && vm.Removed.Count == 1 && vm.Removed[0].Kind == "STARTUP" && vm.Removed[0].Name == "chat-helper.lnk";
        vm.Confirm = question => false;
        vm.RestoreAutorun(vm.Removed[0]);
        Check("the window lists what can be put back, and does nothing unless you answer yes", listed && !File.Exists(startupFile) && vm.Removed.Count == 1);
    }

    static void LiveWatchHelpers()
    {
        Check("the port check ignores short-lived high ports and the order they arrive in",
            LiveWatch.PortSignature(new[] { 445, 135, 50123, 445 }, 49151) == "135,445" && LiveWatch.PortSignature(new[] { 135, 445, 61000 }, 49151) == LiveWatch.PortSignature(new[] { 445, 135 }, 49151)
            && LiveWatch.PortSignature(new[] { 135, 445, 4444 }, 49151) != LiveWatch.PortSignature(new[] { 135, 445 }, 49151) && LiveWatch.PortSignature(null, 49151) == "");
        Check("the account check notices an added account whatever the order or case",
            LiveWatch.Signature(new[] { "user|Ty", "admin|PC\\Ty" }) == LiveWatch.Signature(new[] { "admin|pc\\ty", "user|ty", "user|ty" })
            && LiveWatch.Signature(new[] { "user|ty" }) != LiveWatch.Signature(new[] { "user|ty", "user|backdoor" }));
        Check("the event log is asked for exactly the events the rules use", LiveWatch.BuildQuery(new[] { 4732, 4720, 1102 }) == "*[System[(EventID=1102 or EventID=4720 or EventID=4732)]]");

        var watch = new LiveWatch();
        bool offAtFirst = !watch.IsRunning && watch.Summary == "off";
        watch.Stop(); // stopping something that never started is harmless
        Check("the live watch is off until it is started", offAtFirst && !watch.IsRunning);
    }

    static void LiveAndQuietInTheWindow()
    {
        DateTime now = DateTime.Now;
        var vm = new MainViewModel();
        var apply = typeof(MainViewModel).GetMethod("Apply", BindingFlags.NonPublic | BindingFlags.Instance);
        var posted = new List<string>();
        vm.DiscordPoster = (hook, text) => posted.Add(text);
        string tray = null; vm.AlertRaised += x => tray = x;

        ScanResult full = SampleResult();
        full.Sequence = 10;
        full.Devices[0].Mac = "B8-27-EB-00-00-01"; full.Devices[0].Watched = true;
        full.Devices[1].Watched = true; full.Devices[1].Down = true;
        full.Config.DiscordWebhookProtected = Secrets.Protect("https://discord.com/api/webhooks/1/abc");
        full.Config.QuietHours = true;
        full.Config.QuietStart = Quiet.FormatTime(((now.Hour + 23) % 24) * 60);
        full.Config.QuietEnd = Quiet.FormatTime(((now.Hour + 2) % 24) * 60);
        full.NewEvents.Add(new EventEntry { Ts = now.ToString("s"), Type = "new-device", Severity = "high", Msg = "new device 192.168.1.47" });
        apply.Invoke(vm, new object[] { full });

        Check("the device list shows who made each device", vm.Devices.Count(d => d.Maker.StartsWith("RASPBERRY PI")) == 1 && vm.Devices.Count(d => d.Maker == "PRIVATE ADDRESS") == 2);
        Check("a watched device reads WATCHING, and DOWN once it has gone", vm.Devices.First(d => d.Ip == "192.168.1.20").WatchLabel == "WATCHING" && vm.Devices.First(d => d.Ip == "192.168.1.3").Status == "DOWN" && vm.Devices.First(d => d.Ip == "192.168.1.47").WatchLabel == "WATCH");
        Check("the Windows notification names the latest alert and counts the rest", tray != null && tray.Contains("new device 192.168.1.47") && tray.Contains("(+1 more)"));
        Check("in quiet hours an urgent alert is sent and an ordinary one is held", posted.Count == 1 && posted[0].Contains("new local user account created: backdoor [T1136.001]") && !posted[0].Contains("new device") && vm.HeldAlertCount == 1);

        vm.FlushHeldAlerts(now);
        bool stillHeld = posted.Count == 1 && vm.HeldAlertCount == 1;
        full.Config.QuietHours = false;
        vm.FlushHeldAlerts(now);
        Check("when quiet hours end the held alerts arrive as one summary", stillHeld && posted.Count == 2 && posted[1].Contains("1 alert was held during quiet hours") && posted[1].Contains("new device 192.168.1.47") && vm.HeldAlertCount == 0);

        Check("tabs for features that are not in use are hidden", !vm.ShowProxmoxTab && !vm.ShowLogsTab && vm.ShowRouterTab);
        ScanResult withProxmox = SampleResult();
        withProxmox.Sequence = 11; withProxmox.NewEvents.Clear();
        withProxmox.Config.ProxmoxHost = "192.168.1.5"; withProxmox.Config.SyslogEnabled = true; withProxmox.Config.WatchRouter = false;
        withProxmox.Config.DiscordWebhookProtected = full.Config.DiscordWebhookProtected;
        apply.Invoke(vm, new object[] { withProxmox });
        Check("and they appear once the feature is set up", vm.ShowProxmoxTab && vm.ShowLogsTab && !vm.ShowRouterTab);

        // A live check: this PC only. The device list and the scan time belong to the last full scan.
        string scanTime = vm.LastScan;
        int deviceCount = vm.Devices.Count;
        var quick = new ScanResult { Time = now.AddSeconds(5), Config = withProxmox.Config, Level = "ELEVATED", Elevated = true, Ticker = "live", IsQuick = true, Sequence = 12 };
        quick.PcRows.Add(new CheckRow("AUTORUNS", "212 | 1 new", true, false));
        quick.NetRows.Add(new CheckRow("LAN DEVICES", "3 | 1 unknown", true, false));
        quick.Autoruns.Add(new AutorunItem { Kind = "run", Name = "HKCU\\Evil", Command = "evil.exe", IsNew = true });
        quick.NewEvents.Add(new EventEntry { Ts = now.ToString("s"), Type = "new-autorun", Severity = "high", Msg = "new run autorun: HKCU\\Evil", Technique = "T1547.001" });
        tray = null;
        apply.Invoke(vm, new object[] { quick });
        Check("a live check updates this PC's rows and raises its alert straight away", vm.PcRows.Count == 1 && vm.PcRows[0].Value == "212 | 1 NEW" && vm.Autoruns.Count == 1 && tray != null && tray.Contains("[T1547.001]") && posted.Last().Contains("new run autorun: HKCU\\Evil"));
        Check("a live check leaves the device list and the scan time alone", vm.Devices.Count == deviceCount && vm.LastScan == scanTime);

        ScanResult late = SampleResult();
        late.Sequence = 9; late.Level = "NOMINAL"; late.NewEvents.Clear();
        apply.Invoke(vm, new object[] { late });
        Check("a result that arrives late never overwrites a newer one", vm.Level == "ELEVATED" && vm.PcRows[0].Label == "AUTORUNS");

        var config = AppConfig.CreateDefault();
        bool brandNew = MainViewModel.NeedsWelcome(config, false);
        bool upgraded = MainViewModel.NeedsWelcome(config, true);
        config.Welcomed = true;
        Check("the welcome is shown on a first run only, never to someone upgrading", brandNew && !upgraded && !MainViewModel.NeedsWelcome(config, false) && !MainViewModel.NeedsWelcome(null, false));
        var saved = Store.FromJson<AppConfig>(Store.ToJson(AppConfig.CreateDefault()));
        Check("the new settings start with sensible defaults", saved.LiveWatch && saved.WatchMisses == 2 && !saved.QuietHours && saved.QuietStart == "23:00" && !saved.Welcomed);

        // First run: the welcome is shown and nothing is scanned until it is answered.
        File.Delete(Store.DevicesPath);
        File.Delete(Store.ConfigPath);
        var fresh = new MainViewModel();
        fresh.Start();
        Check("on a first run nothing is scanned until the welcome is answered", fresh.ShowWelcome && !fresh.IsScanning && fresh.Level == "WELCOME" && fresh.PcRows.Count == 0);
        fresh.SetDiscordWebhook = "https://example.com/not-discord";
        fresh.FinishWelcomeCommand.Execute(null);
        Check("a bad webhook on the welcome screen is explained, and it stays open", fresh.ShowWelcome && fresh.WelcomeStatus.Contains("NOT A DISCORD WEBHOOK") && !fresh.IsScanning);
        fresh.Shutdown();
    }
}

static partial class Tests
{
    static byte[] FakeProgram(string marker)
    {
        var bytes = new byte[4096];
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        Encoding.ASCII.GetBytes(marker).CopyTo(bytes, 64);
        return bytes;
    }

    static string MakeZip(string path, params object[] nameThenBytes)
    {
        if (File.Exists(path)) File.Delete(path);
        using (var stream = new FileStream(path, FileMode.CreateNew))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create))
        {
            for (int i = 0; i + 1 < nameThenBytes.Length; i += 2)
            {
                ZipArchiveEntry entry = zip.CreateEntry((string)nameThenBytes[i]);
                byte[] content = (byte[])nameThenBytes[i + 1];
                using (Stream output = entry.Open()) output.Write(content, 0, content.Length);
            }
        }
        return path;
    }

    static void UpdateInstall()
    {
        const string baseUrl = "https://github.com/sivadyt/SecHUD/releases/download/v0.9.0/";
        string digest = new string('a', 64);
        string json = "{\"tag_name\":\"v0.9.0\",\"html_url\":\"https://github.com/sivadyt/SecHUD/releases/tag/v0.9.0\",\"body\":\"New things.\",\"draft\":false,\"prerelease\":false,\"assets\":["
            + "{\"name\":\"SecHUD-v0.9.0.sha256.txt\",\"size\":85,\"digest\":\"sha256:" + new string('b', 64) + "\",\"browser_download_url\":\"" + baseUrl + "SecHUD-v0.9.0.sha256.txt\"},"
            + "{\"name\":\"SecHUD-v0.9.0.zip\",\"size\":430666,\"digest\":\"sha256:" + digest + "\",\"browser_download_url\":\"" + baseUrl + "SecHUD-v0.9.0.zip\"}]}";
        UpdateInfo info = Updater.ParseRelease(json, new Version(0, 8, 0));
        Check("a release's zip and checksum are found by their exact names", info != null && info.CanInstall && info.ZipUrl == baseUrl + "SecHUD-v0.9.0.zip" && info.HashUrl == baseUrl + "SecHUD-v0.9.0.sha256.txt" && info.Digest == digest);

        UpdateInfo elsewhere = Updater.ParseRelease(json.Replace("https://github.com/sivadyt/SecHUD/releases/download/", "https://evil.example/sivadyt/SecHUD/releases/download/"), new Version(0, 8, 0));
        UpdateInfo noZip = Updater.ParseRelease(json.Replace("SecHUD-v0.9.0.zip\",\"size", "Something-else.zip\",\"size"), new Version(0, 8, 0));
        UpdateInfo noChecksum = Updater.ParseRelease("{\"tag_name\":\"v0.9.0\",\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"SecHUD-v0.9.0.zip\",\"browser_download_url\":\"" + baseUrl + "SecHUD-v0.9.0.zip\"}]}", new Version(0, 8, 0));
        Check("a download from anywhere but this project's releases is never installed", elsewhere != null && !elsewhere.CanInstall && elsewhere.ZipUrl == "" && noZip != null && !noZip.CanInstall);
        Check("a release with no checksum is not installed by itself", noChecksum != null && noChecksum.ZipUrl.Length > 0 && !noChecksum.CanInstall);
        Check("download addresses are held to this project's release files",
            Updater.SafeDownloadUrl(baseUrl + "SecHUD-v0.9.0.zip") == baseUrl + "SecHUD-v0.9.0.zip"
            && Updater.SafeDownloadUrl("http://github.com/sivadyt/SecHUD/releases/download/v0.9.0/x.zip") == ""
            && Updater.SafeDownloadUrl("https://github.com/someone-else/SecHUD/releases/download/v0.9.0/x.zip") == ""
            && Updater.SafeDownloadUrl("https://github.com.evil.example/sivadyt/SecHUD/releases/download/v0.9.0/x.zip") == ""
            && Updater.SafeDownloadUrl("https://github.com/sivadyt/SecHUD/archive/main.zip") == ""
            && Updater.SafeDownloadUrl("https://user@github.com/sivadyt/SecHUD/releases/download/v0.9.0/x.zip") == ""
            && Updater.SafeDownloadUrl("https://github.com/sivadyt/SecHUD/releases/download/v0.9.0/x.zip?to=elsewhere") == ""
            && Updater.SafeDownloadUrl("https://github.com:8443/sivadyt/SecHUD/releases/download/v0.9.0/x.zip") == ""
            && Updater.SafeDownloadUrl(null) == "" && Updater.SafeDownloadUrl("") == "");

        string upper = new string('A', 60) + "0f9E";
        Check("a checksum file is read whatever its layout", Updater.ParseHash(upper + "  SecHUD-v0.9.0.zip\r\n") == upper.ToLowerInvariant() && Updater.ParseHash(" " + upper + " *file") == upper.ToLowerInvariant()
            && Updater.ParseHash("not a hash") == "" && Updater.ParseHash(new string('a', 63)) == "" && Updater.ParseHash(new string('g', 64)) == "" && Updater.ParseHash(null) == "");

        string scratch = Path.Combine(Store.Dir, "update-test");
        if (Directory.Exists(scratch)) Directory.Delete(scratch, true);
        Directory.CreateDirectory(scratch);
        string abc = Path.Combine(scratch, "abc.txt");
        File.WriteAllText(abc, "abc");
        Check("SHA-256 is computed correctly", Updater.Sha256File(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // A release zip with the real files plus things that have no business being there.
        byte[] newExe = FakeProgram("new program");
        string zip = MakeZip(Path.Combine(scratch, "release.zip"),
            "SecHUD.exe", newExe, "README.md", Encoding.UTF8.GetBytes("new readme"),
            "../escape.txt", Encoding.UTF8.GetBytes("x"), "..\\escape2.txt", Encoding.UTF8.GetBytes("x"),
            "sub/SecHUD.exe", FakeProgram("wrong one"), "extra.dll", new byte[10], "sechud.EXE", FakeProgram("duplicate"));
        string unpacked = Path.Combine(scratch, "unpacked");
        string error;
        bool unpackedOk = Updater.Unpack(zip, unpacked, out error);
        Check("only the program's own files are taken out of the zip", unpackedOk && Directory.GetFiles(unpacked).Select(Path.GetFileName).OrderBy(n => n).SequenceEqual(new[] { "README.md", "SecHUD.exe" })
            && File.ReadAllBytes(Path.Combine(unpacked, "SecHUD.exe")).SequenceEqual(newExe) && Directory.GetDirectories(unpacked).Length == 0
            && !File.Exists(Path.Combine(scratch, "escape.txt")) && !File.Exists(Path.Combine(scratch, "escape2.txt")));
        string noExe = MakeZip(Path.Combine(scratch, "no-exe.zip"), "README.md", Encoding.UTF8.GetBytes("x"));
        Check("a zip without the program, or a file that is not a zip, is refused", !Updater.Unpack(noExe, Path.Combine(scratch, "u2"), out error) && error.Contains("does not contain")
            && !Updater.Unpack(abc, Path.Combine(scratch, "u3"), out error) && error.Contains("could not be unpacked"));

        Func<string, string> realReader = Updater.VersionReader;
        Func<string, string, long, Action<int>, string> realDownloader = Updater.Downloader;
        try
        {
            Updater.VersionReader = path => "0.9.0.0";
            string exe = Path.Combine(unpacked, "SecHUD.exe");
            bool rightVersion = Updater.VerifyExe(exe, "0.9.0", out error);
            bool wrongVersion = !Updater.VerifyExe(exe, "0.9.1", out error);
            Updater.VersionReader = path => null;
            bool noVersion = !Updater.VerifyExe(exe, "0.9.0", out error);
            Updater.VersionReader = path => "0.9.0.0";
            Check("the new program must be exactly the version the release says", rightVersion && wrongVersion && noVersion && !Updater.VerifyExe(abc, "0.9.0", out error) && error.Contains("not a Windows program"));

            // "Downloads" are served from local files, so nothing here touches the network.
            string served = zip;
            string servedHash = Updater.Sha256File(zip) + "  SecHUD-v0.9.0.zip";
            var asked = new List<string>();
            Updater.Downloader = (url, path, max, progress) =>
            {
                asked.Add(url);
                if (url.EndsWith(".zip")) { File.Copy(served, path, true); if (progress != null) progress(100); }
                else File.WriteAllText(path, servedHash);
                return "";
            };
            var good = new UpdateInfo { Version = "0.9.0", ZipUrl = baseUrl + "SecHUD-v0.9.0.zip", HashUrl = baseUrl + "SecHUD-v0.9.0.sha256.txt", Digest = Updater.Sha256File(zip) };
            var steps = new List<string>();
            string staged;
            bool prepared = Updater.Prepare(good, steps.Add, out staged, out error);
            Check("a release that matches its checksum is downloaded and unpacked", prepared && File.Exists(Path.Combine(staged, "SecHUD.exe")) && asked.Count == 2 && steps.Contains("DOWNLOADING UPDATE 100%") && steps.Contains("CHECKING THE DOWNLOAD..."));

            servedHash = new string('0', 64) + "  SecHUD-v0.9.0.zip";
            bool badFile = !Updater.Prepare(good, null, out staged, out error);
            string badFileError = error;
            servedHash = Updater.Sha256File(zip) + "  SecHUD-v0.9.0.zip";
            var badDigest = new UpdateInfo { Version = "0.9.0", ZipUrl = good.ZipUrl, HashUrl = good.HashUrl, Digest = new string('1', 64) };
            bool badApi = !Updater.Prepare(badDigest, null, out staged, out error);
            Check("a download that does not match either checksum is thrown away", badFile && badFileError.Contains("does not match") && badApi && error.Contains("does not match") && staged == "");

            var wrongPlace = new UpdateInfo { Version = "0.9.0", ZipUrl = "https://evil.example/SecHUD-v0.9.0.zip", Digest = good.Digest };
            int before = asked.Count;
            Check("nothing is fetched for a release from the wrong place, or with no checksum", !Updater.Prepare(wrongPlace, null, out staged, out error) && !Updater.Prepare(new UpdateInfo { Version = "0.9.0", ZipUrl = good.ZipUrl }, null, out staged, out error) && !Updater.Prepare(null, null, out staged, out error) && asked.Count == before);
            Updater.Downloader = (url, path, max, progress) => "could not reach GitHub";
            Check("a failed download is reported, not installed", !Updater.Prepare(good, null, out staged, out error) && error == "could not reach GitHub");

            // The swap: the running program cannot be overwritten, so it is set aside and replaced.
            string app = Path.Combine(scratch, "app");
            Directory.CreateDirectory(app);
            File.WriteAllBytes(Path.Combine(app, "SecHUD.exe"), FakeProgram("old program"));
            File.WriteAllText(Path.Combine(app, "README.md"), "old readme");
            File.WriteAllText(Path.Combine(app, "notes-of-mine.txt"), "mine");
            bool installed = Updater.Install(unpacked, app, out error);
            Check("the new files take the place of the old ones, which are set aside", installed && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe")).SequenceEqual(newExe) && File.ReadAllText(Path.Combine(app, "README.md")) == "new readme"
                && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe.old")).SequenceEqual(FakeProgram("old program")) && File.ReadAllText(Path.Combine(app, "notes-of-mine.txt")) == "mine");
            Check("installing a second time replaces the files set aside earlier", Updater.Install(unpacked, app, out error) && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe.old")).SequenceEqual(newExe));
            Directory.CreateDirectory(Updater.WorkDir);
            Updater.CleanupAfterUpdate(app);
            Check("the next start clears away what the update left behind", !File.Exists(Path.Combine(app, "SecHUD.exe.old")) && !File.Exists(Path.Combine(app, "README.md.old")) && !Directory.Exists(Updater.WorkDir) && File.Exists(Path.Combine(app, "SecHUD.exe")) && File.Exists(Path.Combine(app, "notes-of-mine.txt")));

            // A swap that fails half way puts everything back.
            string app2 = Path.Combine(scratch, "app2");
            Directory.CreateDirectory(app2);
            File.WriteAllBytes(Path.Combine(app2, "SecHUD.exe"), FakeProgram("old program"));
            File.WriteAllText(Path.Combine(app2, "README.md"), "old readme");
            Directory.CreateDirectory(Path.Combine(app2, "LICENSE")); // something in the way
            string staged2 = Path.Combine(scratch, "staged2");
            Directory.CreateDirectory(staged2);
            File.WriteAllBytes(Path.Combine(staged2, "SecHUD.exe"), newExe);
            File.WriteAllText(Path.Combine(staged2, "README.md"), "new readme");
            File.WriteAllText(Path.Combine(staged2, "LICENSE"), "new licence");
            bool failed = !Updater.Install(staged2, app2, out error);
            Check("if the swap fails part way, every file is put back as it was", failed && error.Length > 0 && File.ReadAllText(Path.Combine(app2, "README.md")) == "old readme" && File.ReadAllBytes(Path.Combine(app2, "SecHUD.exe")).SequenceEqual(FakeProgram("old program")) && !File.Exists(Path.Combine(app2, "README.md.old")));
            Check("an update with no program in it is never installed", !Updater.Install(Path.Combine(scratch, "u2"), app2, out error));

            // The button, start to finish.
            Updater.AppDirOverride = app;
            File.WriteAllBytes(Path.Combine(app, "SecHUD.exe"), FakeProgram("old program"));
            servedHash = Updater.Sha256File(zip) + "  SecHUD-v0.9.0.zip";
            Updater.Downloader = (url, path, max, progress) =>
            {
                if (url.EndsWith(".zip")) File.Copy(served, path, true); else File.WriteAllText(path, servedHash);
                return "";
            };

            var vm = new MainViewModel();
            string opened = null, restartPath = null, shown = null, askedQuestion = null;
            vm.PageOpener = url => opened = url;
            vm.ShowMessage = text => shown = text;
            good.Url = "https://github.com/sivadyt/SecHUD/releases/tag/v0.9.0"; good.Notes = "New things.";
            vm.ApplyUpdate(good);
            Check("the button says it will update by itself", vm.UpdateLabel == "UPDATE AVAILABLE: V0.9.0" && vm.UpdateNotes.Contains("closes, updates and opens again by itself"));

            vm.OpenUpdateCommand.Execute(null);
            Check("with no window attached the button opens the download page, as before", opened == good.Url && restartPath == null);

            vm.RestartRequested += path => restartPath = path;
            vm.Ask = question => { askedQuestion = question; return false; };
            opened = null;
            vm.OpenUpdateCommand.Execute(null);
            Check("answering no leaves everything alone", askedQuestion != null && askedQuestion.Contains("version 0.9.0") && !vm.UpdateBusy && restartPath == null && opened == null && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe")).SequenceEqual(FakeProgram("old program")));

            vm.Ask = question => true;
            vm.OpenUpdateCommand.Execute(null);
            for (int i = 0; i < 100 && restartPath == null; i++) Thread.Sleep(50);
            Check("answering yes downloads, installs and asks for the restart", restartPath == Path.Combine(app, "SecHUD.exe") && vm.UpdateLabel == "RESTARTING..." && vm.UpdateBusy && shown == null && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe")).SequenceEqual(newExe));
            vm.OpenUpdateCommand.Execute(null);
            vm.ApplyUpdate(null);
            Check("the button cannot be pressed twice while it is working", vm.UpdateAvailable && vm.UpdateLabel == "RESTARTING...");

            // And when the download is bad: nothing changes, the reason is shown, the page opens.
            File.WriteAllBytes(Path.Combine(app, "SecHUD.exe"), FakeProgram("old program"));
            servedHash = new string('0', 64);
            var vm2 = new MainViewModel();
            string restart2 = null, shown2 = null, opened2 = null;
            vm2.PageOpener = url => opened2 = url;
            vm2.ShowMessage = text => shown2 = text;
            vm2.RestartRequested += path => restart2 = path;
            vm2.Ask = question => true;
            vm2.ApplyUpdate(good);
            vm2.OpenUpdateCommand.Execute(null);
            for (int i = 0; i < 100 && opened2 == null; i++) Thread.Sleep(50);
            Check("a bad download changes nothing, says why, and opens the page instead", restart2 == null && opened2 == good.Url && shown2 != null && shown2.Contains("does not match") && shown2.Contains("Nothing was changed") && !vm2.UpdateBusy
                && vm2.UpdateLabel == "UPDATE AVAILABLE: V0.9.0" && File.ReadAllBytes(Path.Combine(app, "SecHUD.exe")).SequenceEqual(FakeProgram("old program")));
        }
        finally
        {
            Updater.VersionReader = realReader;
            Updater.Downloader = realDownloader;
            Updater.AppDirOverride = null;
        }
    }
}

static partial class Tests
{
    static void TrustNotes()
    {
        string rest;
        Check("the program is picked out of a command line, quoted or not",
            Trust.ExtractPath("\"C:\\Program Files\\Chat\\chat.exe\" --tray", out rest) == "C:\\Program Files\\Chat\\chat.exe" && rest == "--tray"
            && Trust.ExtractPath("C:\\Program Files\\Chat\\chat.exe /min", out rest) == "C:\\Program Files\\Chat\\chat.exe" && rest == "/min"
            && Trust.ExtractPath("rundll32.exe shell32.dll,Control_RunDLL", out rest) == "rundll32.exe" && rest == "shell32.dll,Control_RunDLL"
            && Trust.ExtractPath("notepad", out rest) == "notepad" && rest == ""
            && Trust.ExtractPath("", out rest) == "" && Trust.ExtractPath(null, out rest) == "");
        Check("the path styles Windows services use are understood",
            Trust.ExtractPath("\\??\\C:\\Drivers\\thing.sys", out rest) == "C:\\Drivers\\thing.sys"
            && Trust.ExtractPath("\\SystemRoot\\System32\\drivers\\x.sys", out rest).EndsWith("\\System32\\drivers\\x.sys") && !Trust.ExtractPath("\\SystemRoot\\System32\\drivers\\x.sys", out rest).StartsWith("\\SystemRoot")
            && Trust.ExtractPath("System32\\svchost.exe -k netsvcs", out rest).EndsWith("\\System32\\svchost.exe") && rest == "-k netsvcs");
        Check("unusual places for a startup program are named",
            Trust.LocationWarning("C:\\Users\\ty\\AppData\\Local\\Temp\\x.exe") == "a temp folder" && Trust.LocationWarning("C:\\Users\\ty\\Downloads\\x.exe") == "the Downloads folder"
            && Trust.LocationWarning("C:\\Users\\Public\\x.exe") == "the Public folder" && Trust.LocationWarning("C:\\Users\\ty\\Desktop\\x.exe") == "the Desktop"
            && Trust.LocationWarning("C:\\Program Files\\Chat\\chat.exe") == "" && Trust.LocationWarning("C:\\Windows\\System32\\notepad.exe") == "" && Trust.LocationWarning(null) == "");

        Func<string, SignatureInfo> realReader = Trust.SignatureReader;
        Func<string, bool> realExists = Trust.FileExists;
        Func<string, string> realShortcut = Trust.ShortcutResolver, realDll = Trust.ServiceDllReader, realTask = Trust.TaskActionReader;
        try
        {
            // A made-up PC: which files exist and what their signatures are.
            var signatures = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase)
            {
                { "C:\\Program Files\\Chat\\chat.exe", new SignatureInfo { State = SignatureInfo.Trusted, Signer = "Chat Company Inc." } },
                { "C:\\Users\\ty\\AppData\\Local\\Temp\\updater.exe", new SignatureInfo { State = SignatureInfo.None } },
                { "C:\\Tools\\hobby.exe", new SignatureInfo { State = SignatureInfo.None } },
                { "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", new SignatureInfo { State = SignatureInfo.Trusted, Signer = "Microsoft Windows" } },
                { "C:\\Program Files\\Patched\\app.exe", new SignatureInfo { State = SignatureInfo.Broken, Signer = "Real Vendor" } },
                { "C:\\Program Files\\Odd\\odd.exe", new SignatureInfo { State = SignatureInfo.Untrusted, Signer = "Self Made" } },
                { "C:\\Users\\ty\\Downloads\\signed.exe", new SignatureInfo { State = SignatureInfo.Trusted, Signer = "Chat Company Inc." } },
                { "C:\\Windows\\System32\\svchost.exe", new SignatureInfo { State = SignatureInfo.Trusted, Signer = "Microsoft Windows" } },
                { "C:\\Windows\\System32\\good.dll", new SignatureInfo { State = SignatureInfo.Trusted, Signer = "Microsoft Windows" } },
                { "C:\\Users\\ty\\AppData\\Local\\Temp\\run.vbs", new SignatureInfo() },
                { "C:\\Scripts\\backup.bat", new SignatureInfo() }
            };
            Trust.FileExists = path => signatures.ContainsKey(path);
            Trust.SignatureReader = path => signatures[path];
            Trust.ShortcutResolver = link => link.EndsWith("chat.lnk") ? "\"C:\\Program Files\\Chat\\chat.exe\" --tray" : "";
            Trust.ServiceDllReader = name => name == "GoodSvc" ? "C:\\Windows\\System32\\good.dll" : "";
            Trust.TaskActionReader = name => name == "\\Updater" ? "\"C:\\Users\\ty\\AppData\\Local\\Temp\\updater.exe\" /silent" : "";
            Trust.ClearCache();

            TrustNote signed = Trust.DescribeCommand("\"C:\\Program Files\\Chat\\chat.exe\" --tray");
            Check("a signed program in a normal place reads as fine, with who signed it", signed.Level == TrustNote.Ok && signed.Text == "Signed by Chat Company Inc., and Windows trusts the signature." && signed.Short == "signed by Chat Company Inc.");

            TrustNote temp = Trust.DescribeCommand("C:\\Users\\ty\\AppData\\Local\\Temp\\updater.exe /silent");
            Check("not signed and in a temp folder is a warning", temp.Level == TrustNote.Warn && temp.Text.StartsWith("Not signed, and it runs from a temp folder.") && temp.Short == "not signed, in a temp folder");

            TrustNote hobby = Trust.DescribeCommand("C:\\Tools\\hobby.exe");
            Check("not signed in an ordinary place is only a caution, and says why", hobby.Level == TrustNote.Caution && hobby.Text.Contains("Many small programs are not") && hobby.Short == "not signed");

            TrustNote shell = Trust.DescribeCommand("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc SQBFAFgA");
            Check("PowerShell is never passed off as simply signed by Microsoft", shell.Level == TrustNote.Caution && shell.Text.Contains("runs whatever the rest of the command tells it to") && shell.Text.Contains("Read the command itself") && !shell.Text.StartsWith("Signed by") && shell.Short == "runs a command through powershell.exe");

            TrustNote broken = Trust.DescribeCommand("\"C:\\Program Files\\Patched\\app.exe\"");
            TrustNote untrusted = Trust.DescribeCommand("\"C:\\Program Files\\Odd\\odd.exe\"");
            Check("a broken or untrusted signature is a warning", broken.Level == TrustNote.Warn && broken.Text.Contains("changed after Real Vendor signed it") && untrusted.Level == TrustNote.Warn && untrusted.Text.Contains("Windows does not trust"));

            TrustNote odd = Trust.DescribeCommand("C:\\Users\\ty\\Downloads\\signed.exe");
            Check("signed but running from Downloads is worth a second look", odd.Level == TrustNote.Caution && odd.Text.Contains("the Downloads folder") && odd.Short == "signed by Chat Company Inc., in the Downloads folder");

            TrustNote missing = Trust.DescribeCommand("\"C:\\Gone\\gone.exe\"");
            Check("an entry whose file is gone says so", missing.Level == TrustNote.Caution && missing.Text.Contains("is not there") && missing.Short == "its file is missing" && Trust.DescribeCommand("") == null && Trust.DescribeCommand(null) == null);

            TrustNote script = Trust.DescribeCommand("C:\\Scripts\\backup.bat");
            TrustNote tempScript = Trust.DescribeCommand("\"C:\\Users\\ty\\AppData\\Local\\Temp\\run.vbs\"");
            Check("a script is called a script, and one in a temp folder is a warning", script.Level == TrustNote.Caution && script.Text.StartsWith("A script, not a program") && tempScript.Level == TrustNote.Warn && tempScript.Short == "a script in a temp folder");

            TrustNote viaShortcut = Trust.Describe(new AutorunItem { Kind = "startup", Name = "chat.lnk", Command = "C:\\Users\\ty\\Startup\\chat.lnk" });
            TrustNote deadShortcut = Trust.Describe(new AutorunItem { Kind = "startup", Name = "dead.lnk", Command = "C:\\Users\\ty\\Startup\\dead.lnk" });
            Check("a startup shortcut is judged by the program it points to", viaShortcut.Level == TrustNote.Ok && viaShortcut.Short == "signed by Chat Company Inc." && deadShortcut.Level == TrustNote.Caution);

            TrustNote hosted = Trust.Describe(new AutorunItem { Kind = "service", Name = "GoodSvc", Command = "C:\\Windows\\System32\\svchost.exe -k netsvcs" });
            TrustNote hostedUnknown = Trust.Describe(new AutorunItem { Kind = "service", Name = "MysterySvc", Command = "C:\\Windows\\System32\\svchost.exe -k netsvcs" });
            Check("a service inside the Windows service host is judged by its own file", hosted.Level == TrustNote.Ok && hosted.Text == "Runs inside the Windows service host. Its own file: signed by Microsoft Windows, and Windows trusts the signature." && hostedUnknown.Level == TrustNote.Caution);

            TrustNote task = Trust.Describe(new AutorunItem { Kind = "task", Name = "\\Updater", Command = "" });
            Check("a scheduled task is judged by the program it runs", task.Level == TrustNote.Warn && task.Short == "not signed, in a temp folder" && Trust.Describe(new AutorunItem { Kind = "task", Name = "\\Unknown", Command = "" }) == null && Trust.Describe(null) == null);

            int reads = 0;
            Trust.SignatureReader = path => { reads++; return signatures[path]; };
            Trust.ClearCache();
            var item = new AutorunItem { Kind = "run", Name = "HKCU\\Hobby", Command = "C:\\Tools\\hobby.exe" };
            Trust.Describe(item); Trust.Describe(item); Trust.Describe(item);
            Check("a note is worked out once and then remembered", reads == 1);

            Trust.SignatureReader = path => { throw new InvalidOperationException("boom"); };
            Trust.ClearCache();
            Check("if Windows cannot answer, there is simply no note", Trust.Describe(new AutorunItem { Kind = "run", Name = "HKCU\\X", Command = "C:\\Tools\\hobby.exe" }) == null);
        }
        finally
        {
            Trust.SignatureReader = realReader;
            Trust.FileExists = realExists;
            Trust.ShortcutResolver = realShortcut;
            Trust.ServiceDllReader = realDll;
            Trust.TaskActionReader = realTask;
            Trust.ClearCache();
        }

        if (Path.DirectorySeparatorChar == '\\')
        {
            // The real thing, on real Windows files.
            string notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            SignatureInfo windowsFile = Trust.SignatureReader(notepad);
            Console.WriteLine("        notepad.exe: " + windowsFile.State + " / " + windowsFile.Signer);
            Check("a file that is part of Windows is recognised as signed by Microsoft", windowsFile.State == SignatureInfo.Trusted && windowsFile.Signer.Contains("Microsoft"));

            string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
            SignatureInfo unsignedFile = Trust.SignatureReader(self);
            Check("this test program, which nobody signed, reads as not signed", unsignedFile.State == SignatureInfo.None && unsignedFile.Signer == "");

            TrustNote live = Trust.DescribeCommand("notepad.exe");
            Console.WriteLine("        note for 'notepad.exe': " + (live == null ? "none" : live.Level + " / " + live.Text));
            Check("a bare program name is found and described", live != null && live.Level == TrustNote.Ok && live.Text.StartsWith("Signed by Microsoft"));

            string dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
            if (File.Exists(dotnet))
            {
                SignatureInfo embedded = Trust.SignatureReader(dotnet);
                string tampered = Path.Combine(Store.Dir, "tampered-copy.exe");
                byte[] bytes = File.ReadAllBytes(dotnet);
                bytes[bytes.Length / 2] ^= 0xFF;
                File.WriteAllBytes(tampered, bytes);
                SignatureInfo changed = Trust.SignatureReader(tampered);
                File.Delete(tampered);
                Console.WriteLine("        dotnet.exe: " + embedded.State + " / " + embedded.Signer + "   changed copy: " + changed.State);
                Check("a program with its own signature names its signer", embedded.State == SignatureInfo.Trusted && embedded.Signer.Contains("Microsoft"));
                Check("changing one byte of a signed program breaks its signature", changed.State == SignatureInfo.Broken || changed.State == SignatureInfo.Untrusted);
            }
        }
    }

    static void GuestDevices()
    {
        const string pc = "B8-27-EB-00-00-03", phone = "DA-A1-19-00-00-07", laptop = "00-0C-29-00-00-08", oldPhone = "DE-00-00-00-00-01";
        Func<string, string> realResolver = Scanner.NameResolver;
        Scanner.NameResolver = ip => "";
        try
        {
            File.Delete(Store.DevicesPath);
            DateTime now = DateTime.Now;
            var config = AppConfig.CreateDefault();
            var events = new List<EventEntry>();
            List<DeviceRecord> devices;
            Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);

            events.Clear();
            CheckRow strict = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2", phone, "192.168.1.60"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("by default a phone with a private address is flagged like any new device", strict.IsAlert && strict.Value == "2 | 1 unknown" && events.Count(e => e.Type == "new-device" && e.Severity == "high") == 1 && !devices.Any(d => d.Guest));

            // Same network, with guest handling switched on.
            File.Delete(Store.DevicesPath);
            config.GuestPrivate = true;
            Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            events.Clear();
            CheckRow relaxed = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2", phone, "192.168.1.60", laptop, "192.168.1.61"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("with guests on, the phone is listed quietly and the laptop still alerts", relaxed.IsAlert && relaxed.Value == "3 | 1 unknown | 1 guest"
                && events.Count(e => e.Severity == "high") == 1 && events.Any(e => e.Severity == "high" && e.Msg.Contains("192.168.1.61"))
                && events.Any(e => e.Type == "guest-device" && e.Severity == "info" && e.Msg == "guest device joined: 192.168.1.60 " + phone + " (private address)")
                && devices.First(d => d.Mac == phone).Guest && !devices.First(d => d.Mac == laptop).Guest && !devices.First(d => d.Mac == phone).Approved);

            events.Clear();
            CheckRow approveAll = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2", phone, "192.168.1.60", laptop, "192.168.1.61"), "192.168.1.2", "192.168.1.1", true, events, now, out devices);
            Check("Approve all accepts what was flagged and leaves guests as guests", !approveAll.IsAlert && approveAll.Value == "3 | 0 unknown | 1 guest" && devices.First(d => d.Mac == laptop).Approved && !devices.First(d => d.Mac == phone).Approved);

            // A guest from two weeks ago that never came back, and one the owner approved.
            devices.Add(new DeviceRecord { Mac = oldPhone, Ip = "192.168.1.90", Name = "", Approved = false, FirstSeen = now.AddDays(-20).ToString("s"), LastSeen = now.AddDays(-14).ToString("s") });
            devices.First(d => d.Mac == phone).Approved = true;
            Store.Save(Store.DevicesPath, devices);
            CheckRow pruned = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("a guest that has not been back for a week drops off the list", !devices.Any(d => d.Mac == oldPhone) && pruned.Value == "1 | 0 unknown");
            Check("an approved phone is a known device, not a guest, and is kept", devices.Any(d => d.Mac == phone && d.Approved && !d.Guest));

            devices.Add(new DeviceRecord { Mac = oldPhone, Ip = "192.168.1.90", Name = "", Approved = false, LastSeen = now.AddDays(-14).ToString("s") });
            Store.Save(Store.DevicesPath, devices);
            Scanner.EvaluateLan(config, null, null, null, false, events, now, out devices);
            Check("nothing is dropped while this PC is off the network", devices.Any(d => d.Mac == oldPhone));
            config.GuestPrivate = false;
            CheckRow strictAgain = Scanner.EvaluateLan(config, Seen(pc, "192.168.1.2"), "192.168.1.2", "192.168.1.1", false, events, now, out devices);
            Check("switching guests off flags them again and keeps them listed", strictAgain.IsAlert && strictAgain.Value == "1 | 1 unknown" && devices.Any(d => d.Mac == oldPhone && !d.Guest));

            var vm = new MainViewModel();
            var apply = typeof(MainViewModel).GetMethod("Apply", BindingFlags.NonPublic | BindingFlags.Instance);
            ScanResult result = SampleResult();
            result.NewEvents.Clear();
            result.Devices.First(d => !d.Approved).Guest = true;
            result.Autoruns[0].Note = new TrustNote { Level = TrustNote.Warn, Text = "Not signed, and it runs from a temp folder.", Short = "not signed, in a temp folder" };
            apply.Invoke(vm, new object[] { result });
            Check("the window shows GUEST and does not count it as unknown", vm.Devices[0].Status == "GUEST" && vm.DeviceSummary == "DEVICES (3)");
            Check("a new startup item shows its note, and an approved one does not", vm.Autoruns[0].HasNote && vm.Autoruns[0].Note == "NOT SIGNED, AND IT RUNS FROM A TEMP FOLDER." && vm.Autoruns[0].NoteLevel == "warn" && !vm.Autoruns[1].HasNote);

            ScanResult later = SampleResult();
            later.NewEvents.Clear();
            later.Devices.RemoveAll(d => !d.Approved);
            apply.Invoke(vm, new object[] { later });
            Check("a device dropped from the list leaves the window too", vm.Devices.Count == 2 && vm.DeviceSummary == "DEVICES (2)");
        }
        finally
        {
            Scanner.NameResolver = realResolver;
        }
    }

    static void WeeklySummary()
    {
        var now = new DateTime(2026, 11, 18, 18, 0, 0);
        Func<int, string, string, string, EventEntry> ev = (daysAgo, type, severity, msg) => new EventEntry { Ts = now.AddDays(-daysAgo).ToString("s"), Type = type, Severity = severity, Msg = msg };
        var events = new List<EventEntry>
        {
            ev(1, "new-device", "high", "new device 192.168.1.47"), ev(2, "new-device", "high", "new device 192.168.1.48"),
            ev(3, "new-autorun", "high", "new run autorun: HKCU\\X"), ev(4, "detection", "high", "new local user account: x"),
            ev(5, "mystery", "high", "something else"), ev(1, "approve", "info", "approved device"), ev(1, "level", "info", "status changed"),
            ev(9, "new-device", "high", "too old to count"), new EventEntry { Ts = "not a date", Type = "new-device", Severity = "high" }, null
        };
        var devices = new List<DeviceRecord>
        {
            new DeviceRecord { Mac = "B8-27-EB-00-00-01", Approved = true, LastSeen = now.AddDays(-1).ToString("s") },
            new DeviceRecord { Mac = "B8-27-EB-00-00-02", Approved = true, LastSeen = now.AddDays(-30).ToString("s") },
            new DeviceRecord { Mac = "B8-27-EB-00-00-03", Approved = false, LastSeen = now.ToString("s") },
            new DeviceRecord { Mac = "DA-00-00-00-00-04", Approved = false, Guest = true, LastSeen = now.ToString("s") }
        };
        string busy = Summary.Build(events, devices, "ELEVATED", 1, now, "TYSPC", "0.8.3");
        Check("the weekly summary counts the week's alerts by kind", busy.StartsWith("SecHUD weekly summary for TYSPC (Nov 11 to Nov 18)") && busy.Contains("Status now: ELEVATED")
            && busy.Contains("Alerts this week: 5 (2 new devices, 1 new startup item, 1 detection, 1 other)"));
        Check("it says what is still waiting, and how many devices were around", busy.Contains("Waiting for you: 1 open detection, 1 unknown device") && busy.Contains("Devices: 2 known, 3 seen this week") && busy.EndsWith("SecHUD 0.8.3 is running and watching.") && !busy.Contains("quiet week"));

        string quiet = Summary.Build(new List<EventEntry>(), devices.Take(2).ToList(), "NOMINAL", 0, now, "TYSPC", "0.8.3");
        Check("a quiet week says so in plain words", quiet.Contains("Alerts this week: 0") && !quiet.Contains("Alerts this week: 0 (") && quiet.Contains("Waiting for you: nothing") && quiet.Contains("A quiet week. Nothing new showed up.")
            && Summary.Build(null, null, null, 0, now, "PC", "1.0.0").Contains("Status now: unknown"));

        DateTime utc = now.ToUniversalTime();
        Check("the summary is due after seven days, not before", Summary.IsDue(utc.AddDays(-8).ToString("s") + "Z", utc) && Summary.IsDue(utc.AddDays(-7).ToString("s") + "Z", utc) && !Summary.IsDue(utc.AddDays(-6).ToString("s") + "Z", utc)
            && Summary.IsDue("", utc) && Summary.IsDue(null, utc) && Summary.IsDue("garbage", utc));

        // In the window: the first look only starts the clock.
        File.Delete(Store.SummaryPath);
        var vm = new MainViewModel();
        var apply = typeof(MainViewModel).GetMethod("Apply", BindingFlags.NonPublic | BindingFlags.Instance);
        var posted = new List<string>();
        vm.DiscordPoster = (hook, text) => posted.Add(text);
        vm.MaybeSendWeeklySummary(DateTime.Now);
        bool nothingBeforeScan = posted.Count == 0 && !File.Exists(Store.SummaryPath);

        ScanResult result = SampleResult();
        result.NewEvents.Clear();
        result.Config.DiscordWebhookProtected = Secrets.Protect("https://discord.com/api/webhooks/1/abc");
        apply.Invoke(vm, new object[] { result });
        vm.MaybeSendWeeklySummary(DateTime.Now.AddMinutes(11));
        Check("the first week only starts the clock", nothingBeforeScan && posted.Count == 0 && File.Exists(Store.SummaryPath));

        vm.MaybeSendWeeklySummary(DateTime.Now.AddDays(3));
        bool notYet = posted.Count == 0;
        vm.MaybeSendWeeklySummary(DateTime.Now.AddDays(7).AddHours(1));
        Check("a week later it is sent, once", notYet && posted.Count == 1 && posted[0].StartsWith("SecHUD weekly summary for") && posted[0].Contains("Status now: ELEVATED"));
        vm.MaybeSendWeeklySummary(DateTime.Now.AddDays(7).AddHours(2));
        vm.MaybeSendWeeklySummary(DateTime.Now.AddDays(8));
        Check("and not again until another week has passed", posted.Count == 1);

        result.Config.WeeklySummary = false;
        vm.MaybeSendWeeklySummary(DateTime.Now.AddDays(30));
        result.Config.WeeklySummary = true;
        result.Config.QuietHours = true; result.Config.QuietStart = "00:00"; result.Config.QuietEnd = "23:59";
        vm.MaybeSendWeeklySummary(DateTime.Now.Date.AddDays(40).AddHours(12));
        Check("it respects the off switch and quiet hours", posted.Count == 1);

        result.Config.QuietHours = false;
        vm.SendSummaryCommand.Execute(null);
        Check("Send summary now sends it straight away", posted.Count == 2 && vm.SettingsStatus.StartsWith("SUMMARY SENT"));
        var saved = Store.FromJson<AppConfig>(Store.ToJson(AppConfig.CreateDefault()));
        Check("guests are off and the weekly summary is on unless you change them", !saved.GuestPrivate && saved.GuestDays == 7 && saved.WeeklySummary);
    }
}

/// <summary>Records what setup would do to Windows, without doing it.</summary>
class FakeSetupSystem : ISetupSystem
{
    public List<string> Calls = new List<string>();
    public string Installed = "";
    public void StopRunningApp() { Calls.Add("stop"); }
    public void MakeShortcut(string linkPath, string targetExe, string workingDir) { Calls.Add("shortcut " + linkPath + " -> " + targetExe); }
    public void RemoveShortcut(string linkPath) { Calls.Add("unshortcut " + linkPath); }
    public void RegisterUninstall(string installDir, string version) { Calls.Add("register " + version + " " + installDir); Installed = installDir; }
    public void UnregisterUninstall() { Calls.Add("unregister"); Installed = ""; }
    public void FixStartupEntry(string exePath) { Calls.Add("startup " + exePath); }
    public void RemoveStartupEntry() { Calls.Add("unstartup"); }
    public void Launch(string exePath) { Calls.Add("launch " + exePath); }
    public string InstalledDir() { return Installed; }
}

static partial class Tests
{
    static void SetupProgram()
    {
        SetupOptions parsed = Installer.ParseArgs(new[] { "--UNINSTALL", "--silent", "--dir", "\"C:\\Some Folder\\SecHUD\"", "--remove-data", "--no-launch", "--no-desktop", "--nonsense" });
        SetupOptions plain = Installer.ParseArgs(null);
        Check("setup reads its options, and with none it simply installs", parsed.Uninstall && parsed.Silent && parsed.RemoveData && parsed.NoLaunch && parsed.NoDesktopShortcut && parsed.Dir == "C:\\Some Folder\\SecHUD"
            && !plain.Uninstall && !plain.Silent && !plain.NoLaunch && !plain.NoDesktopShortcut && plain.Dir == "" && Installer.ParseArgs(new[] { "--dir" }).Dir == "");

        string scratch = Path.Combine(Store.Dir, "setup-test");
        if (Directory.Exists(scratch)) Directory.Delete(scratch, true);
        Directory.CreateDirectory(scratch);
        byte[] program = FakeProgram("installed program");
        string zip = MakeZip(Path.Combine(scratch, "release.zip"), "SecHUD.exe", program, "README.md", Encoding.UTF8.GetBytes("readme"), "LICENSE", Encoding.UTF8.GetBytes("licence"));
        string self = Path.Combine(scratch, "SecHUD-Setup.exe");
        File.WriteAllBytes(self, FakeProgram("setup program"));
        string dir = Path.Combine(scratch, "Programs", "SecHUD");
        string exe = Path.Combine(dir, "SecHUD.exe");
        const string baseUrl = "https://github.com/sivadyt/SecHUD/releases/download/v0.9.0/";

        ISetupSystem realSystem = Installer.Windows;
        Func<UpdateInfo> realFinder = Installer.ReleaseFinder;
        Func<string, string> realReader = Updater.VersionReader;
        Func<string, string, long, Action<int>, string> realDownloader = Updater.Downloader;
        string realData = Store.Dir;
        try
        {
            var system = new FakeSetupSystem();
            Installer.Windows = system;
            Updater.VersionReader = path => "0.9.0.0";
            string servedHash = Updater.Sha256File(zip);
            Updater.Downloader = (url, path, max, progress) =>
            {
                if (url.EndsWith(".zip")) { File.Copy(zip, path, true); if (progress != null) progress(50); } else File.WriteAllText(path, servedHash);
                return "";
            };
            var release = new UpdateInfo { Version = "0.9.0", ZipUrl = baseUrl + "SecHUD-v0.9.0.zip", HashUrl = baseUrl + "SecHUD-v0.9.0.sha256.txt", Digest = Updater.Sha256File(zip) };
            Installer.ReleaseFinder = () => release;

            Check("setup installs for the current user unless told where", Installer.TargetDir(new SetupOptions()) == Installer.DefaultDir && Installer.DefaultDir.EndsWith(Path.Combine("Programs", "SecHUD"))
                && Installer.TargetDir(new SetupOptions { Dir = dir }) == Path.GetFullPath(dir));

            var said = new List<string>();
            string version, error;
            bool installed = Installer.Install(new SetupOptions { Dir = dir }, self, said.Add, out version, out error);
            Check("setup downloads the newest release and puts the program in place", installed && version == "0.9.0" && File.ReadAllBytes(exe).SequenceEqual(program) && File.Exists(Path.Combine(dir, "README.md")) && File.Exists(Path.Combine(dir, "LICENSE")) && !File.Exists(exe + ".old"));
            Check("it leaves a copy of itself behind as the uninstaller", File.ReadAllBytes(Path.Combine(dir, "Uninstall.exe")).SequenceEqual(FakeProgram("setup program")));
            Check("it adds Start menu and desktop shortcuts, registers with Windows, and starts SecHUD",
                system.Calls.SequenceEqual(new[] { "stop", "shortcut " + Installer.StartMenuShortcut + " -> " + exe, "shortcut " + Installer.DesktopShortcut + " -> " + exe, "register 0.9.0 " + Path.GetFullPath(dir), "startup " + exe, "launch " + exe }));
            Check("progress is worded for an install, not an update", said.Contains("LOOKING FOR THE NEWEST VERSION...") && said.Contains("DOWNLOADING SECHUD 50%") && said.Contains("INSTALLING...") && said.Contains("STARTING SECHUD...") && !said.Any(x => x.Contains("UPDATE")));

            // Running it again over an existing install is how an old copy is updated or repaired.
            File.WriteAllBytes(exe, FakeProgram("older program"));
            File.WriteAllText(Path.Combine(dir, "my-notes.txt"), "mine");
            system.Calls.Clear();
            bool again = Installer.Install(new SetupOptions { Dir = dir, NoDesktopShortcut = true, NoLaunch = true }, self, null, out version, out error);
            Check("running setup again updates the program and keeps anything else in the folder", again && File.ReadAllBytes(exe).SequenceEqual(program) && File.ReadAllText(Path.Combine(dir, "my-notes.txt")) == "mine" && !File.Exists(exe + ".old"));
            Check("the desktop shortcut and the launch can be switched off", system.Calls.Count(c => c.StartsWith("shortcut")) == 1 && !system.Calls.Any(c => c.StartsWith("launch")));

            // Failures leave the existing install alone, and a running SecHUD is not even stopped.
            File.WriteAllBytes(exe, FakeProgram("older program"));
            system.Calls.Clear();
            servedHash = new string('0', 64);
            bool badDownload = !Installer.Install(new SetupOptions { Dir = dir }, self, null, out version, out error);
            string badError = error;
            Installer.ReleaseFinder = () => { Installer.FindError = "could not reach GitHub"; return null; };
            bool offline = !Installer.Install(new SetupOptions { Dir = dir }, self, null, out version, out error);
            string offlineError = error;
            Installer.ReleaseFinder = () => null;
            bool nothingPublished = !Installer.Install(new SetupOptions { Dir = dir }, self, null, out version, out error);
            Installer.ReleaseFinder = () => new UpdateInfo { Version = "0.9.0", ZipUrl = baseUrl + "SecHUD-v0.9.0.zip" };
            bool unchecked_ = !Installer.Install(new SetupOptions { Dir = dir }, self, null, out version, out error);
            Check("a failed install changes nothing and does not stop a running SecHUD", badDownload && badError.Contains("does not match") && offline && offlineError == "could not reach GitHub" && nothingPublished && unchecked_ && error.Length > 0
                && system.Calls.Count == 0 && File.ReadAllBytes(exe).SequenceEqual(FakeProgram("older program")));

            // Removing it again.
            Installer.ReleaseFinder = () => release;
            servedHash = Updater.Sha256File(zip);
            Installer.Install(new SetupOptions { Dir = dir, NoLaunch = true }, self, null, out version, out error);
            File.WriteAllText(exe + ".old", "left over");
            system.Calls.Clear();
            string data = Path.Combine(scratch, "data");
            Directory.CreateDirectory(data);
            File.WriteAllText(Path.Combine(data, "config.json"), "{}");
            Store.UseDirectory(data);

            Check("the uninstaller finds where SecHUD was installed", Installer.TargetDir(new SetupOptions { Uninstall = true }) == Path.GetFullPath(dir));
            bool removed = Installer.Uninstall(new SetupOptions { Uninstall = true }, null, out error);
            Check("uninstall removes the program, its shortcuts, its startup entry and its Windows entry", removed && !File.Exists(exe) && !File.Exists(exe + ".old") && !File.Exists(Path.Combine(dir, "Uninstall.exe")) && !File.Exists(Path.Combine(dir, "README.md"))
                && system.Calls.SequenceEqual(new[] { "stop", "unstartup", "unshortcut " + Installer.StartMenuShortcut, "unshortcut " + Installer.DesktopShortcut, "unregister" }));
            Check("it only deletes its own files, and keeps your settings unless asked", File.ReadAllText(Path.Combine(dir, "my-notes.txt")) == "mine" && File.Exists(Path.Combine(data, "config.json")));

            File.Delete(Path.Combine(dir, "my-notes.txt"));
            Installer.Install(new SetupOptions { Dir = dir, NoLaunch = true }, self, null, out version, out error);
            bool removedAll = Installer.Uninstall(new SetupOptions { Uninstall = true, Dir = dir, RemoveData = true }, null, out error);
            Check("with nothing else in it the folder goes too, and settings go when asked", removedAll && !Directory.Exists(dir) && !Directory.Exists(data));
            Check("uninstalling when it is not installed is not an error", Installer.Uninstall(new SetupOptions { Uninstall = true, Dir = dir }, null, out error));
        }
        finally
        {
            Store.UseDirectory(realData);
            Installer.Windows = realSystem;
            Installer.ReleaseFinder = realFinder;
            Updater.VersionReader = realReader;
            Updater.Downloader = realDownloader;
        }
    }
}

/// <summary>Stands in for the Windows event log.</summary>

class FakeEvents : IEventSource
{
    public List<RawEvent> Items = new List<RawEvent>();
    public bool DenySecurity;

    public List<RawEvent> Read(string log, int[] ids, DateTime sinceUtc, int max)
    {
        if (DenySecurity && string.Equals(log, Detector.Security, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException();
        return Items.Where(e => string.Equals(e.Log, log, StringComparison.OrdinalIgnoreCase) && ids.Contains(e.Id) && e.TimeUtc >= sinceUtc).ToList();
    }
}
