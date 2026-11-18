using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using SecHUD;

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
