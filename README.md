# SecHUD

A home network security monitor for Windows, written from scratch in C# (WPF, .NET Framework 4.8).
No third-party libraries and no NuGet packages.

Use it only on a network you own or have permission to monitor.

## Install

1. Download the newest `SecHUD-v*.zip` from the [Releases page](https://github.com/sivadyt/SecHUD/releases/latest).
2. Unzip it anywhere and run `SecHUD.exe`. There is no installer.

Windows may show "Windows protected your PC" the first time, because the program is not signed
with a paid certificate. Choose More info, then Run anyway. If you would rather not trust a
downloaded exe, build it yourself from this source (see Build and run).

It needs Windows 10 or 11. Everything it stores stays on your PC under `%LOCALAPPDATA%\SecHUD`.
To remove it, turn off Start with Windows in Settings, exit from the tray, then delete the
program folder and that data folder.

## Updates

About once a day SecHUD asks GitHub whether a newer release exists. If there is one, an
UPDATE AVAILABLE button appears at the top with what changed. It opens the download page: unzip
the new version over the old one and start it again. Your settings and baselines are kept.

The check sends nothing about you or your network, never installs anything by itself, and can
be switched off in Settings.

## What it watches

| Area | Check |
|---|---|
| This PC | Which antivirus is active (asks Windows Security Center, so a third-party product counts) |
| This PC | Firewall profiles (domain, private, public) |
| This PC | Failed logins in the last 24 hours (event 4625) |
| This PC | Listening TCP ports and the process behind each, against a baseline |
| This PC | Autoruns: Run keys, startup folders, services and scheduled tasks, against a baseline |
| This PC | Local accounts and Administrators membership, compared between scans |
| This PC | Detection rules over Windows events, tagged with MITRE ATT&CK techniques |
| Network | Every device on the LAN, found by ARP sweep and tracked by MAC address |
| Network | The gateway's MAC address (a change is the classic sign of ARP spoofing) |
| Network | The DNS servers this PC uses (a change nobody made is how DNS hijacking shows up) |
| Network | Access points broadcasting your Wi-Fi name (a new one may be an evil twin) |
| Network | Ports the router forwards from the internet, read over UPnP |
| Network | Watched hosts: reachable or not, and days left on the TLS certificate |
| Network | Proxmox node and guests through its API (optional) |
| Network | Syslog from other devices, with a password-guessing rule (optional) |

The first scan becomes the baseline. After that, anything new flips the status to ELEVATED until
you approve it. Every change is appended to `events.log`.

## Detection rules

| Event | Meaning | ATT&CK | Level |
|---|---|---|---|
| Security 4720 | Local user account created | T1136.001 | high |
| Security 4732 | Account added to Administrators | T1098 | high |
| Security 1102, System 104 | Event log cleared | T1070.001 | high |
| Security 4698 | Scheduled task created | T1053.005 | medium |
| System 7045 | New service installed | T1543.003 | medium |
| Security 4624 type 10 | Remote desktop logon | T1021.001 | info |
| Defender 1116 | Malware detected | | high |
| Defender 5001 | Real-time protection disabled | T1562.001 | high |
| Account watch | New local account, or new Administrators member | T1136.001, T1098 | high |
| Syslog | 5 login failures from one source in 10 minutes | T1110 | high |
| Autoruns | New Run key or startup item | T1547.001 | high |
| Gateway | Gateway MAC address changed | T1557.002 | high |
| DNS | DNS servers changed | T1557 | high |
| Wi-Fi | New access point using your network name | T1557.004 | high |
| Router | New port forward | | high |

High detections stay open, and keep the status ELEVATED, until you dismiss them. Every flagged
row has its own Approve or Dismiss button. Approve all accepts everything at once.

Flagged autoruns also have a Deny button, which removes the item from Windows after asking you
to confirm. Nothing is thrown away: a Run entry is logged with its command, a startup file is
moved, and a scheduled task is exported as XML, all under `removed-autoruns` in the data folder.
Items under HKLM need SecHUD started as administrator, and services are left to you.

### Your own rules

Settings has an Edit my rules button that opens `rules.json`. Each entry is one detection:

    {
      "enabled": true,
      "log": "Security",
      "id": 4728,
      "contains": "",
      "technique": "T1098",
      "severity": "high",
      "message": "member added to a global security group"
    }

`contains` is optional text the event must include. `severity` is high, medium or info. Rules
are re-read on every scan, so there is nothing to rebuild.

## Build and run

Double-click `build.cmd`, or run `dotnet build -c Release` and start `bin\Release\SecHUD.exe`.
You can also open `SecHUD.csproj` in Visual Studio and press F5.

Closing the window hides it to the system tray so it keeps watching. Exit is in the tray menu.

## Prove it works

`tests\live-test.cmd` does two harmless things an attacker would do, waits while you watch SecHUD
catch them, then undoes both: a new startup entry (T1547.001) and, when run as administrator, a
new disabled local account (T1136.001).

`run-tests.cmd` builds and runs the automated tests. They cover the detection rules, baselines,
parsers and the window's logic using fake inputs and a temporary folder, so they never touch
your real data or send anything.

## Publishing a release (for the maintainer)

1. Raise `<Version>` in `SecHUD.csproj`.
2. Run `release.cmd`. It builds, runs the tests, and writes `release\SecHUD-v<version>.zip` with its SHA-256.
3. On GitHub, draft a new release with the tag `v<version>`, describe what changed, attach the zip and publish.

The tag is what installed copies compare with their own version, so it has to match.

## Tabs

| Tab | What it shows |
|---|---|
| Devices | Every device seen. Click a name to rename it. Ports checks which common services a device offers. |
| Ports | Listening ports on this PC and their processes |
| Autoruns | Everything that starts by itself, new items first |
| Router | Your public address and every port the router forwards inward |
| Proxmox | Node load and the state of each VM and container |
| Events | The event log with ATT&CK tags, searchable |
| Logs | Syslog lines received from other devices, searchable |
| History | Devices online, alerts and status per hour for the last day, plus host uptime |
| Settings | Everything configurable, including Discord alerts and Start with Windows |

Export report (bottom right) saves an HTML report to `Documents\SecHUD Reports`.

## Optional setup

**Failed logins and Security-log rules.** Reading the Security log needs membership in the built-in
Event Log Readers group. Run this once in an admin PowerShell, then sign out and back in:

    Add-LocalGroupMember -Group "Event Log Readers" -Member $env:USERNAME

Without it those rows show `NO ACCESS` or `PARTIAL` and everything else still works. New accounts
and new administrators are caught either way, because those are found by comparing the account
list, not by reading the log. A log that could not be read keeps its place, so once you grant
access the events missed in the meantime (up to two days) are still reported.

**Discord alerts.** In Discord: channel settings, Integrations, Webhooks, New Webhook, Copy Webhook
URL. Paste it in Settings and press Send test.

**Proxmox.** In Proxmox: Datacenter, Permissions, API Tokens, Add. Give the token the PVEAuditor
role (read-only). Enter the host, the token ID (for example `root@pam!sechud`) and the secret in
Settings. The first certificate the app sees is remembered, and a different one later is refused
and reported.

**Syslog.** Turn it on in Settings, then on the Linux box add one line to
`/etc/rsyslog.d/90-sechud.conf` (use this PC's address) and restart rsyslog:

    *.* @192.168.1.50:514

**Wi-Fi twin check.** If this PC is on a cable, type your Wi-Fi name in Settings. A mesh system or
extender legitimately shows up as extra access points: approve them once. On recent Windows 11
builds the check needs Location services switched on, or the row reads `NEEDS LOCATION`.

## Data

Everything is plain JSON or text under `%LOCALAPPDATA%\SecHUD`:

| File | Purpose |
|---|---|
| `config.json` | Settings. Secrets inside are encrypted with Windows DPAPI for your account |
| `devices.json` | Known devices, their names, approved or not |
| `known-ports.json`, `known-autoruns.json`, `known-accounts.json`, `known-forwards.json`, `known-access-points.json` | Baselines |
| `removed-autoruns\` | What Deny took out, kept so it can be put back |
| `rules.json` | Your own detection rules |
| `events.log` | One JSON object per line |
| `history.csv` | One line per scan |
| `syslog.log` | Received syslog lines |

## Known limits

- Scheduled tasks under `\Microsoft\Windows\` are not tracked, because Windows adds and removes its
  own tasks there constantly.
- Services and tasks are tracked by name, so a changed binary path on an existing service is not flagged.
- The Ports check on a device tries about 30 common ports, not all 65535.
- The router list needs UPnP switched on in the router. Many ship with it off, and the row then reads `NO UPNP`.
- Switching a VPN on can change the DNS servers. Approve the new setting once and both are trusted.
- SecHUD runs as a normal user and never asks for admin.

## What it sends

ARP requests on your own private subnet (never a public range, never more than 1022 addresses),
a TCP connect to the hosts you list, a port check of a LAN device only when you click Ports, one
UPnP search on the LAN and a few requests to your own router, and alerts to your Discord webhook
if you set one, plus one request a day to GitHub for the latest version number. Nothing else
leaves your network. Exported reports leave out your public address.

## Layout

| Path | Contents |
|---|---|
| `Core/Scanner.cs` | Runs every check and detects changes |
| `Core/Detections.cs` | Windows event rules and ATT&CK mapping |
| `Core/Autoruns.cs`, `Core/Accounts.cs`, `Core/Antivirus.cs` | Persistence, account and antivirus checks |
| `Core/Syslog.cs`, `Core/Proxmox.cs`, `Core/Discord.cs`, `Core/PortScanner.cs` | Network integrations |
| `Core/Wifi.cs`, `Core/Upnp.cs` | Wi-Fi access points and router port forwards |
| `Core/Updater.cs` | The check for a newer release |
| `Core/History.cs`, `Core/Report.cs` | History file, charts data and HTML export |
| `Core/Store.cs`, `Core/Secrets.cs`, `Core/Models.cs` | Storage, DPAPI secrets, data types |
| `Core/Native.cs` | The two Windows API calls (SendARP, GetExtendedTcpTable) |
| `Core/ViewModels.cs` | What the window binds to, and the scan loop |
| `MainWindow.xaml`, `App.xaml` | The window and its theme |
| `tests/` | Automated tests and the live test script |
| `release.cmd`, `tools/` | Builds the zip for a GitHub release |
