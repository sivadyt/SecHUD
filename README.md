# SecHUD

A home network security monitor for Windows, written from scratch in C# (WPF, .NET Framework 4.8).
No third-party libraries and no NuGet packages.

Use it only on a network you own or have permission to monitor.

## How it works, in one example

1. Something adds itself to the Windows startup list. That is one of the most common ways
   malware makes sure it comes back after a reboot (MITRE ATT&CK T1547.001).
2. Windows tells SecHUD the Run key changed. SecHUD re-checks this PC, compares the startup list
   with the baseline it took on day one, and finds one entry it has never seen.
3. A second or two later the status reads ELEVATED, the entry is at the top of the Autoruns tab
   marked NEW, the event is logged with its ATT&CK technique, and your phone buzzes with the
   Discord alert.
4. You decide. Approve if it is something you installed. Deny removes it from Windows and
   keeps a record, so Restore can put it back if you change your mind.

`tests\live-test.cmd` runs exactly this, plus a new user account, so you can watch it happen.

## Install

1. Download [SecHUD-Setup.exe](https://github.com/sivadyt/SecHUD/releases/latest/download/SecHUD-Setup.exe).
2. Run it and press Install.

That is all. A small window downloads the newest version, installs it for you, adds Start menu
and desktop shortcuts, and starts it. There is nothing to unzip and no administrator password
is needed. Running the installer again later updates or repairs an existing copy and keeps
your settings.

Windows may show "Windows protected your PC" the first time, because the program is not signed
with a paid certificate. Choose More info, then Run anyway. If you would rather not trust a
downloaded exe, build it yourself from this source (see Build and run).

It needs Windows 10 or 11. The program goes in `%LOCALAPPDATA%\Programs\SecHUD`, and everything
it stores stays on your PC under `%LOCALAPPDATA%\SecHUD`. To remove it, open Installed apps in
Windows Settings, find SecHUD and choose Uninstall. You are asked whether to keep your settings.

Prefer to do it by hand? The [Releases page](https://github.com/sivadyt/SecHUD/releases/latest)
also has `SecHUD-v*.zip`: unzip it anywhere and run `SecHUD.exe`.

## Updates

About once a day SecHUD asks GitHub whether a newer release exists. If there is one, a yellow
UPDATE AVAILABLE button appears at the top. Click it, answer Yes, and SecHUD downloads the new
version, closes, and opens again by itself a few seconds later. Your settings and baselines are
kept. There is nothing to unzip and nothing to find.

How it stays safe:

- Nothing is downloaded or installed until you click the button and say yes.
- The download only ever comes from this project's releases on github.com, over HTTPS.
- It is only used if its SHA-256 matches the checksum published with the release, and the
  program inside is exactly the version the release says it is.
- Only the program's own files are replaced. The old ones are set aside first, so if anything
  goes wrong part way they are put straight back.
- If the update cannot be installed for any reason (no internet, a folder SecHUD may not write
  to), it says why and opens the download page instead.

The check itself sends nothing about you or your network and can be switched off in Settings.

Versions 0.7.0 and 0.8.0 do not have this yet. Their button opens the download page: download
`SecHUD-Setup.exe` from it and run it. It closes the old copy, installs the new one and starts
it, and from then on updates are one click.

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

## Ignoring a program

A media server, a game launcher or a sync tool can open a different port every time it runs.
Approving ports one by one never ends, so you can ignore the program instead:

- In Settings, under Ignored programs, every program that has a port open right now is listed.
  Press Ignore next to it.
- Or on the Ports tab, press Ignore program on that program's row.
- For a program that is not running right now, press Add a program in Settings and browse to it.

You are asked first and shown who signed the program. From then on no port it opens is
flagged. The rule matches the full path of the program file, so something that only borrows
the name from another folder (a favourite trick of malware) is still flagged. Stop ignoring,
in the same place, undoes it. Everything else about that program is still watched: if it adds
itself to startup, you still hear about it.

### Router forwards

Ignoring a program covers the ports it opens on this PC. A port it asks the *router* to open is
a separate thing, listed on the Router tab, and each forward there has two more buttons:

- **Deny** asks the router to close that port, so it stops being reachable from the internet.
  If the program is still running it may ask again, so the lasting fix is to switch the feature
  off in the program itself (in Plex: Settings, Remote Access). Some routers only let the device
  that opened a forward close it, and SecHUD tells you when that happens.
- **Ignore** stops flagging forwards with that name, for a program that asks for a new port
  each time. Know the limit: the router takes each program's word for the name. When the router
  also says which device a forward goes to, the rule is tied to that device. When it does not
  (some answer 0.0.0.0), anything on your network using the same name is ignored too.

## Live watch

A full scan runs every two minutes (you can change that). Between scans the live watch lets
Windows report changes on this PC as they happen, and SecHUD re-checks the PC straight away:

| What | How it is noticed |
|---|---|
| Run keys, the service list, scheduled tasks | Windows registry change notifications |
| Firewall profiles, Defender settings, DNS settings | Windows registry change notifications |
| The two Startup folders | File change notifications |
| Events the detection rules use | A subscription to those event logs |
| Listening ports | Compared every two seconds |
| Local accounts and administrators | Compared every two seconds |

A burst of changes (an installer writing several keys) is handled as one check. If something
keeps changing without pause, the checks slow down so SecHUD never becomes the busy program.
New devices on the network are found by the ARP sweep, so those still appear on the next scan.
Live watch can be switched off in Settings.

## Devices

The device list shows who made each device, worked out from the first half of its MAC address
using the public IEEE registry (packed into the exe, nothing is looked up online). Phones,
tablets and laptops often invent an address for each network to make tracking harder. Those
read PRIVATE ADDRESS, because no maker owns them.

Have visitors often? Settings has "Treat phones with a private address as guests". With it on,
a new private-address device is listed as GUEST without an alert, and it drops off the list a
week after it was last seen. It is off by default, because a stranger's phone looks the same
as a friend's. Approve a guest to keep it as a known device.

Press Watch on a device you care about, such as a camera, doorbell or NAS. If it misses two
sweeps in a row you get an alert, and another line when it is back. Phones go quiet whenever
they sleep, so watching one mostly tells you when its screen is off.

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

A new startup item also gets a short note saying what SecHUD could find out about the program
behind it:

| Note | What it means |
|---|---|
| Signed by (name), and Windows trusts the signature | The maker is known. Cyan. |
| Not signed | Nobody vouches for it. Common for small hobby programs. Yellow. |
| Not signed, and it runs from a temp folder | Programs you installed on purpose rarely look like this. Red. |
| The signature is broken | The file was changed after it was signed. Red. |
| Starts powershell.exe (or cmd, rundll32, mshta...) | A Windows tool that runs whatever the rest of the command says. The signature tells you nothing here, so read the command. Yellow. |
| A script, not a program | Scripts cannot be signed this way. Open it in Notepad. |
| The file it points to is not there | Usually left over from something that was removed. |

A signature shows who made a program, not that the program is good, so treat the note as one
clue. For shortcuts, services and scheduled tasks the note is about the program they really
run. The check is done by Windows itself and nothing is looked up online.

Flagged autoruns also have a Deny button, which removes the item from Windows after asking you
to confirm. Nothing is thrown away: a Run entry is recorded with its command, a startup file is
moved, and a scheduled task is exported as XML, all under `removed-autoruns` in the data folder.
Denied items are listed under the Autoruns tab with a Restore button that puts them back exactly
as they were. Items under HKLM need SecHUD started as administrator, and services are left to you.

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

Double-click `build.cmd`, or run `dotnet build SecHUD.csproj -c Release` and start
`bin\Release\SecHUD.exe`. You can also open `SecHUD.csproj` in Visual Studio and press F5.
`build-setup.cmd` builds the installer into `setup\bin\Release\SecHUD-Setup.exe`.

Closing the window hides it to the system tray so it keeps watching. Exit is in the tray menu.

## Prove it works

`tests\live-test.cmd` does two harmless things an attacker would do, waits while you watch SecHUD
catch them within seconds, then undoes both: a new startup entry (T1547.001) and, when run as
administrator, a new disabled local account (T1136.001).

`tests\update-test.cmd` tries the update button for real. It copies your build to a temporary
folder and starts it with `--test-update`, which offers the latest release whatever version the
copy is. Click the button and watch it download, close and reopen.

`run-tests.cmd` builds and runs the automated tests. They cover the detection rules, baselines,
parsers and the window's logic using fake inputs and a temporary folder, so they never touch
your real data or send anything.

## Publishing a release (for the maintainer)

Every push to GitHub is built and tested there on a clean Windows machine (the Actions tab shows
the result). Publishing is a separate step, so nothing reaches other people by accident:

1. Raise `<Version>` in `SecHUD.csproj` and add a section for it at the top of `CHANGELOG.md`.
   That section becomes the release text people see in the app.
2. On GitHub open Actions, pick "Build and release", and press Run workflow.

GitHub builds the exe and the installer, runs the tests, does a real install and uninstall on
its own machine, and publishes the release with the tag `v<version>`. Installed copies compare that tag with their own version, so everyone on an older
one sees UPDATE AVAILABLE within a day. Pushing a tag such as `v0.8.0` does the same thing.

`release.cmd` still makes the same zip on your own PC, for trying a build before publishing it.

## Tabs

| Tab | What it shows |
|---|---|
| Devices | Every device seen, with its maker. Click a name to rename it. Watch alerts you when it goes offline. Ports checks which common services it offers. |
| Ports | Listening ports on this PC and their processes |
| Autoruns | Everything that starts by itself, new items first, and what you denied with a Restore button |
| Router | Your public address and every port the router forwards inward (shown when the router check is on) |
| Proxmox | Node load and the state of each VM and container (shown once a Proxmox host is set) |
| Events | The event log with ATT&CK tags, searchable |
| Logs | Syslog lines received from other devices, searchable (shown when syslog intake is on) |
| History | Devices online, alerts and status per hour for the last day, plus host uptime |
| Settings | Everything configurable, including Discord alerts and Start with Windows |

Export report (bottom right) saves an HTML report to `Documents\SecHUD Reports`. The window can
be resized or maximized, and it opens at the size you left it.

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

**Weekly summary.** With a webhook saved, SecHUD sends one message a week: the status, how many
alerts there were and of what kind, anything still waiting for you, and how many devices were
around. A monitor that is working well is silent for days, and this is how you know it has not
simply stopped. The first one arrives a week after you set it up. Send summary now in Settings
shows you one straight away, and the checkbox next to it switches the weekly one off.

**Quiet hours.** Switch them on in Settings and give a start and end time (24-hour clock, for
example 23:00 until 07:00). Ordinary alerts, such as a new device or startup item, are held and
sent as one summary when quiet hours end. Urgent ones still arrive straight away: protection
switched off, a new account or administrator, cleared logs, malware, and tampering with the
gateway, DNS or Wi-Fi. Quiet hours only affect Discord. The app itself always shows everything.

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
| `removed-autoruns\` | What Deny took out, kept so Restore can put it back |
| `window.json` | The window size |
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
- The live watch covers this PC. A new device on the network is found by the next sweep, not instantly.
- A firewall or antivirus change is noticed live through the registry. If a product keeps its
  switch somewhere else, the change is found on the next scan.
- The maker list is a snapshot of the IEEE registry, so a very new maker can show up blank.
- SecHUD runs as a normal user and never asks for admin.

## What it sends

ARP requests on your own private subnet (never a public range, never more than 1022 addresses),
a TCP connect to the hosts you list, a port check of a LAN device only when you click Ports, one
UPnP search on the LAN and a few requests to your own router (including a request to close a
forward when you press Deny on it), and alerts to your Discord webhook
if you set one, plus one request a day to GitHub for the latest version number. Nothing else
leaves your network. Exported reports leave out your public address.

## Layout

| Path | Contents |
|---|---|
| `Core/Scanner.cs` | Runs every check and detects changes (full scans and live checks) |
| `Core/LiveWatch.cs` | Asks Windows to report changes as they happen |
| `Core/Detections.cs` | Windows event rules and ATT&CK mapping |
| `Core/Autoruns.cs`, `Core/Accounts.cs`, `Core/Antivirus.cs` | Persistence, account and antivirus checks |
| `Core/Syslog.cs`, `Core/Proxmox.cs`, `Core/Discord.cs`, `Core/PortScanner.cs` | Network integrations |
| `Core/Wifi.cs`, `Core/Upnp.cs` | Wi-Fi access points and router port forwards |
| `Core/Vendors.cs`, `Data/oui.gz` | Device makers by MAC address (the public IEEE registry) |
| `Core/Quiet.cs`, `Core/Summary.cs` | Quiet hours and the weekly summary for Discord |
| `Core/Trust.cs` | The "is this safe?" note: signatures and file locations |
| `Core/Updater.cs` | The check for a newer release, and the one-click update |
| `Core/History.cs`, `Core/Report.cs` | History file, charts data and HTML export |
| `Core/Store.cs`, `Core/Secrets.cs`, `Core/Models.cs` | Storage, DPAPI secrets, data types |
| `Core/Native.cs` | The few Windows API calls .NET has no wrapper for |
| `Core/ViewModels.cs` | What the window binds to, and the scan loop |
| `MainWindow.xaml`, `App.xaml` | The window and its theme |
| `tests/` | Automated tests and the live test script |
| `setup/` | SecHUD-Setup.exe: the installer and uninstaller |
| `release.cmd`, `tools/` | Builds the zip on your own PC |
| `.github/workflows/release.yml`, `CHANGELOG.md` | Builds, tests and publishes releases on GitHub |
