# What changed

The newest version is at the top. The text under each version is what people see in the app
when an update is available.

## 0.8.5

- Every program on the Ports tab now has an **Ignore program** button, not only flagged ones.
- Settings, under Ignored programs, has **Add a program**: browse to any program and ignore it,
  even when it is not running.

## 0.8.4

- **Ignore a program.** Some programs, such as Plex or a game launcher, open different ports
  every time they run and kept setting off alerts. In Settings, under Ignored programs, pick the
  program and press Ignore. A flagged port on the Ports tab has the same button. Only that exact
  program file is ignored, and Stop ignoring undoes it.
- A new listening port now says who is behind it: the program, whether it is signed, and by whom.

## 0.8.3

- **"Is this safe?" notes.** A new startup item now says what is behind it in plain words:
  who signed the program, whether Windows trusts that signature, and whether it runs from an
  odd place such as a temp folder. The same few words are added to the alert.
- **Guests.** A new setting lists phones and tablets that use a private address as GUEST
  without raising an alert. Off unless you switch it on.
- **Weekly summary.** If Discord alerts are set up, SecHUD sends one message a week with what
  happened, so a quiet week still shows it is working. Settings has a button to see one now.

## 0.8.2

- **An installer.** New here? Under Assets below, download `SecHUD-Setup.exe` and run it. A small
  window downloads SecHUD, installs it, adds Start menu and desktop shortcuts, and starts it.
  There is nothing to unzip. Windows may show a blue "Windows protected your PC" box the first
  time: choose More info, then Run anyway.
- Already have SecHUD? Just press the yellow update button, or run the installer over it. Your
  settings are kept either way.
- SecHUD can now be removed from Installed apps in Windows Settings, like any other program.

## 0.8.1

- **One-click updates.** From this version on, updating is one button. When a new version is
  out, click the yellow UPDATE AVAILABLE button at the top and answer Yes. SecHUD downloads it,
  closes, and opens again by itself.

**Updating to this version is the last time you do it by hand:**

1. On this page, under Assets, click `SecHUD-v0.8.1.zip` to download it.
2. Close SecHUD: right-click its icon near the clock and choose Exit.
3. Open the zip and drag everything in it into your SecHUD folder. Say yes to replacing the files.
4. Start SecHUD again.

## 0.8.0

- **Live watch.** SecHUD no longer waits for the next scan to notice a change on this PC. Windows
  tells it the moment a startup entry, service, scheduled task, account, listening port, firewall
  or antivirus setting changes, and the alert arrives within a second or two.
- **Who made it.** The device list shows the maker of each device, worked out from its MAC
  address. Phones that invent a private address are labelled as such.
- **Watch a device.** Press Watch on a camera, doorbell or NAS and you are alerted when it goes
  offline.
- **Welcome screen.** A first run explains the baseline and offers the Wi-Fi and Discord setup
  before anything is scanned.
- **Restore.** Anything removed with Deny is listed under the Autoruns tab with a Restore button.
- **Quiet hours.** Ordinary Discord alerts can be held overnight and sent as one summary. Urgent
  ones still arrive straight away.
- The window can be resized and maximized, and remembers its size.
- The Proxmox, Router and Logs tabs only appear when those features are switched on.
- Discord now gets every alert from a scan, not only the last one.

## 0.7.0

- First public release.
