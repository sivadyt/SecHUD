# What changed

The newest version is at the top. The text under each version is what people see in the app
when an update is available.

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
