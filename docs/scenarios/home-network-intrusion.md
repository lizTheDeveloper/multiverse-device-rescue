# Home network intrusion

**`home_network_intrusion`** — 14 modules, a 6-phase guide.

## Who this is for

Someone got onto your home Wi-Fi, or you think they might have. Or your machine
has become inexplicably slow and hot, which is often cryptomining. The two
problems arrive together often enough that this profile covers both: an
intruder on the network, and the mining and monitoring software that tends to
come with them.

!!! danger "Read this before you start"
    The guide's very first step is *"Decide whether this is a safety situation
    first."* If the person who may have got in is someone you know — a partner,
    an ex, a family member, a housemate — then changing the Wi-Fi password
    tells them you know. That can escalate a dangerous situation, and the
    safety plan comes before the technical cleanup.

    In the US: National Domestic Violence Hotline, 1-800-799-7233.
    Internationally: <https://stopstalkerware.org>. Please read Phase 0 before
    Phase 1.

## What to run

```console
$ rescue --auto --profile home_network_intrusion
$ rescue guide home_network_intrusion
```

Before you run the network inventory, count your devices. Every phone, laptop,
tablet, TV, speaker, console, printer, smart plug, doorbell, and thermostat.
The inventory can only tell you "there are eleven things here" — only you can
say whether eleven is the right number.

## The order matters, and it is not the obvious one

The profile is deliberately sequenced: **reclaim the network, then clean the
devices, then change the passwords.** Its own description says why — *"a
cleaned device rejoining a compromised network is compromised again"*, and a
password changed while someone is still on the network is a password they
watched you set.

Most people's instinct is to change the Wi-Fi password first. That is Phase 2,
not Phase 1, and account passwords are Phase 4.

## What the tool does

Fourteen read-only checks in three groups.

**The network — who is on it, and is anyone intercepting?**

| Module | What it answers | Platforms |
| --- | --- | --- |
| `lan_device_inventory` | What is actually on the local network | macOS, Windows, Linux |
| `arp_spoof_check` | Is something intercepting local traffic | macOS, Windows, Linux |
| `router_security_audit` | What administrative services the router exposes | macOS, Windows, Linux |
| `wifi_security_audit` | Encryption and configuration of the wireless network | macOS |

**Cryptojacking — what is running, what restarts it, and the browser.**

| Module | What it answers | Platforms |
| --- | --- | --- |
| `crypto_miner_detect` | Is a miner running | macOS |
| `win_crypto_miner_detect` | Is a miner running | Windows |
| `crypto_miner_persistence` | What brings the miner back after you kill it | macOS, Windows, Linux |
| `browser_cryptojacking_check` | Is a page or extension mining in your browser | macOS, Windows, Linux |
| `process_scanner` | What is running, against a known-unwanted list | macOS, Windows, Linux |

**Access to the machine itself.**

| Module | What it answers | Platforms |
| --- | --- | --- |
| `stalkerware_scan` | Is monitoring software installed | macOS, Windows, Linux |
| `remote_login_check` | Is remote access enabled, who is logged in | macOS |
| `win_remote_access_audit` | Remote Desktop and remote-access tooling | Windows |
| `suspicious_connections` | Unexpected outbound connections | macOS |
| `open_ports_scan` | What this machine is listening on | macOS |

`crypto_miner_persistence` is the one to read carefully. Killing a miner is
easy and pointless on its own — the startup entry that relaunches it is the
actual problem, which is why the guide's Phase 3 does them in that order.

## What stays human-led

Nearly all of the recovery, because most of it happens in the router's admin
interface and at your providers.

- Signing in to the router, ideally over a cable.
- Updating router firmware — first, before any settings change, because a
  firmware update can reset settings.
- Changing the admin password and the Wi-Fi passphrase.
- Turning off WPS, remote administration, port forwarding, DMZ, guest network.
- Checking the router's DNS servers.
- Factory-resetting the router if settings will not stick.
- Naming every device on the inventory list.
- Deciding a device is beyond cleaning and reinstalling it.

The tool tells you what the router is exposing and what is on the network. It
does not log in to your router and never asks for its password.

## The phases

| Phase | Title | Time | What happens |
| --- | --- | --- | --- |
| 0 | Before You Touch Anything | 15 min | Is this a safety situation? · Write down what made you suspicious · Find a device and network you can trust · Understand the order and why |
| 1 | See Who Is On The Network | 45 min | **Inventory local devices** · **Check for interception** · Name every device · Cross-check the router's own list · Why blocking by MAC address is not worth it |
| 2 | Take The Router Back | 1 hr | **Audit what the router exposes** · Sign in over a cable · Firmware first · Change admin password and passphrase · Turn off WPS · Turn off remote admin, check DNS · Clear port forwarding, DMZ, guest network · Factory reset if needed |
| 3 | Clean The Devices | 1–2 hr per device | **Look for mining** · **Find what restarts it** · **Check the browser** · **Check who else has access** · Remove in the right order · Every device, not just the interesting one · Consider a clean reinstall |
| 4 | Rebuild Accounts And Keep Them Out | 2 hr, then 15 min/month | *Only now* change passwords · 2FA starting with email · Sign out everything else · Accounts attached to the house, not just to you · Separate what needn't be together · Set a date to check again |
| 5 | Resources, Tiplines, And Free Help | reference | Do not call a support number you found by searching · If the person is someone you know · Free expert help · Where to report · If money was touched, switch guides · Understanding the equipment |

Phase 5's first step is worth reading even if you skip the rest: search adverts
for "router support" and "remove virus" are bought by scammers, and calling one
while you are already compromised is how a bad day becomes a much worse one.

## What it will never ask you for

Your router's admin password, your Wi-Fi passphrase, your account passwords, or
any one-time code. The router audit probes what the router exposes to the
network; it does not sign in. Everything inside the router's admin interface is
done by you, in your browser.

## Afterwards

```console
$ rescue export --profile home_network_intrusion
```

If money or accounts were touched, switch to
[identity theft recovery](identity-theft-recovery.md) — Phase 5 says the same.
