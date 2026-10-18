---
title: "Secure your home router"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - network.router_security_audit.admin_service_open
  - network.router_security_audit.upnp_enabled
  - network.router_security_audit.router_manual_review
steps_for:
  network.router_security_audit.admin_service_open: [1, 2, 3]
  network.router_security_audit.upnp_enabled: [1, 4]
  network.router_security_audit.router_manual_review: [1, 5]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
monitoring_risk: true
---

This walkthrough covers the `router_security_audit` check. Your router is the
front door to every device in your house, and most of its important settings
can only be seen by signing in to it, so this check reports what it can see
from the network and reminds you of the rest. Most of what it reports is
routine router housekeeping rather than a sign that anyone has been in.

## Step 1: Decide whether this is a safety situation first

If someone close to you (a partner, an ex, a housemate, a family member) may
have set up your router, or may be watching what passes through it, stop and
read this before changing anything. Changing router settings can tell them
they have been found out. If that person has ever frightened you, the safest
order of operations is different from the technical one, and it is worth
getting help planning it.

In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text
START to 88788. The Coalition Against Stalkerware (stopstalkerware.org) lists
services in other countries.

If you are only tidying up your own router, carry on to the next step.

## Step 2: Read the finding for which service it found

This check reports each administration service the router offers to every
device on your network. They are not equally serious, so read which one the
finding names.

If it names an ordinary router admin page (the usual web page you sign in to,
over HTTP or HTTPS), that is informational. It is how the router is normally
managed, and it is not on its own a sign of a problem. If remote
management is also turned on and you don't use it, you can disable that. Make
sure the admin page is protected by a strong, unique password.

If it names a risky service (Telnet, FTP, SSH, or TR-069 remote management),
that is worth acting on. These are services most home routers do not need
reachable from the Wi-Fi. Telnet in particular sends the admin password in
plain text.

## Step 3: Turn off a risky service you do not use

Do this only after Step 1, and only for a risky service the finding named.
Log in to your router's settings and look for the section that controls
remote access or administration. If you do not use remote management, disable
it. If you do, make sure it is protected by a strong, unique password. Turn
off remote/internet administration and "cloud" management too if you do not
use them.

If the setting will not stay off, or settings you did not change reappear, the
router may be compromised. Hold the reset pin for 30 seconds to factory reset
it, then set it up again from scratch. Do not restore a saved configuration
backup, because it restores any unwanted changes along with yours.

## Step 4: Consider turning off UPnP

UPnP lets any program on your network tell the router to open a port to the
internet, with no password and no prompt. Malware uses it to make an infected
computer reachable from outside.

Log in to your router's settings (usually by typing 192.168.1.1 or 192.168.0.1
into a web browser; check the sticker on your router) and look for a setting
named UPnP or Universal Plug and Play. Turning it off is a real trade-off:
games consoles, some video-call software, and torrent clients rely on it and
may warn about a "strict NAT" afterwards. If you turn it off, first check the
Port Forwarding or NAT section and delete any rule you did not create. Those
are the holes UPnP already opened.

## Step 5: Work through the settings this check cannot see

Open your router's admin panel (usually http://192.168.1.1 or
http://192.168.0.1; check the sticker on the router). If you can, do this from
a computer connected by cable.

1. Check for firmware updates and install them first. Router vulnerabilities
   are actively exploited, and the later steps do not help if a known
   vulnerability is still present.
2. Change the admin password from the default to something strong and unique,
   different from the Wi-Fi password. If it is still the one printed on the
   router, treat the router as already compromised.
3. Change your Wi-Fi password if it is the default one printed on the router.
   Set security to WPA3, or WPA2-AES if WPA3 is not offered. Never WEP, never
   WPA/TKIP, never open.
4. Disable WPS (Wi-Fi Protected Setup). It has a known brute-force
   vulnerability and defeats a strong Wi-Fi password.
5. Turn off UPnP (a setting named UPnP or Universal Plug and Play). It lets
   any program on your network ask the router to open a port to the internet
   with no password. Games consoles and some video-call software rely on it,
   so you may see a "strict NAT" warning afterwards. Delete any port-forwarding
   rule you did not create.
6. Check the DNS servers on the router's WAN or Internet page. If they are not
   your provider's or a resolver you chose (for example 9.9.9.9 or 1.1.1.1),
   someone may have redirected your household's browsing; reset them.
7. Delete port-forwarding rules and any "DMZ host" you did not create.
8. Check the guest network: leaving it open with no password is an unlocked
   back door onto the same hardware.
9. Reboot the router, then run this check again.

If the settings will not stick, or unwanted settings reappear, hold the reset
pin for 30 seconds to factory reset the router, then set it up again from
scratch. Do not restore a saved configuration backup, because it restores any
unwanted changes along with yours.
