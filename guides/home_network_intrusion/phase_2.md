---
profile: home_network_intrusion
phase: 2
title: "Take The Router Back"
automatable_steps: [1]
human_only_steps: [2, 3, 4, 5, 6, 7, 8]
estimated_time: "1 hour"
---

## Step 1: Audit what the router is offering to the network

Run `router_security_audit`. It checks which administrative services your
router is offering to every device on the Wi-Fi — remote login services, the
admin page, provider management interfaces — and whether UPnP is enabled.

Everything after this step happens in the router's own settings, because the
settings that decide whether someone can get back in are not visible from
outside it.

## Step 2: Sign in to the router, ideally over a cable

Connect a computer to the router with an Ethernet cable if you can, so the
next steps do not travel over a network someone else may be watching. Then
open the gateway address the audit reported in a browser.

If the admin password is still the one printed on the underside of the router,
assume the router has already been reconfigured by someone else, and read
every setting below rather than trusting any of them.

## Step 3: Update the firmware first

Look for Firmware Update, Router Update, or Administration. Install whatever
is offered and let it reboot.

Do this before anything else. If the router has a known vulnerability, new
passwords do not help — the way in was never the password.

## Step 4: Change the admin password and the Wi-Fi passphrase

Two different passwords, both long, neither used anywhere else:

- The **admin password** protects the router's settings.
- The **Wi-Fi passphrase** is what devices use to join.

Set the wireless security mode to WPA3. If the router does not offer it,
WPA2-AES (sometimes shown as WPA2-PSK AES) is acceptable. Never WEP, never
WPA/TKIP, never open — those are broken and can be cracked in minutes by
someone parked outside.

## Step 5: Turn off WPS

WPS lets a device join using an eight-digit PIN instead of the passphrase, and
that PIN can be broken offline. Leaving it on makes the strong passphrase you
just set irrelevant. Turn it off.

## Step 6: Turn off remote administration, and check the DNS servers

Find Remote Management, Remote Access, Web Access from WAN, or cloud
management, and turn it off. The router's settings should only be reachable
from inside the house.

Then open the Internet or WAN page and look at the DNS servers. They should be
your provider's, or a resolver you deliberately chose (for example 1.1.1.1 or
9.9.9.9). Anything else means someone redirected every device in the house to
a name server they control — every phone, TV, and laptop, without touching any
of them. Reset it if it is not what you expect.

## Step 7: Clear out port forwarding, DMZ, and the guest network

Delete every port-forwarding rule you did not create yourself, and switch off
any "DMZ host". These are open doors from the internet to a specific device
inside the house, and UPnP can create them automatically on a program's
request.

Check the guest network too. An open guest network with no password is a
second way onto the same hardware.

## Step 8: If the settings will not stick, factory reset

If changes do not save, or old settings reappear, the router itself is
compromised. Hold the reset pin for 30 seconds to factory reset it, then set it
up again from scratch.

Do not restore a saved configuration backup — that restores the intruder's
changes along with yours. Set it up by hand.

When the router is done, re-run Step 1 and Phase 1 to confirm the network
looks the way you expect.
