---
profile: home_network_intrusion
phase: 1
title: "See Who Is On The Network"
automatable_steps: [1, 2]
human_only_steps: [3, 4, 5]
estimated_time: "45 minutes"
---

## Step 1: Inventory the devices on the local network

Run the profile's local-network checks. `lan_device_inventory` lists every
device that has recently talked to this computer, with the manufacturer behind
each hardware address where it can be identified.

Two things to know before reading the list. It only shows devices that have
been active recently, so it can be incomplete — the router's own admin page is
the authoritative list. And modern phones deliberately use a different,
randomly generated hardware address on every network, so a phone will not
match the address printed on its box. That is privacy behaviour, not an
intruder.

## Step 2: Check whether anything is intercepting traffic

`arp_spoof_check` looks for the specific pattern that traffic interception
leaves behind: one device answering for addresses that belong to others,
usually the router's.

If it reports gateway impersonation, treat the network as actively monitored.
Stop using it for anything sensitive until Phase 2 is done — no logins, no
password changes, no banking. Switch to mobile data for those.

Mesh systems and Wi-Fi extenders can produce the same pattern legitimately. If
you have one, that is the likely explanation; confirm it before panicking.

## Step 3: Name every device on the list

Go through the inventory one line at a time and say what each device is out
loud: phone, laptop, TV, printer, thermostat, doorbell, games console, smart
plug. Most households are surprised by the count — twenty is normal now.

For anything you cannot name, unplug or power off a suspected device and
re-run Step 1. The entry that disappears is that device.

## Step 4: Cross-check against the router's own device list

Sign in to the router (Phase 2 covers how) and open its list of connected
devices — it may be called Attached Devices, Device List, Client List, or
DHCP Clients. It shows devices your computer has not spoken to, which the scan
in Step 1 cannot see.

Compare the two lists. Anything on the router's list that you cannot account
for is the thing to focus on.

## Step 5: Do not bother blocking devices by hardware address

Most routers offer MAC filtering, and it feels like the obvious answer. It is
not: a hardware address can be changed in seconds, and blocking one only tells
the intruder which address to stop using.

The change that actually removes everyone you have not authorised is a new
Wi-Fi passphrase, which is Phase 2.
