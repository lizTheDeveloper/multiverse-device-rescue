---
title: "Review the devices on your network"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - network.lan_device_inventory.lan_inventory
  - network.lan_device_inventory.unrecognised_device
  - network.lan_device_inventory.device_count_exceeded
steps_for:
  network.lan_device_inventory.lan_inventory: [1, 2]
  network.lan_device_inventory.unrecognised_device: [1, 2, 3, 4]
  network.lan_device_inventory.device_count_exceeded: [1, 2, 3, 4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
monitoring_risk: true
---

This walkthrough covers the `lan_device_inventory` check, which lists the
devices that have recently talked to this computer over the local network. A
device you do not recognise, or more devices than you expected, is usually
something of your own that you have not thought of yet: phones, laptops, TVs,
printers, doorbells and smart plugs all count, and twenty is normal now.
Identify each one before treating it as an intruder.

## Step 1: Decide whether this is a safety situation first

If the person who may have joined your network is someone you know (a
partner, an ex, a housemate, a family member), stop and read this before
doing anything else. Cutting off someone's access tells them they have been
found out. If that person has ever frightened you, the safest order of
operations is different from the technical one, and it is worth getting help
planning it.

In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text
START to 88788. The Coalition Against Stalkerware (stopstalkerware.org) lists
services in other countries.

If you have no reason to think it is someone you know, carry on to the next
step. Looking at the list changes nothing.

## Step 2: Check the router's own device list

The list from this check only shows devices that have recently talked to this
computer, so it can be incomplete. The router's own admin page is the full
list. Sign in to the router and open its list of connected devices; it may be
called Attached Devices, Device List, Client List, or DHCP Clients. It shows
devices your computer has not spoken to.

Compare the two lists. Anything on the router's list that you cannot account
for is the thing to focus on. Modern phones use a different, randomised
hardware address for each network, so a phone will not match the address
printed on its box. That is normal privacy behaviour, not an intruder.

## Step 3: Name every device

Go through the list one device at a time and say what each one is out loud:
phone, laptop, TV, printer, thermostat, games console, doorbell, smart plug.
Ask the people in the house whether they added a new phone or gadget. If the
finding names a single device, start with that one.

For anything you cannot name, unplug it or switch it off and run the check
again. The entry that disappears is that device. If every device turns out to
be yours, there is nothing more to do.

## Step 4: If you still cannot account for a device, change the Wi-Fi passphrase

Do this only after Step 1, and only if Steps 2 and 3 left a device you cannot
explain. Do not bother blocking it by its hardware address: an address can be
changed in seconds, and blocking one only tells the intruder which address to
stop using. The change that removes everyone you have not authorised is:

1. Change the Wi-Fi password on the router to a new, long passphrase.
2. Change the router's admin password too, and make it different from the
   Wi-Fi password.
3. Reconnect your own devices with the new password.
4. Run this check again. Anything still present after the change either has
   the new password or is connected by cable.

If unknown devices come back after a password change, the router itself may be
compromised. Factory reset it, update its firmware, and set it up again from
scratch. The walkthrough for securing your home router covers this.
