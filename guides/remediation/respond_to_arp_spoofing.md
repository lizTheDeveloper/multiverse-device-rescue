---
title: "Respond to a device answering for your router"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - network.arp_spoof_check.gateway_impersonation
  - network.arp_spoof_check.duplicate_mac
  - network.arp_spoof_check.locally_administered_gateway
  - network.arp_spoof_check.multiple_gateways
steps_for:
  network.arp_spoof_check.gateway_impersonation: [1, 2, 3]
  network.arp_spoof_check.duplicate_mac: [1, 2, 3]
  network.arp_spoof_check.locally_administered_gateway: [1, 2]
  network.arp_spoof_check.multiple_gateways: [1, 4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
monitoring_risk: true
---

This walkthrough covers the four things the `arp_spoof_check` module can
flag: your router's hardware address also answering for other devices, one
hardware address claiming several devices, a router with a software-chosen
hardware address, and a computer set to send traffic through more than one
router. Each one has innocent explanations (Wi-Fi extenders, mesh systems,
virtual machines, a VPN), so identify the device before treating it as an
attack.

## Step 1: Decide whether this is a safety situation first

Stop and read this before changing anything. It matters most if the person
who may have set this up is someone you know (a partner, an ex, a housemate, a
family member). Cutting off someone's access tells them they have been found
out. If the person who may have set this up has ever frightened you, the
safest order of operations is different from the technical one, and it is
worth getting help planning it.

In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text
START to 88788. The Coalition Against Stalkerware (stopstalkerware.org) lists
services in other countries.

If it is a stranger, a neighbour, or you have no idea, carry on to the next
step. If the finding said another device is answering for your router, do
not sign in to anything, and do not change any passwords while connected to
this network in the meantime. Switch to a phone's mobile data for anything
that matters; mobile data is not on this network.

## Step 2: Confirm from the router itself

If the finding said your router's hardware address was being used by other
devices, or that the router's address looks fake: look at the label on the
underside of the router, or its admin page, and compare the hardware (MAC)
address printed there with the address the finding reported. If they differ,
another device is impersonating the router and everything you send is passing
through it first.

If the finding said one hardware address was claiming several devices, it is
low confidence: virtual machines and some network gear do this legitimately.
Identify which device it is before treating it as an attack.

Then open the router's own list of connected devices. It may be called
Attached Devices, Device List, Client List, or DHCP Clients. It is the
authoritative list, and it shows devices your computer has not spoken to.
Compare it with what you own and say what each device is out loud. Anything
you cannot account for is the thing to focus on.

One caution: some mesh systems and Wi-Fi extenders legitimately answer for
the router. If the address belongs to your own extender, that explains the
result. For anything you cannot name, unplug or power off the suspected
device and run the check again; the entry that disappears is that device.

## Step 3: Take the router back

Do this only after Step 1, and only once Step 2 has shown that the router is
being impersonated or that there is a device on the network you do not
recognise and cannot explain (if you do not recognise it, unplug it from your
network). In that case an interceptor may already be on the network, so treat
the Wi-Fi password as compromised. In this order:

1. Connect a computer to the router by cable if you can, so the next steps do
   not go over the air.
2. Install any pending router firmware update. If the router has a known
   vulnerability, new passwords do not help.
3. Change the router's admin password and the Wi-Fi passphrase. They are two
   different passwords, both long, neither used anywhere else.
4. Set the wireless security mode to WPA3, or WPA2-AES if WPA3 is
   unavailable. Never WEP, never WPA/TKIP, never open.
5. Turn off WPS, which lets a device join without the password.
6. Reconnect your devices and run this check again.

If changes do not save, or old settings reappear, the router itself is
compromised: hold the reset pin for 30 seconds to factory reset it, then set
it up again by hand. Do not restore a saved configuration backup, because it
restores the intruder's changes along with yours.

Then change the passwords of accounts you used while the interception was
active, starting with email. Do that from a device on a different network.

## Step 4: Check for a second router or a VPN

When "set to send traffic through more than one router" is the only finding,
a VPN or a virtual machine is the usual cause. Check whether you are running
one. If you are not, restart your router and your computer. If this
persists, check that your Wi-Fi password has not been shared, and if it has
been, work through Step 1 and then Step 3.
