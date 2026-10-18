---
title: "Fix a wired (Ethernet) connection problem"
estimated_time: ""
platforms: [macos]
remediates:
  - network.ethernet_diagnostics.interface_inactive
  - network.ethernet_diagnostics.self_assigned_ip
  - network.ethernet_diagnostics.non_standard_mtu
  - network.ethernet_diagnostics.link_speed_mismatch
  - network.ethernet_diagnostics.high_packet_errors
steps_for:
  network.ethernet_diagnostics.interface_inactive: [1, 2, 3, 5, 9]
  network.ethernet_diagnostics.self_assigned_ip: [1, 2, 3, 4, 5, 6, 9]
  network.ethernet_diagnostics.non_standard_mtu: [7]
  network.ethernet_diagnostics.link_speed_mismatch: [2, 3, 8, 9]
  network.ethernet_diagnostics.high_packet_errors: [2, 3, 8, 9]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7, 8, 9]
monitoring_risk: false
---

This walkthrough covers the `ethernet_diagnostics` check, which looks at the
wired network connection on this Mac. These findings are about the cable,
the port or the settings of the connection, not about someone having broken
in.

## Step 1: Check the cable at both ends

Your computer sees the Ethernet port, but it is not connected to a network
that is giving it an address. This usually means the cable is unplugged, or
the other end (like your router) is off.

Check that your Ethernet cable is firmly plugged into both your computer and
your router or wall port. If it is plugged in, try unplugging and replugging
it.

## Step 2: Try a different Ethernet cable

A damaged cable, a loose connection or a faulty port can cause a connection
that is not active, runs slower than it should, or makes errors while sending
or receiving data.

Try a different Ethernet cable. Check that the cable you were using is not
damaged or bent.

## Step 3: Try a different port

If a different cable does not help, plug into a different port on your
router or switch.

If you use a USB-C dock or adapter, try a different USB-C port on your Mac.

## Step 4: Restart your router

Restart your router and wait a minute, then check whether your connection
returns. If it does not, try unplugging and replugging the Ethernet cable.

## Step 5: Restart your Mac

Restart your Mac from the Apple menu: Apple menu > Restart. Then check
whether the Ethernet connection comes back.

## Step 6: Renew the address lease

Your Mac gave itself a temporary address because your router did not give it
a proper one, so you likely have no internet access.

Open System Settings > Network, select Ethernet, click "Details…" ("Advanced…" on
older macOS), go to TCP/IP, and choose "Renew DHCP Lease".

## Step 7: Check the data size (MTU) setting

Your Ethernet port is set to handle data chunks of a different size from the
standard 1500. This setting is usually chosen by your network equipment, not
by a person. It is unlikely to cause problems, but it can sometimes make
certain websites or apps load slowly.

If nothing seems wrong, there is nothing to do right now. If you want to look
at it, open System Settings > Network, select Ethernet, click "Details…"
("Advanced…" on older macOS), and go to Hardware to check the MTU setting.
If it is not 1500, you can change it back to 1500, then click OK and
reconnect. Only change the MTU if you know your network requires it. If you
notice slow internet speeds, try restarting your router.

## Step 8: Check the switch or router and the adapter

If you use a switch, check that its port is set to auto-negotiate and is not
forced to 100 Mbps. Check your router or switch for issues.

If you use a docking station or adapter, you can also try it in a different
USB-C port, try a different docking station, or update the adapter's
firmware if available.

## Step 9: Consider the adapter

If the problem continues after trying the steps above, the adapter may be
faulty. Try a different adapter.
