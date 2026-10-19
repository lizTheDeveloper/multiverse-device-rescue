---
title: "Secure your Wi-Fi connection"
estimated_time: ""
platforms: [macos]
remediates:
  - network.wifi_security_audit.wep_connected
  - network.wifi_security_audit.open_network_connected
  - network.wifi_security_audit.wpa2_only
  - network.wifi_security_audit.wep_saved
  - network.wifi_security_audit.open_saved
steps_for:
  network.wifi_security_audit.wep_connected: [1, 5]
  network.wifi_security_audit.open_network_connected: [2]
  network.wifi_security_audit.wpa2_only: [3]
  network.wifi_security_audit.wep_saved: [4, 5]
  network.wifi_security_audit.open_saved: [4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
monitoring_risk: false
---

This walkthrough covers the `wifi_security_audit` check, which looks at the
security type of the Wi-Fi network your Mac is connected to and of the
networks it has saved. Which steps apply depends on what the finding named.

## Step 1: Stop using the WEP network you are connected to

WEP is an old security type that is easily broken, so people nearby can read
the internet traffic on that network, including passwords and messages.
If this is your own network, see Step 5 first.

Open System Settings > Wi-Fi, select your current network, and click 'Forget
This Network'. Connect to a different, secure network instead, and do not use
the WEP one for sensitive tasks.

## Step 2: Leave the open network, or protect yourself on it

An open network has no encryption, so anyone on the same Wi-Fi can see your
internet traffic, including passwords and messages.

Open System Settings > Wi-Fi and connect to a different, secure network. If
you must use this one, turn on a VPN before doing anything sensitive, and do
not log in to banking, email or other accounts on it.

## Step 3: Consider moving a WPA2 network to WPA3

WPA2 is a secure standard, but it is older. WPA3 is harder to break. This is
not an emergency, and nothing about this finding means anyone has been
watching your traffic.

If you control the Wi-Fi router, change the security setting on the router
itself. The guide "Secure your home router" walks through it: set security to
WPA3, or WPA2-AES if WPA3 is not offered. If someone else runs the network,
ask your provider or IT to enable WPA3.

## Step 4: Remove unsafe networks from your Mac's saved list

Your Mac may connect automatically to a saved WEP or open network whenever it
sees one.

Open System Settings > Wi-Fi, click 'Wi-Fi Details', select the WEP or open
networks the finding named, and click the '-' button to remove them. Prefer
networks secured with WPA2 or WPA3 instead.

## Step 5: If the WEP network is your own, fix it on the router

The fix for your own network is on the router, not on the Mac. Change its
security type there to WPA3, or WPA2-AES if WPA3 is not offered; the guide
"Secure your home router" covers it. Never WEP, never open. If someone else
runs the network, ask the network owner to upgrade it to WPA2 or WPA3.
