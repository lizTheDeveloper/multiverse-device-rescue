---
title: "Check that your VPN is protecting your traffic"
estimated_time: ""
platforms: [macos]
remediates:
  - network.vpn_leak_check.dns_leak
  - network.vpn_leak_check.split_tunneling
  - network.vpn_leak_check.vpn_not_connected
steps_for:
  network.vpn_leak_check.dns_leak: [1, 4]
  network.vpn_leak_check.split_tunneling: [2, 4]
  network.vpn_leak_check.vpn_not_connected: [3, 4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
monitoring_risk: false
---

This walkthrough covers the `vpn_leak_check` check, which looks at whether
your VPN is covering your internet traffic the way you would expect. These
findings are about settings, not about someone having broken in.

## Step 1: Turn on DNS leak protection

Your VPN is connected, but your device is still sending some web lookups
(DNS) to servers outside the VPN. That may mean the websites you visit are
visible to your internet provider, even though the rest of your traffic is
hidden.

Open your VPN app and look for a setting called "DNS Leak Protection" or
"Kill Switch" and turn it on.

If your VPN app does not have one, open System Settings > Network, select
your VPN and click 'Details...'. Look for DNS or Privacy settings and verify
that DNS leak protection is enabled. Some VPN providers offer custom DNS
servers that route through the VPN tunnel.

If your VPN provider doesn't have built-in DNS leak protection, you can
manually configure your DNS to use the VPN provider's DNS servers, or switch
to a VPN provider with strong privacy features. You can test for DNS leaks
at tools like dnsleaktest.com.

## Step 2: Check split tunneling

Your VPN is connected, but your device has more than one default network
route. That suggests "split tunneling" is active, meaning some of your
internet traffic bypasses the VPN.

Open your VPN app and check for a "Split Tunneling" or "Bypass" setting. If
you want full privacy, turn it off. You can also open System Settings >
Network, select your VPN and click 'Details...', then look for "Split
tunneling" or "Route all traffic" options and make sure "Route all traffic
through VPN" is enabled.

Some applications or network requirements may need split tunneling. Only
turn it off if you do not need it for your workflow.

## Step 3: Connect to your VPN

A VPN profile is set up on your Mac but is not currently connected. That is
usually normal if you only use it sometimes. If you expected it to be
running, your internet traffic is not currently encrypted by the VPN.

Open your VPN app and check if it is turned on. If you meant for it to be
active, connect to it. You can also open System Settings > Network, locate
your VPN in the list, click it and select 'Connect', then check that its
status shows 'Connected'.

VPNs are valuable for privacy, especially on public networks. Make sure you
trust the VPN provider, as they can see all your network traffic.

## Step 4: Review the VPNs on this Mac

If you do not recognise a VPN in your list, or want to look over the VPN
apps and protocols you have, follow the "Review VPN configuration"
walkthrough.
