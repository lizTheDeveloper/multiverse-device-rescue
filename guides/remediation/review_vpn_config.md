---
title: "Review VPN configuration"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.vpn_config.no_vpn
  - security.vpn_config.pptp_detected
  - security.vpn_config.vpn_list
  - security.vpn_config.third_party_vpns
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `vpn_config` module can flag: no
VPN being configured at all, a deprecated/insecure PPTP VPN profile, the
general inventory of configured VPN services, and third-party VPN apps
detected via their network extensions. None of these findings mean you've
been compromised on their own — most people don't run a VPN at all, and
that's fine for typical use — but a PPTP profile or an unrecognized
third-party VPN app is worth a deliberate look, since a VPN sees and can
redirect all of your traffic.

## Step 1: Replace a PPTP VPN profile (WARNING)

PPTP has known, practically exploitable cryptographic weaknesses (weak
MS-CHAPv2 authentication, no longer considered secure) and should not be
relied on for anything sensitive. Sending traffic over a PPTP "VPN"
provides much less protection than it appears to.

1. Note the VPN name and confirm you recognize it: System Settings →
   Network → (select the VPN service in the sidebar).
2. If you no longer need it, remove it: select the service, click the
   minus (–) button.
3. If you do need VPN connectivity from this provider/server, check
   whether they offer a modern protocol (IKEv2, WireGuard, or a current
   OpenVPN config) instead, and set that up before removing the PPTP
   profile so you're not left without VPN access.
4. Re-run the scan to confirm the PPTP profile is gone (or replaced) from
   the configuration list.

## Step 2: Review the general VPN inventory (INFO)

The module lists every VPN service configured via `scutil`, along with its
protocol and connection status, regardless of whether it's flagged as
insecure.

1. Review the listed name/type/status for each VPN.
2. For any you don't recognize, treat it the same as an unrecognized
   third-party app (Step 3) — investigate before trusting it, since a VPN
   profile you didn't create could have been added by something else to
   redirect your traffic.
3. Remove unused or duplicate VPN entries you no longer need: System
   Settings → Network → select the service → minus (–) button.
4. For VPNs you keep, prefer modern protocols (IKEv2, WireGuard, current
   OpenVPN) over legacy ones.

## Step 3: Review third-party VPN apps (INFO)

Third-party VPN apps (Mullvad, Proton VPN, ExpressVPN, WireGuard clients,
etc.) install network extensions to route traffic, which this module
detects via `systemextensionsctl list`.

1. Review the listed app names/bundle identifiers.
2. Confirm each one is a VPN provider you actually installed and trust.
3. If you find one you don't recognize, don't just trust it because it's
   signed — check System Settings → Privacy & Security → Network Extensions
   (or Login Items & Extensions on newer macOS) for details, and if it's
   unfamiliar, remove the app from Applications and its extension from
   there.
4. If an unrecognized VPN extension is actively routing your traffic
   (check System Settings → Network for an active connection you didn't
   start), treat this as a potential compromise: disconnect it, remove the
   app, and change passwords for accounts used while connected from a
   separate, known-clean device.

## Step 4: No VPN configured (INFO)

If no VPN is configured at all, this is simply informational — most
day-to-day use doesn't require one. Consider setting one up if you
regularly use public/untrusted Wi-Fi and want traffic encryption and IP
masking, but no action is required otherwise.
