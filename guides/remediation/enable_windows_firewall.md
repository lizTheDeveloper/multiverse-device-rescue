---
title: "Enable the Windows Firewall (all profiles)"
estimated_time: "10 minutes"
platforms: [windows]
remediates:
  - security.win_firewall.public_profile_disabled
  - security.win_firewall.private_domain_profile_disabled
automatable_steps: []
human_only_steps: [1, 2]
---

Windows Firewall filters unsolicited inbound connections separately for each
network profile (Domain, Private, Public). Turning a profile on is very
low-risk — it only affects unsolicited inbound traffic, not outbound
connections or normal browsing — but it can prompt for or block a local
service you deliberately run that other devices connect to (file sharing, a
LAN game server, a local dev server reached from your phone). Before
enabling, have a rough idea of what you use this machine for on that network
so you're not surprised by a prompt afterward.

## Step 1: Public profile disabled (CRITICAL)

The Public profile applies whenever this machine is on an untrusted network
(coffee shop Wi-Fi, airport, a network you don't control). With it off, the
machine accepts unsolicited inbound connections from anyone else on that
network — the highest-risk case, since you have no trust relationship with
other devices there.

1. Confirm current state: `netsh advfirewall show publicprofile`.
2. Enable it from an elevated (Administrator) prompt: `netsh advfirewall set
   publicprofile state on`. Or via GUI: Control Panel → Windows Defender
   Firewall → "Turn Windows Defender Firewall on or off" → enable for Public
   network settings.
3. If you run something that needs inbound access on public networks
   (uncommon — most home users don't), Windows will prompt to allow it
   through the next time it tries to accept a connection; allow only apps
   you recognize.
4. Re-run the scan (`win_firewall`) to confirm the Public profile now
   reports as enabled.

## Step 2: Private/Domain profile disabled (WARNING)

The Private profile applies to networks you've marked as trusted (home,
a friend's house); Domain applies when joined to a Windows domain. Less
urgent than Public since it's already a semi-trusted network, but it's
still attack surface most home setups don't need turned off.

1. Confirm current state: `netsh advfirewall show privateprofile` (or
   `domainprofile`).
2. Confirm you're not relying on something on this network that needs
   inbound access from this machine before enabling — e.g. a shared
   printer, file share, media server, or a local dev server another device
   on your LAN connects to.
3. Enable it from an elevated prompt: `netsh advfirewall set privateprofile
   state on` (or `domainprofile`). Via GUI: same Control Panel path as
   Step 1, but for Private/Domain network settings.
4. If a LAN service you use stops being reachable from another device
   afterward, Windows should prompt to allow it the next time it tries to
   accept a connection — allow it explicitly rather than disabling the
   firewall again.
5. Re-run the scan to confirm the profile now reports as enabled.

If the scan reports all profiles enabled, no action is needed — that's the
secure baseline. For a deeper look at specific inbound rules (not just
whether the firewall is on), see `review_windows_firewall_rules.md`.
