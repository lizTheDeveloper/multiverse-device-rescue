---
profile: home_network_intrusion
phase: 3
title: "Clean The Devices"
automatable_steps: [1, 2, 3, 4]
human_only_steps: [5, 6, 7]
estimated_time: "1-2 hours per device"
---

## Step 1: Look for cryptocurrency mining

Run `crypto_miner_detect` (macOS) or `win_crypto_miner_detect` (Windows).
These look at what is running right now: miner process names, command lines
containing a mining pool or a wallet address, and live connections to mining
pool ports.

Mining is what a hot, loud, slow machine usually turns out to be. It is also
rarely the first thing that happened — it is what someone does with access
they already had, which is why the rest of this guide exists.

## Step 2: Find what restarts the miner

Run `crypto_miner_persistence`. Killing a miner achieves nothing if a startup
entry launches it again a minute later, and that is the normal arrangement.

This check looks at startup items, scheduled tasks, cron entries, service
definitions, and shell startup files for mining commands, and for the miner's
own configuration file — the one containing the pool address and the wallet
being paid.

Note down the wallet address before deleting anything. It is the clearest
evidence of what was happening.

## Step 3: Check the browser

Run `browser_cryptojacking_check`. Mining does not need to be a program: a
browser extension can mine for as long as the browser is open, and process
lists will only ever show Chrome.

This checks installed extensions for mining code, startup pages set to mining
sites, and hosts-file entries pointing mining domains somewhere unexpected.

## Step 4: Check who else has access to the machine

Run `stalkerware_scan`, `remote_login_check` (macOS) or
`win_remote_access_audit` (Windows), and `process_scanner`.

Three different things come out of this, and they need to be told apart:

- **Monitoring software** sold for watching another person. If nobody told you
  it was there, someone installed it to watch what you do. Re-read Phase 0
  Step 1 before removing it.
- **Remote access tools** — TeamViewer, AnyDesk, VNC, ScreenConnect. Ordinary
  software that gives someone complete control of the screen. Common leftovers
  from "tech support" phone scams.
- **Adware and fake cleaners**, which are a nuisance rather than surveillance,
  but tend to arrive by the same route.

## Step 5: Remove in the right order

For each thing found:

1. Record it first — a screenshot, the file path, the date.
2. Remove the startup entry, then reboot.
3. Delete the program itself.
4. Re-run the checks.

If something reappears after a reboot, stop. Something else on the machine
still has enough privilege to rebuild it, and removing symptoms one at a time
will not get ahead of it. That is the point at which a full operating-system
reinstall is the faster and more certain option.

## Step 6: Do every device, not just the interesting one

Everything that was on the network needs looking at: every laptop and desktop,
phones and tablets, and the devices nobody thinks of as computers — the TV,
the streaming stick, the cameras, the printer, the smart speakers.

For the ones you cannot scan, the practical action is the same: install
pending updates, change any password associated with them, and factory reset
anything that behaves oddly. Cameras and video doorbells deserve particular
attention, because access to them is access to the inside of the house.

## Step 7: Consider a clean reinstall for the worst device

A full reinstall is the only way to be certain, and on the machine that was
most affected it is often less work than repeatedly chasing things that come
back.

If you do it: back up documents and photos only, never applications or system
settings, and never restore a full system image made while the machine was
compromised.
