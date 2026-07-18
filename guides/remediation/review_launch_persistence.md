---
title: "Review and clean launchd persistence (LaunchAgents/LaunchDaemons)"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.launchd_persistence_audit.known_malware
  - security.launchd_persistence_audit.suspicious_path
  - security.launchd_persistence_audit.keepalive_runatload
  - security.launchd_persistence_audit.non_apple_info
  - security.launch_agent_audit.too_many_agents
  - security.launch_agent_audit.agent_info
  - security.launch_agent_audit.suspicious_path
  - security.launch_agent_audit.missing_program
  - security.launch_agent_audit.obfuscated_name
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers findings from both `launchd_persistence_audit`
(scans `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
`/Library/LaunchDaemons`) and `launch_agent_audit` (scans
`~/Library/LaunchAgents` and `/Library/LaunchAgents`). Both modules look at
overlapping directories from different angles — one flags known-malware
labels and suspicious execution paths, the other flags agent count,
obfuscated names, and dangling references — so they're remediated together
here. All steps are human-only: removing a `launchd` item stops whatever it
runs, and some of what's flagged (INFO-level non-Apple items, agent
inventory) may be software you deliberately installed, so nothing is
auto-applied.

## Step 1: Remove known-malware and suspicious-path items first

These are the highest-confidence findings from `launchd_persistence_audit`
(known malware label prefixes, or a program path in `/tmp`, `/var/tmp`, or a
hidden directory) and from `launch_agent_audit` (a launch agent pointing
into `/tmp`/`/var/tmp` or a hidden directory).

For each flagged label:

1. Inspect before removing: `launchctl list | grep <label>` and
   `cat <path-to-plist>` (path is one of `~/Library/LaunchAgents/`,
   `/Library/LaunchAgents/`, or `/Library/LaunchDaemons/`, reported in the
   finding).
2. Unload it: `launchctl unload <path-to-plist>` (or, on newer macOS,
   `launchctl bootout gui/$(id -u) <path-to-plist>` for user agents, or
   `launchctl bootout system <path-to-plist>` for system daemons).
3. Move the plist to a quarantine folder rather than deleting outright, so
   you can inspect it later if needed: `mkdir -p ~/launchd-quarantine &&
   mv <path-to-plist> ~/launchd-quarantine/`.
4. If the finding included a `program` path pointing at an executable you
   don't recognize, inspect it (`file <path>`, `codesign -v <path>`) before
   removing it separately.
5. Confirm removal: `launchctl list | grep <label>` should return nothing.

## Step 2: Review non-Apple KeepAlive+RunAtLoad persistence

A non-Apple `launchd` item with both `KeepAlive=true` and `RunAtLoad=true`
restarts itself automatically and starts on every login — a legitimate
pattern for some background apps (sync clients, VPN helpers) but also a
common persistence technique for unwanted software.

1. Read the plist referenced in the finding and identify the vendor/app it
   belongs to.
2. If it's software you intentionally installed and want running
   continuously, no action is needed — this finding is informational once
   verified.
3. If it's unfamiliar, follow the same inspect → unload → quarantine
   sequence as Step 1.

## Step 3: Investigate obfuscated names and missing-program agents

`launch_agent_audit` flags two additional suspicious patterns:

- **Obfuscated name**: the agent's `Program`/`ProgramArguments` points at an
  executable with a 1–2 character name — unusual for legitimate software.
- **Missing program**: the agent references an executable that no longer
  exists on disk, which can indicate malware that already deleted itself
  after establishing the persistence entry.

For each:

1. Read the full plist to see the label and intended program path.
2. For obfuscated names, check the file itself if it still exists
   (`file <path>`, `codesign -v <path>`) to judge whether it's legitimate
   tooling with a short binary name or something suspicious.
3. For missing-program entries, treat the dangling reference as suspicious
   by default — there's no executable left to inspect, so err on the side
   of removing the persistence entry using the Step 1 procedure.

## Step 4: Review the overall agent count and non-Apple inventory

Informational findings: `launch_agent_audit` flags when you have more than
20 user-level LaunchAgents (unusual and worth a general review), and
`launchd_persistence_audit` lists every non-Apple item it found (INFO
severity) so you have full visibility into what launches automatically.

1. List your user LaunchAgents: `ls ~/Library/LaunchAgents/`.
2. For each entry not already addressed above, identify which app installed
   it and confirm you still want it running at login.
3. Remove ones you no longer need using the Step 1 unload/quarantine
   sequence, keeping the ones tied to software you actively use.
