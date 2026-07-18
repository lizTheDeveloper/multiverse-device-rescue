---
title: "Remove Miasma worm persistence safely"
estimated_time: "30 minutes"
platforms: [macos, linux, windows]
remediates:
  - security.ai_worm_persistence.deadman_switch_launchagent
  - security.ai_worm_persistence.deadman_switch_systemd_unit
  - security.ai_worm_persistence.known_malicious_launchagent
  - security.ai_worm_persistence.malicious_systemd_unit
  - security.ai_worm_persistence.scheduled_task_persistence
  - security.ai_worm_persistence.shell_profile_injection
  - security.ai_worm_persistence.sessionstart_hook
  - security.ai_worm_persistence.heuristic_persistence_artifact
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7]
---

## Step 1: Disconnect from the network, then neutralize the dead-man switch FIRST

**Do this before anything else. Read the whole step before you touch the keyboard.**

The Miasma worm installs a dead-man switch — a `com.user.gh-token-monitor`
LaunchAgent on macOS, or a `gh-token-monitor.service` systemd `--user` unit on
Linux. It periodically calls the GitHub API with a stolen personal access
token. If that token starts returning HTTP `4xx` (which is exactly what happens
the moment you revoke it), the switch interprets revocation as "we've been
caught" and runs a destructive payload (`rm -rf ~/`). Do **not** revoke the
token or remove any other persistence yet.

1. **Physically disconnect from the network.** Turn off Wi-Fi and unplug
   Ethernet. This is what makes the rest of this step safe: with no network,
   the switch's request to GitHub fails with a *connection error*, not a `4xx`.
   A connection error is not the revocation signal, so the switch stays
   dormant while you disable it. Keep the machine offline until Step 7.

2. **Confirm the switch is present before acting.** Inspect, do not delete yet.
   - macOS: `launchctl list | grep gh-token-monitor` and
     `cat ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
   - Linux: `systemctl --user status gh-token-monitor.service` and
     `cat ~/.config/systemd/user/gh-token-monitor.service`

3. **Neutralize the running agent, then remove its definition.**
   - macOS: `launchctl bootout gui/$(id -u)/com.user.gh-token-monitor`
     (on older macOS: `launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`),
     then move the plist out of the auto-load directory:
     `mv ~/Library/LaunchAgents/com.user.gh-token-monitor.plist ~/miasma-quarantine/`
   - Linux: `systemctl --user stop gh-token-monitor.service`, then
     `systemctl --user disable gh-token-monitor.service`, then move the unit
     file to a quarantine directory rather than deleting it outright.

4. **Verify it is no longer running** (`launchctl list` / `systemctl --user
   status`) and shows no active process before moving on. Keep the quarantined
   file for forensic reference — do not shred it yet.

Only once the dead-man switch is confirmed inert should you proceed.

## Step 2: Remove the remaining known-malicious agents and units

These are high-confidence, known-malicious entries (e.g.
`com.user.update-monitor` on macOS, `update-monitor.service` on Linux). They
are not dead-man switches, so they are safe to remove outright once Step 1 is
complete.

- macOS: for each flagged label, `launchctl bootout
  gui/$(id -u)/<label>` (or `launchctl unload <plist>`), then move the plist to
  your `~/miasma-quarantine/` directory.
- Linux: for each flagged unit, `systemctl --user stop <unit>` then
  `systemctl --user disable <unit>`, then move the `.service` file to
  quarantine.

Re-run the scan (`rescue check`, or the `ai_worm_persistence` module) to
confirm these no longer appear as high-confidence findings.

## Step 3: Remove Windows scheduled-task persistence

On Windows the worm persists via a Scheduled Task that runs a script from a
`%temp%`, `%appdata%`, or similar location.

1. Inspect first: `schtasks /Query /TN "<TaskName>" /V /FO LIST` and read the
   "Task To Run" value. Confirm it points at a temp/appdata script and is not a
   legitimate task you recognize.
2. Only after confirming, delete it: `schtasks /Delete /TN "<TaskName>" /F`.
3. Locate and remove the dropped script the task pointed at, after inspecting
   its contents.

## Step 4: Clean injected shell-profile lines

The worm may inject a self-reinfection line into shell startup files
(`~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`, `~/.zprofile`) —
typically a `curl … | bash`, `eval "$(curl …)"`, or a `source` of a script in
`/tmp` or a hidden directory.

These are heuristic (medium-confidence) matches, so **inspect before deleting.**

1. Open the flagged file and read the reported line in context. Confirm it is
   not a legitimate tool installer you added yourself.
2. Back up the file (`cp ~/.zshrc ~/.zshrc.miasma.bak`).
3. Remove only the injected line, leaving the rest of the file intact.
4. Open a fresh shell and confirm no error and no re-download occurs.

## Step 5: Remove malicious Claude Code SessionStart hooks

The worm can add a `SessionStart` hook in `~/.claude/settings.json` that
re-executes its payload every time an agent session starts.

1. Open `~/.claude/settings.json` and read the `hooks.SessionStart` entries.
2. High-confidence entries matching a known IOC command can be removed. For
   low-confidence "review manually" entries, inspect the command carefully and
   confirm it is not a hook you or your team intentionally configured before
   removing it.
3. Back up the file, then delete only the offending hook object, preserving
   valid JSON and any legitimate hooks.

## Step 6: Investigate heuristic (bun-referencing) artifacts

Medium-confidence findings flag background agents that reference the `bun`
runtime (Miasma's payload interpreter) or call AI API endpoints
(`api.anthropic.com`, `api.openai.com`,
`generativelanguage.googleapis.com`) from a persistence entry. These are
**heuristics, not confirmed malware** — inspect before deleting.

1. For each flagged plist / unit, read the full file and identify what it
   actually launches.
2. If it is a legitimate developer tool you installed, leave it and note it.
3. If it is unfamiliar and matches the worm's behavior (downloading/executing
   code, calling AI endpoints unprompted), quarantine it using the same
   stop-then-move approach as Steps 1–2.
4. When in doubt, keep the file quarantined rather than deleted so it can be
   analyzed.

## Step 7: Rotate credentials from a known-clean device

Only now — with every persistence mechanism neutralized and the machine still
offline — rotate anything the worm could have exfiltrated.

1. From a **different, known-clean device**, revoke the stolen GitHub personal
   access token and any other tokens/SSH keys that lived on the infected
   machine. Because persistence is already gone, the dead-man switch can no
   longer react to the revocation.
2. Rotate cloud, AI-provider (Anthropic/OpenAI/Google), and package-registry
   credentials that were present on the infected host.
3. Review GitHub audit logs and recent commits/actions for unauthorized
   activity.
4. Reconnect the infected machine to the network only after persistence is
   confirmed gone and credentials are rotated. Consider a full OS reinstall if
   you cannot fully account for what the worm executed.
