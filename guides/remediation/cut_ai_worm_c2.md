---
title: "Cut AI worm command-and-control network activity"
estimated_time: "20 minutes"
platforms: [macos, linux, windows]
remediates:
  - security.ai_worm_network.known_malicious_connection
  - security.ai_worm_network.stepsecurity_bypass
  - security.ai_worm_network.beaconing_detected
  - security.ai_worm_network.token_harvesting_subprocess
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

## Step 1: Terminate processes with known-malicious connections

A high-confidence finding here means an active network connection was
matched against a known AI worm C2/exfiltration domain or IP in the shared
IOC database.

1. Before terminating anything, note the process name, PID, and destination
   from the finding — you'll need this to identify what else that process
   may have touched (files written, credentials read).
2. Terminate the process: `kill <pid>` (send `SIGTERM` first; escalate to
   `kill -9 <pid>` only if it doesn't exit).
3. Identify what launched it — check its parent process
   (`ps -o ppid= -p <pid>` before you kill it, if possible) and any
   persistence mechanism that might relaunch it (see the
   `ai_worm_persistence` module/walkthrough).
4. Do not simply block the destination and leave the process running —
   the process itself is the compromise; the network connection is only the
   symptom you happened to observe.

## Step 2: Remove the StepSecurity hosts-file bypass

The worm can add an `/etc/hosts` (or Windows `hosts`) entry that redirects
`agent.stepsecurity.io`, disabling CI/CD security monitoring for
StepSecurity-protected pipelines.

1. Open the hosts file
   (`/etc/hosts` on macOS/Linux,
   `C:\Windows\System32\drivers\etc\hosts` on Windows) and locate the line
   containing `agent.stepsecurity.io`.
2. Back up the file, then remove only that line — do not touch other
   legitimate hosts entries.
3. Confirm DNS resolution is restored: `dig agent.stepsecurity.io` (or
   `nslookup` on Windows) should now return StepSecurity's real IP, not a
   local override.
4. If you run CI/CD pipelines protected by StepSecurity, check recent
   pipeline runs for gaps in monitoring coverage while the bypass was
   active.

## Step 3: Investigate beaconing patterns (medium confidence — inspect first)

A beaconing finding means a process maintained an identical connection to
the same destination across two samples taken ~5 seconds apart — a pattern
consistent with periodic C2 polling, but also produced by many legitimate
background services (sync clients, chat apps, package managers checking for
updates).

1. Identify the process and destination from the finding. Look up the
   destination (`whois`, reverse DNS) to see if it's a recognizable
   legitimate service.
2. If the process is unfamiliar or the destination is unrecognized, inspect
   the process's binary path and command line
   (`ps -p <pid> -o command=`) before deciding whether to terminate it.
3. If you determine it is malicious, terminate it as in Step 1 and check
   for an associated persistence mechanism so it doesn't restart.
4. If it turns out to be a legitimate app you use regularly, no action is
   needed — false positives here are expected and are why this finding is
   medium, not high, confidence.

## Step 4: Respond to GitHub token harvesting, then rotate from a clean device

A high-confidence finding means a process executed `gh auth token` — a
known technique AI worms use to steal a GitHub personal access token
directly from the `gh` CLI's local credential store.

1. Terminate the offending process (Step 1's approach) before doing
   anything else — it may still be running and could re-harvest a rotated
   token.
2. **From a different, known-clean device** (not the affected machine),
   revoke the GitHub token: GitHub Settings → Developer settings →
   Personal access tokens → revoke the token used by `gh` on the affected
   machine, or run `gh auth logout` from a clean environment against that
   account and re-authenticate with a fresh token.
3. Review GitHub's audit log and recent activity (new SSH keys, new PATs,
   unexpected pushes/clones, unfamiliar Actions runs) for anything that
   happened using the harvested token before you revoked it.
4. Re-authenticate `gh` on the affected machine only after confirming no
   persistence mechanism will re-harvest the new token (cross-reference with
   the `ai_worm_persistence` and `ai_worm_git_ssh` walkthroughs).
