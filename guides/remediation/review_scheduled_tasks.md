---
title: "Review scheduled tasks (LaunchAgents/LaunchDaemons)"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.scheduled_tasks_audit.suspicious_launch_agent
  - security.scheduled_tasks_audit.disabled_launch_agent
  - security.scheduled_tasks_audit.launch_agent_info
  - security.scheduled_tasks_audit.excessive_user_agents
automatable_steps: []
human_only_steps: [1, 2, 3]
---

`scheduled_tasks_audit` parses every plist in
`~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
`/Library/LaunchDaemons` and flags ones that run from a suspicious path
(`/tmp`, `/var/tmp`, `Downloads`, `Temp`), have an obfuscated
numeric/very-short label, or auto-run an unsigned-looking script from an
unknown publisher. All steps are human-only: a launch agent might be tied
to software you use daily, so removal is always your call after
inspection.

## Step 1: Investigate suspicious launch agents/daemons

For each `suspicious_launch_agent` (WARNING) finding:

1. Read the plist at the `location` path reported in the finding
   (`cat <location>` or open in a text editor) and note the `Program`/
   `ProgramArguments` and the `reason` given (suspicious path, obfuscated
   label, or unknown-publisher auto-run).
2. If the referenced program still exists on disk, inspect it before
   touching anything: `file <path>`, `codesign -dv --verbose=4 <path>`.
3. If you don't recognize the vendor/purpose, unload it rather than
   deleting outright:
   - User agent: `launchctl bootout gui/$(id -u) <location>` (or
     `launchctl unload <location>` on older macOS).
   - System daemon: `sudo launchctl bootout system <location>`.
4. Quarantine the plist instead of deleting it immediately, so you can
   restore it if it turns out to be legitimate:
   `mkdir -p ~/launchagent-quarantine && mv <location>
   ~/launchagent-quarantine/`.
5. If the referenced executable is also unfamiliar and suspicious, move it
   to the same quarantine folder rather than running `rm -rf` on it.
6. Confirm it's gone: `launchctl list | grep <label>` should return
   nothing.

## Step 2: Clean up disabled agents left on disk

`disabled_launch_agent` (INFO) findings mean the plist has `Disabled=true`
but is still sitting on disk — not a security risk by itself, just clutter
from a past uninstall.

1. Confirm it's actually disabled and not loaded:
   `launchctl list | grep <label>` should return nothing.
2. If you no longer use the associated app, remove the plist file
   directly: `rm <location>` (safe here, since it's already inert — no
   unload needed).
3. If unsure which app it belongs to, leave it — being disabled means it
   poses no active risk.

## Step 3: Review the general agent/daemon inventory and count

`launch_agent_info` (INFO) lists every launch agent/daemon found so you
have full visibility, and `excessive_user_agents` (WARNING) fires when you
have more than 20 user-level agents — not inherently malicious, but worth a
general spring-cleaning since it can slow boot time.

1. List your user agents: `ls -la ~/Library/LaunchAgents`.
2. For each entry not already addressed in Steps 1–2, identify which
   installed app it belongs to and confirm you still want it running at
   login.
3. For ones you no longer need, follow the Step 1 unload → quarantine
   sequence rather than deleting the live file directly.
