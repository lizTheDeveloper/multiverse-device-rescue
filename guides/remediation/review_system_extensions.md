---
title: "Review macOS System Extensions"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.system_extensions.unusual_state
  - security.system_extensions.active_extension
automatable_steps: []
human_only_steps: [1, 2]
---

`system_extensions` runs `systemextensionsctl list` and reports each
registered System Extension (the modern, user-space replacement for
kexts — network filters, endpoint security agents, driver extensions).
System Extensions run with elevated system access but outside the kernel,
so removing one is generally lower-risk than removing a kext — but they
still often control security tools (VPNs, firewalls, EDR agents), so
disabling one can leave a gap in your protection rather than close one.
All steps are human-only.

## Step 1: Investigate activated extensions

`active_extension` (INFO) lists every extension currently activated and
running with system-level privileges — informational, but worth a full
review since these run continuously.

1. Identify the vendor from the `team_id` and extension `name`/bundle ID in
   the finding.
2. Confirm it's tied to software you intentionally installed (VPN client,
   firewall, backup tool, EDR/antivirus agent, etc.).
3. If it's a security tool (firewall, EDR, VPN) you rely on, leave it
   active — disabling it *reduces* your protection. Only disable if you're
   certain you no longer use the associated app.
4. To disable one you've confirmed you don't need: open **System
   Settings → General → Login Items & Extensions**, find the extension
   under the relevant category, and toggle it off there (this is the only
   supported way to deactivate most System Extensions — there is no safe
   equivalent of deleting a kext file).
5. If you don't recognize the vendor and it isn't tied to anything you
   installed, treat it as suspicious: research the bundle ID/team ID
   before disabling, since some legitimate low-level tools use
   non-obvious names.

## Step 2: Investigate extensions stuck in an unusual state

`unusual_state` (WARNING) means the extension is not in a normal
`activated` state — for example stuck `waiting for user approval`. This
often means an installer registered the extension but the user never
approved it, or approval was revoked.

1. Note the reported `state` and identify which app/vendor requested the
   extension.
2. If you recognize and want the extension, approve it: **System
   Settings → General → Login Items & Extensions**, find it under the
   relevant category, and allow it. You may need to restart the
   associated app afterward.
3. If you don't recognize the requesting app, do not approve it. Instead,
   identify and uninstall the app that registered it via its own
   uninstaller — an unapproved extension has no system access until
   approved, so leaving it unapproved is the safe default.
4. Re-run `systemextensionsctl list` to confirm the state resolved as
   expected (either `activated` after your approval, or the entry gone
   after uninstalling the source app).
