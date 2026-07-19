---
title: "Verify and re-enable SIP and Gatekeeper"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.sip_gatekeeper.sip_status
  - security.sip_gatekeeper.gatekeeper_status
  - security.gatekeeper_quarantine_check.gatekeeper_disabled
  - security.gatekeeper_quarantine_check.gatekeeper_enabled
  - security.gatekeeper_quarantine_check.sip_disabled
  - security.gatekeeper_quarantine_check.sip_enabled
  - security.gatekeeper_quarantine_check.quarantine_removed
  - security.gatekeeper_quarantine_check.gatekeeper_assessment_failed
  - security.gatekeeper_quarantine_check.gatekeeper_working
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers both `sip_gatekeeper` and
`gatekeeper_quarantine_check`, which both check System Integrity
Protection (`csrutil status`) and Gatekeeper (`spctl --status`) from
different angles. `sip_gatekeeper` is the lighter check (WARNING on
disabled). `gatekeeper_quarantine_check` treats a disabled SIP or
Gatekeeper as CRITICAL (since it also reports the INFO-level "confirmed
enabled" case for full visibility), and additionally checks a fixed list
of common apps in `/Applications` for a manually-removed quarantine flag,
and runs a live Gatekeeper assessment against Safari to confirm the
mechanism is actually functioning end-to-end, not just reporting
"enabled". They're remediated together since both point at the same two
underlying protections.

**Important: both SIP and Gatekeeper are core macOS security protections.**
Disabling either one reduces your system's defenses — SIP stops even root
from modifying protected system files and code-injecting into system
processes, and Gatekeeper verifies code signatures before running
downloaded apps. If you (or a previous owner of this machine) disabled
either intentionally for development work, weigh that need against the
security cost before re-enabling. If you did *not* knowingly disable them,
treat a disabled state as a red flag: it's a common step in malware
persistence chains, since a lot of malicious payloads and installers
disable these to keep working undetected.

## Step 1: Confirm intent and re-enable SIP if disabled

`sip_status` (WARNING) fires when `csrutil status` doesn't report
"enabled".

1. Before touching anything, think about whether you (or a trusted admin)
   disabled SIP deliberately — for example, for kernel-level debugging,
   hackintosh compatibility, or a development toolchain that needs to
   patch system frameworks. If yes and you still need that capability,
   you may choose to leave SIP disabled — that's a legitimate but
   security-reducing tradeoff, and it's your call to make consciously,
   not by default.
2. If you don't recognize the reason it's disabled, treat it as
   suspicious and re-enable it:
   - Reboot into Recovery Mode (Intel: hold Cmd+R at startup; Apple
     Silicon: hold the power button until "Loading startup options"
     appears, then choose Options).
   - Open **Terminal** from the Utilities menu.
   - Run: `csrutil enable`
   - Reboot normally.
3. Confirm: `csrutil status` should report
   "System Integrity Protection status: enabled."

## Step 2: Confirm intent and re-enable Gatekeeper if disabled

`gatekeeper_status` (WARNING) fires when `spctl --status` doesn't report
"assessments enabled".

1. Same reasoning as Step 1: if you deliberately disabled Gatekeeper to
   run a specific unsigned/internal tool, prefer allow-listing that one
   app over leaving Gatekeeper off globally — `sudo spctl --add --label
   'Approved App' /path/to/app` lets you keep protection on for
   everything else.
2. To re-enable Gatekeeper globally: `sudo spctl --master-enable`
3. Confirm: `spctl --status` should report "assessments enabled."

The `gatekeeper_disabled`/`sip_disabled` (CRITICAL) and
`gatekeeper_enabled`/`sip_enabled` (INFO) findings from
`gatekeeper_quarantine_check` describe the same two settings — use the
same steps above. The CRITICAL severity here (vs. WARNING from
`sip_gatekeeper`) doesn't change the remediation, just the urgency: treat
these as a priority if you didn't knowingly disable them yourself.

## Step 3: Review apps with a manually-removed quarantine flag

`quarantine_removed` (WARNING) lists common apps in `/Applications`
(Safari, Chrome, Firefox, VS Code, Spotify, Discord, Slack, Telegram, VLC)
whose `com.apple.quarantine` extended attribute is missing — meaning
Gatekeeper's first-launch verification was bypassed for that app, either
intentionally (a common step for pirated/cracked software, or by
developers testing unsigned builds) or by something else stripping it.

1. For each flagged app, inspect the install: `mdls -name
   kMDItemWhereFroms <app path>` (if quarantine metadata is fully gone,
   this may return nothing — that's itself informative).
2. Check the app's code signature: `codesign -dv --verbose=4 <app path>`.
   A valid signature from the expected vendor is reassuring even without
   the quarantine flag; an invalid or ad-hoc signature is a strong warning
   sign.
3. If you deliberately removed the flag yourself (e.g. `xattr -d
   com.apple.quarantine` after downloading a signed build from an
   unusual channel) and the signature checks out, no action is needed.
4. If you don't recall doing this, or the signature doesn't check out,
   don't just delete the app outright — first quarantine your own copy
   for inspection (move it to a holding folder rather than trashing it),
   then reinstall the app fresh from the vendor's official source.
5. Restore Gatekeeper's ability to re-check it going forward by
   re-downloading via a normal browser (which re-applies the quarantine
   flag automatically) rather than manually re-adding the xattr.

## Step 4: Verify Gatekeeper is functioning, not just "enabled"

`gatekeeper_assessment_failed` (WARNING) means a live test assessment
(`spctl --assess` against `/Applications/Safari.app`) didn't return a
clear accepted/rejected result — `spctl --status` can report "enabled"
while the assessment mechanism itself is broken. `gatekeeper_working`
(INFO) confirms the opposite: the live test succeeded.

1. Run the same test manually with full output: `spctl -a -t execute
   -vvv /Applications/Safari.app` and read the verbose reason.
2. If the command errors out entirely (not just a "rejected" result —
   rejected is actually a valid working response), try resetting
   Gatekeeper's rule database: `sudo spctl --reset-default`.
3. Re-run the assessment to confirm it now returns a clear
   accepted/rejected verdict rather than an error.
4. If it still fails after a reset, this may indicate deeper system
   corruption — consider running Apple Diagnostics or, if other integrity
   findings are also present, treat this as part of a broader compromise
   investigation rather than an isolated Gatekeeper bug.
