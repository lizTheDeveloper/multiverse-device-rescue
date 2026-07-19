---
title: "Re-enable and tighten User Account Control (UAC)"
estimated_time: "10 minutes"
platforms: [windows]
remediates:
  - security.win_uac_check.uac_disabled
  - security.win_uac_check.uac_never_notify
  - security.win_uac_check.secure_desktop_disabled
  - security.win_uac_check.uac_configured_ok
automatable_steps: []
human_only_steps: [1, 2, 3]
---

UAC is one of the most fundamental defenses on Windows — it stops software
(including malware) from silently gaining administrator rights. All three
settings below should be enabled; they are rarely disabled intentionally by
a user, but sometimes get turned off by malware, aggressive "debloat"
scripts, or well-meaning-but-wrong tutorials. Confirm current state before
changing anything, since on managed/work machines UAC policy may be
centrally controlled.

## Step 1: Re-enable UAC entirely (critical — if fully disabled)

With `EnableLUA=0`, every process runs with full administrator rights
without any prompt — this is the highest-priority finding here.

1. Confirm current state: `reg query
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   EnableLUA`.
2. Re-enable from an elevated (Administrator) prompt: `reg add
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   EnableLUA /t REG_DWORD /d 1 /f`.
3. Restart the system — this setting only takes effect after a reboot.
4. Re-run the scan after restarting to confirm UAC now reports as enabled.

## Step 2: Change UAC prompt behavior away from "Never notify"

`ConsentPromptBehaviorAdmin=0` means administrators get no prompt at all for
privileged actions — functionally similar risk to UAC being off, just for
admin accounts specifically.

1. Confirm current state: `reg query
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   ConsentPromptBehaviorAdmin`.
2. Set it to the default, balanced behavior (level 5 — "notify me only when
   apps try to make changes"): Settings > System > About > Advanced system
   settings > Advanced tab > User Account Control, and move the slider to
   the default position. Or from an elevated prompt: `reg add
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f`.
3. Re-run the scan to confirm.

## Step 3: Re-enable the secure desktop for UAC prompts

Without the secure desktop, UAC prompts render on the normal desktop, where
malware can draw a convincing fake prompt (a "UAC spoofing" phishing
technique) over the real one.

1. Confirm current state: `reg query
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   PromptOnSecureDesktop`.
2. Re-enable via the same User Account Control settings panel as Step 2 —
   ensure "secure desktop" behavior is on (it's the default when the slider
   isn't at the bottom), or from an elevated prompt: `reg add
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v
   PromptOnSecureDesktop /t REG_DWORD /d 1 /f`.
3. Re-run the scan to confirm.

If the scan instead reports UAC as "properly configured", no action is
needed — that's the informational healthy-state finding.
