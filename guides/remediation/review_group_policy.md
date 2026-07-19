---
title: "Review Windows Group Policy findings"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_group_policy_audit.stale_domain_policies
  - security.win_group_policy_audit.restrictive_policy
  - security.win_group_policy_audit.weak_password_policy
  - security.win_group_policy_audit.applocker_configured
  - security.win_group_policy_audit.status_report
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Group Policy settings on a home PC are either leftovers from a former
domain/work enrollment, or (less commonly) evidence of unauthorized
tampering with system restrictions. **Inspect what a policy actually does
before removing or overriding it** — some restrictive-looking policies are
intentionally set by parental controls, MDM/work enrollment you still rely
on, or IT-managed configurations you don't want to break. There is no
automatable fix here; every step requires you to look at the actual policy
source before acting.

## Step 1: Stale domain Group Policies on a non-domain machine (WARNING)

Group Policies from a domain are still applied even though this machine is
no longer domain-joined — common after leaving a job, replacing a work
laptop's domain membership, or an incomplete unenrollment.

1. Confirm current domain status: `(Get-WmiObject
   Win32_ComputerSystem).PartOfDomain` (PowerShell) should read `False`.
2. List what's still applied: `gpresult /r /scope:computer` and `gpresult
   /r /scope:user` (from the finding data, `computer_gpos`/`user_gpos`).
3. Force a policy refresh first, which often clears genuinely stale
   entries: `gpupdate /force`, then re-run the scan.
4. If policies persist after a refresh, they may be cached locally under
   `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\History` —
   back up that key (`reg export` to a file) before removing entries, since
   incorrect edits here can affect policy processing generally.
5. Re-run the scan to confirm the stale policies are gone.

## Step 2: Feature disabled by policy (WARNING)

Command Prompt, Task Manager, Registry Editor, or Control Panel is disabled
via policy. This is a legitimate parental-control or corporate-lockdown
setting in many cases, but it's also a technique malware and unauthorized
"tech support" scams use to prevent you from investigating or terminating
them.

1. Note which feature is disabled and via which registry key
   (`DisableCMD`, `DisableTaskMgr`, `DisableRegistryTools`,
   `NoControlPanel`) from the finding.
2. Think back: did you, a parent/guardian, an employer's MDM, or "IT
   support" (verify this was a legitimate call, not a scam) set this up
   intentionally? If yes and still wanted, no action needed.
3. If unexpected, check where the policy is coming from: run `gpresult
   /h gpreport.html` and open the report to see which GPO/policy set it —
   local policy (not from a domain) shows up under Local Group Policy.
4. If it's local (not managed by a domain/MDM you rely on) and you don't
   recognize setting it, remove it via `gpedit.msc` (if available on your
   Windows edition) by navigating to the relevant policy and setting it to
   "Not Configured", or delete the specific registry value under
   `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` or
   `HKLM\Software\Policies\Microsoft\Windows\System` after backing it up
   with `reg export`.
5. If you can't explain how it got there and this coincides with other
   suspicious behavior, cross-check
   `respond_to_windows_malware_indicators.md` before assuming it's benign.
6. Run `gpupdate /force` and re-run the scan to confirm.

## Step 3: Weak minimum password length policy (WARNING)

The local password policy allows passwords shorter than 8 characters —
weaker than Microsoft's recommended baseline, making accounts on this
machine easier to brute-force if an attacker gets a chance to attempt
local logins.

1. Confirm current value: `net accounts` and look at "Minimum password
   length".
2. From an elevated Command Prompt, raise it: `net accounts
   /minpwlen:14` (14 is a reasonable modern minimum; adjust to your
   organization's policy if applicable).
3. This only affects future password changes, not existing passwords — if
   any account currently has a shorter password, it stays valid until
   next changed. Consider prompting affected users to update their
   password.
4. Re-run the scan to confirm.

## Step 4: AppLocker policies configured (INFO)

AppLocker or software restriction policies are active, which can restrict
which applications are allowed to run. This is informational — it may be
a deliberate security control (in a managed environment) or an artifact of
previous configuration.

1. Check what's actually restricted: `Get-AppLockerPolicy -Effective -Xml`
   and review the rule collections.
2. If this machine is under active IT/MDM management, leave AppLocker
   policies alone — they're likely intentional.
3. If you're the sole administrator and don't recall configuring
   AppLocker, review the AppLocker event logs (Applications and Services
   Logs → Microsoft → Windows → AppLocker) for any denied executions,
   which will tell you what it's actually blocking day-to-day.
4. No action is required unless AppLocker is causing problems you can't
   explain — this finding exists to make you aware it's active.

## Step 5: Group Policy status report (INFO)

Summarizes domain-join status and applied GPO counts — use it as a
baseline while working through Steps 1-4 and to confirm changes took
effect on re-scan.
