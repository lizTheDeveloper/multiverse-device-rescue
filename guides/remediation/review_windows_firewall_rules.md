---
title: "Review Windows Firewall rule configuration"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_firewall_rules_audit.default_inbound_allow
  - security.win_firewall_rules_audit.rule_allows_all_programs
  - security.win_firewall_rules_audit.rule_allows_all_ports
  - security.win_firewall_rules_audit.excessive_rules
  - security.win_firewall_rules_audit.summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers what `win_firewall_rules_audit` can flag beyond
whether the firewall is simply on or off (see `enable_windows_firewall.md`
for that): a dangerous default-allow inbound policy, individual rules that
are too permissive, an excessive rule count, and the summary. Always
**confirm what a rule is used for before narrowing or removing it** — Windows
Firewall with Advanced Security (`wf.msc`) shows a rule's program, ports, and
profile scope, and many rules are created automatically by installed
software for legitimate reasons.

## Step 1: DefaultInboundAction set to Allow (CRITICAL)

A firewall profile with `DefaultInboundAction: Allow` accepts any inbound
connection that isn't explicitly blocked by a rule — the opposite of the
intended default-deny posture, and far more dangerous than a single
permissive rule since it affects everything not otherwise covered.

1. Confirm current state: `Get-NetFirewallProfile | Select-Object Name,
   DefaultInboundAction` (PowerShell).
2. Open `wf.msc` → right-click the top-level firewall node → Properties →
   select the affected profile tab (Domain/Private/Public) → set "Inbound
   connections" to "Block (default)".
3. This change can surface connectivity issues for services that were
   silently relying on the allow-by-default policy — after applying, check
   that anything you deliberately expose (file sharing, a local dev/game
   server reached from other devices) still works; if not, add an explicit
   allow rule for that specific program/port rather than reverting to
   allow-by-default.
4. Re-run the scan (`win_firewall_rules_audit`) to confirm.

## Step 2: Rule allows all programs (WARNING)

A rule with `Program: Any` lets *any* executable on the system accept
inbound traffic matching that rule's ports/profile — if a program you didn't
intend is running, it can use this rule too.

1. Open `wf.msc` → Inbound Rules → find the rule by name from the finding.
2. Check its Programs and Services tab and General/Protocols and Ports tab
   to understand what it's actually meant to allow.
3. If you can identify the specific program that needs this rule, edit the
   rule's "Programs and Services" tab to point at that program's path
   instead of "All programs".
4. If you don't recognize the rule or can't attribute it to software you
   use, disable it first (right-click → Disable Rule) rather than deleting,
   confirm nothing breaks over the next few days, then delete it if still
   unneeded.
5. Re-run the scan to confirm.

## Step 3: Rule allows all ports (WARNING)

A rule with `LocalPort: Any` accepts inbound traffic on any port for the
matched program/profile — wider exposure than necessary for almost any
legitimate use case.

1. Open `wf.msc` → Inbound Rules → find the rule by name from the finding.
2. Identify what port(s) the associated program/service actually needs
   (check its documentation, or observe active connections with `Get-
   NetTCPConnection` while using the feature that needs this rule).
3. Edit the rule's Protocols and Ports tab to specify the exact port(s)
   instead of "All Ports".
4. If you can't determine a legitimate need, disable the rule first, verify
   nothing breaks, then delete it.
5. Re-run the scan to confirm.

## Step 4: Excessive enabled inbound allow rules (WARNING)

More than 100 enabled inbound allow rules makes it impractical to keep
track of what's actually needed, increasing the odds that a stale or
unwanted rule goes unnoticed.

1. Export the full rule list for review: `Get-NetFirewallRule -Direction
   Inbound -Action Allow -Enabled True | Select-Object DisplayName, Profile
   | Export-Csv rules.csv`.
2. Go through the export and group rules by the application/vendor they
   belong to — most bulk rule counts come from a handful of applications
   creating several rules each (browsers, game platforms, sync clients).
3. For software you no longer use, disable its rules in `wf.msc` rather
   than deleting immediately, confirm nothing depends on them, then remove.
4. Re-run the scan to confirm the count has dropped meaningfully; getting to
   zero excess isn't the goal, just an auditable, recognizable list.

## Step 5: Rule audit summary (INFO)

The summary finding reports profile status, total enabled inbound allow
rule count, and how many were flagged for allowing all programs or all
ports. Use it as your before/after checkpoint while working through Steps
1-4 and as a baseline for future scans.
