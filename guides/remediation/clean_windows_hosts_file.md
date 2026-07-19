---
title: "Clean up the Windows hosts file"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_hosts_file.security_domain_redirect
  - security.win_hosts_file.excessive_entries
  - security.win_hosts_file.entries_summary
  - security.win_hosts_file_check.blocked_security_domains
  - security.win_hosts_file_check.redirected_legitimate
  - security.win_hosts_file_check.large_file_size
  - security.win_hosts_file_check.file_permissions
  - security.win_hosts_file_check.entry_count_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers findings from both `win_hosts_file` and
`win_hosts_file_check`, which independently scan the same file
(`C:\Windows\System32\drivers\etc\hosts`) for overlapping but distinct
signals: security/banking domain redirects, antivirus-update domain
blocks, excessive/oversized entries, and incorrect file permissions. The
hosts file is a legitimate customization point — ad-blocking tools (Pi-hole
style hosts files), local development (`mysite.local`), and some parental
controls all add entries intentionally — so **inspect every flagged entry
before removing it** rather than wiping the file. Never delete or replace
the whole hosts file blindly; edit it entry-by-entry in a text editor
running as Administrator, and consider copying the current file somewhere
safe first (`copy
C:\Windows\System32\drivers\etc\hosts %USERPROFILE%\Desktop\hosts.backup`)
so you can compare or revert if you remove something you needed.

## Step 1: Security/banking domains redirected (critical)

A banking, payment, or major platform domain (e.g. a bank, PayPal, Microsoft,
Google, GitHub) is redirected to a non-localhost IP. This is a classic
credential-theft or man-in-the-middle technique: redirecting a trusted
domain to an attacker-controlled server that mimics the real site.

1. Back up the hosts file per the note above before editing anything.
2. Open the hosts file as Administrator: Notepad running elevated, then
   File → Open → `C:\Windows\System32\drivers\etc\hosts`.
3. Locate the flagged line(s) (listed in the finding's `redirects` data) and
   confirm the destination IP is not one you recognize as your own
   (e.g. a local DNS sinkhole you deliberately run). If you don't recognize
   it, delete that line (or comment it out with a leading `#` if you'd
   rather keep a record) and save.
4. Treat this as a strong malware indicator: run a full antivirus scan (see
   `enable_windows_antivirus.md`) and check for other compromise signs via
   `respond_to_windows_malware_indicators.md`.

## Step 2: Antivirus/security update domains blocked (critical)

An antivirus vendor or Windows Update domain is blocked or redirected. This
specifically prevents your machine from receiving security updates or virus
definition updates — a technique malware uses to keep itself from being
detected or removed.

1. Same procedure as Step 1: back up, open elevated, locate the flagged
   domain(s) (listed in `blocked_domains`), and remove or comment out the
   line unless you deliberately blocked it (uncommon, but some corporate
   policies restrict update domains to a specific internal mirror).
2. After removing the block, verify updates work: Settings → Windows
   Update → Check for updates, and re-run `enable_windows_antivirus.md`'s
   Step 3 (update definitions) to confirm connectivity is restored.
3. This combination — security domains blocked plus banking domains
   redirected — is a strong signal of active malware, not a one-off
   misconfiguration; prioritize a full malware scan after cleaning the file.

## Step 3: Legitimate domains redirected to suspicious IPs

A well-known domain (social media, shopping, dev platforms) is redirected
to a non-localhost IP, without being on the higher-priority
security/banking list from Step 1.

1. Confirm the destination IP: is it an IP you recognize (e.g. your own
   local proxy/pi-hole/dev environment), or unfamiliar?
2. If unfamiliar, remove the entry the same way as Step 1.
3. If you run a local ad-blocking or parental-control tool that
   legitimately redirects tracking subdomains, this can be a false
   positive for those specific entries — the flag is best treated as "worth
   a second look," not automatically malicious, when it's a known tool.

## Step 4: Excessive or oversized hosts file

Either a very high entry count (`win_hosts_file`, over 50 entries) or a file
size over 1MB (`win_hosts_file_check`) was detected. This is most often a
sign of an ad-blocking hosts file (some tools add tens of thousands of ad
domains) rather than malware, but it's worth confirming.

1. Check whether you intentionally installed a hosts-based ad blocker
   (common examples redirect thousands of ad/tracker domains to
   `0.0.0.0`/`127.0.0.1`). If so, and all entries point to localhost, this
   is expected and no action is needed.
2. If you don't recognize having installed such a tool, review a sample of
   entries (`Get-Content $env:windir\System32\drivers\etc\hosts | Select
   -First 50` in PowerShell) to see if they look like ad-blocking domains
   (typically ad/analytics-sounding names) or something else entirely.
3. If the content doesn't match a deliberate ad-blocker and you don't
   recognize it, consider restoring the file from a known-clean backup or
   the default Windows hosts file (which contains only comments and no
   active entries) rather than trying to hand-edit thousands of lines.

## Step 5: Incorrect hosts file permissions

The hosts file's ACL indicates non-Administrator accounts have write
access. By default only Administrators and SYSTEM should be able to modify
this file — if any authenticated user or "Everyone" has write/modify
access, any process (including malware without elevated privileges) can
tamper with it.

1. Confirm current permissions: `icacls
   C:\Windows\System32\drivers\etc\hosts` (elevated Command Prompt).
2. Reset to Windows defaults: `icacls C:\Windows\System32\drivers\etc\hosts
   /reset` (elevated). This restores standard Administrators/SYSTEM-only
   write access without touching the file's content.
3. Re-check permissions afterward to confirm only Administrators and SYSTEM
   have write/modify/full-control entries.

## No issues found / informational entry counts

If the only findings are the `entries_summary` / `entry_count_summary` INFO
findings, the hosts file has entries but none matched the suspicious
patterns above — review the listed custom entries at your leisure to
confirm you recognize them, but no urgent action is needed.
