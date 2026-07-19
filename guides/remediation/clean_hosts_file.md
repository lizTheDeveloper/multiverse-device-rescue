---
title: "Clean up a tampered /etc/hosts file"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.hosts_file_check.clean_hosts
  - security.hosts_file_check.large_hosts_count
  - security.hosts_file_check.suspicious_ip_redirect
  - security.hosts_file_check.wellknown_domain_redirect
  - security.hosts_file_check.bank_domain_redirect
  - security.hosts_file_check.custom_entries_list
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `hosts_file_check` module can flag
in `/etc/hosts`: a clean file, a large number of custom entries, entries
redirecting to non-loopback IPs, well-known domains redirected to
suspicious IPs, banking domains redirected (the most severe case), and the
general inventory of custom entries. `/etc/hosts` overrides DNS entirely
for the listed hostnames, so malware that wants to intercept traffic to a
specific site (often a bank, to phish credentials) often does it here.
Legitimate ad-blockers also use large hosts files (usually redirecting to
`0.0.0.0`/`127.0.0.1`, which this module already treats as safe), so a
large *count* alone is not damning — it's the redirect *targets* that
matter most.

## Step 0: Back up before editing

Before making any change, back up the current file so you can restore it
if you remove something you needed:
`sudo cp /etc/hosts /etc/hosts.bak-$(date +%Y%m%d)`.

## Step 1: Respond to banking domain redirects (CRITICAL)

A banking or payment domain (PayPal, Chase, Bank of America, etc.) pointed
at anything other than `127.0.0.1`/`0.0.0.0` is very likely a phishing
setup — traffic meant for your bank is being sent to an attacker's server
instead of being blocked or resolved normally.

1. Note the domain(s) and the redirect IP from the finding.
2. Open `/etc/hosts` (`sudo nano /etc/hosts`) and locate the matching
   line(s).
3. Delete those specific lines (do not delete the whole file, and do not
   touch the default `127.0.0.1 localhost` / `::1 localhost` /
   `255.255.255.255 broadcasthost` lines).
4. Save and re-run the scan to confirm the redirect is gone.
5. Since this is a strong compromise indicator, don't stop at the hosts
   file: check for the process/persistence mechanism that made the change
   (recently installed apps, unfamiliar `launchctl list` entries, unfamiliar
   profiles under System Settings → Privacy & Security → Profiles) and
   remove it, then change your banking password from a separate, known-clean
   device — if the redirect was live, credentials entered on the fake page
   may already be compromised.

## Step 2: Review well-known domain redirects (WARNING)

A well-known non-financial domain (Google, Facebook, GitHub, etc.)
redirected to a non-loopback IP is also a strong signal of interference,
though lower stakes than a banking redirect.

1. Note the domain(s) and redirect IP.
2. Confirm you didn't add this yourself intentionally (some people redirect
   `facebook.com`/`youtube.com` to `127.0.0.1` for self-imposed blocking —
   that case wouldn't trigger this finding since it uses a safe IP, but
   confirm anyway).
3. If unexplained, remove the line(s) from `/etc/hosts` as in Step 1 and
   re-scan.
4. Treat repeated unexplained redirects across multiple domains as a signal
   to check for malware/persistence as described in Step 1.

## Step 3: Review other non-loopback redirects (WARNING)

Any entry pointing a hostname at an IP other than `127.0.0.1`, `0.0.0.0`,
or `::1` is worth a look even if the domain isn't on the well-known or bank
lists — it could be a legitimate internal/dev hostname override, or an
unfamiliar redirect.

1. Note the hostname(s) and IP(s) from the finding.
2. If you recognize this as your own entry (e.g. pointing a local dev
   domain like `myapp.test` at `192.168.x.x` for a VM, or a `/etc/hosts`
   entry from a VPN/corporate tool), no action needed.
3. If you don't recognize it, remove the line and re-scan.

## Step 4: Review the large-entry-count and general inventory findings (INFO/WARNING)

A large number of custom entries, or just the general list of what's in the
file, is informational unless the individual entries above raised flags.

1. Skim the listed entries. Ad-blocker lists (many entries all pointing to
   `127.0.0.1`/`0.0.0.0`) are expected and not a concern.
2. If you don't recognize the tool that installed a large ad-blocker-style
   list, confirm you still want it; if not, remove the block of entries
   with your editor of choice (`sudo nano /etc/hosts`), or uninstall/turn
   off whatever tool manages it rather than hand-editing if it's actively
   managed.
3. No action is needed when the file is reported clean (only default
   `localhost`/`broadcasthost` entries).
