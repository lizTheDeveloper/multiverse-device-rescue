---
title: "Fix DNS hijacking or poisoning"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.dns_poisoning_check.malicious_dns
  - security.dns_poisoning_check.suspicious_dns
  - security.dns_poisoning_check.dns_resolution_issue
  - security.dns_poisoning_check.dns_config
  - security.dns_poisoning_check.dns_over_https
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `dns_poisoning_check` module can
flag: DNS servers that are outright malicious/sinkholes, DNS servers that
are merely non-standard, unexpected resolution of major domains, general
DNS configuration status, and DNS-over-HTTPS status. DNS hijacking redirects
your traffic (including logins) to attacker-controlled servers without any
other visible sign of compromise, so a malicious-DNS finding should be
treated urgently, while a suspicious-DNS or resolution-mismatch finding
should be investigated before you assume the worst — VPNs, corporate
networks, and some privacy tools legitimately set custom DNS.

## Step 1: Respond to malicious DNS servers (CRITICAL)

If a configured DNS server matches a known null-route/sinkhole address
(`0.0.0.0`, `127.0.0.1` used as the *system's* DNS server rather than a
local resolver you intentionally run), this is a strong indicator of
tampering — either malware changed your DNS settings, or a compromised
router/network is redirecting you.

1. Confirm the current setting yourself: `scutil --dns` or System Settings
   → Network → (your network) → Details → DNS.
2. Note whether this network's DNS was configured by you intentionally (a
   local ad-blocking resolver you run on `127.0.0.1`, for example) — if so
   this may be a false positive; otherwise treat it as compromise.
3. Reset DNS to automatic: System Settings → Network → (your network) →
   Details → DNS tab → remove custom entries with the minus (–) button, or
   set to Automatic/DHCP.
4. Flush the DNS cache: `sudo dscacheutil -flushcache; sudo killall
   -HUP mDNSResponder`.
5. If you're on Wi-Fi, also check the router's DNS settings (via its admin
   page) — a compromised router can push malicious DNS to every device on
   the network, in which case fixing just this Mac isn't enough. Change the
   router admin password if you find unauthorized changes there.
6. Re-run the scan to confirm DNS now reports as clean, then check for a
   root cause on this Mac: unfamiliar profiles (System Settings → Privacy &
   Security → Profiles) or unfamiliar login items/launch agents that could
   have made the change, since resetting DNS without removing the cause
   means it may return.

## Step 2: Review non-standard DNS servers (WARNING)

A DNS server that isn't one of the well-known public resolvers (Google,
Cloudflare, Quad9, OpenDNS) and doesn't look like a typical ISP/router
address is flagged for review — this is common for VPNs, corporate
networks, and privacy-focused resolvers, so it is not automatically bad.

1. Note the server IP(s) from the finding.
2. Check where this came from: is it your VPN's DNS, your workplace's
   internal resolver, or a resolver you configured yourself (e.g. a
   self-hosted Pi-hole)? If so, no action needed.
3. If you don't recognize the source, look up the IP (WHOIS/reverse DNS)
   to see who operates it.
4. If it's unexplained, reset to automatic/known-good DNS the same way as
   Step 1 (System Settings → Network → DNS tab), then flush the cache.

## Step 3: Investigate unexpected domain resolution (WARNING)

The module resolves a handful of major domains (apple.com, google.com,
microsoft.com) and flags it if the result falls outside that domain's
known IP ranges — a possible sign of DNS redirection.

1. Note the domain and the IP it resolved to.
2. Re-resolve it against a known-good public resolver directly:
   `dig +short <domain> @1.1.1.1` and compare to the system's answer
   (`dig +short <domain>`). If they differ, DNS is likely being
   intercepted somewhere between this Mac and the resolver.
3. If they match, the mismatch is more likely a stale IP-range list in the
   checker (large companies rotate/expand their IP blocks) than an actual
   problem — no action needed.
4. If they genuinely differ, follow Step 1's remediation (reset DNS to
   automatic, flush cache, check the router) and re-test.

## Step 4: Review general DNS configuration and DoH status (INFO)

These are informational findings — a summary of currently configured DNS
servers when they all look legitimate, a note that configuration couldn't
be read, or that DNS-over-HTTPS is enabled.

1. If DNS-over-HTTPS is reported enabled, no action is needed — this is a
   positive finding that reduces DNS eavesdropping/tampering risk.
2. If DNS configuration couldn't be retrieved, run `scutil --dns` yourself
   to confirm settings are what you expect; this is usually a permissions
   or sandboxing artifact of the scan rather than an actual problem.
3. If the configuration summary lists servers you don't recognize, treat it
   the same as Step 2 above.
