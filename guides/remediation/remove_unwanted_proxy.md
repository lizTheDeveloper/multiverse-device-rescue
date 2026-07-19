---
title: "Remove an unwanted network proxy"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.network_proxy.pac_url_detected
  - security.network_proxy.proxy_enabled
  - security.network_proxy.no_proxies
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers everything the `network_proxy` module can flag: a
Proxy Auto-Configuration (PAC) file URL, an explicitly configured HTTP/
HTTPS/SOCKS proxy, and the clean "no proxies configured" state. A rogue
proxy or PAC file lets an attacker (or malware) intercept and rewrite your
web traffic, including injecting ads or capturing credentials, without
needing a foothold anywhere else on the network — so unexplained proxy
settings on a home machine are a meaningful finding. Before removing
anything, confirm you or your organization didn't set it up intentionally
(corporate MDM, a legitimate ad-blocking/filtering proxy, or a VPN client
that manages proxy settings itself).

## Step 1: Remove an unexpected PAC URL (CRITICAL)

A PAC (Proxy Auto-Configuration) file tells the system which proxy to use
per-destination, potentially routing only specific sites (e.g. banking)
through an attacker's proxy while leaving everything else normal — making
it harder to notice. This is rare on home machines and common on corporate
ones, so context matters.

1. Note the interface (Wi-Fi/Ethernet) and PAC URL from the finding.
2. If this is a work machine under MDM/corporate management, check with
   your IT department before changing anything — this may be intentional
   and required for corporate network access.
3. If this is a personal machine and you didn't set this up: open System
   Settings → Network → (interface) → Details → Proxies tab, and uncheck
   "Automatic Proxy Configuration."
4. Save/Apply, then re-run the scan to confirm the PAC URL is gone.
5. Since this is a strong compromise indicator on a home machine, also
   check for how it got set: unfamiliar configuration profiles (System
   Settings → Privacy & Security → Profiles — remove any you don't
   recognize) and recently installed apps/browser extensions, since some
   adware/malware installs a profile specifically to push proxy settings.
6. If you find and remove a malicious profile, treat any credentials
   entered while the proxy was active as potentially compromised and
   change them from a separate, known-clean device.

## Step 2: Review an explicitly configured proxy (WARNING)

An HTTP, HTTPS, or SOCKS proxy explicitly enabled on an interface routes
all matching traffic through that proxy server — legitimate on corporate
networks and with some privacy/filtering tools, but a hijacking vector if
unexpected.

1. Note the interface and which proxy type(s) (HTTP/HTTPS/SOCKS) plus the
   configured server address from the finding.
2. Check whether you recognize the server address — is it a proxy you or
   your organization set up intentionally (corporate proxy, ad-blocking
   proxy like a local Pi-hole/Privoxy instance, VPN client managing its own
   proxy)?
3. If intentional, no action is needed.
4. If unexpected: open System Settings → Network → (interface) → Details →
   Proxies tab, uncheck the relevant proxy type(s), Save/Apply.
5. Re-run the scan to confirm the proxy is no longer reported as enabled.
6. As in Step 1, if this was unexpected, check for a configuration profile
   or recently installed software that could have set it, and remove the
   root cause, not just the setting.

## Step 3: No action needed for the clean state (INFO)

When no proxy is configured on either interface, the module reports this
as informational — this is the expected, healthy state for most home
machines. No action needed.
