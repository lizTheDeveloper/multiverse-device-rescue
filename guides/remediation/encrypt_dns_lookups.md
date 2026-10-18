---
title: "Encrypt your DNS lookups"
estimated_time: ""
platforms: [macos]
remediates:
  - network.dns_over_https_check.unencrypted_dns
  - network.dns_over_https_check.no_encryption_configured
  - network.dns_over_https_check.encrypted_dns_provider
steps_for:
  network.dns_over_https_check.unencrypted_dns: [1, 2, 3, 4, 5, 6]
  network.dns_over_https_check.no_encryption_configured: [1, 2, 3, 4, 5, 6]
  network.dns_over_https_check.encrypted_dns_provider: [6]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
monitoring_risk: false
---

This walkthrough covers the `dns_over_https_check` check, which looks at how
your Mac looks up website names. Nothing here is urgent, and nothing about
these findings means anyone has been watching you.

## Step 1: Know what encrypted DNS does and does not do

Every time your browser looks up a website, it sends a DNS query, usually to
your internet provider, in plain text. That means your provider, or anyone
else on your local network, can see every site name you look up.

Encrypted DNS (DNS over HTTPS or over TLS) hides those lookups from your
provider. It still sees which servers you connect to, so this is one layer,
not invisibility.

Changing which DNS server answers is a different thing. This changes who
answers, not who can see: the lookups still travel unencrypted, so your
provider can still read them. Pick who answers on purpose. Quad9 is run by a
Swiss not-for-profit foundation that says it never logs your IP address, and
it blocks known malware and phishing sites. Cloudflare is a company.

## Step 2: Turn on encrypted DNS in your browser

In Firefox, open Settings > Privacy & Security > DNS over HTTPS and choose
Increased or Max Protection.

In Chrome, open Settings > Privacy and security > Security and turn on Use
secure DNS.

## Step 3: Change which DNS server your Mac uses

This changes who answers, not who can see. To do it, open System Settings >
Network, select your active network connection, and click 'Details...'. Go
to the 'DNS' tab and click '+' to add DNS servers. Add Quad9 (9.9.9.9,
149.112.112.112) first, or Cloudflare (1.1.1.1, 1.0.0.1).

## Step 4: Install an encrypted DNS profile

To encrypt the lookups for the whole Mac, check your DNS provider's website
for a macOS profile. Import the profile in System Settings > General >
Profiles.

## Step 5: On your phone

On Android, open Settings > Network > Private DNS and set it to
'dns.quad9.net' (Quad9, the not-for-profit) or 'one.one.one.one'
(Cloudflare). On iPhone, install Cloudflare's 1.1.1.1 app, which encrypts
lookups on Wi-Fi and cellular.

## Step 6: Check that it is working

On Quad9, visit on.quad9.net, which says whether you are using Quad9. On
Cloudflare, visit one.one.one.one/help (or https://1.1.1.1/help), which says
whether your lookups are encrypted. dnsleaktest.com shows which servers are
answering. Some applications override system DNS, so check app-specific
settings too.
