---
title: "Review trusted root certificates"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.certificate_trust_audit.suspicious_certificates
  - security.certificate_trust_audit.self_signed_root_certs
  - security.certificate_trust_audit.expired_certificates
  - security.certificate_trust_audit.user_added_certs
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `certificate_trust_audit` module can
flag in the System keychain's root certificate store: certificates with
names suggesting traffic interception, self-signed non-Apple root CAs,
expired certificates, and the general inventory of non-Apple root
certificates. A root certificate in your trust store can silently
man-in-the-middle any HTTPS connection your Mac makes, so this store is
worth reviewing periodically — but legitimate corporate MDM/VPN/EDR
software, and developer proxy tools you installed on purpose, also add
entries here. **Verify a certificate's provenance before deleting it from
the keychain** — removing a certificate a corporate MDM profile or VPN
client depends on can break connectivity to internal resources.

## Step 1: Investigate a suspicious certificate (critical)

Flagged because the certificate's subject name contains a keyword
suggesting traffic interception or debugging (`proxy`, `inspect`, `mitm`,
`debug`). Root certificates like this are exactly how corporate SSL-
inspecting proxies work, and also exactly how attacker-installed
interception certificates work — the name alone can't distinguish them.

1. Note the certificate subject/name(s) from the finding.
2. Open Keychain Access (Applications > Utilities > Keychain Access),
   select the "System" keychain, and locate the certificate by name.
3. Determine provenance before touching it:
   - Check System Settings > Profiles for a configuration profile that
     installed it (common for corporate MDM/VPN/proxy tools) — if present,
     and you recognize the organization, this is very likely a deliberate
     corporate SSL-inspection proxy and expected on a managed device.
   - Check if you installed a specific dev tool that adds a local proxy CA
     (Charles Proxy, Fiddler, mitmproxy) — if you use one of these for
     debugging, this is expected.
   - If neither explains it, treat it as a potential compromise: don't
     delete yet — first check what else on the system might be affected
     (unexpected VPN/proxy configuration in Network settings, unfamiliar
     LaunchAgents) so you understand the scope before cleaning up.
4. Once you've confirmed it's unwanted, delete it in Keychain Access:
   select the certificate, press Delete, and enter your admin password
   when prompted.
5. After removal, check your Mac's proxy settings (System Settings >
   Network > [interface] > Details > Proxies) for a proxy configuration you
   didn't set, since interception certificates are commonly paired with a
   forced proxy.

## Step 2: Review self-signed root certificates

Flagged for non-Apple root certificates whose issuer matches their own
subject (self-signed) — again, this covers both legitimate dev-proxy tools
and potential interception certificates.

1. Note the certificate name(s).
2. Apply the same provenance check as Step 1 (MDM profile, known dev tool,
   or unexplained).
3. If it's a dev tool you no longer use, or unexplained, remove it via
   Keychain Access as in Step 1.
4. If it's tied to an active corporate profile you still need, leave it —
   removing it may break access to internal sites your organization
   proxies.

## Step 3: Remove expired certificates

An expired root certificate can't be used for interception (clients should
reject it), but keeping stale entries around adds clutter and can mask a
newer, more relevant finding.

1. Note the certificate name(s).
2. Open Keychain Access, locate each one, confirm the expiration date shown
   matches, and delete it — this is low-risk cleanup since an expired root
   cert isn't providing any active function.

## Step 4: Review the full user-added certificate inventory

Informational — lists every non-Apple root certificate present.

1. Read through the list and confirm you can account for each one (a VPN
   client, an MDM profile, a specific dev tool).
2. For anything you can't explain, apply the provenance check from Step 1
   before deciding whether to remove it.
3. Re-run the scan after any corporate device re-enrollment or major
   software install, since new entries can appear silently as part of an
   installer.
