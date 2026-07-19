---
title: "Review system and login keychain certificates"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.certificate_audit.expired_certificates
  - security.certificate_audit.user_root_cas
  - security.certificate_audit.total_certificates
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `certificate_audit` module can
flag: expired certificates in the System keychain, user-installed root
CAs in the login keychain, and the overall certificate inventory count.
Certificate deletion is destructive and can break TLS trust for
legitimate services (corporate VPNs, MDM, internal tools) if you remove
the wrong one — **verify what a certificate is for before removing it**,
and back up the keychain first.

## Step 1: Back up before touching any keychain

1. Before deleting anything, export a backup of the keychain(s) you're
   about to edit: open Keychain Access.app, select the keychain (System
   or login), File > Export Items, and save a `.p12`/`.keychain` copy
   somewhere safe. This lets you re-import a certificate if you remove
   something you needed.

## Step 2: Review and remove expired certificates

`expired_certificates` lists certificates past their expiry date.

1. Open Keychain Access.app, go to the System keychain, and use the
   "Expired" smart category (or sort by expiration) to find the flagged
   certificates by name.
2. For each one, click "Get Info" and check what it was issued for. Most
   expired certificates are harmless (an old CA or service cert that's
   simply aged out and been superseded), but confirm it isn't something
   still actively referenced by a VPN profile, MDM enrollment, or
   internal service before deleting — an expired cert that's still
   referenced by a config can cause connection failures if removed while
   still in use, until that config is also updated.
3. Delete only the ones you've confirmed are stale and unreferenced.

## Step 3: Verify provenance of user-installed root CAs before removing

`user_root_cas` lists root certificate authorities installed in the
login keychain (as opposed to Apple's built-in trusted roots). A root CA
being trusted means anything it signs is trusted system-wide — this is
powerful and is exactly the mechanism used by corporate MDM
(for TLS inspection / internal services) and, less legitimately, by
malware or adware wanting to intercept traffic.

1. For each flagged root CA, click "Get Info" in Keychain Access and note
   the issuer/subject name and installation date.
2. **Verify provenance before removing anything**: cross-reference the
   name against your organization's known MDM/corporate CA (check with
   IT if you're on a managed device — see `mdm_enrollment` module
   findings) or a VPN client you deliberately installed. Legitimate
   examples include corporate network inspection certs, some VPN clients,
   and developer tools like `mkcert`.
3. If a root CA doesn't match anything you or your organization
   installed deliberately, treat it as suspicious: do not simply delete
   it as a first step. Instead, search the exact certificate name/issuer
   online, check whether it's tied to a known adware/MITM tool, and
   consider a broader malware sweep (see `respond_to_malware_indicators.md`
   or `act_on_clamav_findings.md`) before removing it, since an
   unexplained trusted root is a stronger signal of compromise than most
   individual findings.
4. Once confirmed unwanted, remove it via Keychain Access: select it,
   right-click > Delete, then confirm you want to remove it from the
   login keychain.

## Step 4: Review certificate inventory

`total_certificates` is informational — the overall System keychain
count. No action is required; it's provided as context for the findings
above and as a baseline to compare against on future scans (a sudden
large increase in count is worth investigating even without a specific
flagged certificate).
