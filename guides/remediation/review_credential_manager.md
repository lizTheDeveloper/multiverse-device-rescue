---
title: "Review Windows Credential Manager entries"
estimated_time: "15 minutes"
platforms: [windows]
remediates:
  - security.win_credential_manager_audit.credential_sprawl
  - security.win_credential_manager_audit.domain_credentials_non_domain_joined
  - security.win_credential_manager_audit.generic_credentials_sensitive_services
  - security.win_credential_manager_audit.inventory_summary
automatable_steps: []
human_only_steps: [1, 2, 3]
---

`win_credential_manager_audit` inventories what's stored in Windows
Credential Manager and flags patterns worth a second look — it does not
identify specific bad credentials, only signals that review is warranted.
**Inspect every credential before deleting it** — Credential Manager entries
are frequently relied on by apps, mapped network drives, and saved Remote
Desktop connections, and removing the wrong one can break something you use
daily.

## Step 1: Review for credential sprawl (excessive stored credentials)

1. Open Credential Manager: Win+R, `control /name Microsoft.CredentialManager`.
2. Go through the "Windows Credentials" and "Generic Credentials" lists. For
   each entry, check the target name and note whether it's for a service or
   app you still use.
3. For entries you no longer recognize or that reference old/archived
   projects, expand the entry and click "Remove" — only for ones you're
   confident are stale. When unsure, leave it; sprawl alone is not a
   critical risk, just hygiene.
4. Re-run the scan afterward — the credential count finding clears once the
   total drops below the threshold.

## Step 2: Review cached domain credentials on a non-domain-joined machine

Cached domain credentials on a machine that isn't currently part of that
domain are usually leftovers from a previous domain membership or a past
remote session — but confirm before removing, since a machine can be
temporarily off-domain (e.g. VPN not connected) while still legitimately
needing those credentials later.

1. Confirm this machine is genuinely not expected to rejoin that domain: `wmic
   computersystem get partofdomain,domain`.
2. If confirmed stale, open Credential Manager and remove the flagged domain
   credential entries.
3. If you're not sure whether this device will rejoin a domain, leave the
   credentials in place and re-check later instead of guessing.

## Step 3: Review generic credentials for sensitive services

Generic-type credentials for services like cloud consoles, source control,
or password managers are functionally just stored secrets — worth a closer
look, especially if you don't remember saving them.

1. For each flagged entry, confirm in Credential Manager whether you (or an
   app you use, like a Git credential helper or a cloud CLI) actually saved
   it intentionally.
2. If it's legitimate and actively used, no action is needed — Generic type
   is a normal storage mechanism for many tools, it's just less strongly
   scoped than Domain Password credentials.
3. If you don't recognize it or no longer use that service, remove it via
   Credential Manager.
4. Where practical, prefer an app-specific token/API key with limited scope
   over a full account password stored as a generic credential.

The inventory summary finding is informational — it lists the total count
and breakdown by type/service for your own awareness and doesn't require
action on its own.
