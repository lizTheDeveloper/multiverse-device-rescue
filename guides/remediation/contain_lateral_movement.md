---
title: "Contain AI worm lateral movement and credential exposure"
estimated_time: "30 minutes"
platforms: [macos, linux, windows]
remediates:
  - security.ai_worm_lateral.credential_harvesting
  - security.ai_worm_lateral.supply_chain_artifact
  - security.ai_worm_lateral.imds_access
  - security.ai_worm_lateral.npm_publish_credentials
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

## Step 1: Quarantine credential-harvesting storage files, then rotate

This module intentionally does **not** flag standard credential files
(`~/.aws/credentials`, `~/.ssh/id_rsa`) just for existing — only files at
worm-specific storage locations from the shared IOC database are flagged
here, so a hit means something actively wrote stolen credentials to disk.

1. Inspect the flagged file's contents first — this tells you exactly which
   credentials were captured (GitHub PATs, SSH keys, npm tokens, cloud
   keys, etc.) and is essential for a precise rotation in the next step.
2. Quarantine, don't delete: move it to `~/.rescue_quarantine/` so it's
   preserved for forensic reference:
   ```
   mkdir -p ~/.rescue_quarantine
   mv <flagged-path> ~/.rescue_quarantine/
   ```
3. **From a known-clean device**, rotate and revoke every credential type
   identified in Step 1 — do not rotate from the still-possibly-compromised
   machine, since a still-running worm process could re-harvest the new
   credential immediately.
4. Cross-check with the `ai_worm_persistence` and `ai_worm_network`
   walkthroughs — a credential-harvesting file usually implies an active
   persistence mechanism and/or C2 connection elsewhere on the system that
   should be remediated in the same session.

## Step 2: Remove supply-chain compromise artifacts, then rotate

High-confidence findings here matched a known dropper/workflow filename
(e.g. `.github/workflows/shai-hulud-workflow.yml`, `setup_bun.js`,
`bun_environment.js`) inside a project directory — these ran with whatever
credentials were available in that project's environment.

1. Inspect the artifact before removing it — read what it does, particularly
   which secrets/environment variables or cloud credentials it reads or
   exfiltrates.
2. Remove the file from the repository. If it was committed to git history,
   plan to rewrite history or rotate the repository entirely once
   credentials are secured — a removed-but-still-in-history file is not
   fully remediated.
3. Check every clone/checkout of the affected repository, not just the one
   you scanned — the same artifact may exist in multiple working copies or
   CI runners.
4. **From a known-clean device**, rotate every credential reachable from
   that project's CI/CD environment: GitHub Actions secrets, npm publish
   tokens, and any cloud IAM credentials/roles the pipeline had access to.
   Review your CI provider's run history for unauthorized executions of the
   malicious workflow.

## Step 3: Investigate IMDS access from unrecognized processes (medium confidence)

A finding here means a process not on the recognized cloud-CLI allowlist
(aws, gcloud, az, terraform, kubelet, etc.) connected to the cloud instance
metadata service (`169.254.169.254`) — a common way to harvest cloud IAM
credentials without needing local credential files at all.

1. Identify the process from the finding (name, PID) and inspect its
   command line and binary path
   (`ps -p <pid> -o command=`) before acting — legitimate but unlisted
   tooling can also query IMDS.
2. If unfamiliar or clearly not something you run, terminate the process
   (`kill <pid>`) and investigate what launched it.
3. **From a known-clean device or the cloud provider's console**, rotate or
   revoke the IAM role/credentials associated with this host's instance
   profile, and review the cloud provider's IAM activity log for
   unauthorized API calls made using metadata-service-derived credentials.
4. If this is a cloud instance (not a personal laptop), also consider
   terminating and replacing the instance from a known-good image rather
   than trying to fully clean it in place.

## Step 4: Review active npm publish credentials (informational)

This is an informational finding — the module detected that `npm whoami`
returns an authenticated user, meaning the local npm CLI currently holds
valid publish credentials. This is normal for developers who publish
packages; it is only concerning in the context of the other findings this
module (or `ai_worm_lateral`/`ai_worm_network`) may have surfaced.

1. Confirm you (or your team) intentionally authenticated npm on this
   machine, and that the reported username matches your account.
2. If this session was not one you initiated, or if other high-confidence
   findings fired alongside it, treat the npm token as compromised:
   revoke it from https://www.npmjs.com/settings (Access Tokens) from a
   known-clean device, and generate a fresh token only after the machine is
   confirmed clean.
3. Review your npm account's publish history for packages/versions you did
   not publish yourself.
4. As routine hygiene, prefer short-lived, automation-scoped npm tokens over
   long-lived personal publish tokens where your workflow allows it.
