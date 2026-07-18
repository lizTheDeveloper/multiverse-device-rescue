---
title: "Clean AI worm filesystem artifacts safely"
estimated_time: "20 minutes"
platforms: [macos, linux, windows]
remediates:
  - security.ai_worm_filesystem.known_payload_path
  - security.ai_worm_filesystem.known_hash_match
  - security.ai_worm_filesystem.obfuscated_script
automatable_steps: []
human_only_steps: [1, 2, 3]
---

## Step 1: Quarantine known-malicious payload files

High-confidence findings here matched a path in the shared IOC database
against a known AI worm payload location (e.g. dropped scripts under
`~/.local/bin`, `~/.config`, `~/.cache`, `/tmp`, or `/var/tmp`).

1. **Inspect before moving anything.** Open each flagged file and read its
   contents. Note what it does — this matters for later steps (Step 3
   credential rotation depends on knowing what the payload could see).
2. **Quarantine, don't delete.** Move the file to a dedicated quarantine
   directory rather than removing it outright, so it's available for later
   forensic review:
   ```
   mkdir -p ~/.rescue_quarantine
   mv <flagged-path> ~/.rescue_quarantine/
   ```
3. **Check for related processes.** If the file was executable, confirm no
   running process still references it (`lsof <path>` on macOS/Linux,
   Task Manager on Windows) before quarantining. Terminate any such process
   first.
4. Re-run the scan (`rescue check`, or the `ai_worm_filesystem` module) to
   confirm the file no longer appears as a high-confidence finding.

## Step 2: Handle known-hash matches (byte-identical malware)

These findings matched a file's SHA-256 hash directly against the IOC
database's known-malware hash list — the highest-confidence signal this
module produces, since it means the file is byte-for-byte identical to a
previously catalogued sample.

1. Confirm the reported path and hash in the finding data before acting.
2. Quarantine the file using the same `mv` approach as Step 1 — do not
   `rm` it, since a byte-identical hash match is exactly the kind of sample
   worth preserving for analysis or sharing with a security team.
3. If the file has appeared in multiple locations (e.g. copied into several
   project directories), quarantine every copy and note all original paths.

## Step 3: Review obfuscated scripts (medium confidence — inspect first)

These findings are heuristic: a script under a scanned directory contains a
pattern associated with obfuscation techniques used by AI worm payloads
(base64-encoded `exec`/`eval`, `atob`-decoded `eval`, or a `curl | bash` /
`wget | sh` style pipeline). This is **not** a confirmed match — many
legitimate install scripts use similar patterns.

1. Open the flagged file and read the matched pattern in context (the
   finding includes the matched snippet). Determine whether it is a tool
   installer you intentionally added, or something unfamiliar.
2. If it's an installer you recognize and trust, leave it in place and note
   it as reviewed — no action needed.
3. If it's unfamiliar, or it decodes/executes content you can't account
   for, quarantine it (Step 1's `mv` approach) rather than deleting it, and
   treat any credentials the script's process could have accessed as
   potentially exposed.
4. When in doubt, keep the file quarantined rather than deleted so it can be
   analyzed later, and consider rotating credentials that were reachable
   from the account/session where the script ran.
