---
title: "Review Safari extensions and content blockers"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.safari_extensions.legacy_extensions
  - security.safari_extensions.app_extensions
  - security.safari_extensions.extension_bloat
  - security.safari_extensions.content_blockers_enabled
  - security.safari_extensions.content_blockers_disabled
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers `safari_extensions` findings specific to Safari:
deprecated `.safariextz` legacy extensions, the current app extension
inventory, too many extensions installed, and whether content blockers are
enabled. For extensions matching known malware/adware names or excessive
permission grants, see `review_browser_extensions.md` (the
`browser_extension_audit` module covers that cross-browser).

## Step 1: Remove legacy .safariextz extensions

Safari dropped support for the old `.safariextz` extension format; anything
still present is not just unsupported, it's a known abuse vector from the
era before Apple locked extensions down to the App Store/notarized model.

1. Note the extension name(s) from the finding.
2. Try removing via the GUI first: Safari > Settings > Extensions.
3. If not removable there (common for legacy format), locate the file(s) in
   `~/Library/Safari/Extensions/` — back up the folder first (`cp -R
   ~/Library/Safari/Extensions ~/Desktop/safari-extensions-backup-YYYYMMDD`),
   then delete the specific `.safariextz` file(s) you identified, not the
   whole directory.
4. Restart Safari and confirm the extension no longer appears.
5. If you relied on that extension's functionality, look for a modern App
   Store replacement rather than trying to re-enable the legacy format.

## Step 2: Review the installed Safari extension inventory

Informational — lists all detected Safari app extensions.

1. Read through the list and confirm you recognize and use each one.
2. For anything unfamiliar, check Safari > Settings > Extensions for more
   detail on the publisher, or search the extension's bundle identifier.
3. Remove anything you don't recognize or no longer need via Safari >
   Settings > Extensions > select > Uninstall.

## Step 3: Reduce Safari extension bloat

Flagged when more than 5 Safari extensions are installed. Each extension
runs code on pages you visit, so more installed extensions is a larger
overall attack surface even if none individually is malicious.

1. Open Safari > Settings > Extensions.
2. For each extension, ask whether you've used it recently; remove ones you
   haven't.
3. Prefer keeping one tool per category (one ad blocker, one password
   manager) rather than several overlapping ones.

## Step 4: Content blockers

Two different findings, both informational-to-low-severity:

- If content blockers are **enabled**, this is good — no action needed.
- If content blockers are **not enabled**, consider turning one on for
  privacy/performance:
  1. Install a content blocker from the App Store (e.g. a reputable ad/
     tracker blocker) if you don't already have one.
  2. Enable it: Safari > Settings > Extensions > Content Blockers, toggle
     the blocker(s) you want active.
  3. This is optional hardening, not a fix for an active compromise — treat
     it as a "nice to have" rather than urgent.
