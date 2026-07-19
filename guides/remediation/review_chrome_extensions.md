---
title: "Review Chrome extensions and permissions"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.chrome_extensions.broad_permissions
  - security.chrome_extensions.extension_bloat
  - security.chrome_extensions.installed_extensions
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers `chrome_extensions` findings specific to Chrome's
extension permission model: extensions requesting broad permissions
(`<all_urls>`, `tabs`, `webRequest`, `activeTab`, `scripting`), too many
extensions installed, and a general inventory. For extensions matching
known malware/adware names, see `review_browser_extensions.md` (the
`browser_extension_audit` module covers name-based detection across all
browsers).

## Step 1: Review an extension with broad permissions

Broad permissions like `<all_urls>` or `webRequest` let an extension read
and modify traffic on every site you visit. Many legitimate categories of
extension genuinely need this (ad blockers, password managers, translation
tools, session/tab managers) — this finding is a prompt to verify the
specific extension, not evidence of a problem.

1. Note the extension name and the specific broad permissions listed.
2. Open `chrome://extensions/`, find the extension, and click "Details" to
   see its full permission list and description.
3. Cross-check the extension's stated purpose against what it's asking for
   — a "note taking" extension asking for `webRequestBlocking` on all URLs
   is a mismatch worth investigating; a password manager asking for the
   same is expected.
4. Check the publisher and the Chrome Web Store listing: install count,
   rating, and whether reviews mention unexpected behavior.
5. If it doesn't check out, remove it: `chrome://extensions/` → find it →
   Remove. If it does, no action is needed — you can optionally restrict
   its site access to specific sites instead of all sites via "Details" >
   "Site access" if you want to reduce scope without removing it entirely.

## Step 2: Reduce Chrome extension bloat

Flagged when more than 10 extensions are installed. More installed
extensions means more background code and a larger attack surface, even
when each one is individually trustworthy.

1. Go to `chrome://extensions/`.
2. For each extension, ask whether you've actually used it in the last
   month; remove ones you haven't.
3. Consolidate overlapping tools (e.g. multiple screenshot/clipping
   extensions) down to one you trust.

## Step 3: Review the full extension inventory

Informational — lists every detected Chrome extension with its requested
permissions.

1. Read through the list and confirm you recognize each entry and its
   permission set.
2. For anything unfamiliar, look it up by name in the Chrome Web Store
   before deciding whether to keep it — some extensions arrive bundled with
   other software installs without a clear prompt.
3. Re-run the scan periodically; a new, unrecognized entry appearing
   between scans is worth investigating even if it turns out benign.
