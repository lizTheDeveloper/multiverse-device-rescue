---
title: "Review browser extensions"
estimated_time: "25 minutes"
platforms: [macos]
remediates:
  - security.browser_extension_audit.malicious_extension
  - security.browser_extension_audit.adware_extension
  - security.browser_extension_audit.excessive_permissions
  - security.browser_extension_audit.extension_bloat
  - security.browser_extension_audit.installed_extensions
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers `browser_extension_audit` findings across Chrome,
Firefox, and Safari: extensions matching known malware/adware names,
extensions requesting an unusually broad set of dangerous permissions, too
many extensions installed overall, and a general inventory of what's
installed. Review before removing anything — the "excessive permissions"
and "installed extensions" findings are not proof of a problem by
themselves, just a prompt to look.

## Step 1: Remove a known-malicious extension (critical)

The scan matched an installed extension's name against a documented list of
malicious extensions (Superfish, Babylon, Conduit, and similar).

1. Note the browser and extension name/ID from the finding.
2. Remove it immediately:
   - **Chrome**: `chrome://extensions/` → find the extension → Remove.
   - **Firefox**: `about:addons` → Extensions → find it → Remove.
   - **Safari**: Safari > Settings > Extensions → find it → Uninstall.
3. After removing, check the browser's homepage and default search engine
   (see `fix_browser_hijack.md`) — these malicious extensions commonly
   change those settings too, and removing the extension doesn't revert
   settings it already changed.
4. Clear the browser's cache and restart it to ensure no leftover injected
   content persists in open tabs.

## Step 2: Remove a known adware/PUP extension

The scan matched an extension name against known adware/potentially-unwanted
program names (Hola VPN, Web of Trust, Stylish, toolbar/coupon-injector
extensions, and similar).

1. Note the browser and extension name from the finding.
2. Confirm you actually intended to install it — some of these (e.g. Hola
   VPN) are used deliberately despite being flagged for known privacy
   issues (Hola resells your bandwidth as an exit node). If you understand
   and accept that tradeoff, no action is required.
3. If unwanted, remove it via the same per-browser steps as Step 1.

## Step 3: Review an extension with excessive dangerous permissions

Flagged when an extension requests 3+ permissions from a high-risk set
(`<all_urls>`, `webRequest`, `webRequestBlocking`, `cookies`, `tabs`). Many
legitimate extensions (ad blockers, password managers, session managers)
need exactly this permission set to function, so this is a prompt to
verify, not a verdict.

1. Note the extension name, browser, and the specific permissions listed.
2. Check the extension's actual purpose against the permissions it asks
   for — a password manager needing `<all_urls>` and `tabs` is expected; a
   simple "screenshot tool" needing `webRequestBlocking` and `cookies` is
   not.
3. Check the publisher: is it from a company/developer you recognize and
   trust, with a reasonable install count and review history in the
   extension store?
4. If it doesn't check out, remove it via the per-browser steps in Step 1.
   If it does, no action is needed.

## Step 4: Reduce extension bloat

Flagged when the total extension count across all browsers exceeds 15.
More installed extensions means a larger attack surface and more code
running on every page you visit, even if each individual extension is
benign.

1. Open each browser's extension management page (`chrome://extensions/`,
   `about:addons`, Safari > Settings > Extensions).
2. For each extension, ask: have I used this in the last month? If not,
   remove it — you can always reinstall later if needed.
3. Prefer consolidating overlapping functionality (e.g. multiple ad
   blockers) down to one trusted extension.

## Step 5: Review the full extension inventory

Informational — lists every detected extension per browser along with its
permissions.

1. Read through the list and confirm you recognize every entry.
2. For anything unfamiliar, look it up in the relevant extension store by
   name/ID before deciding whether to keep or remove it — an extension you
   don't remember installing may have come bundled with other software.
3. Re-run the scan periodically; new extensions appearing between scans is
   worth noticing even if each one turns out to be legitimate.
