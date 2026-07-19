---
title: "Fix browser hijacking (homepage / search engine / policy)"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.browser_hijack_check.safari_homepage_suspicious
  - security.browser_hijack_check.safari_search_engine_suspicious
  - security.browser_hijack_check.chrome_managed_by_policy
  - security.browser_hijack_check.chrome_homepage_suspicious
  - security.browser_hijack_check.chrome_search_engine_suspicious
  - security.browser_hijack_check.firefox_homepage_suspicious
  - security.browser_hijack_check.firefox_search_engine_suspicious
  - security.browser_hijack_check.all_browsers_clean
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `browser_hijack_check` module can
flag: a Safari, Chrome, or Firefox homepage/search engine that doesn't match
a known-legitimate provider, and Chrome being controlled by an enterprise
policy. None of these are conclusive proof of hijacking on their own — a
homepage set to a company intranet page, or a search engine your employer's
MDM configured, will also trigger these checks. Inspect before changing
anything, and only reset settings you've confirmed you didn't set yourself.

## Step 1: Investigate a suspicious homepage (Safari/Chrome/Firefox)

1. Note which browser and the flagged homepage URL from the finding.
2. Ask yourself whether you (or a legitimate installer/IT policy) set this
   deliberately — a company intranet, a personal site, or a niche search
   portal will all fail the "known legitimate" check without being hijacked.
3. If you don't recognize the URL, open it cautiously in a new private/incognito
   tab (not by trusting it as your homepage) and inspect where it redirects —
   hijacked homepages commonly funnel through an ad/redirect chain before
   landing on a fake search page.
4. If confirmed unwanted, reset it:
   - **Safari**: Safari > Settings > General > Homepage — set to
     `about:blank` or a trusted site.
   - **Chrome**: Chrome > Settings > On Startup — select "Open the New Tab
     page" or enter a trusted URL.
   - **Firefox**: Firefox > Settings > Home > Homepage and new windows — set
     to a trusted page.
5. After resetting, check the browser's installed extensions (see
   `review_browser_extensions.md`) — homepage hijacks are frequently
   delivered alongside a malicious extension, and resetting the homepage
   alone won't remove the underlying cause if one is present.

## Step 2: Investigate a suspicious default search engine

1. Note which browser and the flagged search engine/provider string.
2. Confirm you didn't intentionally switch to a niche provider (Startpage,
   Ecosia, Brave Search, a corporate search proxy) — these are legitimate
   but won't match the built-in "known good" list.
3. If unrecognized, check the browser's extension list first (a rogue
   extension is a common way search defaults get silently changed) before
   just flipping the setting back, so you address the root cause.
4. Reset the default search engine:
   - **Safari**: Safari > Settings > Search — choose Google, Bing,
     DuckDuckGo, or Yahoo.
   - **Chrome**: Chrome > Settings > Search engine — pick a legitimate
     provider from the dropdown, and remove any unrecognized custom search
     engines listed under "Manage search engines."
   - **Firefox**: Firefox > Settings > Search — pick a legitimate default
     and remove unrecognized entries from the search engine list.

## Step 3: Review Chrome enterprise policy management

Chrome reporting itself as managed by policy is not inherently malicious —
this is normal on a company-issued or MDM-enrolled Mac. It's worth a look
because some hijack techniques abuse policy-like configuration to force
extensions or settings.

1. Open `chrome://policy` in Chrome and review the listed policies and their
   source.
2. If this is a work machine enrolled in MDM, and the policies match what
   you'd expect from your organization (e.g. extension allowlists, safe
   browsing settings), no action is needed.
3. If you don't recognize the organization/profile managing the browser, or
   this is a personal machine that shouldn't be managed at all, that's a
   stronger signal — check System Settings > Profiles for an unexpected
   configuration profile and remove it after confirming you don't need it,
   then reinstall Chrome cleanly if policies persist.

## Step 4: No issues found

If the scan reports only the `all_browsers_clean` INFO finding, no
homepage, search engine, or policy anomalies were detected in any installed
browser — no action is needed.
