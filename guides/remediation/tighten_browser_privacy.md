---
title: "Tighten Safari and browser privacy settings"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.browser_privacy_check.do_not_track_disabled
  - security.browser_privacy_check.fraud_warning_disabled
  - security.browser_privacy_check.cookies_always_allow
  - security.browser_privacy_check.autofilll_passwords_enabled
  - security.browser_privacy_check.installed_browsers
  - security.browser_privacy_check.saved_passwords
  - security.browser_privacy_check.privacy_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `browser_privacy_check` module
can flag: Safari's Do Not Track, fraud-warning, and cookie-blocking
settings, whether password autofill is enabled, and inventory findings
about installed browsers and saved passwords. All changes are made
through Safari's own Settings UI — nothing here is auto-applied, since
some of these (like cookie policy) can affect site functionality you
rely on.

## Step 1: Enable fraud website warnings (recommended first)

`fraud_warning_disabled` means Safari won't warn you before visiting a
known phishing/malicious site.

1. Open Safari > Settings > Security.
2. Enable "Warn when visiting a fraudulent website."

## Step 2: Enable Do Not Track

`do_not_track_disabled` means Safari isn't sending the DNT signal to
sites.

1. Open Safari > Settings > Privacy.
2. Enable "Ask websites not to track me." Note this is a request, not an
   enforcement mechanism — sites can ignore it — but it's a free, no-risk
   signal to enable.

## Step 3: Restrict overly permissive cookie policy

`cookies_always_allow` means Safari is set to allow all cookies,
including third-party/advertiser cookies.

1. Open Safari > Settings > Privacy.
2. Change "Block all cookies" configuration to a more restrictive option
   such as blocking third-party and advertiser cookies (Safari's default
   is "Prevent cross-site tracking," which is usually the right choice).
3. If a specific site you rely on breaks after tightening this (some
   older SSO or embedded-widget-heavy sites depend on third-party
   cookies), you can add a site-specific exception rather than reverting
   the global policy.

## Step 4: Review password autofill (informational)

`autofilll_passwords_enabled` is informational, not necessarily a
problem — autofill is generally safe because it's backed by your
system keychain and login password. It's worth a second look only if
your login password is itself weak.

1. If you're unsure how strong your login password is, that's the actual
   thing to fix (see `login_password_policy` / `screen_lock_check`
   module guidance) rather than disabling autofill, which is a
   convenience feature with a real usability cost if turned off.
2. If you still want to disable it: Safari > Settings > Passwords and
   toggle off "AutoFill passwords and passkeys."

## Step 5: Review browser and saved-password inventory

`installed_browsers` and `saved_passwords` are informational.

1. Confirm every listed browser is one you actually use. An unfamiliar
   browser you don't remember installing is worth investigating — check
   when it was installed and whether it came bundled with something
   else.
2. For browsers other than Safari (Chrome, Firefox), review their
   privacy settings independently in each browser's own settings pane —
   this module only inspects Safari's configuration in depth.
3. The saved-password count is informational context; periodically
   reviewing and removing entries for accounts you no longer use (via
   Safari > Settings > Passwords, or Keychain Access) is good hygiene but
   not required by this finding alone.
