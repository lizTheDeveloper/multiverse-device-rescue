---
title: "Review Screen Time and parental controls"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.screen_time_audit.screen_time_enabled
  - security.screen_time_audit.screen_time_no_passcode
  - security.screen_time_audit.content_privacy_restrictions
  - security.screen_time_audit.downtime_enabled
  - security.screen_time_audit.app_limits_configured
  - security.screen_time_audit.communication_limits_configured
  - security.screen_time_audit.screen_time_disabled
  - security.screen_time_parental.screen_time_enabled
  - security.screen_time_parental.screen_time_no_passcode
  - security.screen_time_parental.content_privacy_restrictions
  - security.screen_time_parental.content_privacy_disabled_with_children
  - security.screen_time_parental.app_limits_configured
  - security.screen_time_parental.downtime_enabled
  - security.screen_time_parental.communication_limits_configured
  - security.screen_time_parental.adult_content_filtering
  - security.screen_time_parental.ask_to_buy_enabled
  - security.screen_time_parental.screen_time_disabled_with_children
  - security.screen_time_parental.screen_time_disabled
  - security.screen_time_parental.managed_accounts
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers what the `screen_time_audit` and `screen_time_parental`
modules inventory: whether Screen Time is enabled, whether it's protected by
a passcode, the state of Content & Privacy Restrictions, Downtime, App
Limits, and Communication Limits, plus (for `screen_time_parental`) managed
child accounts, adult content filtering, and purchase ("Ask to Buy")
restrictions. All of it is informational review — Screen Time is a
legitimate feature for managing your own usage or a family member's device,
so nothing here is auto-applied. The goal is to confirm the configuration
matches what you actually intend, not to assume any particular state is
wrong.

## Step 1: Set a Screen Time passcode if Screen Time is enabled (important)

Screen Time without a passcode can be turned off, or have its limits
changed, by anyone using the account — including the exact person the
controls are meant to apply to.

1. Open System Settings > Screen Time.
2. Click "Use Screen Time Passcode" (or "Change Screen Time Passcode" if one
   already exists but wasn't detected — the scan can only see whether the
   passcode key is set).
3. Enter a passcode that's different from the account login password and
   not shared with the person Screen Time is meant to restrict.

## Step 2: Review Content & Privacy Restrictions

1. Open System Settings > Screen Time > Content & Privacy.
2. Confirm the current restrictions (app ratings, explicit content, web
   content filtering, Siri restrictions) match what you intend for this
   device. If the finding reported restrictions as enabled, verify the
   specific rules rather than assuming the defaults are right.
3. If restrictions are disabled and you expected them on, enable them here.

## Step 3: Review Downtime, App Limits, and Communication Limits

These three features work together to shape when and how the device can be
used.

1. Open System Settings > Screen Time > Downtime and confirm the schedule
   (if any) matches your intent — e.g., off during work/school hours,
   bedtime hours blocked.
2. Open App Limits and review which categories or apps have daily caps, and
   whether the cap values still make sense.
3. Open Communication Limits and confirm the allowed-contacts list is
   current — remove anyone who shouldn't have unrestricted contact access
   during Downtime.

## Step 4: Decide whether Screen Time should be enabled at all

If the scan reported Screen Time as disabled, that's not inherently a
problem — it's only useful if you actually want usage monitoring or limits
on this device.

1. If this is a personal device with no need for usage limits, no action is
   needed.
2. If you do want Screen Time (self-monitoring, or managing a family
   member's device), enable it: System Settings > Screen Time > Turn On,
   then set a passcode (Step 1) and configure the features in Step 3.

## Step 5: Review managed/child accounts and protections that depend on them

The `screen_time_parental` scan additionally flags cases where this device
has managed/child accounts but the protections meant for them are missing
or disabled.

1. If the scan reported managed/child accounts, open System Settings >
   Screen Time and confirm the list of accounts matches who you expect to
   have restricted access on this device.
2. If Content & Privacy Restrictions were reported as **disabled while
   managed accounts exist**, this is worth acting on promptly: open System
   Settings > Screen Time > [child account] > Content & Privacy and enable
   restrictions appropriate for that account's age.
3. If Screen Time itself was reported as **disabled while managed accounts
   exist**, enable it for that account and configure a passcode (Step 1),
   App Limits, Downtime, and Communication Limits (Step 3) — an unmanaged
   Screen Time state on a child account means none of the intended controls
   are active.

## Step 6: Review adult content filtering and purchase approval

1. Open System Settings > Screen Time > [child account] > Content &
   Privacy > Content Restrictions and confirm adult content / web filtering
   is set the way you expect for that account.
2. Open Family Sharing settings and confirm "Ask to Buy" is configured for
   accounts that should require purchase approval — if the scan reported it
   as enabled, periodically review pending/approved purchase requests to
   make sure they still look reasonable.
