---
title: "Check an app whose safety seal is broken or missing"
estimated_time: "20 minutes"
platforms: [macos, windows]
remediates:
  - security.code_signature_audit.tampered_binary
  - security.code_signature_audit.unsigned_system_app
  - security.code_signature_audit.gatekeeper_rejected
steps_for:
  security.code_signature_audit.tampered_binary: [1, 2]
  security.code_signature_audit.unsigned_system_app: [1]
  security.code_signature_audit.gatekeeper_rejected: [1, 3]
automatable_steps: []
human_only_steps: [1, 2, 3]
---

Software makers put a digital seal on their apps. The seal proves who made the
app and that nobody has changed it since. A broken seal means the app was
changed after the maker released it, and a missing seal means the maker can't be
checked. Both are reasons to ask where the app came from. Many missing seals are
harmless (free tools, software you built yourself, older programs), but a broken
seal on an app you didn't expect deserves attention.

**Before you remove anything:** if someone you know may be monitoring you,
removing an app they installed can alert that person. Talk to an advocate first
(US National DV Hotline: 1-800-799-7233, or text START to 88788). Take a photo
of the finding and write down the app name. That is your record.

## Step 1: Check if you installed this app

Look at the app name and location shown in the finding. Ask yourself: did I
install this, or did a program I trust install it? If it's a tool you downloaded
from its maker's website, or one you built yourself, an unsigned seal is expected.

## Step 2: Replace an app with a broken seal

A broken seal means the file was changed. The safe fix is a fresh copy:

1. Download the app again from the maker's own website or from the App Store
   (Mac) or Microsoft Store (Windows). Never use a link from an ad or an email.
2. Close the app. On a Mac, drag the old copy out of Applications; on Windows,
   open **Settings > Apps > Installed apps**, find it and choose **Uninstall**.
3. Install the fresh copy.

If you don't recognise the app at all, don't open it. Follow the note above
before removing it.

## Step 3: Understand the "macOS won't accept it" warning

This usually means the app is signed but not approved by Apple, which is normal
for software from outside the App Store. If you trust where it came from, you can
leave it. If you aren't sure, install the App Store or maker's current version
in its place.
