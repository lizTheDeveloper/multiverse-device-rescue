---
title: "Set a firmware password / review Startup Security"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.firmware_password.chip_type_detection_failed
  - security.firmware_password.chip_type
  - security.firmware_password.firmware_password_set
  - security.firmware_password.firmware_password_not_set
  - security.firmware_password.firmware_password_unknown
  - security.firmware_password.firmware_password_permission_denied
  - security.firmware_password.firmware_password_unavailable
  - security.firmware_password.startup_security_info
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers everything the `firmware_password` module can flag.
On Intel Macs it can report a missing/present firmware password (or that the
check couldn't run); on Apple Silicon Macs it reports informational status
about the Startup Security Utility, which replaces firmware passwords on
that hardware. Setting or changing a firmware password is human-only: it
requires booting into Recovery Mode, and — critically — a forgotten firmware
password can only be reset by Apple, with proof of ownership. Record it
somewhere safe, never in this tool.

## Step 1: Set a firmware password on an Intel Mac (`firmware_password_not_set`)

No firmware password means anyone with physical access can boot from
external media or reach Recovery Mode and potentially bypass the login
password.

1. Confirm current status yourself first: `sudo /usr/libexec/firmwarepasswd
   -check` (requires admin privileges — see Step 3 if this fails).
2. Restart and hold Cmd+R at startup to boot into Recovery Mode.
3. From the menu bar, choose Utilities > Firmware Password Utility (or
   Startup Security Utility on some macOS versions, which includes the same
   option).
4. Click **Turn On Firmware Password**, then set a strong password.
5. **Record this password securely** — save it to a password manager or
   write it down and store it somewhere physically safe. Never paste it
   into this tool, chat, or any note synced to an account you don't fully
   control. If you forget it, the only recovery path is a proof-of-purchase
   visit to Apple Support/an Apple Store — there is no software reset.
6. Restart normally and re-run the scan to confirm the password is now
   detected as set.

## Step 2: Review Startup Security Utility settings (Apple Silicon)

On Apple Silicon Macs, `startup_security_info` is informational — there is
no separate firmware password; instead, Secure Boot and allowed-OS policy
are controlled here. Review, don't blindly harden, since stricter settings
can block booting older/external OS installs you may still need.

1. Restart and hold the power button until "Loading startup options"
   appears, then choose Options > Continue to enter Recovery Mode.
2. Open Utilities > Startup Security Utility, select the internal disk, and
   authenticate as an admin.
3. Review the **Security Policy** (Full/Reduced/Permissive) and **Secure
   Boot** (Full/Medium/No Security) settings against your needs — Full
   Security is the safest default for most users; only relax it if you
   specifically need to boot older macOS versions or unsigned kernel
   extensions and understand the tradeoff.
4. Leave settings unchanged unless you have a specific reason to adjust
   them; this step is about verification, not automatic hardening.

## Step 3: Resolve check failures (unknown / permission denied / unavailable / chip detection failed)

These findings mean the module couldn't get a definitive answer, not that
anything is necessarily wrong.

1. If `firmware_password_permission_denied` was reported, re-run `sudo
   /usr/libexec/firmwarepasswd -check` yourself with admin privileges to
   get a real answer.
2. If `firmware_password_unavailable` or `chip_type_detection_failed` was
   reported, confirm you're on genuine Apple hardware running a supported
   macOS version — these utilities are expected to exist on all
   Apple-shipped Macs.
3. If `firmware_password_unknown` was reported, the output format from
   `firmwarepasswd -check` wasn't recognized; run it manually and read the
   result directly.

## Step 4: Informational findings

`chip_type` and `firmware_password_set` are informational confirmations —
no action needed. If `firmware_password_set` is present, no further steps
are required for this device.
