---
title: "Verify MDM enrollment and review configuration profiles"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.mdm_enrollment.mdm_enrolled
  - security.mdm_enrollment.supervised
  - security.mdm_enrollment.no_mdm
  - security.mdm_enrollment.profiles_installed
  - security.mdm_enrollment_check.mdm_enrollment
  - security.mdm_enrollment_check.restrictions_profiles
  - security.mdm_enrollment_check.all_profiles
  - security.mdm_enrollment_check.dep_status
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`mdm_enrollment` and `mdm_enrollment_check` both scan Mobile Device
Management (MDM) enrollment status, supervision, and installed
configuration profiles. **Do not attempt to remove MDM enrollment or delete
profiles yourself if this is a legitimate employer- or school-managed
device** — MDM unenrollment on a supervised device typically requires a
factory reset or IT-issued unenrollment, and removing the wrong profile can
break VPN, email, Wi-Fi, or app-restriction configuration, or in the worst
case leave the device unable to boot correctly into a usable state
("bricking" it from a usability standpoint until IT re-provisions it). The
goal here is verification and awareness, not removal.

## Step 1: Determine whether this MDM enrollment is expected

Both modules may report MDM enrollment, supervision, or a specific MDM
server name.

1. Ask yourself: is this a work-issued, school-issued, or otherwise
   organization-owned device? If yes, MDM enrollment (and supervision) is
   almost certainly legitimate and expected — no action needed beyond
   awareness.
2. If you don't recognize this device as belonging to an organization, or
   you got it secondhand, treat the MDM server name reported in the finding
   as a lead: search for it, or ask whoever you got the device from whether
   they know about an enrollment.
3. View full enrollment details for context: `sudo profiles show -verbose`
   (or `profiles status -type enrollment`).
4. **Do not attempt to remove enrollment yourself** based on this scan
   alone — verify with the organization first, since removal on a
   supervised device can require a full factory reset and re-provisioning.

## Step 2: Review installed configuration profiles

This is inventory information — profiles can come from MDM, manual
installation, or enterprise software, and often provide legitimate
functionality (VPN, Wi-Fi, email, restrictions).

1. List all profiles with detail: `sudo profiles list -verbose`.
2. Cross-reference the reported profile names/counts against what you
   expect for this device (e.g. a VPN profile for work, a Wi-Fi profile for
   school).
3. If you find a profile you don't recognize and this is **not** a managed
   device, that's worth investigating — it could indicate the device was
   enrolled without your knowledge. Removing an unexpected profile on an
   unmanaged personal device is safe: `sudo profiles remove -identifier
   <profile_identifier>`.
4. If this **is** a managed device, do not remove unfamiliar profiles
   without checking with IT first — they may be required for security or
   compliance and removal could violate organizational policy or break
   required functionality.

## Step 3: Review restriction profiles specifically

`mdm_enrollment_check` separately flags profiles whose names suggest they
impose restrictions (parental controls, content filtering, managed app
restrictions).

1. Review the listed restriction profile names.
2. If this is a family device with parental controls you set up
   intentionally, this is expected — no action needed.
3. If this is a managed device, restrictions are typically organizational
   policy — contact IT if a restriction seems wrong or is blocking
   something you need, rather than removing the profile.

## Step 4: No-MDM / DEP status (informational)

If the scan reports no MDM enrollment, or reports Device Enrollment
Program (DEP) status, these are informational and require no action —
they simply describe the device's current management state for your
awareness.
