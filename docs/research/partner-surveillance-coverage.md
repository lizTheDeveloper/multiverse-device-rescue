# Partner surveillance: research tactics vs. what Reclaim City checks

This is a defender's coverage map. It lists the tactics that published research
says people use to surveil an intimate partner, and for each one, whether a
Reclaim City scan would notice it today. Tactics are described only at the
level of the category the papers use.

Ratings:

- **Caught**: a check on this computer reports it, on the platforms named.
- **Partly**: some evidence is reported, or only on some platforms, or only
  known products are recognised.
- **Not caught**: a desktop check could see it, but none does today.
- **Out of scope**: it happens on a phone, on a provider's website, or away from
  any device, so a computer checkup can't see it.

Module names are the engine checks in `modules/<category>/<name>/`. Codes map
to walkthroughs in [the remediation catalog](../REMEDIATION_CATALOG.md).

## Sources

1. Emily Tseng, Rosanna Bellini, Nora McDonald, Matan Danos, Rachel Greenstadt,
   Damon McCoy, Nicola Dell, Thomas Ristenpart. "The Tools and Tactics Used in
   Intimate Partner Surveillance: An Analysis of Online Infidelity Forums."
   29th USENIX Security Symposium, August 2020.
   <https://www.usenix.org/conference/usenixsecurity20/presentation/tseng>
   (preprint: <https://arxiv.org/abs/2005.14341>). The taxonomy below is its
   Table 3 and Section 7.
2. Rahul Chatterjee, Periwinkle Doerfler, Hadas Orgad, Sam Havron, Jackeline
   Palmer, Diana Freed, Karen Levy, Nicola Dell, Damon McCoy, Thomas
   Ristenpart. "The Spyware Used in Intimate Partner Violence." IEEE Symposium
   on Security and Privacy, 2018.
   <https://www.cs.cornell.edu/~rahul/papers/IPV_Spyware.pdf>. App classes from
   Section IV and Fig. 5.
3. Diana Freed, Jackeline Palmer, Diana Minchala, Karen Levy, Thomas Ristenpart,
   Nicola Dell. "'A Stalker's Paradise': How Intimate Partner Abusers Exploit
   Technology." CHI 2018, Montréal. <https://doi.org/10.1145/3173574.3174241>.
   Categories from Table 2.

## Tseng et al. taxonomy (Table 3)

### Tool-based attacks that require physical access

| Tactic | What it is | Coverage | What we check, and why that rating |
| --- | --- | --- | --- |
| Phone backup recovery tool | Reads messages and other data out of a phone or its backup, including a backup kept on a shared computer or in shared cloud storage. | **Not caught** | `mvt_spyware_scan` finds iPhone/Android backups on this computer, but only to offer a spyware scan. Nothing reports that a backup is there, whose device it came from, or whether it's encrypted. Reading the phone itself is out of scope. |
| Keylogger | Records everything typed on the person's device. | **Partly** | macOS: `keylogger_indicators` reads Input Monitoring grants, logged keyboard event taps, and known keylogger names (`security.keylogger_indicators.*`). Windows and Linux: only name matching in `stalkerware_scan` (`security.stalkerware_scan.monitoring_software_found`), plus generic process and startup checks. Renamed builds and plug-in hardware keyloggers aren't recognised. |
| Screen recording spyware | Takes screenshots or recordings of the person's screen. | **Partly** | macOS: `privacy_permissions_audit` and `app_permissions` list apps allowed to record the screen, and flag screen recording combined with Accessibility (`security.privacy_permissions_audit.screen_recording_access`, `.screen_accessibility_combo`). `stalkerware_scan` names workplace-monitoring products, whose main feature is screen capture. Windows has no equivalent view. |
| GPS tracker on the person or car | Hides a location-tracking device on the person, in a bag, or in a vehicle. | **Out of scope** | A separate physical device. A computer can't see it. |
| Audiovisual recorder in car or home | Hides a camera or voice recorder in a shared space. | **Partly** | `lan_device_inventory` lists every device on the home Wi-Fi with its maker, and flags unrecognised ones (`network.lan_device_inventory.unrecognised_device`). It doesn't label which ones are cameras. Recorders that don't use the home network, and anything in a car, are out of scope. |

### Tool-based attacks that do not require physical access

| Tactic | What it is | Coverage | What we check, and why that rating |
| --- | --- | --- | --- |
| Shared phone plan features | Uses the account holder's access to a family phone plan for call and text records, and the carrier's family locator. | **Out of scope** | This happens on the carrier's website and the phone. |
| Shared cloud tools | Uses a shared or known cloud account to see the person's messages, photos, location history, or synced devices without touching their phone. | **Partly** | macOS: `icloud_status` names the Apple Account signed in on this Mac. `appleid_security_check`, `find_my_mac_check` and `location_services` report Find My and location sharing. `privacy_audit` reports Significant Locations (`security.privacy_audit.significant_locations`). `session_revocation_scan` counts browser profiles and system accounts that stay signed in (`security.session_revocation_scan.*`, macOS and Windows). Not checked: whether Messages or Photos on this computer sync to someone else's account, browser sync accounts, or messaging apps' linked desktop sessions. Settings on the provider's website are out of scope. |
| Router monitoring tools | Watches or changes the person's Internet traffic at the home router or on the network. | **Partly** | `router_security_audit` (admin services open, UPnP), `arp_spoof_check` (another device posing as the router) and `lan_device_inventory` run on all three platforms. `dns_poisoning_check` (macOS) flags DNS set to a personal filtering-service profile, whose owner can see every site looked up (`rescue/dns_providers.py`). Proxy checks: `network_proxy_check`, `network_proxy` (macOS), `win_proxy_detect` (Windows). `certificate_trust_audit` (macOS) flags added root certificates, which intercepting encrypted traffic needs. Logging set up on the router itself is invisible when the computer just uses the router for DNS. Windows root certificates and Windows DNS profile addresses aren't checked. |
| Reverse lookup directories | Looks up a phone number or name in people-search sites. | **Out of scope** | Happens on third-party websites. |

### Coercion and subterfuge

| Tactic | What it is | Coverage | What we check, and why that rating |
| --- | --- | --- | --- |
| Using physical proximity to gain access | Uses time near the person (watching them type a passcode, using the device while they sleep) to unlock it or get past sign-in protections. | **Partly** | Settings that make this easier: `screen_lock_check`, `lock_screen_check` and `login_window_settings` (macOS: lock delay, automatic login, password hints), `user_account_audit` (macOS) and `win_user_accounts` (Windows: automatic login, guest account). `sudo_touchid` reports how many fingerprints are enrolled, as information only. Not checked: when this computer was recently unlocked or signed in to, or the Windows lock-after-idle setting. Code capture and SIM changes happen on the phone and the provider's side, so they're out of scope. |
| Convincing the partner to give total access | Pressures the person into handing over passwords and devices as a sign of trust. | **Out of scope** | A social tactic. Access that's handed over looks the same as the person's own. What it leaves on the computer is covered by the other rows. |
| Catfishing (fake profiles) | Uses a fake social-media identity to see content the person has restricted. | **Out of scope** | Happens on social-media platforms. |

### Outsourced attacks

| Tactic | What it is | Coverage | What we check, and why that rating |
| --- | --- | --- | --- |
| Hiring a private investigator | Pays a third party to watch the person. | **Out of scope** | Not a technology on the person's device. |

**Counts for the Tseng taxonomy (13 tactics):** Caught 0, Partly 6, Not caught 1,
Out of scope 6.

## Chatterjee et al.: classes of surveillance-capable software

Chatterjee et al. studied phone apps, but the same classes exist as desktop
software.

| App class | What it is | Coverage | What we check, and why that rating |
| --- | --- | --- | --- |
| Overt spyware | Sold for covertly monitoring another adult. | **Caught** (known products) | `stalkerware_scan` matches running processes, installed software, app folders and startup entries against 23 stalkerware entries (macOS, Windows, and a few Linux), with safety-first guidance before removal. A product it has no name for, or a renamed copy, isn't recognised. |
| Subordinate tracking (parental and employee monitoring) | Legitimate monitoring products, repurposed against an adult. | **Partly** | `stalkerware_scan` reports 8 workplace-monitoring and 3 parental-control products, with the context to judge them. On macOS, `screen_time_audit` and `screen_time_parental` report Screen Time restrictions and Communication Limits, and `mdm_enrollment` / `mdm_enrollment_check` report management profiles (`security.mdm_enrollment.*`). Windows' built-in family controls aren't checked. |
| Personal tracking (anti-theft, remote control) | The owner's own tools, used by someone else who has the login. | **Caught** | `remote_access_tools` (macOS and Windows) reports each remote-control tool, whether it can let someone in unattended, whether it's running, and when it last did (`security.remote_access_tools.*`). Also `remote_login_check`, `sharing_services` (macOS), and `win_rdp_check`, `win_remote_access_audit` (Windows). Phone anti-theft apps are out of scope. |
| Mutual tracking (family and couple locators) | Shared location apps. | **Partly** | On the Mac, `find_my_mac_check` and `location_services` report whether this computer shares its location. These apps mostly live on the phone, which is out of scope. |
| Bundled tracking (built into the OS or the carrier) | Built-in tracking, turned on remotely with the account's credentials. | **Out of scope** | Account and carrier side. |
| Any of the above on an iPhone | Same classes on the phone. | **Partly** | `mvt_spyware_scan` runs Amnesty's MVT over a local iPhone backup. It runs only in the `iphone_spyware_check` profile, skips backups over 2 GB, and catches only published indicators. MVT's default indicator list includes a stalkerware set alongside the mercenary-spyware sets. Android phones and phones with no backup on this computer aren't covered. |

## Freed et al.: abuse categories (Table 2)

| Category | Coverage | Why |
| --- | --- | --- |
| Ownership-based access (abuser owns the device, account, or family plan) | **Partly** | We report the computer-side signs: which Apple Account is signed in (`icloud_status`), admin accounts (`user_account_audit`, `win_local_admin_audit`), management profiles and Screen Time. Accounts and plans themselves are out of scope. |
| Account/device compromise (compelled or guessed passwords, then spyware, tracking, monitoring, lockout, impersonation) | **Partly** | The spyware, tracking and monitoring results are the rows above. `session_revocation_scan` lists what stays signed in after a password change. Password guessing, lockout and impersonation happen at the provider, and `rescue guide digital_security_reset` walks the person through them. |
| Harmful messages or posts | **Out of scope** | Happens on messaging and social platforms. |
| Exposure of private information | **Out of scope** | Happens on platforms and websites. |

## Biggest gaps a desktop checkup could cover

Ranked by how often the research mentions the tactic and how directly a
read-only check could see it.

1. **Cloud sync to an account the person doesn't control** (macOS, Windows).
   Check which accounts this computer's Messages, Photos, location sharing and
   browser sync use, and list any messaging apps signed in on the desktop. The
   person then confirms each one is theirs. Tseng et al. found shared cloud
   tools among the most commonly discussed tactics.
2. **Phone backups on this computer** (macOS, Windows). List local
   phone backups by device name and date, and say whether each is encrypted,
   without reading their contents. An unencrypted backup on a shared computer
   is what backup recovery tools read.
3. **Monitoring parity on Windows** (Windows). Show apps allowed to use the
   camera, microphone and location, with their last-used times. Add
   browser-extension and added-root-certificate audits, and check Windows DNS
   for filtering-service profile addresses. All of these exist on macOS only
   today.
4. **Recent sign-in and unlock history** (all three). Show a short timeline
   of local sign-ins, unlocks and wake-from-sleep events, so the person can spot
   ones they didn't make. Use only what the OS lets a standard user read. This
   is the evidence the physical-proximity tactic leaves.
5. **Biometric and lock settings, framed for this threat** (macOS, Windows).
   Say how many fingerprints or face enrolments the device has and ask "are
   these all yours?" (the macOS count is already read by `sudo_touchid`, as
   information only). Add Windows' lock-after-idle setting.
6. **Built-in family and management controls on Windows** (Windows). Report
   whether this account belongs to a family group, or is controlled by
   management policy, the way `screen_time_parental` and `mdm_enrollment` do on
   macOS.
7. **Cameras on the home network** (all three). In `lan_device_inventory`,
   label devices whose maker mainly builds cameras or recorders, so the person
   can check them first.

Note: `stalkerware_scan` is in a full scan and in the `identity_theft_recovery`
and `home_network_intrusion` profiles, but not in `digital_security_reset`, the
profile for "someone's in my accounts". No profile is aimed at partner
surveillance.
