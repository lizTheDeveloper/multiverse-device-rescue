# Digital security reset

**`digital_security_reset`** — 20 modules, a 6-phase guide, and in the desktop
app an account checklist played as missions.

## Who this is for

You have been hacked, or you strongly suspect it. Someone got into an account,
or the machine is doing things you did not ask for, and you need to work out
what is true and then take your accounts back.

This is the profile for the immediate aftermath. It assumes you are stressed,
and its first phase is about that rather than about computers.

Use [identity theft recovery](identity-theft-recovery.md) instead if the damage
is financial — credit opened in your name, tax fraud, benefits fraud. Use
[home network intrusion](home-network-intrusion.md) if the way in was your
Wi-Fi.

## What to run

```console
$ rescue scan --profile digital_security_reset      # the device checks (read-only)
$ rescue guide digital_security_reset               # the recovery walkthrough
```

Then work the guide, marking steps off as you finish them:

```console
$ rescue guide digital_security_reset --complete 1
```

!!! warning "Run this from a device you trust, if you can"
    If the machine you are scanning may be compromised, do the *account*
    recovery from a different device. Changing a password on a machine with a
    keylogger hands the new password straight over. The guide's Phase 1 exists
    to help you decide.

## What the tool does

Twenty read-only checks, in a deliberate order. `evidence_bundle` runs
first — repairs destroy the record of what happened, so evidence readiness is
assessed before anything else reports a problem to fix.

| Module | What it answers | Platforms |
| --- | --- | --- |
| `evidence_bundle` | What could be preserved before you start changing things | macOS, Windows, Linux |
| `malware_scan_indicators` | Are there known malware indicators on disk | macOS |
| `suspicious_processes` | Is anything unexpected running right now | macOS |
| `remote_login_check` | Is remote access enabled, and who is logged in | macOS |
| `network_connections_monitor` | What is this machine talking to | macOS |
| `browser_extension_audit` | Is an extension reading your pages and credentials | macOS |
| `app_permissions` | What has camera, microphone, screen, and accessibility access | macOS |
| `sharing_services` | What is this machine offering to the network | macOS |
| `code_signature_audit` | Have signed applications been tampered with | macOS, Windows |
| `launch_agent_audit` | What starts in the background when you log in | macOS |
| `launchd_persistence_audit` | What has set itself up to keep running | macOS |
| `scheduled_tasks_audit` | What runs on a schedule | macOS |
| `keylogger_indicators` | Is anything set up to record your typing | macOS |
| `privacy_permissions_audit` | Which apps hold monitoring permissions | macOS |
| `session_revocation_scan` | What stays logged in after a password change | macOS, Windows |
| `network_proxy_check` | Is your traffic sent through a proxy you didn't set up | macOS |
| `hosts_file_check` | Does the hosts file send a site's name somewhere else | macOS |
| `win_remote_access_audit` | Are remote-access tools (TeamViewer, AnyDesk, VNC) installed | Windows |
| `win_rdp_check` | Is Remote Desktop turned on | Windows |
| `win_proxy_detect` | Is your traffic sent through a proxy you didn't set up | Windows |

`session_revocation_scan` is the device-side half of account recovery. It
answers *what is still signed in on this computer* — nothing more. The account
half is in [Your accounts, in order](#your-accounts-in-order) below.

!!! info "This profile is strongest on macOS"
    Fourteen of the twenty modules are macOS-only. On Windows you get six; on
    Linux you get one. The guide is platform-independent and is the larger half of
    the work regardless — but if you are on Linux, pair it with the
    [Linux security checkup](linux-security-checkup.md).

## What stays human-led

Everything that touches an account. The tool cannot log in as you and should
not try.

- Changing passwords, at each provider.
- Turning on two-factor authentication.
- Revoking sessions and connected third-party apps.
- Reading sign-in activity logs.
- Calling your bank.
- Deciding whether to wipe and reinstall.

The modules tell you what is observable on the device. The guide tells you what
to do about it, in what order, and why that order.

## The phases

Six phases, spread over several sessions.

| Phase | Title | Steps |
| --- | --- | --- |
| 0 | Emergency Grounding | Ground yourself · Check whether you can still get in · Write down what you've already noticed |
| 1 | Reality Check | **Run a full device scan** · List every account tied to this identity · Check recent sign-in activity |
| 2 | Immediate Protective Actions | **Sort out what lets someone in, or use another device** · Change your email password · Sign out devices you don't recognize · Check the recovery phone and email · Check forwarding and mail rules · Remove connected apps and app passwords · Turn on two-step sign-in · Use your provider's own hacked-account page |
| 3 | Systematic Cleanup | Change passwords on the accounts that matter most · Contact your bank (and your mobile carrier) · Write down your progress |
| 4 | Rebuilding Security | Make your passwords and sign-ins stronger, at your own pace · Review phone app permissions |
| 5 | Mental Health Maintenance | Acknowledge the effort this took · Tell someone you trust · Schedule a one-week check-in |

Steps in **bold** are the automatable ones — a module does that part. Every
other step is yours.

Two things worth noticing about the ordering. **Email comes first** in Phase 2,
because your email is the recovery path for almost every other account;
securing anything else first is building on sand. And **Phase 5 is not
filler** — recovering from a compromise is genuinely stressful and
time-consuming, and the guide treats finishing well as part of the job.

## Your accounts, in order

This is the same list the desktop app shows as missions when you pick
"I think I've been hacked" and play it as a game ("Take your accounts back").
One decision per step: done, doesn't apply, or need help. The app saves only
which kind of email you use and your answers, on your computer; never an
address, a password or a code.

**First**

1. **Could this be someone you know?** If it may be a partner, ex, family
   member or housemate, talk to an advocate before you change account
   settings: signing them out or changing a password shows them you noticed
   (US National DV Hotline: 1-800-799-7233, or text START to 88788). The app
   asks this each time and never saves the answer.
2. **Use a device you trust.** If the device checks found remote access, a
   browser extension that can read sign-in pages, a proxy or a background task
   you don't recognize, do the account steps on your phone or another device
   you trust until those are sorted.

**Your email** (its password resets reach almost every other account)

3. Which email do your accounts use: Google, Microsoft, Apple, or something else.
4. Can you still sign in? If not, use the provider's own account recovery.
5. Change the password.
6. Sign out every device you don't recognize.
7. Check the recovery phone and email.
8. Check forwarding and mail rules (and, in Gmail, who has been granted access).
9. Remove apps you don't recognize.
10. Remove app passwords.
11. Turn on two-step sign-in, and remove any phone or app on it that isn't yours.

**Your other accounts, in this order**

12. Your password manager: its main password, and devices you don't recognize.
13. Your bank and cards: payments you didn't make.
14. Your phone's account (Apple Account or Google): devices you don't recognize.
15. Your mobile carrier: confirm nobody set up forwarding of your texts.
16. Social media and messaging: new password, sign out other devices, check what was sent as you.

**Afterwards**

17. Write down what happened, on paper or another device you trust.

For Google, Microsoft and Apple, the app shows where each setting lives,
copied from their help pages, and links to those pages. Their own
hacked-account pages:

- Google: [Secure a hacked or compromised Google Account](https://support.google.com/accounts/answer/6294825)
- Microsoft: [How to recover a hacked or compromised Microsoft account](https://support.microsoft.com/en-us/help/10494)
- Apple: [If you think your Apple Account has been compromised](https://support.apple.com/en-us/102560)

## Learn it properly

The guide keeps only the emergency steps for passwords and two-step sign-in.
To learn the rest at your own pace, [Reclaim City](https://play.multiversegames.ai/reclaim-city/)
is a free game from the same team. Its
["My email got hacked" Quick Quest](https://play.multiversegames.ai/reclaim-city/#/district/master-keys)
opens The Master Keys, which walks you through new passwords and two-step
sign-in for your email one account at a time. You don't need an account, and
your progress stays in your browser.

If someone close to you may be monitoring you, talk to an advocate before you
change account settings (US National DV Hotline: 1-800-799-7233).

## What it will never ask you for

Stated in the profile's own description: *"This tool never asks for an account
password, a one-time code, or a recovery code."*

Nor a recovery key, a seed phrase, or your password manager's master password.
The device checks read local state. The account work happens on each provider's
own website, typed by you, into their login form — never into this tool.

If anything presenting itself as this tool asks you to type a credential into
it, that is not this tool.

## Afterwards

```console
$ rescue export --profile digital_security_reset
```

Writes a redacted case to `~/.rescue/cases/` — the Markdown file is the one to
send to someone helping you. Read it first; see
[Privacy](../privacy.md#the-redacted-case-export).
