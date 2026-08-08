# Scenarios

A **profile** is a scenario. It selects the modules that matter for one
situation, configures them for that threat, and — for four of the seven — pairs
them with a phased human walkthrough that tracks your progress across sessions.

```console
$ rescue profiles                        # list them
$ rescue --auto --profile <name>         # run the checks (read-only)
$ rescue guide <name>                    # the human walkthrough, where one exists
```

## Which one do I need?

| If this is your situation | Use |
| --- | --- |
| I think I've been hacked. Accounts, device, or both. | [Digital security reset](digital-security-reset.md) |
| There are strangers on my Wi-Fi, or my machine is mining crypto for someone. | [Home network intrusion](home-network-intrusion.md) |
| Someone is using my identity — credit, taxes, benefits, accounts opened in my name. | [Identity theft recovery](identity-theft-recovery.md) |
| I installed a compromised package, or I'm worried about an AI-driven worm. | [AI worm response](ai-worm-response.md) |
| I think there's spyware on my iPhone or iPad. | [iPhone / iPad spyware check](iphone-spyware-check.md) |
| I want a security review of a Linux machine. | [Linux security checkup](linux-security-checkup.md) |
| I'm visiting family and want to leave their laptop in better shape. | [Home for the holidays](home-for-the-holidays.md) |

Not sure? Start with `rescue scan` — a plain whole-machine read-only pass — and
come back once you know more. If you have an AI provider configured,
`rescue recommend` will talk you to a profile.

## At a glance

| Profile | Modules | Guide | Best on |
| --- | ---: | --- | --- |
| [`digital_security_reset`](digital-security-reset.md) | 12 | 6 phases | macOS (10 of 12 are macOS-only) |
| [`home_network_intrusion`](home-network-intrusion.md) | 14 | 6 phases | macOS, Windows |
| [`identity_theft_recovery`](identity-theft-recovery.md) | 12 | 7 phases | macOS, Windows |
| [`ai_worm_response`](ai-worm-response.md) | 6 | none | all three |
| [`iphone_spyware_check`](iphone-spyware-check.md) | 1 | none — see the [walkthrough](../CHECK_IPHONE_FOR_SPYWARE.md) | all three (scans a backup on your computer) |
| [`linux_security_checkup`](linux-security-checkup.md) | 10 | none | Linux |
| [`home_for_the_holidays`](home-for-the-holidays.md) | 4 | 1 phase, 13 steps | macOS |

Modules that do not support your platform are filtered out before the scan
starts, so a profile on the "wrong" platform runs a subset rather than failing.
Check the [module catalog](../modules.md) for exactly what exists where.

## What every scenario has in common

**All checks are read-only.** `--auto` never changes your system on the shipped
tree — the summary line prints the number of changes made, and it is always
zero. See [Trust and safety](../trust-and-safety.md#auto-mode-is-read-only).

**None of them will ever ask you for a secret.** No account password, no
one-time code, no recovery code, no seed phrase, no master password. Account
work happens on the provider's own website, done by you.

**The device half and the human half are different jobs.** For most of these
scenarios the modules answer one narrow question — *is this device itself the
problem?* — and the guide carries the actual recovery, because the recovery
happens at banks, providers, credit bureaus, and routers, not on your disk.

**Progress is saved.** `rescue guide <name> --complete <n>` marks a step done in
`~/.rescue/sessions/<name>.json`. Close the terminal, come back next week.

**Nothing is sent anywhere.** Unless you explicitly enable the AI layer. See
[Privacy](../privacy.md).

!!! danger "Before you start, if the person involved is someone you know"
    If a partner, ex-partner, family member, or housemate may be the one with
    access, removing their access can escalate a dangerous situation. The safety
    plan comes first. In the US: National Domestic Violence Hotline,
    1-800-799-7233. Internationally: <https://stopstalkerware.org>. The
    [home network intrusion](home-network-intrusion.md) guide opens with this,
    deliberately.
