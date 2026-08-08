# Identity theft recovery

**`identity_theft_recovery`** — 12 modules, a 7-phase guide.

## Who this is for

Someone is using your identity. Credit opened in your name, a tax return filed
before yours, benefits claimed, accounts you never made. This is the longest of
the scenarios because the recovery genuinely is long — the guide's own time
estimates run to *"several weeks of follow-up"* and *"20 minutes a month"* for
two years.

Almost none of this work happens on a computer. It happens with banks, credit
bureaus, and government agencies. The guide is the substance here; the modules
answer exactly one question.

## What to run

```console
$ rescue --auto --profile identity_theft_recovery
$ rescue guide identity_theft_recovery
```

The walkthrough doubles as a checklist that survives the process:

```console
$ rescue guide identity_theft_recovery --complete 3
```

Progress is saved in `~/.rescue/sessions/identity_theft_recovery.json`, which
matters more here than anywhere else — you will be coming back to this for
weeks, and the guide remembers where you were.

## What the tool does

One question: **is the device you are doing the recovery from itself the leak?**
Because doing recovery from a compromised machine hands the new passwords
straight back.

**Is something watching this machine?**

| Module | What it answers | Platforms |
| --- | --- | --- |
| `stalkerware_scan` | Is monitoring software installed | macOS, Windows, Linux |
| `keylogger_indicators` | Is something capturing keystrokes | macOS |
| `malware_scan_indicators` | Known malware indicators on disk | macOS |
| `win_malware_indicators` | Known malware indicators on disk | Windows |
| `suspicious_processes` | Unexpected processes running now | macOS |
| `win_suspicious_processes` | Unexpected processes running now | Windows |
| `process_scanner` | Running processes against a known-unwanted list | macOS, Windows, Linux |

**The browser, where credential theft usually lives.**

| Module | What it answers | Platforms |
| --- | --- | --- |
| `browser_extension_audit` | Is an extension reading your pages | macOS |
| `browser_hijack_check` | Has the browser's search or homepage been redirected | macOS |
| `certificate_trust_audit` | Has a certificate been installed that can decrypt your HTTPS | macOS |

**Is somebody else still logged in?** — the simplest explanation of all.

| Module | What it answers | Platforms |
| --- | --- | --- |
| `remote_login_check` | Remote access enabled, who is logged in | macOS |
| `win_remote_access_audit` | Remote Desktop and remote-access tooling | Windows |

That is the entire technical contribution. If any of it finds something, the
guide's Phase 1 Step 4 tells you to do the rest of the recovery from a
different device.

## What stays human-led

All of it, past Phase 1. Specifically:

- Freezing credit at Equifax, Experian, and TransUnion — **and** at the four
  smaller bureaus the guide names that nobody mentions.
- Filing the FTC report at IdentityTheft.gov, which is the keystone step in the
  US and is free.
- Filing a police report.
- Protecting the tax file and reporting SSN misuse.
- Pulling all three credit reports and marking up every line.
- **Blocking** fraudulent accounts rather than merely disputing them — a
  distinction the guide is emphatic about.
- Notifying creditors in writing; handling debt collectors properly.
- Upgrading to the seven-year extended fraud alert once you have the FTC report.
- Keeping the recovery log, and the follow-up schedule.

The tool cannot call a bank, and a program that offered to would be lying about
what it does.

## The phases

| Phase | Title | Time | What happens |
| --- | --- | --- | --- |
| 0 | The First Hour | 1 hr | Start a recovery log · Write down what you know · Know this is not your fault · Understand the order and why · Decide about the immediate money |
| 1 | Make Sure The Device Is Not The Leak | 45 min | **Scan for monitoring and malware** · **Check the browser** · **Check who else is logged in** · If anything was found, switch devices · Secure email and phone first |
| 2 | Freeze Everything (Stop New Damage) | 2 hr | Freeze all three major bureaus · Freeze the three nobody mentions · Place a fraud alert · Call every bank and card issuer · Change financial and government passwords · Reclaim the mail · Non-US equivalents |
| 3 | Report It Officially | 2–3 hr | FTC report at IdentityTheft.gov · Police report · Protect the tax file · Report SSN misuse · Report to the financial regulator · Report your specific flavour of theft · Update the log |
| 4 | Dispute And Undo The Damage | 3 hr, then weeks | Pull all three reports and mark every line · Block, do not merely dispute · Notify creditors in writing · Handle debt collectors properly · Set a follow-up schedule · Log every dispute with its deadline |
| 5 | Monitor, Rebuild, And Look After Yourself | 1 hr, then 20 min/month | Seven-year extended fraud alert · Stop prescreened offers · Set the monitoring rhythm · Fix structural weaknesses · What to expect over two years · Acknowledge what this cost |
| 6 | Resources, Tiplines, And Free Help | reference | How fake helplines work · Free case-managed help · Official reporting channels · The bureaus and databases nobody mentions · If the person knows you · Legal help, mostly free · Non-US channels · What is already exposed |

Only Phase 1's first three steps are automatable. Everything else is you, a
phone, and a log.

Phase 6 Step 1 is worth reading before you dial anything: search results for
"Equifax fraud number" and "IRS help line" are bought by scammers, and someone
mid-identity-theft is exactly who they are looking for.

## What it will never ask you for

Your Social Security number. Your date of birth. Your account numbers. Your
credit report. Your passwords or one-time codes. None of that ever enters this
tool — the device checks read local system state, and every piece of personal
information in this recovery is given directly to the bureau, agency, or bank
that needs it.

Note that the guide is US-centric in its specifics (FTC, SSN, the three
bureaus), with non-US equivalents called out in Phase 2 Step 7 and Phase 6
Step 7.

## Afterwards

```console
$ rescue export --profile identity_theft_recovery
```

The redacted case is useful evidence for the "what did you check" question, and
attaches cleanly to a support request. Read it before you send it — it removes
credential-shaped strings, emails, your username, home path, and hostname, but
module output is free text. See [Privacy](../privacy.md#the-redacted-case-export).
