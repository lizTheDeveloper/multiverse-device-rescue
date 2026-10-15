# Using Device Rescue as an AI assistant

You're helping someone who thinks something is wrong with their computer. They
may be frightened. This file tells you how to run the scan, read its output,
and explain the result without making things worse.

If the person just wants the app, send them to the download buttons in the
[README](README.md). You don't need anything below for that.

## Rules

1. **Look, don't touch.** Use `rescue scan --json`, `rescue export`, and
   `rescue run <module> < /dev/null`. All of these are read-only (the one
   exception: a scan removes a "marked as yours" entry from Device Rescue's
   own list when that item is gone, and says so). Don't pass
   `--auto` or `--yes`, because both apply fixes. A fix needs the person to
   agree to that specific change after you've explained it. `rescue known add`
   (marking a finding as "mine") counts as a change too: the person runs it
   and answers its question themselves; never pass `--i-understand` for them.
   In scan output, a finding with `data.marked_by_user: true` is something
   someone marked on this computer (a background task, a sharing setting, a
   proxy, an extension, a list of apps...). Mention it; don't treat it as
   cleared. `data.mark_stale: true` means it was marked but has changed since.
2. **Never ask for a password, a one-time code, or a recovery code.** The tool
   never needs one, so don't ask the person to paste one into the chat.
3. **"Couldn't run" doesn't mean "clean."** A module with `"supported": false`
   or `"status": "error"` checked nothing. Say so.
4. **Check before removing stalkerware.** If the person thinks a partner, ex,
   or housemate is monitoring them, removing that software can alert the
   person who installed it. Before suggesting removal, give them the safety
   note in the README and ask whether removal is safe for them.
5. **Don't start heavy scans on your own.** `iphone_spyware_check` runs MVT
   over an iPhone backup and can take a long time and a lot of memory. Ask
   first.

## Install (from source only)

This project is **not on PyPI**. A package with this name on a registry is
someone else's.

```bash
git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
cd multiverse-device-rescue
uv venv && uv pip install .          # or: python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/rescue version
```

## Pick what to run

| The person says… | Run |
| --- | --- |
| "Something's wrong" / not sure | `rescue scan --json` |
| "I got hacked" / "someone's in my accounts" | `rescue export --profile digital_security_reset --stdout` |
| "Someone's on my Wi-Fi" / "computer is hot and slow" | `rescue export --profile home_network_intrusion --stdout` |
| "My identity was stolen" | `rescue export --profile identity_theft_recovery --stdout` |
| "I installed a bad npm/pip package" / developer machine | `rescue export --profile ai_worm_response --stdout` |
| "Fix up my parent's laptop" | `rescue export --profile home_for_the_holidays --stdout` |
| "Is there spyware on my iPhone?" (needs a local backup) | ask first, then `rescue run iphone_spyware_check < /dev/null` |
| Linux machine | `rescue export --profile linux_security_checkup --stdout` |

`rescue profiles` lists all profiles. `rescue guide <profile>` prints the
human walkthrough that goes with each one. Share it with the person, a step at
a time.

A full scan runs a few hundred checks and **can take 5–15 minutes** with no
output until the end. Run it in the background with a generous timeout. Don't
kill it and retry. A few `Module check timed out: …` lines on stderr are
normal.

## Read the output

`rescue scan --json` prints one JSON document on stdout:

```jsonc
{
  "schema_version": 1,
  "platform": "darwin",
  "modules": [
    {
      "name": "launch_agents_audit",
      "status": "ok",                 // "error" = the check crashed
      "error": null,
      "supported": true,              // false = could not run here; NOT clean
      "unsupported_reason": null,
      "findings": [
        {
          "title": "…",
          "description": "…",          // plain-language explanation
          "severity": "critical",      // critical | warning | info
          "category": "security",
          "code": "security.launch_agents_audit.unsigned",  // remediation key, may be null
          "confidence": 0.8,           // may be null
          "data": { },                 // module-specific evidence
          "made_by": [                 // optional: who made each program the finding names
            { "subject": "…", "name": "Google LLC", "verified": true,
              "how": "Developer ID signature", "location_note": "",
              "what": "Google Chrome: Google's web browser, for visiting websites." }
                                       // "what" only for known programs whose signed identity was verified
          ]                            // skip with `rescue scan --json --no-attribution`
        }
      ]
    }
  ]
}
```

- Sort by severity. Most real scans produce plenty of `info` findings, so
  lead with `critical`, then `warning`.
- A finding `code` maps to a step-by-step fix in
  [docs/REMEDIATION_CATALOG.md](docs/REMEDIATION_CATALOG.md). Use that text
  rather than improvising a fix.
- `data` often contains paths, process names, and account names. Quote only
  what the person needs to see.
- If you need something shareable, use `rescue export`. It redacts
  credentials, emails, and account names.

## Explain it to the person

- Start with the bottom line: "I found two things worth your attention, and
  neither means you've been hacked", or "I found something that looks like
  monitoring software."
- Give one next step at a time. Leave out module names unless they ask.
- Be honest about limits. Name what couldn't be checked, and remember that a
  clean scan lowers the odds of a problem without ruling one out.
- For anything about accounts (passwords, 2FA, sessions), the fix happens at
  the provider's website, and the person does it. Walk them through it with
  `rescue guide digital_security_reset`.

## Pointers

- [docs/cli.md](docs/cli.md): every command and flag
- [docs/commands.md](docs/commands.md): every system command each check can run; `rescue scan --trace` streams the ones that actually ran as `{"exec": …}` lines on stderr
- [docs/THREAT_REMEDIATION.md](docs/THREAT_REMEDIATION.md): threat → command
- [docs/trust-and-safety.md](docs/trust-and-safety.md): what the tool does and doesn't do
