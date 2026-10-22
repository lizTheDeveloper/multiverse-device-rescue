# Privacy

Short version: everything happens on your machine. There is no telemetry, no
analytics, no crash reporting, and no account. Three things reach the network and
all need you to ask: `rescue update`, the optional AI layer, and the "who runs
this address" lookups after a connection watch you start. One more happens
during a normal scan, once: the AI tools check downloads a free tool
(HackMyAgent) from the npm registry the first time it runs. That is an
ordinary package download: the registry sees your IP address and npm's usual
description of itself (npm and Node.js versions, operating system, processor
type), and nothing else about your computer is sent.
`rescue scan --no-downloads` turns it off.

## What the tool touches

**It reads local system state.** Process lists, disk and mount information,
network interfaces and the neighbour table, systemd units, cron entries, launch
agents, XDG autostart entries, shell startup files, installed package lists,
system logs and journal output, firewall and SSH configuration, browser
extension manifests, startup items, and metadata about keychains and credential
stores.

**It does not read your secrets.** There is no code path that opens a password
manager vault, extracts keychain or Credential Manager *contents*, reads
browser history or page contents, or opens your documents and photos. The
`evidence_bundle` module prints the exclusion list when it runs:

```text
Never collected, under any circumstances:
  Passwords, passphrases, and password-manager vaults
  Authentication tokens, cookies, and session identifiers
  Keychain and Credential Manager contents
  Private keys of any kind
  Browser history and page contents
  Documents, photos, and other personal files
```

**It never asks you to type a secret.** No prompt in the tool accepts an
account password, a one-time code, a recovery code, or a master password. Your
operating system may prompt you for an administrator password on its own
dialog; the tool never sees what you type there.

## What is written to disk

Only these, and only when you run the command that writes them:

| Path | Written by | Contains |
| --- | --- | --- |
| `~/.rescue/sessions/<profile>.json` | `rescue guide` | Which guide steps you have marked complete. No findings. |
| `~/.rescue/cases/case-<timestamp>.{json,md}` | `rescue export` | A redacted record of one scan. |
| `~/.config/rescue/revoked_signers.json` | `rescue trust revoke` | Signer IDs you have stopped trusting, and why. |
| `~/.local/share/rescue/content/` | `rescue update` | The verified content checkout. |
| `<user cache>/ReclaimCity/hackmyagent-<version>/` | `rescue scan` (the AI tools check), once | The downloaded copy of HackMyAgent. No findings. Safe to delete. |

Case files are written with owner-only permissions (`0600`) where the
filesystem supports it, because even redacted they describe a machine's
security posture and land somewhere other local accounts may be able to read.

Nothing else is persisted. A `rescue scan` writes nothing else: the AI tools
check points HackMyAgent's own settings folder, its telemetry file
(normally `~/.config/opena2a/telemetry.json`), its temp folder and npm's
download cache at temp folders and deletes them afterwards, so nothing lands
in `~/.opena2a`, `~/.config/opena2a` or `~/.npm`. One write can't be
redirected: HackMyAgent's start-up self-check appends a line to
`~/.nanomind/integrity-events.jsonl`. Right after the run Reclaim City undoes
it: it deletes the file (and the folder, if it made it) or cuts the file back
to its earlier length, but only when it is still the same file, not a link,
and every new line is one of HackMyAgent's self-check events from this run.
Otherwise it leaves the file as it is and the finding says so
(`left_in_home`). Run by hand, HackMyAgent adds that line every time. `<user cache>` is `~/Library/Caches` on macOS, `$XDG_CACHE_HOME` or
`~/.cache` on Linux, and `%LOCALAPPDATA%` on Windows.

## What leaves the machine

Five things, exhaustively:

1. **`rescue update`** contacts the configured content git remote when you run
   it. It sends nothing about your machine — it is a `git fetch`. (On the
   current release it fails before contacting anything, because the shipped
   signer keys are placeholders. See
   [Trust and safety](trust-and-safety.md#signed-content-updates).)
2. **The AI layer**, when you explicitly enable it. Detailed below.
3. **Individual checks that use the network by their nature** — a speed test
   measures throughput, a LAN inventory sends ARP/neighbour queries on your own
   local segment. These talk to your network, not to the project. Read the
   module if you want to be certain what a specific check does.
4. **The connection watch's lookups.** After a `rescue watch` you start (or
   for each address you type into `rescue lookup`), each public address is
   sent to RIPE NCC (`stat.ripe.net`) and to `rdap.org`. rdap.org redirects
   your computer to the regional registry that holds the address (ARIN, RIPE
   NCC, APNIC, LACNIC or AFRINIC), and your computer then asks that registry
   directly. The address is also looked up in reverse DNS, and the name that
   comes back is looked up again to confirm it, both through your computer's
   own resolver (which asks your DNS provider). Only the addresses are sent,
   never what was in the connections, and private addresses are never sent.
   Like any website, each service also sees your computer's public IP
   address, and the request names the app and its version (Reclaim City).
   `rescue watch --no-lookups` turns this off. See
   [the CLI reference](cli.md#rescue-watch-watch-connections-for-a-few-minutes).
5. **The AI tools check's one-time download.** The first time a scan runs
   the `ai_agent_audit` check, it downloads HackMyAgent and the packages it
   needs (about 51 MB) from `registry.npmjs.org` with `npm ci`, pinned to
   exact versions and integrity hashes in `vendor/hackmyagent/`. What is
   sent is a normal package download: the package names and versions, and
   npm's User-Agent, which names the npm and Node.js versions, the operating
   system and the processor type. Like any website, the registry sees your
   computer's public IP address. Your own `.npmrc` files are not used (npm
   gets empty ones), so an npm login token in them is not sent; a proxy set
   in the `HTTPS_PROXY` environment variable is still used. Nothing else
   about your computer is sent. Later scans reuse the copy and don't use the
   network. When HackMyAgent runs, its usage reporting is off
   (`OPENA2A_TELEMETRY=off`) and it is told not to share its findings
   (`--no-contribute`). `rescue scan --no-downloads` (or
   `RESCUE_NO_DOWNLOADS=1`) turns the download off; `rescue export` and
   `rescue run` take the same flag.

   What HackMyAgent itself looks at, all on the computer: the list of
   running programs with their command lines (`ps aux`), to spot AI tools
   that are running; AI tools' settings files in your home folder; and the
   computer's hardware ID (`ioreg` on macOS, `/etc/machine-id` on Linux, the
   `MachineGuid` registry value on Windows), which it hashes into an install
   ID for its own telemetry file. That file goes into the throwaway folder
   and is deleted, and with telemetry off the ID is never sent. On start it
   also clears old `hma-check-*` and `arp-lab-*` folders from its temp
   folder, which is the throwaway folder too.

There is no "phone home" on launch, no version check, no usage counter, and no
error reporting.

## What the AI layer sends

The AI layer is **off unless two separate things are true**:

1. A provider is configured through an environment variable —
   `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `OLLAMA_HOST`.
2. You explicitly ask for it on the command line — `--copilot` on `rescue
   --auto` or `rescue run`, or the `rescue explain` / `rescue recommend`
   commands, which are themselves the opt-in.

Miss either and you get:

```text
This feature requires an AI provider.
Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.
```

### The exact payload

For `--copilot` and `rescue explain`, the message body is built by
`build_findings_summary` in `rescue/ai/explainer.py`, one line per finding:

```text
[<category>/<module>] (<severity>) <finding title>: <finding description>
```

That is all. **Not sent:** your hostname, username, home path, IP addresses,
serial numbers, the `Finding.data` payloads, your `SystemProfile`, the list of
modules that ran, or anything about checks that found nothing.

The accompanying system prompt is a fixed instruction to write a 2–4 sentence
plain-language narrative and to neither suggest shell commands nor claim to fix
anything.

For `rescue recommend`, what is sent is what you type at the prompt, plus the
model's turns. It is a conversation you drive; type only what you want to send.

!!! warning "Finding descriptions are free text and are not redacted before sending"
    Findings are written by 287 modules, and a description can legitimately
    contain a file path, a process name, or a service name from your machine.
    The AI payload is **not** run through the redaction pipeline that
    `rescue export` uses. If that matters to you, use a local provider:

    ```console
    $ export RESCUE_AI_PROVIDER=ollama
    $ rescue explain
    ```

    With Ollama the request goes to `http://localhost:11434` (or your
    `OLLAMA_HOST`) and never leaves the machine.

### Who receives it

Whoever runs the provider you configured:

| Provider | Enabled by | Data goes to |
| --- | --- | --- |
| Anthropic | `ANTHROPIC_API_KEY` | Anthropic's API, under their terms. |
| OpenAI | `OPENAI_API_KEY` | OpenAI's API, under their terms. |
| Ollama | `OLLAMA_HOST`, or `RESCUE_AI_PROVIDER=ollama` | Your own Ollama instance — local by default. |

When more than one is configured, the order of preference is `RESCUE_AI_PROVIDER`
first, then Anthropic, then OpenAI, then Ollama. Set `RESCUE_AI_PROVIDER`
explicitly if you care which one gets your data.

The AI layer can never take down a scan: the deterministic results are printed
first, and a provider failure is reported as a warning with "(the scan results
above are unaffected)".

## The redacted case export

`rescue export` produces the artifact you are most likely to paste into a chat
window, an email, or a public issue — so redaction runs over **every** string
that leaves, including free-text descriptions from modules the export code
cannot audit individually.

### What is removed

| Removed | Replaced with |
| --- | --- |
| PEM private key blocks | `[redacted] private key` |
| `Authorization:` / `Proxy-Authorization:` header values (rest of line) | `[redacted]` |
| `api_key=`, `secret=`, `password=`, `token=`, `access_key=` and similar assignments | `[redacted]` |
| GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | `[redacted] github token` |
| OpenAI-style keys (`sk-…`) | `[redacted] api key` |
| Slack tokens (`xoxb-`, `xoxp-`, …) | `[redacted] slack token` |
| JWTs (`eyJ….….…`) | `[redacted] jwt` |
| AWS access key IDs (`AKIA…`) | `[redacted] aws key id` |
| Email addresses | `[redacted] email` |
| Your home directory path | `~` |
| Your account name (3+ characters) | `[user]` |
| The hostname | `[redacted]` |

Redaction is recursive: it runs over finding titles, descriptions, error text,
unsupported reasons, action titles and descriptions, rollback and verification
metadata, notes, and every string nested inside a `Finding.data` dictionary.
Values that are not JSON-serialisable are stringified and then redacted, so an
unexpected type cannot cause the whole case to be lost.

The export is also honest about what happened: guidance is recorded as guidance
even if a module flagged it successful, and an action is only recorded as
`changed_the_system` when it was a mutation that executed and succeeded.

### What redaction cannot promise

The tool says this itself, every time:

```text
Both files are redacted, but module output is free text — read them before
sharing.
```

Patterns catch credential *shapes*. They cannot catch a secret that does not
look like one, a company-internal hostname in a service name, a project name in
a file path, or a person's name in a Wi-Fi SSID. **Read the Markdown file
before you send it.** It is written for exactly that.

Note also that `rescue scan --json` is **not** redacted — it is the raw result
stream for local tooling. Use `rescue export` for anything you intend to share.

## Guide progress

`~/.rescue/sessions/<profile>.json` stores the profile name, the current phase,
and the step numbers you have marked complete. It contains no findings and
nothing about your machine, and deleting it simply resets your progress.
