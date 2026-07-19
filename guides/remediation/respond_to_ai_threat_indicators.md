---
title: "Respond to AI threat indicators"
estimated_time: "30 minutes"
platforms: [macos]
remediates:
  - security.ai_threat_indicators.ai_api_connection
  - security.ai_threat_indicators.ai_api_key_found
  - security.ai_threat_indicators.cron_ai_call
  - security.ai_threat_indicators.launchagent_ai
  - security.ai_threat_indicators.python_node_ai_process
  - security.ai_threat_indicators.ai_config_file
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers everything the `ai_threat_indicators` module can
flag: processes connecting to known AI API endpoints (OpenAI, Anthropic,
Google, Cohere, and similar), AI API keys present in environment variables,
cron jobs referencing AI endpoints or tools, LaunchAgents/LaunchDaemons with
AI-related references, Python/Node processes mentioning AI packages, and
files matching AI-agent configuration naming patterns.

Read this carefully before acting: **most of these findings are expected
noise for anyone who does AI development work.** If you use the OpenAI or
Anthropic API, run Claude Code or similar tools, work with LangChain, or
keep API keys in your shell profile, you will legitimately trigger several
of these checks every single scan. The module cannot tell "the developer's
own tooling" apart from "an unauthorized/rogue agent someone else planted on
this machine" — that judgment call is yours. The goal of this guide is
helping you make that call quickly and confidently, not treating every hit
as an incident.

## Step 1: Triage — is this your own AI tooling?

Before working through the specific findings below, answer this once for
the whole scan: do you (or does someone with legitimate access to this
machine) intentionally use AI APIs, agent frameworks, or coding assistants
here?

1. If yes, and every flagged process/key/file traces back to tools you
   recognize (this CLI tool itself, a coding assistant, a personal project
   using an LLM API), most of these findings are expected — skim Steps 2–6
   to confirm nothing is *unexpected* mixed in, then you're done.
2. If you don't do AI development work on this machine at all, or a
   specific finding doesn't match anything you recognize, treat that
   specific finding as suspicious and follow the relevant step below.
3. The highest-value question per finding isn't "is this AI-related" (it
   almost certainly is, that's what triggered it) — it's "did *I* put this
   here, and does it match a tool I actually chose to install."

## Step 2: Investigate AI API connections (critical)

A running process has an active connection to a known AI API endpoint
(`api.openai.com`, `api.anthropic.com`, etc.). This is flagged CRITICAL
because an active outbound connection is the strongest signal something is
actively using an AI service right now — but note this fires just as
readily for your own terminal-based AI coding assistant as for anything
unauthorized.

1. Note the process name and endpoint from the finding.
2. Check whether the process is a tool you launched (a CLI coding
   assistant, a script you wrote, a browser tab with an AI web app open).
3. If yes, no action needed — this is expected traffic.
4. If you don't recognize the process, investigate further before assuming
   the worst: `lsof -p <pid>` to see its full file/network footprint, and
   `ps -p <pid> -o ppid,command` to see what launched it and with what
   arguments — a legitimate but unfamiliar tool (installed by IT, or by a
   dependency you didn't expect) is more common than a genuinely rogue
   agent.
5. If, after investigating, the process is truly unaccounted for and it's
   also making unusual local activity (reading files broadly, spawning
   subprocesses, persisting via a LaunchAgent — see Step 4), treat this as
   a possible unauthorized-agent compromise: disconnect from the network,
   identify and remove the persistence mechanism (Step 4), quarantine the
   binary (move to `~/Desktop/quarantine-YYYYMMDD/` rather than deleting),
   and consider whether any credentials or files it had access to should be
   rotated/reviewed.

## Step 3: Review AI API keys in environment variables

An `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or similar variable is set in your
current environment.

1. Check whether you set this intentionally (in `~/.zshrc`, `~/.bashrc`, a
   `.env` file you source, or your terminal session directly).
2. If yes, no action needed — though it's good hygiene to confirm the key
   is scoped/rate-limited on the provider's dashboard and not a shared or
   overly-privileged credential.
3. If you don't recognize setting it, check where it's defined: `grep -rl
   "<KEY_NAME>" ~/.zshrc ~/.bashrc ~/.zprofile ~/.bash_profile ~/.profile`
   and any `.env` files in project directories you have open.
4. If you find it was set by software you didn't expect to need an AI API
   key, treat that software with suspicion (see Step 1's guidance) and
   investigate it before removing anything.
5. If genuinely unexplained, revoke the key from the provider's dashboard
   (this invalidates it regardless of where it's stored) and remove the
   `export` line from whatever file defined it.

## Step 4: Investigate suspicious cron jobs

A crontab entry calls an AI API endpoint directly, or combines an AI tool
reference (claude, gpt, langchain, etc.) with `curl`, `wget`, `python`, or
`node`.

1. Run `crontab -l` yourself and find the matching line.
2. Check whether it's a job you set up (a scheduled script that calls an
   LLM API for some personal automation) — if so, no action needed.
3. If you don't recognize the entry, do not run any command from it
   manually to "test" it — instead read it carefully to understand what
   it does (what it downloads, what it sends data to).
4. Remove unrecognized entries: `crontab -e` and delete the line, or
   `crontab -r` to clear all cron jobs if you don't rely on cron for
   anything else (back up `crontab -l > ~/crontab-backup.txt` first).
5. If the cron entry references a script file, quarantine that file too
   (move it, don't delete, so you can review it further) and check whether
   anything else on the system also references it.

## Step 5: Investigate LaunchAgents/LaunchDaemons with AI references

A plist under `~/Library/LaunchAgents`, `/Library/LaunchDaemons`, or
`/System/Library/LaunchDaemons` contains a reference to an AI API endpoint
or AI tool name.

1. Note the plist path from the finding and inspect it:
   `plutil -p <path>` to see its `Label` and `ProgramArguments`.
2. Check whether this is a launch agent you set up intentionally (some
   AI coding assistants or agent frameworks install a background service
   this way) — if so, no action needed.
3. If unrecognized, unload it before removing: `launchctl unload <path>`
   (`sudo` for system-level daemons under `/Library/LaunchDaemons` or
   `/System/Library/LaunchDaemons` — treat anything unexpected under
   `/System/Library` with particular suspicion, since third-party software
   should not normally install there).
4. Quarantine the plist and the binary it references (from
   `ProgramArguments`) rather than deleting immediately.
5. Reboot and confirm with `launchctl list | grep <label>` that it no
   longer loads.

## Step 6: Review Python/Node processes and AI config files

These are the lowest-severity (INFO) findings: a running Python/Node
process whose command line mentions an AI package or tool name, or a file
under `~/.config`/`~/.local` whose name matches an AI-related pattern.

1. For process findings, check the full command
   (`ps -p <pid> -o command=`) — this is very commonly your own virtualenv,
   IDE extension, or a dependency of a project you have open, not a
   standalone rogue process.
2. For config file findings, open the file (read-only) and confirm it
   belongs to software you installed intentionally (many legitimate
   CLI tools and IDE extensions store config exactly here, e.g. `~/.config/
   <tool>/`).
3. If either turns out to be unaccounted for, escalate: apply the process
   scrutiny from Step 2, or quarantine the config file, depending on which
   applies.
4. Given these are INFO-level, if you can't quickly confirm or deny
   legitimacy and there's no corroborating higher-severity finding (Steps
   2–5) alongside it, it's reasonable to note it and move on rather than
   spending significant time chasing a low-confidence signal in isolation.
