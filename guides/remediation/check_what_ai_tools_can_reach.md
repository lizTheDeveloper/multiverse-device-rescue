---
title: "Check what your AI tools can reach"
platforms: [macos, linux, windows]
remediates:
  - security.ai_agent_audit.credentials_in_ai_config
  - security.ai_agent_audit.risky_mcp_server
  - security.ai_agent_audit.ai_inventory
  - security.ai_agent_audit.could_not_check
  - security.ai_agent_audit.changed_during_run
steps_for:
  security.ai_agent_audit.credentials_in_ai_config: [1]
  security.ai_agent_audit.risky_mcp_server: [2]
  security.ai_agent_audit.ai_inventory: [3]
  security.ai_agent_audit.could_not_check: [4]
  security.ai_agent_audit.changed_during_run: [5]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

AI assistants such as Claude Code, Cursor, GitHub Copilot and Claude Desktop
keep settings files in your home folder. Those files can hold secret keys, and
they list the add-ons (called MCP servers) that let the assistant reach things
outside the chat: files, a browser, a database. This check lists them using a
free tool called HackMyAgent. Nothing here means you've been hacked. It's
about making sure each tool can reach only what you meant it to.

## Step 1: Move a secret key out of an AI tool's settings file

The finding names the file, the line, and the name the key is saved under. We
never read or show the key itself.

1. Work out what the key is for. The name usually says (for example, a name
   ending in `_API_KEY` that starts with a company or product name). If you
   don't recognise it, ask whoever set the tool up before you change anything.
2. Sign in to that service's website, make a new key, and delete the old one
   there. Deleting it at the service is what makes the old copy useless,
   wherever else it might have travelled (a backup, a synced folder, a shared
   screenshot).
3. Open the settings file in a text editor and remove the line with the old
   key. Put the new key where the AI tool's own instructions suggest. Many
   tools can read a key from your system's password store or from an
   environment variable instead of a file.
4. Run the checkup again. The finding goes away once the key is no longer in
   the file.

## Step 2: Trim an add-on that can reach too much

The finding names the AI tool, the add-on, and what the add-on lets the
assistant do (for example, read and change a database, or read and change
files across the whole computer).

1. Ask yourself whether you use this add-on. If you don't, or don't remember
   adding it, remove it. In most tools the add-ons are listed in a file named
   in the finding (for Cursor, `~/.cursor/mcp.json`; for Claude Desktop,
   `claude_desktop_config.json`; for Claude Code, the `mcpServers` section of
   `~/.claude.json` or `claude mcp remove <name>`). Delete that add-on's entry
   and restart the tool.
2. If you do use it, give it the least it needs:
   - a database add-on: connect it with an account that can only read, and
     only to the database you're working on;
   - a files add-on: point it at one project folder, never at `/` or your
     whole home folder;
   - a browser add-on: use a separate browser profile that isn't signed in to
     your email or bank.
3. Run the checkup again.

Why this matters: an AI assistant follows instructions it finds in what it
reads. A web page or document can contain hidden instructions, and an add-on
with broad reach turns those into real actions.

## Step 3: Look over the list of AI tools

This is a list, not a problem. Read it and look for anything you don't
remember installing: an AI tool, or an add-on you don't recognise. If
something is unfamiliar, search for its name before removing it, or ask
whoever set up the computer.

The check looks at the settings for your whole account. It doesn't look
inside each project folder, because that can take minutes. To look inside one
project folder, use the command shown in the finding: it moves into the folder
where Reclaim City keeps its copy of HackMyAgent and runs the same `detect`
command on the folder you name, with sharing and usage reporting off.

## Step 4: If this check couldn't run

The finding says why:

- **Node.js isn't installed, is too old, or didn't start.** HackMyAgent runs on Node.js.
  If you use AI coding tools and want this check, install the LTS version
  from <https://nodejs.org> and run the checkup again. If you don't use AI
  coding tools, you can skip it. Reclaim City never installs Node.js for you.
- **Downloads are turned off.** The scan was run with `--no-downloads` (or
  `RESCUE_NO_DOWNLOADS=1`). Run it without that to include this check. The
  first run downloads HackMyAgent from the npm registry (about 51 MB) into
  your user cache folder; later runs reuse it.
- **The download didn't finish.** Usually the connection dropped. Run the
  checkup again later. Nothing half-downloaded is left behind.
- **The download didn't match.** The files that arrived weren't the ones
  Reclaim City expects, so they weren't kept. Run the checkup again later;
  if it keeps happening, update Reclaim City.
- **A file Reclaim City needs is missing, or its working copy couldn't be
  made.** Reinstalling or updating Reclaim City fixes a missing file. If the
  working copy couldn't be made, the disk may be full: free some space and
  run the checkup again. Neither is a sign that anything was changed.
- **The saved copy had changed.** Before every run, Reclaim City checks each
  file of its saved copy against the list it ships with. This copy didn't
  match, so it wasn't run, and it was deleted. The next checkup that's allowed to
  download fetches a fresh one. If it happens again, mention it to whoever
  helps you with your computer.
- **The checkup had administrator rights.** A downloaded tool is never run
  with those rights. Run the checkup the normal way (no `sudo`, no "Run as
  administrator").
- **HackMyAgent's own settings are on this computer.** Someone has used
  HackMyAgent here before, and running it would change its settings
  (`~/.hackmyagent/config.json`), so Reclaim City leaves it alone. Run your
  own copy the way you usually do, with `--no-contribute` if you don't want
  it to share what it finds.
- **HackMyAgent stopped or its answer couldn't be read.** Run the checkup
  again. If its self-check failed, delete the folder named in the finding;
  the next checkup downloads a fresh copy.

A check that couldn't run tells you nothing either way: it doesn't mean your
AI tools are fine, or that something is wrong.

## Step 5: If the checker's files changed while it was running

Reclaim City checks HackMyAgent's files again right after it runs. This time
they had changed while it was running. That shouldn't happen, and it can mean
another program on this computer swapped in its own code, which would then
have run with Reclaim City's permissions (on a Mac, that can include Full
Disk Access). Reclaim City threw the results away and deleted its saved copy,
so the next checkup downloads a fresh one.

1. Don't panic, and don't start deleting things. Write down the date and time.
2. Run a full checkup (without `--no-downloads`). Look closely at what it says
   about things set to start automatically (background tasks, login items,
   launch agents) and at programs you don't recognise.
3. If the full checkup flags something, follow its own walkthrough.
4. If you're not sure what you're looking at, ask someone you trust who helps
   you with computers, and show them this finding.
5. If it happens again on the next checkup, treat this computer as possibly
   compromised: change important passwords from a different device, and get
   help.
