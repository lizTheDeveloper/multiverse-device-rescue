---
title: "Secure git, npm, MCP configs, and SSH access after an AI worm"
estimated_time: "30 minutes"
platforms: [macos, linux, windows]
remediates:
  - security.ai_worm_git_ssh.git_hookspath_hijack
  - security.ai_worm_git_ssh.git_templatedir_hijack
  - security.ai_worm_git_ssh.npmrc_git_override
  - security.ai_worm_git_ssh.rogue_mcp_server
  - security.ai_worm_git_ssh.repo_hook_file
  - security.ai_worm_git_ssh.ssh_authorized_keys_recent
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

## Step 1: Reset hijacked git global config (core.hooksPath / init.templateDir)

AI worms (e.g. Shai-Hulud-style supply-chain attacks) commonly set
`core.hooksPath` or `init.templateDir` globally so that every `git clone` or
`git init` silently installs a malicious hook that runs on future git
operations.

1. Inspect first: `git config --global core.hooksPath` and
   `git config --global init.templateDir`. Read what the value points at —
   a directory you set up yourself for a legitimate hook manager (husky,
   lefthook, pre-commit, overcommit) is not a problem.
2. If the value points somewhere you don't recognize, or matches a known IOC
   path, unset it:
   ```
   git config --global --unset core.hooksPath
   git config --global --unset init.templateDir
   ```
3. Before unsetting, inspect the hook scripts in that directory (don't run
   them) to understand what they were doing — this may inform which
   credentials to rotate in Step 5.

## Step 2: Remove the npm `git=node` override

`.npmrc` files (global `~/.npmrc`, or a project-local one) can contain
`git=node`, which replaces the `git` binary npm invokes with `node` — a
known technique to slip past `npm install --ignore-scripts` protections.

1. Open the flagged `.npmrc` and confirm the `git=node` line yourself.
2. Remove only that line, leaving the rest of the file intact. Back up the
   file first if it has other custom configuration you want to preserve.
3. Run `git --version` after editing to confirm npm now resolves the real
   git binary again.

## Step 3: Remove rogue MCP server entries

MCP client configs (`~/.claude/settings.json`, `~/.claude.json`,
`~/.cursor/mcp.json`, `~/.continue/config.json`) can have a malicious MCP
server injected into `mcpServers`, matched here against a known-bad server
name in the shared IOC database.

1. Open the flagged config file and locate the `mcpServers` entry named in
   the finding. Read its command/args — this tells you what it was capable
   of running.
2. Back up the config file, then remove only that server's JSON object,
   preserving valid JSON and any legitimate MCP servers you configured.
3. Restart any MCP clients (Claude Code, Cursor, etc.) so the change takes
   effect, and confirm the rogue server no longer appears in the client's
   server list.

## Step 4: Quarantine suspicious repo hook files

Findings here are either IOC-confirmed dropper/hook files at known paths
(`.claude/setup.mjs`, `.cursor/rules/setup.mdc`, `.github/setup.js`) or a
medium-confidence heuristic match (a `.vscode/tasks.json` configured to
auto-run on folder open).

1. Open the flagged file and read its full contents before touching it.
2. For IOC-confirmed hook files (high confidence): quarantine rather than
   delete — move it to `~/.rescue_quarantine/` (create the directory if
   needed) so you keep a copy for reference.
3. For the `tasks.json` auto-run heuristic (medium confidence): confirm
   whether the `runOn: folderOpen` task is something your team intentionally
   configured (some teams do use this for legitimate dev setup). If not
   recognized, quarantine the file the same way.
4. Check every clone of the affected repository (not just the one you
   happened to scan) — the same hook file may be present in multiple
   working copies.

## Step 5: Review recently modified SSH authorized_keys, then rotate credentials

A low-confidence finding fires whenever `~/.ssh/authorized_keys` was
modified in the last 7 days — this is not proof of compromise (you may have
added a key yourself), but it's worth a deliberate review given everything
else found by this module.

1. Open `~/.ssh/authorized_keys` and read every key line. For each one,
   confirm you recognize the comment/fingerprint and know which device it
   corresponds to.
2. Remove any key you cannot account for. Back up the file first
   (`cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak`).
3. **Only from a known-clean device**, and only after Steps 1–4 above are
   complete: rotate SSH keys, GitHub/GitLab personal access tokens, npm
   publish tokens, and MCP server credentials that were reachable from this
   machine. Review your git host's audit log for unfamiliar clones, pushes,
   or new SSH keys added around the time of infection.
4. Regenerate SSH keypairs if you cannot be confident private key material
   was not read, and update `authorized_keys` on any other machines/servers
   that trusted the old key.
