---
title: "Update a Node.js or PHP that attackers can break into"
platforms: [macos, linux, windows]
remediates:
  - security.vulnerable_runtimes.exploited_rce
  - security.vulnerable_runtimes.old_copy_affected
  - security.vulnerable_runtimes.version_unknown
  - security.vulnerable_runtimes.runtime_inventory
steps_for:
  security.vulnerable_runtimes.exploited_rce: [1, 2]
  security.vulnerable_runtimes.old_copy_affected: [3]
  security.vulnerable_runtimes.version_unknown: [4]
  security.vulnerable_runtimes.runtime_inventory: [5]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

Node.js and PHP are the programs that run many websites and developer tools.
Some versions have a bug that attackers are using right now to take over
computers from outside: the finding names the bug (for example Node2Shell,
CVE-2026-111497, or PHP2Shell, CVE-2026-109618 and CVE-2026-109619). It's on
CISA's list of Known Exploited Vulnerabilities, the US government's list of
bugs being used in real attacks. Finding one doesn't mean you've been hacked.
It means this copy needs updating.

## Step 1: Update the copy the finding names

The finding says where the copy is, how it was installed, and the exact
command that updates it for that installer. Run that command in a terminal.
For example:

- Homebrew: `brew update && brew upgrade node` (or the formula named, such
  as `node@22` or `php@8.3`).
- nvm, fnm, asdf, mise or Volta: install the fixed version the finding names,
  then switch your projects to it and remove the old one.
- The Node.js installer: download the newer installer from
  https://nodejs.org/en/download and run it.
- MAMP, XAMPP, Herd or Laragon: update the app to a release that includes
  the fixed PHP version, and stop its web server until then.
- Linux system packages: install your system's updates. Distributions
  sometimes fix a bug without changing the version number, so check your
  distribution's security notices before assuming a copy is still affected.

If the finding says the version line "no longer gets fixes", there is no
update on that line: move to the newer line it names.

## Step 2: Check for signs of a break-in, if it was exposed

If this copy ran a website or service that other computers could reach (a
server, or a development server open to your network), the bug may already
have been used. Run the AI Worm & Spyware Response checkup and look at what
starts on its own. On a server, a professional incident responder is worth
it.

## Step 3: Remove an old copy Homebrew left behind

Homebrew keeps older versions after an update until you clean up. Nothing
uses them unless a project points at them directly. `brew cleanup <formula>`
(the finding gives the exact command) removes them.

## Step 4: A copy whose version we couldn't read

Run it yourself with `--version` (Node.js) or `-v` (PHP) in a terminal and
compare the number with the fixed versions in the advisory. If you don't know
what installed it, the folder it's in usually says.

## Step 5: Look over the list

This is every copy of Node.js and PHP found in the usual places. Copies you
don't use can be removed. Copies of Node.js inside desktop apps built on
Electron (Slack, VS Code, Discord and others) aren't in this list; keep those
apps updated.
