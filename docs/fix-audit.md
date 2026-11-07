# "Fix it for me" audit

The desktop app may show a "Fix it for me" button only for a module that passes
every one of these tests:

1. The change is reversible, by the person, with steps we can write in plain words.
2. It is low impact: nothing else stops working, no data is lost.
3. It does exactly what one sentence says ("Turns on your Mac's firewall").
4. It needs no administrator password.
5. It touches only the setting or file the finding is about.
6. It cannot be wrongly aimed (no ids or paths that go stale between the scan and the fix).

Any doubt is a NO. A wrong automatic fix on a frightened person's computer is
worse than none; the "How to fix this" steps remain for everything declined here.

Only modules listed with verdict `OFFER` may appear in `rescue/app_fixes.json`.
`tests/test_app_fixes.py` fails if a module with a state-changing `fix()` is
missing from this table, if the table lists a module whose `fix()` is guidance
only, or if the allowlist names a module that is not marked `OFFER` here.

Method: every `modules/*/*/__init__.py` was parsed, and `fix()` plus every helper
reachable from it was searched for state-changing calls (subprocess, kill,
unlink, rmtree, write, move, mkdir, chmod, `ActionKind.MUTATION`). The other
modules' `fix()` only return guidance text (some contain `sudo ...` commands in
strings for the person to read; none run them).

Result: 11 modules have a state-changing `fix()`. **0 are offerable today.** Two
engine-level actions, `disable_launch_agent` and `quarantine_file`, are offered
instead (last rows).
The feature, the allowlist and the gate are in place and tested, so a module can
be added later once its `fix()` is narrowed and re-audited.

| Module | What fix() really does | Verdict | Reason |
| --- | --- | --- | --- |
| `startup_auditor` | Runs `launchctl unload -w ~/Library/LaunchAgents/<label>.plist` for EVERY matched finding in one go. The list it matches mixes real scareware (MacKeeper, Genieo, Pirrit) with updaters (Google Keystone, Microsoft AutoUpdate, Java) and a working antivirus (Avast). | NO | Fixes all findings at once, so one card's button would change other items. Several matches are security updaters or an antivirus whose removal leaves the person less safe. Unloading adware does not remove it, so "fixed" would overpromise. Candidate for a future per-item version limited to the scareware/adware entries. |
| `firewall_audit` | Runs `socketfilterfw --setglobalstate on` and `--setstealthmode on`. | NO | Needs administrator rights (its own error text says so), so it would fail for a normal user. Stealth mode can also break device discovery. |
| `win_firewall` | Runs `netsh advfirewall set <profile> state on`. | NO | Needs Administrator. Turning a profile on can cut off a network the person relies on (remote desktop, shared printers). |
| `win_defender` | Runs `Set-MpPreference -DisableRealtimeMonitoring $false` or `Update-MpSignature`. | NO | Needs Administrator. Real-time protection is often off on purpose when another antivirus is installed; forcing it on creates conflicts. Tamper Protection can silently refuse. |
| `win_antivirus_status` | Same two PowerShell commands as `win_defender`. | NO | Same reasons as `win_defender`. |
| `win_updates` | Runs `Start-Service -Name wuauserv`. | NO | Needs Administrator. The service is often stopped deliberately by policy or a management tool. |
| `ai_worm_filesystem` | Moves files flagged "high confidence" into `~/.rescue_quarantine`. | NO | Moves files, and the person may be dealing with an active compromise or want to keep evidence. Detection confidence is a heuristic. Needs a human decision per file. |
| `ai_worm_git_ssh` | Unsets global git config keys, edits `.npmrc`, edits MCP server config files, moves repo hook files. | NO | Edits configuration files a developer may rely on, with no undo copy. Wrong edits can break their tools or destroy evidence. |
| `ai_worm_lateral` | Deletes files flagged as malicious artifacts. | NO | Permanent deletion with no undo. Rotating exposed credentials must come first and cannot be automated. |
| `ai_worm_network` | Sends SIGTERM to a process id taken from the scan, and rewrites the hosts file. | NO | The process id can be reused by a different program between the scan and the fix, so it could close the wrong program. Rewriting `/etc/hosts` needs admin. |
| `ai_worm_persistence` | Unloads and deletes launch agents, systemd units and scheduled tasks, and rewrites shell profiles, settings hooks. | NO | Deletes persistence entries and rewrites files with no undo copy, and the order matters for dead-man-switch malware. Needs human guidance. |
| `disable_launch_agent` | Engine action, not a module `fix()`. Stops one background job (`launchctl bootout gui/<uid>/<label>`) and moves its plist from the person's own `~/Library/LaunchAgents` to `~/Library/Application Support/Device Rescue/Quarantine`, with a JSON manifest (original path, label, time, sha256). Undo moves it back and runs `launchctl bootstrap`. | OFFER | 1. Reversible in one click (Undo), or by moving the file back. 2. One job stops; nothing is deleted. 3. One sentence says it. 4. No password: it is the person's own user domain and their own file. 5. Touches only the one named plist. 6. The path is re-validated at run time (regular file, not a symlink, owned by the user, directly inside their LaunchAgents, parseable, Label equals file name), and never `/Library` or `/System`; the scan is not trusted. Offered only for warning/critical findings from the persistence audits, on the exact plist the finding names (`data.plist`; the label is used to find a file only when the finding names none). Several checks often report the same job, so the app retires the other cards' buttons once one has turned it off, and a request for a file in LaunchAgents that is already gone (turned off from another card, or removed by hand) answers `nothing_to_fix` rather than a refusal. Caveat: whoever set the job up may notice it stopped, so the app adds a warning for the "someone is watching me" situation. |
| `quarantine_file` | Engine action, not a module `fix()`. Moves one file a malware scan matched (`malware_file_scan` with Apple's XProtect rules, or `clamav_scanner`) into `~/Library/Application Support/Device Rescue/Quarantine/Files` (Linux: `~/.local/share/device-rescue/quarantine/files`), renamed `<id>.quarantined` and set read-only (0400, never executable), with a JSON manifest (original path, sha256, size, permissions, time, which check found it). The move is `os.link` + `unlink` on the same disk, or an O_EXCL copy checked against the sha256 across disks; the original is removed only if it is still the same inode, size and mtime that was checked. Undo (`rescue undo --quarantine-id <id>`, or the app's Undo) moves it back and restores its permissions without set-user/group-id bits. `rescue quarantine list` shows what is held. | OFFER | 1. Reversible in one click (Undo), or from Terminal. 2. One file moves; nothing is deleted. 3. One sentence says it. 4. No password: only the person's own files in folders they can write. 5. Touches only the one named file. 6. Re-validated at run time: a regular file, not a symlink, owned by the person, in a folder they can write, not in the quarantine folder, and never an operating-system file (macOS: /System, /usr except /usr/local, /bin, /sbin, /Library/Apple, or anything with the SIP `restricted` or an immutable flag; Linux: /usr, /bin, /lib, /etc, /boot). Refusals say why in plain words. Offered only for critical matches from those two checks (`data.path`). Not on Windows: Defender keeps its own quarantine (Protection history). Caveat: monitoring software (a match whose rule, verdict or file name looks like it) carries the advocate safety note in its `fixable`, shown above the confirmation, because whoever set it up may notice it's gone. |

## Adding a module later

1. Narrow `fix()` so it acts on exactly one named setting and cannot touch more.
2. Add its row here with verdict `OFFER` and the reason it passes all six tests.
3. Add an entry to `rescue/app_fixes.json` (`will_change`, `how_to_undo`).
4. `pytest tests/test_app_fixes.py` must pass.
