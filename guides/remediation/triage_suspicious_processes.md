---
title: "Triage suspicious processes"
estimated_time: "25 minutes"
platforms: [macos]
remediates:
  - security.suspicious_processes.known_malware
  - security.suspicious_processes.suspicious_paths
  - security.suspicious_processes.suspicious_names
  - security.suspicious_processes.high_cpu
  - security.suspicious_processes.unsigned_apps
  - security.suspicious_processes.all_clean
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `suspicious_processes` module can
flag: processes matching known adware/malware names (Genieo, MacKeeper,
Shlayer, and similar), processes running from temp/Downloads/Desktop,
processes with obfuscated or hidden-looking names, sustained high-CPU
processes, and apps in `/Applications` without a readable bundle ID. Each
category has a different confidence level, so investigate before removing
anything — several of these (especially unsigned apps and suspicious names)
have legitimate explanations.

## Step 1: Remove known malware processes (critical)

The scan matched a running process name against a list of well-documented
macOS adware/malware families (Genieo, VSearch, MacKeeper,
"Advanced Mac Cleaner", Shlayer, Bundlore, Adload, Pirrit, and similar).
These are consistently reported as unwanted or malicious across independent
sources.

1. Note the PID(s) and command(s) from the finding.
2. Check for a persistence mechanism before killing anything — these
   families commonly install a LaunchAgent to relaunch themselves: search
   `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
   `/Library/LaunchDaemons` for a plist referencing the process name, and
   `launchctl unload <path>` it first if found.
3. Stop the process: `killall -9 <name>` for each flagged process.
4. Locate the application bundle (usually in `/Applications` or
   `~/Library/Application Support`) and quarantine it — move it to a dated
   folder (`~/Desktop/quarantine-YYYYMMDD/`) rather than deleting outright,
   so you have it available if you want to confirm identification via a
   scanner (e.g. VirusTotal) first.
5. Remove the persistence plist found in step 2 the same way.
6. Reboot and re-run the scan to confirm the process no longer appears and
   hasn't relaunched.
7. Check Safari/Chrome/Firefox for extensions or changed default search
   engine/homepage — these families commonly hijack browser settings
   alongside installing the background process; revert anything unexpected.
8. Investigate how it arrived (a bundled "free" download, a fake Flash
   Player update, a cracked app) so you avoid reinstalling the same source.

## Step 2: Investigate processes from suspicious locations

Processes launched directly from `/tmp`, `/var/tmp`, `~/Downloads`, or
`~/Desktop` are unusual — legitimate installed software normally runs from
`/Applications` or a Library location, not a scratch/staging directory.

1. Note the PID, path, and command from the finding.
2. Check what the file actually is before doing anything: `file <path>`
   and, if it's a script, read its contents with a text editor (don't
   execute it further) rather than running it again.
3. If you recognize it as something you downloaded and ran deliberately
   (e.g. a one-off script, an installer you haven't cleaned up yet), it may
   be benign — but move it out of the temp/staging location once you're
   done with it.
4. If you don't recognize it, kill the process (`kill <pid>`) and quarantine
   the file (move, don't delete, to `~/Desktop/quarantine-YYYYMMDD/`) for
   further analysis before permanent deletion.
5. Check `lsof -p <pid>` (while still running, before you kill it, if
   possible) to see what other files/connections it touched — this can
   reveal a broader footprint worth investigating.

## Step 3: Investigate processes with suspicious names

A process name that's hidden (dot-prefixed) or looks like a random
hex/obfuscated string is a common malware pattern, but can also be a
legitimate helper process or daemon with an intentionally opaque name.

1. Note the PID and command from the finding.
2. Look up the exact process name — many hex-looking or dot-prefixed names
   belong to known system helpers, browser components, or dev tools once
   you search for them.
3. Check the binary's location and code signature:
   `codesign -dv <path-to-binary>` — a valid Apple Developer ID signature is
   a strong (though not absolute) signal of legitimacy.
4. If unsigned and unrecognized, follow the quarantine procedure from Step
   2 rather than deleting immediately.
5. If signed and traceable to known software, no action is needed.

## Step 4: Investigate high-CPU processes

A process sustained above 80% CPU that isn't a known safe process (browser,
compiler, media app) could be resource-abuse malware (a miner, a
scraper/bot) or could be legitimate work you're doing.

1. Check whether the usage correlates with something you're intentionally
   running (a build, an export, an indexing job) — if so, no action needed.
2. If unexplained, use Activity Monitor's "Sample Process" or `lsof -p
   <pid>` to see what the process is doing (files open, network
   connections).
3. If it's making outbound network connections you can't account for
   alongside the high CPU, treat this as a possible cryptominer or bot —
   see the `remove_cryptominer.md` walkthrough for the fuller
   investigation/removal procedure for that specific case.
4. If you can't explain the activity and it recurs, run a reputable
   anti-malware scan (e.g. Malwarebytes for Mac) before deciding to remove
   anything.

## Step 5: Review unsigned apps in /Applications

An app without a readable `CFBundleIdentifier` (or one `defaults read`
can't parse) is often just an oddly-packaged legitimate app, an app the
system couldn't fully verify, or leftover cruft — not necessarily malware.
This is the lowest-confidence category here.

1. For each flagged app, check where it came from: the Mac App Store,
   Homebrew, a direct download from a vendor site, or something you don't
   recall installing.
2. Verify its publisher via Gatekeeper: right-click the app, choose Open,
   and check what macOS reports about its signature/notarization status —
   or run `spctl -a -vv /Applications/<App>.app`.
3. If you recognize and trust the app (common for some indie/open-source
   tools that aren't notarized), no action is needed.
4. If you don't recognize it or can't verify its publisher, drag it to
   Trash from Finder (standard app removal is sufficient here — these are
   typically not deeply persistent malware, just unverified apps) and empty
   the Trash once you're confident.
5. If, after removing, you notice other symptoms (browser hijacking,
   unexpected LaunchAgents, continued high CPU), escalate to the relevant
   step above or the `respond_to_malware_indicators.md` walkthrough for a
   fuller sweep.

## No issues found

If the scan reports only the `all_clean` INFO finding, process scanning
found no known malware names, no suspicious paths, no obfuscated names, no
sustained high-CPU outliers, and no unsigned apps in `/Applications` — no
action is needed.
