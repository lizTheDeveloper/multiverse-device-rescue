---
title: "Remove cryptocurrency miner"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.crypto_miner_detect.known_miner
  - security.crypto_miner_detect.high_cpu_process
  - security.crypto_miner_detect.mining_pool_connection
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `crypto_miner_detect` module can
flag: processes matching known cryptocurrency-miner binary names,
unexplained sustained high-CPU processes that could be a miner, and network
connections on ports or to domains commonly used by mining pools. Crypto
miners are typically installed as a payload of some other compromise (a
malicious app, a compromised installer, or a browser exploit), so removing
the miner process alone is not enough — you also need to find how it got in.

## Step 1: Remove a known cryptocurrency miner (critical)

The scan matched a running process against a list of known miner binaries
(e.g. XMRig, minerd, T-Rex, NBMiner).

1. **Disconnect from the network** (Wi-Fi off / Ethernet unplugged) before
   doing anything else — this stops the miner from communicating with its
   pool and can reduce its incentive to persist/reinstall itself, and
   prevents any companion malware from exfiltrating data while you work.
2. Note the PID and command line from the finding (`command` field), and
   confirm it yourself: `ps -p <pid> -o pid,ppid,%cpu,command`.
3. Identify the parent process too (`ppid` above) — miners are frequently
   launched by a dropper or a LaunchAgent, and killing only the child lets
   the parent relaunch it.
4. Check for a persistence mechanism before killing anything:
   `launchctl list | grep -i <process-name>` and search
   `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and
   `/Library/LaunchDaemons` for a matching plist. If found, `launchctl
   unload <path>` first so it doesn't respawn.
5. Kill the process: `kill -9 <pid>` (or the parent if that's where it was
   launched from).
6. Locate the binary on disk from the `command` path in the finding and
   quarantine it — move it to a dated folder
   (`~/Desktop/quarantine-YYYYMMDD/`) rather than deleting immediately, so
   you retain a sample if you want to submit it to a scanner (e.g.
   VirusTotal) or need it for later reference.
7. Remove any persistence plist you found in step 4 the same way (move, don't
   delete outright, until you've confirmed the process doesn't come back).
8. Reboot and re-run this scan to confirm the process and connection no
   longer appear.
9. Investigate how it arrived: check recently installed apps (`system_profiler
   SPApplicationsType` sorted by install date), recent Downloads, and any
   pirated/cracked software or "free" utility you installed around when you
   first noticed slowdowns — that's the most common vector for miners.
   Remove that source too, not just the miner binary.
10. Only permanently delete the quarantined items once you're confident
    the machine is clean and you no longer need them.

## Step 2: Investigate high-CPU processes

A process pinned above 80% CPU that isn't a recognized system/app process
could be a miner using an unfamiliar binary name, or could be entirely
legitimate (a video export, a compile job, a Spotlight re-index).

1. Open Activity Monitor and sort by CPU to confirm the process and
   percentage match the finding.
2. Check whether the CPU usage correlates with something you're doing
   (compiling code, running a data job, exporting video) — if so, this is
   likely a false positive and no action is needed.
3. If unexplained, check the process's binary path (`ps -p <pid> -o
   comm=` or Activity Monitor's "Open Files and Ports" / "Sample Process")
   and look for signs it's not a normal application (running from `/tmp`,
   `/var/tmp`, `~/Library/Application Support` under an unfamiliar name, or
   with no visible Dock icon/menu bar presence).
4. If suspicious, follow Step 1's quarantine procedure rather than deleting
   immediately, and check for an associated network connection using
   `lsof -p <pid>` — sustained outbound traffic to an unfamiliar host
   alongside high CPU is a strong miner signal.
5. If you can't explain the CPU usage and can't rule out malware, run a
   reputable anti-malware scan (e.g. Malwarebytes for Mac) before deciding
   whether to remove the process.

## Step 3: Investigate mining pool connections

A connection on a known mining-pool port (3333, 4444, 5555, etc.) or to a
domain matching mining-pool naming patterns (`*.pool.*`, `*mining*`,
`stratum+tcp://...`) is a strong signal of active mining activity, even if
the process name itself doesn't match a known miner binary — miners are
often renamed to evade simple name-based detection.

1. Note the process, PID, and port/address from the finding.
2. Confirm the connection is still active: `lsof -i -n -P | grep <pid>`.
3. Research the destination address/domain if it's not obviously a known
   pool — a WHOIS lookup or a search for the domain plus "mining pool" will
   usually confirm it quickly.
4. If confirmed, follow the kill-and-quarantine procedure from Step 1
   (check for persistence first, then kill, then quarantine the binary,
   then investigate how it arrived on the system).
5. If the port/domain match turns out to be a false positive (some
   legitimate services reuse these ports, e.g. some game servers or
   internal tooling), no action is needed — but double check the process
   really is what it claims to be before dismissing it.
