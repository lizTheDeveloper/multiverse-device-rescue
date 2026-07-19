---
title: "Review active network connections"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.network_connections_monitor.backdoor_ports
  - security.network_connections_monitor.high_connection_count
  - security.network_connections_monitor.unusual_ports
  - security.network_connections_monitor.private_ip_connections
  - security.network_connections_monitor.connection_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `network_connections_monitor`
module can flag: connections on ports commonly used by known
backdoor/C2 tools, processes with an unusually high number of established
connections, connections on non-standard ports, connections to private-IP
ranges, and the general connection-count summary. Most legitimate software
(dev tools, sync clients, games, VPNs) can trip the lower-severity checks
here, so this is an investigate-and-confirm walkthrough — don't kill
processes on sight, confirm first.

## Step 1: Investigate backdoor-port connections (CRITICAL)

A connection on a port commonly associated with backdoor/remote-access
tools (4444, 5555, 8080, 8888, 1337, 31337) is the highest-priority finding
here, though note some of these (notably 8080) are also common legitimate
HTTP-alternate ports, so confirm before assuming compromise.

1. Note the process, PID, and remote address:port from the finding.
2. Confirm what's actually connected: `lsof -p <PID>` and `ps -p <PID> -o
   pid,ppid,command`.
3. Check whether the process is a proxy, dev server, or other tool you
   intentionally run on that port — if so, no action is needed.
4. Verify the binary's code signature: `codesign -dv <path-to-binary>`. An
   unsigned or ad-hoc-signed binary in an unusual location is a stronger
   signal.
5. If you can't explain it, check for a persistence mechanism before
   touching the process: `launchctl list | grep <name>`, and search
   `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
   `/Library/LaunchDaemons` for a matching plist.
6. If confirmed suspicious, stop the process and quarantine the binary
   (move it to `~/Desktop/quarantine-YYYYMMDD/` rather than deleting it) so
   it can't relaunch, then remove any persistence entry found in step 5.
7. If this looks like an active backdoor/C2 channel, treat the machine as
   compromised: disconnect from the network, and once clean, change
   passwords for accounts accessed from this machine from a separate,
   known-clean device.

## Step 2: Investigate high connection counts (WARNING)

More than 20 simultaneous established connections from a single process
can be entirely normal for a browser, sync client, or download manager —
but can also indicate botnet activity or the machine being used to scan or
attack other hosts.

1. Note the process and connection count from the finding.
2. Check the destinations: `lsof -i -nP | grep <pid>`. Many connections to
   a small number of distinct hosts is more consistent with legitimate
   sync/streaming behavior; many connections to many different, unrelated
   hosts is more consistent with scanning or botnet fan-out.
3. If it's a browser, sync tool, or download manager you recognize and are
   actively using, no action needed.
4. If unexplained, follow Step 1's investigation-then-quarantine approach
   before terminating anything.

## Step 3: Review unusual-port connections (WARNING)

A connection on a port outside the small "well-known" list (80, 443, 53,
22, 993, 587) is common for legitimate apps (games, custom APIs, media
servers) and is not inherently suspicious.

1. Note the process and remote address:port.
2. Check whether the process and its documented behavior explain the
   port choice (many apps use custom high ports for their own protocols).
3. If the process itself is unfamiliar or unsigned, treat it with the same
   scrutiny as Step 1.
4. If the process is clearly legitimate and well-known, no action needed —
   this is usually a false positive from the finite well-known-port list.

## Step 4: Review private-IP connections and the connection summary (INFO)

Connections to private IP ranges (your LAN) and the overall connection
count are informational — most home/office networks have plenty of
legitimate LAN traffic (printers, smart-home devices, file sharing,
other computers).

1. Skim the listed private-IP connections; if they match devices you
   recognize on your network, no action needed.
2. If you see connections to private IPs you don't recognize as belonging
   to your network, or from a process you don't expect to be doing LAN
   discovery/communication, investigate as in Step 2.
3. The connection-count summary is purely informational; re-run the scan
   periodically to build a baseline of what's normal for this machine so
   future spikes are easier to spot.
