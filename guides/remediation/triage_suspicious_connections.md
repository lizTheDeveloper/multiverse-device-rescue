---
title: "Triage suspicious network connections"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.suspicious_connections.unusual_listening_port
  - security.suspicious_connections.unusual_outbound_connection
  - security.suspicious_connections.high_connection_count
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `suspicious_connections` module can
flag: processes listening on non-standard ports, established outbound
connections on non-standard ports from processes not on the known-safe
list, and processes with an unusually high number of simultaneous
connections. All three findings here are WARNING/INFO severity because
non-standard ports and multiple connections are common for entirely
legitimate software (dev servers, sync tools, game clients, VPNs) — this is
an investigate-and-confirm walkthrough, not an assume-malicious one.

## Step 1: Investigate unusual listening ports

A process listening on a port outside the standard service list (SSH, HTTP,
HTTPS, mail, common databases) could be a legitimate local service — or a
backdoor / remote-access tool.

1. Note the process, PID, and port from the finding.
2. Confirm what's actually listening: `lsof -i :<port>` and `ps -p <pid>
   -o pid,ppid,command`.
3. Check whether you intentionally run a local service on this port (a dev
   server, Docker container, database, sync tool, VPN client, media server).
   If so, this is expected — no action needed, though consider whether it
   should be bound to `127.0.0.1` instead of all interfaces if you don't
   need LAN/remote access to it.
4. If you don't recognize the process or the port, research the port number
   (many common backdoor/RAT tools use consistent, documented ports) and the
   binary's location and code signature (`codesign -dv <path>`).
5. If it can't be explained, don't just kill the process — first check for a
   persistence mechanism (`launchctl list | grep <name>`, and search
   `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
   `/Library/LaunchDaemons` for a matching plist) so you can remove that
   too, then stop the process and quarantine the binary (move to
   `~/Desktop/quarantine-YYYYMMDD/` rather than deleting) for further
   analysis.
6. If you confirm this is a remote-access backdoor (accepts inbound
   connections you didn't set up), treat the machine as compromised:
   disconnect from the network, and once clean, change passwords for
   accounts accessed from this machine from a separate known-clean device.

## Step 2: Investigate unusual outbound connections

An established outbound connection on a non-standard port from a process
that isn't in the module's known-safe list could be legitimate app traffic
(games, sync services, custom APIs) — or exfiltration/command-and-control
(C2) traffic.

1. Note the process, PID, and port from the finding.
2. Identify the remote endpoint: `lsof -i -n -P | grep <pid>` gives you the
   remote IP/host; a reverse lookup or WHOIS can tell you who owns it.
3. Check whether the process is software you recognize and whether its
   documented behavior explains the connection (many legitimate apps phone
   home to update servers, telemetry endpoints, or sync services on
   non-standard ports).
4. If the destination is unfamiliar and the process itself is also
   unfamiliar or unsigned, treat this as a higher-priority investigation:
   check for persistence (as in Step 1) before killing the process, then
   quarantine the binary rather than deleting it.
5. If the destination or process is unclear but the process itself is
   clearly legitimate (a signed, well-known app), this is more likely a
   false positive from a non-standard-but-legitimate port choice — no
   action needed, but note it for future reference.
6. If you confirm exfiltration or C2 activity, follow the "compromised
   machine" guidance in Step 1: disconnect from the network, remove the
   process and its persistence mechanism, and change credentials from a
   separate device afterward.

## Step 3: Review high connection counts

More than 10 simultaneous connections from a single process that isn't in
the known-safe list is informational — it can be entirely normal for
browsers with many tabs, sync clients, or download managers, but can also
indicate C2 beaconing (repeated check-ins to a control server) or the
machine being used to scan/attack other hosts.

1. Note the process and connection count from the finding.
2. Check what the connections are to: `lsof -i -n -P | grep <process>` —
   many connections to a small number of distinct hosts is more consistent
   with a sync/download client; many connections to many different hosts on
   the same port pattern is more consistent with scanning or C2 fan-out.
3. If the process is one you recognize and use for exactly this kind of
   activity (a download manager, a backup/sync tool, a browser), no action
   is needed.
4. If unexplained, treat it the same as an unusual outbound connection
   (Step 2): investigate the destinations, check for persistence, and only
   remove the process/binary once you've confirmed it isn't legitimate.
