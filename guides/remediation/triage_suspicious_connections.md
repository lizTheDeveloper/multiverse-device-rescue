---
title: "Triage suspicious network connections"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - security.suspicious_connections.unusual_listening_port
  - security.suspicious_connections.unusual_outbound_connection
  - security.suspicious_connections.high_connection_count
  - security.suspicious_connections.couldnt_check
steps_for:
  security.suspicious_connections.unusual_listening_port: [1]
  security.suspicious_connections.unusual_outbound_connection: [2]
  security.suspicious_connections.high_connection_count: [3]
  security.suspicious_connections.couldnt_check: [4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `suspicious_connections` module can
flag: processes listening on non-standard ports, established outbound
connections on non-standard ports from processes not on the known-safe
list, processes with an unusually high number of simultaneous connections,
and the case where the check couldn't read the list at all. The findings
here are WARNING/INFO severity because non-standard ports and multiple
connections are common for entirely legitimate software (dev servers, sync
tools, game clients, VPNs) — this is an investigate-and-confirm walkthrough,
not an assume-malicious one.

## Step 1: Check what is listening on the flagged port

A program listening on a port outside the standard service list (SSH, HTTP,
HTTPS, mail, common databases) could be a legitimate local service — or a
backdoor / remote-access tool. Ports that listen only on this computer
(localhost) are listed for information: nothing on your network or the
internet can reach them. A port whose program couldn't be confirmed is also
listed without a warning, with the reason (on Linux, other accounts'
programs are hidden without admin rights; on Windows, a service's name can
show while where it lives is hidden).

1. Note the program, PID, and port from the finding.
2. Confirm what's actually listening and where it lives:
   - **Mac:** `lsof -i :<port>` and `ps -p <pid> -o pid,ppid,command`.
   - **Linux:** `ss -tlnp` shows which program has the port open, for
     programs running as you; an administrator sees every owner with
     `sudo ss -tnap`. `ls -l /proc/<pid>/exe` shows where it lives (use
     `sudo ls -l /proc/<pid>/exe` for another account's program).
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu), go to the Network tab and look under Listening Ports to
     see where the program lives. In PowerShell,
     `Get-NetTCPConnection -State Listen -LocalPort <port>` shows the
     owner's PID.
3. Check whether you intentionally run a local service on this port (a dev
   server, Docker container, database, sync tool, VPN client, media server).
   If so, this is expected — no action needed, though consider whether it
   should be bound to `127.0.0.1` instead of all interfaces if you don't
   need LAN/remote access to it.
4. If you don't recognize the program or the port, look up the app name to
   see if it is a known remote access tool, research the port number (many
   common backdoor/RAT tools use consistent, documented ports), and check
   that your firewall doesn't let it in:
   - **Mac:** System Settings > Network > Firewall. Check the binary's code
     signature with `codesign -dv <path>`.
   - **Linux:** check that your firewall does not allow the port in.
   - **Windows:** Windows Security > Firewall & network protection > Allow
     an app through firewall.
5. If it can't be explained, look for what starts it again after a restart
   (on a Mac: `launchctl list | grep <name>`, and search
   `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
   `/Library/LaunchDaemons` for a matching plist). Write down the name and
   location and ask a trusted professional before removing anything.
6. If you confirm this is a remote-access backdoor (accepts inbound
   connections you didn't set up), treat the machine as compromised:
   disconnect from the network, and once clean, change passwords for
   accounts accessed from this machine from a separate known-clean device.

## Step 2: Check where the app is sending data

An established outbound connection on a non-standard port from a program
that isn't in the module's known-safe list could be legitimate app traffic
(games, sync services, custom APIs) — or exfiltration/command-and-control
(C2) traffic. Programs with a familiar name, or using a port for push
notifications (5223, 5228), are listed for information; a program can pick
any name, so the tool hasn't verified who made them. A connection whose
program couldn't be confirmed is listed without a warning, with the reason.

1. Note the program, PID, and port from the finding.
2. Identify the remote endpoint:
   - **Mac:** `lsof -i -n -P | grep <pid>`.
   - **Linux:** `ss -tnp` shows each connection with the program that
     opened it.
   - **Windows:** Resource Monitor's Network tab, under TCP Connections, or
     `Get-NetTCPConnection -OwningProcess <pid>` in PowerShell. To see where
     the program lives, open Task Manager, go to the Details tab,
     right-click it and choose Open file location.

   Looking up who owns the address (a reverse lookup or WHOIS) is itself a
   disclosure: whichever service you ask learns which address you're
   curious about. Only public addresses are worth looking up, never ones on
   your own network.
3. If you don't recognize the program, search for its name online to see if
   it is a known app, and whether its documented behavior explains the
   connection (many legitimate apps phone home to update servers, telemetry
   endpoints, or sync services on non-standard ports).
4. If the destination is unfamiliar and the program itself is also
   unfamiliar or unsigned, treat this as a higher-priority investigation:
   look for what starts it again after a restart (on a Mac, `launchctl list
   | grep <name>` and the LaunchAgents/LaunchDaemons folders), write down
   the name and location, and ask a trusted professional before removing
   anything.
5. If the destination or program is unclear but the program itself is
   clearly legitimate (a signed, well-known app), this is more likely a
   false positive from a non-standard-but-legitimate port choice — no
   action needed, but note it for future reference.
6. If you confirm exfiltration or C2 activity, treat the machine as
   compromised: disconnect from the network, and once clean, change
   credentials for accounts accessed from this machine from a separate
   known-clean device.

## Step 3: Check why the app has so many connections

More than 10 simultaneous connections from a single program that isn't in
the known-safe list is informational — it can be entirely normal for
browsers with many tabs, sync clients, or download managers, but can also
indicate C2 beaconing (repeated check-ins to a control server) or the
machine being used to scan/attack other hosts.

1. Note the program and connection count from the finding.
2. Check what the connections are to:
   - **Mac:** `lsof -i -n -P | grep <process>`.
   - **Linux:** `ss -tnp | grep <process>`.
   - **Windows:** Resource Monitor's Network tab, under TCP Connections, or
     `Get-NetTCPConnection -OwningProcess <pid>` in PowerShell.

   Many connections to a small number of distinct hosts is more consistent
   with a sync/download client; many connections to many different hosts on
   the same port pattern is more consistent with scanning or C2 fan-out.
3. If the program is one you recognize and use for exactly this kind of
   activity (a download manager, a backup/sync tool, a browser), no action
   is needed.
4. If unexplained, search for the program's name online to see if it is a
   known app, find out where it lives (Task Manager's Details tab, Open
   file location, on Windows; `ls -l /proc/<pid>/exe` on Linux;
   `ps -p <pid> -o pid,ppid,command` on a Mac), and ask a trusted
   professional before removing anything.

## Step 4: When the check couldn't read the connections

The check couldn't read the list of network connections, so it hasn't
checked anything. That is not the same as a clean result. The finding gives
the reason.

1. Run the scan again.
2. To look yourself:
   - **Mac:** `lsof -i -n -P` in Terminal.
   - **Linux:** `ss -tunap` in a terminal.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu) and go to the Network tab, or run `Get-NetTCPConnection`
     in PowerShell.
3. If it still can't run, say so when you describe the scan's result:
   suspicious connections are one of the things it couldn't check.
