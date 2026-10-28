---
title: "Review active network connections"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - security.network_connections_monitor.backdoor_ports
  - security.network_connections_monitor.high_connection_count
  - security.network_connections_monitor.unusual_ports
  - security.network_connections_monitor.private_ip_connections
  - security.network_connections_monitor.connection_summary
  - security.network_connections_monitor.unnamed_connections
  - security.network_connections_monitor.couldnt_check
steps_for:
  security.network_connections_monitor.backdoor_ports: [1]
  security.network_connections_monitor.high_connection_count: [2]
  security.network_connections_monitor.unusual_ports: [3]
  security.network_connections_monitor.private_ip_connections: [4]
  security.network_connections_monitor.connection_summary: [4]
  security.network_connections_monitor.unnamed_connections: [5]
  security.network_connections_monitor.couldnt_check: [6]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
monitoring_risk: true
---

This walkthrough covers everything the `network_connections_monitor`
module can flag: connections on ports commonly used by known
backdoor/C2 tools, processes with an unusually high number of established
connections, connections on non-standard ports, connections to private-IP
ranges, the general connection-count summary, connections whose program
couldn't be seen, and the case where the check couldn't read the list at
all. Most legitimate software (dev tools, sync clients, games, VPNs) can trip
the lower-severity checks here, so this is an investigate-and-confirm
walkthrough: confirm what a program is before doing anything about it.

## Step 1: Check for dangerous remote access connections

A connection on a port commonly associated with backdoor/remote-access
tools (4444, 5555, 8080, 8888, 1337, 31337) is the highest-priority finding
here, though note some of these (notably 8080) are also common legitimate
HTTP-alternate ports, so confirm before assuming compromise.

1. Note the program, PID, and remote address:port from the finding.
2. Confirm what's actually connected and where the program lives:
   - **Mac:** `lsof -p <PID>` and `ps -p <PID> -o pid,ppid,command`.
   - **Linux:** `ss -tnap` shows each connection with the program that
     opened it; `ls -l /proc/<PID>/exe` shows where that program lives.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu) and look on the Network tab for the program. In
     PowerShell, `Get-NetTCPConnection -OwningProcess <PID>` lists its
     connections. In Task Manager's Details tab, right-click the program
     and choose Open file location to see where it lives.
3. Check whether the program is a proxy, dev server, or other tool you
   intentionally run on that port — if so, no action is needed.
4. Check who made it:
   - **Mac:** `codesign -dv <path-to-binary>`. An unsigned or
     ad-hoc-signed binary in an unusual location is a stronger signal.
   - **Linux:** `dpkg -S <path>` or `rpm -qf <path>` shows whether a
     package installed it.
   - **Windows:** right-click the file, choose Properties, and look at the
     Digital Signatures tab.
5. If you can't explain it, look for what starts it again after a restart
   before touching anything. On a Mac: `launchctl list | grep <name>`, and
   search `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
   `/Library/LaunchDaemons` for a matching plist. Run a full malware scan
   (Windows Security on Windows; ClamAV, for example, on Linux).
6. If it still looks suspicious, write down the name and location and ask a
   trusted professional before removing anything.
7. If this looks like an active backdoor/C2 channel, treat the machine as
   compromised: disconnect from the network, and once clean, change
   passwords for accounts accessed from this machine from a separate,
   known-clean device.

## Step 2: Check if an app is connecting to too many places

More than 20 simultaneous established connections from a single program (the
limit is higher for browsers and developer tools) can be entirely normal for
a browser, sync client, or download manager — but can also indicate botnet
activity or the machine being used to scan or attack other hosts.

1. Note the program and connection count from the finding.
2. Check the destinations:
   - **Mac:** `lsof -i -nP | grep <PID>`.
   - **Linux:** `ss -tnap | grep pid=<PID>`.
   - **Windows:** look at the remote addresses it talks to in Resource
     Monitor's Network tab, or run `Get-NetTCPConnection -OwningProcess
     <PID>` in PowerShell.

   Many connections to a small number of distinct hosts is more consistent
   with legitimate sync/streaming behavior; many connections to many
   different, unrelated hosts is more consistent with scanning or botnet
   fan-out.
3. If it's a browser, sync tool, or download manager you recognize and are
   actively using, no action needed.
4. If unexplained, find out where the program lives and who made it (on a
   Mac, `ps -p <PID> -o pid,ppid,command` and `codesign -dv <path>`; on
   Linux, `ls -l /proc/<PID>/exe`; on Windows, Task Manager's Details tab,
   Open file location, then the file's Properties > Digital Signatures).
   Research the program name and file online. If it still looks suspicious,
   write down the name and location and ask a trusted professional before
   removing anything.

## Step 3: Check connections on unusual ports

A connection on a port outside the small "well-known" list (80, 443, 53,
22, 993, 587) is common for legitimate apps (games, custom APIs, media
servers) and is not inherently suspicious. Ports 5223 and 5228 are listed
separately: Apple and Google use them for push notifications, so they're
normal for chat and mail apps. A port number does not prove who is using
it, so check that you recognize the programs listed.

1. Note the program, the remote address:port, and which way the connection
   goes: out from your computer to another one, or in from another computer
   to a port your computer listens on. A connection that came in deserves
   more care than one your own program started.
2. Check whether the program and its documented behavior explain the
   port choice (many apps use custom high ports for their own protocols).
   Research the port number online. If the program is `ssh` and the
   address and port match a `Host` entry in your `~/.ssh/config`, this is
   an SSH session to a server set up in your SSH settings. If you started
   it, it's yours; to end it, type `exit` in the Terminal window running
   it, or close that window.
3. To see what's using the port, and which program started it:
   - **Mac:** `lsof -i :<port>`, and `ps -p <PID> -o pid,ppid,command`
     for its full command and its parent (the program that started it).
   - **Linux:** `ss -tnap`, and `ps -p <PID> -o args=` for its full command.
   - **Windows:** in Resource Monitor's Network tab, look under TCP
     Connections for the program using the port.
4. If the program itself is unfamiliar, find out where it lives and who
   made it (on a Mac, `codesign -dv <path>`; on Windows, the file's
   Properties > Digital Signatures; on Linux, `dpkg -S <path>` or
   `rpm -qf <path>`), and research its name online.
5. If the program is clearly legitimate and well-known, no action needed —
   this is usually a false positive from the finite well-known-port list.

## Step 4: Check connections to devices on your local network

Connections to private IP ranges (your LAN) and the overall connection
count are informational — most home/office networks have plenty of
legitimate LAN traffic (printers, smart-home devices, file sharing,
other computers).

1. Look at the connections to addresses starting 10., 172.16 to 172.31,
   or 192.168.:
   - **Mac:** `lsof -i -nP | grep -E '(10\.|172\.|192\.168)'`.
   - **Linux:** `ss -tnp | grep -E '(10\.|172\.|192\.168)'`.
   - **Windows:** open Resource Monitor, go to the Network tab and look
     under TCP Connections for those remote addresses.
2. If they match devices you recognize on your network, no action needed.
3. If you see connections to private IPs you don't recognize as belonging
   to your network, or from a program you don't expect to be doing LAN
   discovery/communication, find out what the program is and where it
   lives before doing anything else.
4. The connection-count summary is purely informational; re-run the scan
   periodically to build a baseline of what's normal for this machine so
   future spikes are easier to spot.

## Step 5: Find out which program owns a connection the check couldn't see

Some connections came without a program name. On Linux (and for other
accounts' programs on a Mac), the computer shows which program owns a
connection only for your own programs unless the check runs as admin. On
Windows, a connection can carry the name of a Windows service while Windows
hides where the program lives unless the check runs as admin; that is
normal for Windows' own services on your local network, but a name alone
doesn't prove it. The check couldn't say whether these connections are
expected, so it lists them without a warning.

1. Look at them with admin rights:
   - **Mac:** `sudo lsof -i -nP` shows every program's connections.
   - **Linux:** `sudo ss -tnap` shows each connection with the program
     that opened it.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu), go to the Network tab and look under TCP Connections.
2. Or run this check again as an administrator.
3. If a program there is unfamiliar, search for its name online.

## Step 6: When the check couldn't read the connections

The check couldn't read the list of network connections, so it hasn't
checked anything. That is not the same as a clean result. The finding gives
the reason.

1. Run the scan again.
2. To look yourself:
   - **Mac:** `lsof -i -nP` in Terminal.
   - **Linux:** `ss -tunap` in a terminal.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu) and go to the Network tab, or run `Get-NetTCPConnection`
     in PowerShell.
3. If it still can't run, say so when you describe the scan's result:
   open connections are one of the things it couldn't check.
