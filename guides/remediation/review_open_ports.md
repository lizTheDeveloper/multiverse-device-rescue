---
title: "Review open network ports"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - security.open_ports_scan.exposed_risky_ports
  - security.open_ports_scan.listening_ports
  - security.open_ports_scan.couldnt_check
steps_for:
  security.open_ports_scan.exposed_risky_ports: [1]
  security.open_ports_scan.listening_ports: [2]
  security.open_ports_scan.couldnt_check: [3]
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `open_ports_scan` module can flag:
database/service ports bound to all network interfaces (0.0.0.0), the
general inventory of listening ports on the machine, and the case where the
check couldn't read the list at all. Neither of the first two findings means
you've been compromised — plenty of legitimate local development setups
listen on 0.0.0.0 — but both are worth a deliberate look, since an
unnecessarily exposed database is a common way attackers on the same network
or a misconfigured cloud instance get in. This is an investigate-and-confirm
walkthrough: don't stop or reconfigure a service until you've confirmed you
don't need it exposed the way it currently is.

## Step 1: Check if risky apps are open to your network

A database or service port (MySQL, PostgreSQL, MongoDB, Elasticsearch,
Redis, CouchDB, InfluxDB) listening on `0.0.0.0` instead of `127.0.0.1`
accepts connections from anything that can reach the machine over the
network, not just programs on the same computer.

1. Note the port, program, and address from the finding.
2. Confirm what's listening and why:
   - **Mac:** `lsof -i :<port>` and `ps -p <pid> -o pid,ppid,command`.
   - **Linux:** `ss -tlnp` lists listening ports and their programs, and
     `ps -p <pid> -o args=` shows the full command. Programs that belong to
     other accounts show only when an administrator runs `ss`.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu), go to the Network tab and look under Listening Ports. In
     PowerShell, `Get-NetTCPConnection -LocalPort <port>` shows the
     connection and its `OwningProcess` (the PID); Task Manager's Details
     tab shows the program with that PID.
3. Ask whether you actually need this service reachable from other devices
   (a shared dev database for a team, a service accessed from your phone on
   the same LAN) or whether it only needs to be reachable from this machine
   (the common case for local development databases).
4. If you don't need remote/LAN access:
   - Back up the service's configuration file before editing it (e.g. `cp
     /etc/mysql/my.cnf /etc/mysql/my.cnf.bak-$(date +%Y%m%d)`).
   - Edit the config to bind to `127.0.0.1` instead of `0.0.0.0` (for
     MySQL: `bind-address = 127.0.0.1`; for PostgreSQL:
     `listen_addresses = 'localhost'` in `postgresql.conf`; for Redis:
     `bind 127.0.0.1` in `redis.conf`).
   - Restart the service and look again (the same command or Resource
     Monitor view as above) to confirm it now shows `127.0.0.1` instead of
     `*`/`0.0.0.0`.
5. If you do need remote access, prefer a narrower mechanism than leaving
   the port open to the world: an SSH tunnel, a VPN, or firewall rules
   (see the firewall walkthroughs) that restrict the source IP range,
   rather than binding to all interfaces with no other protection.
6. If the service also has application-level authentication (a database
   password, an API key), confirm it's actually enabled and not a
   default/blank credential — an exposed port with a default password is
   effectively an exposed port with no password.

## Step 2: Review all apps listening for connections

The module also reports every listening port it finds, regardless of risk
level, so you have a full picture of what's reachable.

1. Read through the listed `program on address:port` entries. An entry
   whose program couldn't be named (on Linux, a program that belongs to
   another account) says so instead of guessing.
2. For each one you don't immediately recognize, check what it is:
   - **Mac:** `lsof -i :<port>` and `ps -p <pid> -o pid,ppid,command`, or
     `lsof -iTCP -sTCP:LISTEN -nP` for every listening port at once.
   - **Linux:** `ss -tlnp` lists every listening port and its program.
     Programs that belong to other accounts show only when an administrator
     runs it.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu), go to the Network tab and look under Listening Ports. In
     PowerShell, `Get-NetTCPConnection -State Listen` lists the same ports
     with each owner's PID, which Task Manager's Details tab matches to a
     program.
3. Close or disable services you no longer use rather than leaving them
   running — fewer listening ports means a smaller attack surface. Stop the
   service through its normal mechanism: its own quit or stop command or
   setting, `launchctl unload` for a LaunchAgent/Daemon you control on a
   Mac, `systemctl disable --now <service>` on Linux, or `services.msc` on
   Windows. That way it doesn't just start again.
4. For services you do want, prefer binding to `127.0.0.1` unless you
   specifically need LAN or remote reachability (edit the service's own
   configuration file to bind to `127.0.0.1` instead of `0.0.0.0`).
5. Re-run the scan after making changes to confirm the port list reflects
   only what you intend to expose.

## Step 3: When the check couldn't read the list of ports

The check couldn't read the list of listening ports, so it hasn't checked
anything. That is not the same as a clean result. The finding gives the
reason.

1. Run the scan again.
2. To look yourself:
   - **Mac:** `lsof -iTCP -sTCP:LISTEN -nP` in Terminal.
   - **Linux:** `ss -tlnp` in a terminal.
   - **Windows:** open Resource Monitor (type "Resource Monitor" in the
     Start menu), go to the Network tab and look under Listening Ports.
3. If it still can't run, say so when you describe the scan's result:
   listening ports are one of the things it couldn't check.
