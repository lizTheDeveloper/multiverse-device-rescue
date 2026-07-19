---
title: "Review open network ports"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.open_ports_scan.exposed_risky_ports
  - security.open_ports_scan.listening_ports
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers everything the `open_ports_scan` module can flag:
database/service ports bound to all network interfaces (0.0.0.0), and the
general inventory of listening ports on the machine. Neither finding means
you've been compromised — plenty of legitimate local development setups
listen on 0.0.0.0 — but both are worth a deliberate look, since an
unnecessarily exposed database is a common way attackers on the same network
or a misconfigured cloud instance get in. This is an investigate-and-confirm
walkthrough: don't stop or reconfigure a service until you've confirmed you
don't need it exposed the way it currently is.

## Step 1: Investigate exposed risky ports (WARNING)

A database or service port (MySQL, PostgreSQL, MongoDB, Elasticsearch,
Redis, CouchDB, InfluxDB) listening on `0.0.0.0` instead of `127.0.0.1`
accepts connections from anything that can reach the machine over the
network, not just processes on the same Mac.

1. Note the port, process, and address from the finding.
2. Confirm what's listening and why: `lsof -i :<port>` and `ps -p <pid> -o
   pid,ppid,command`.
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
   - Restart the service and re-run `lsof -i :<port>` to confirm it now
     shows `127.0.0.1` instead of `*`/`0.0.0.0`.
5. If you do need remote access, prefer a narrower mechanism than leaving
   the port open to the world: an SSH tunnel, a VPN, or firewall rules
   (see the firewall walkthroughs) that restrict the source IP range,
   rather than binding to all interfaces with no other protection.
6. If the service also has application-level authentication (a database
   password, an API key), confirm it's actually enabled and not a
   default/blank credential — an exposed port with a default password is
   effectively an exposed port with no password.

## Step 2: Review the full listening-port inventory (INFO)

The module also reports every listening port it finds, regardless of risk
level, so you have a full picture of what's reachable.

1. Read through the listed `process on address:port` entries.
2. For each one you don't immediately recognize, check what it is:
   `lsof -i :<port>` and `ps -p <pid> -o pid,ppid,command`.
3. Close or disable services you no longer use rather than leaving them
   running — fewer listening ports means a smaller attack surface. Stop the
   service through its normal mechanism (its own quit/stop command, or
   `launchctl unload` for a LaunchAgent/Daemon you control) rather than
   killing the process directly, so it doesn't just restart.
4. For services you do want, prefer binding to `127.0.0.1` unless you
   specifically need LAN or remote reachability (see Step 1 for how).
5. Re-run the scan after making changes to confirm the port list reflects
   only what you intend to expose.
