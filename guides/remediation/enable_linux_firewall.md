---
title: "Turn on your firewall"
estimated_time: "10 minutes"
platforms: [linux]
remediates:
  - security.linux_firewall_check.no_firewall
  - security.linux_firewall_check.firewall_inactive
  - security.linux_firewall_check.default_allow_inbound
automatable_steps: []
human_only_steps: [1, 2, 3]
---

A firewall decides which other computers on the network are allowed to connect
to yours. Without one, any program you start can be reached by anyone on the
same network: cafe wifi, a hotel, a shared office. Turning it on is a safe,
common change and will not break normal browsing, email or video calls.

## Step 1: Install a simple firewall if there isn't one

Open **Software** (or your package manager) and install **ufw**. Many
systems already include it. The graphical version is called **GUFW**; installing
it gives you a window instead of commands.

## Step 2: Turn it on and block incoming connections

- With **GUFW**: open it, switch **Status** to **On**, and set **Incoming** to
  **Deny**.
- Optional, from a terminal:
  `sudo ufw default deny incoming` then `sudo ufw enable`.

Leave **Outgoing** on **Allow**. If you use sharing, remote desktop or SSH to
reach this computer on purpose, add an allow rule for that one service.

## Step 3: Check it is running

In GUFW the status should say **On**. Optional, from a terminal:
`sudo ufw status verbose` should show **Status: active** and
**Default: deny (incoming)**.
