---
profile: infected_device
phase: 1
title: "How Is It Doing?"
automatable_steps: []
human_only_steps: [1, 2, 3]
---

## Step 1: If it starts but acts infected

Pop-ups, a changed home page, programs you didn't install, a fan running
hard while you do nothing. Keep it offline and go to Phase 2 to copy off
your files, then Phase 3 to check it with Reclaim City from a Rescue Stick.

## Step 2: If it barely starts

Very slow, crashes, or so many pop-ups you can't work. Start it in safe
mode: the computer starts with only what it needs, so most malware doesn't
load.

On a Mac with Apple silicon (Apple menu > About This Mac says "Chip: Apple
M…"): shut it down, then press and hold the power button until you see
"Loading startup options". Select the startup disk, then press and hold
**Shift** and click **Continue in Safe Mode**.

On an Intel Mac: turn it on and immediately press and hold **Shift** until
the login window appears.

When it worked, the login window says **Safe Boot** in the top-right corner.

On Windows: open Windows Recovery. From Windows, go to **Settings** >
**System** > **Recovery** and click **Restart now** next to **Advanced
startup** (Windows 10: **Update & Security** > **Recovery**), or hold
**Shift** while you click **Power** > **Restart**. Then choose
**Troubleshoot** > **Advanced options** > **Startup Settings** > **Restart**,
and press **4** for safe mode. Don't press 5: that one turns the network on.

Then go to Phase 2.

## Step 3: If it won't start

Reclaim City can't help directly here. It runs inside the computer's own
system, so it can't check a computer that won't start, and it can't check
one computer from another.

On a Mac, try macOS Recovery. Apple silicon: shut down, press and hold the
power button until "Loading startup options" appears, click **Options**,
then **Continue**. Intel: press the power button, then immediately press
and hold **Command (⌘)-R** until you see an Apple logo or a spinning globe.
If it asks you to choose a Wi-Fi network, don't: you can copy files and
erase without one.

On Windows, Windows Recovery opens by itself after Windows fails to start a
few times. To force it, hold the power button to turn it off while Windows
is starting, twice; on the third start you see **Automatic Repair**. If the
disk is encrypted with BitLocker, you'll need its recovery key. It's often
saved in the owner's Microsoft account: look it up from a different device.

From there you can usually copy files off (Phase 2) and then erase and
reinstall (Phase 4). If none of this works, take it to a repair shop or the
maker's support, and tell them it's infected and must stay offline.
