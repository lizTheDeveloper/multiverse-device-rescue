---
profile: infected_device
phase: 3
title: "Check It Offline with a Rescue Stick"
automatable_steps: []
human_only_steps: [1, 2, 3]
---

## Step 1: Install Reclaim City from a Rescue Stick

On a clean computer, a helper builds a USB Rescue Stick with the installers
on it. Plug it into the infected computer (still offline), open
**START-HERE**, and install the app. No internet is needed.

## Step 2: Run the checkup with the internet off

Open Reclaim City and choose **A computer I don't want to turn on or
connect**, then **Check this computer**. From the command line, the same
checks are `rescue scan --profile infected_device`. Every check in it works
offline. The AI tools check runs only if its helper was saved earlier;
otherwise it says it couldn't check, which is expected here.

## Step 3: Read the results honestly

Start with "Needs attention now". "Couldn't check" means that check didn't
run: it isn't a clean result. And on a computer that was clearly infected,
a clean result doesn't prove it's clean: malware can hide from programs
running on the same system. If the computer stays slow, keeps showing
pop-ups, or you found monitoring software, the honest answer is Phase 4.
If someone you know may have installed monitoring software, removing it can
alert them: talk to an advocate first.
