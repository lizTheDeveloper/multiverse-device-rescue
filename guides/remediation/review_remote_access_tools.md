---
title: "Check a remote-access tool (TeamViewer, AnyDesk, ScreenConnect and others)"
estimated_time: "20 minutes"
platforms: [macos, windows]
remediates:
  - security.remote_access_tools.tool_found
  - security.remote_access_tools.several_tools
  - security.remote_access_tools.unattended_recent
  - security.remote_access_tools.running_now
steps_for:
  security.remote_access_tools.tool_found: [2, 3, 4, 5]
  security.remote_access_tools.running_now: [1, 2, 3, 4, 5]
  security.remote_access_tools.unattended_recent: [1, 2, 3, 4, 5, 6]
  security.remote_access_tools.several_tools: [1, 5, 6]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
monitoring_risk: true
---

A remote-access tool lets someone else see and control this computer. Every
tool this check looks for is ordinary software: IT departments, shops and
family helpers use them every day. They are also how most tech-support scams
get in. The finding tells you what the checkup could see: when the tool was
added, whether it can let someone in without you clicking yes, whether it's
running now, and when it last let someone in. Where it says "Couldn't tell",
the checkup couldn't read that part; it doesn't mean "no".

## Step 1: If it's running now, go offline first

If the finding says the tool is running now, someone may be able to see this
screen.

1. Turn off Wi-Fi (on a Mac: the Wi-Fi icon in the menu bar; on Windows: the
   network icon at the bottom right), or unplug the network cable.
2. If you're on a phone call with someone who asked you to install or open
   this tool, hang up. Your bank, Apple, Microsoft and your internet provider
   don't call and ask you to install remote-access software.
3. Carry on with the steps below while offline.

## Step 2: Decide whether it's yours

Think back to around the date the finding gives for when it was added.

1. Did you install it yourself, or did a shop or IT person you contacted
   install it for you? If you still use it, it's yours: you can mark it as
   yours, and the checkup will stop warning about it until something changes,
   such as a new connection.
2. Did someone who contacted you (a call, a pop-up, an email or a text that
   said something was wrong with your computer, an account, a refund or a
   payment) ask you to install it? Treat it as a scam and follow Step 6.
3. If you don't remember, look at when it last let someone in, if the finding
   says. A connection you don't remember is a reason to remove it.

## Step 3: Turn off unattended access

If the finding says it can let someone in without you clicking yes, it has a
part that starts by itself and waits for connections.

1. If you keep the tool, open its own settings and turn off unattended
   access (TeamViewer: "Grant easy access" and "Start TeamViewer with
   system"; AnyDesk: "Unattended access" under Security). Set a new
   password for it if it has one.
2. Check its list of trusted devices or contacts and remove any you don't
   recognise.

## Step 4: Remove it if you don't need it

1. On a Mac: quit the tool, then drag it from Applications to the Trash.
   Some tools (AnyDesk, TeamViewer) also have an uninstall option in their
   own menu, which removes the part that starts by itself.
2. On Windows: open Settings, then Apps, then Installed apps, find the tool,
   and choose Uninstall.
3. Restart the computer and run the checkup again to make sure it's gone.

## Step 5: Check for a second tool

Scammers often install a second remote-access tool, so that removing one
doesn't lock them out.

1. Run the checkup again after removing a tool.
2. If it finds another remote-access tool you didn't install, go back to
   Step 2 for that one too.

## Step 6: If it was a scam

Do these in order, from a different phone or computer if you can.

1. Call your bank, using the number on the back of your card, not one the
   caller gave you. Tell them someone may have had access to your computer.
2. Change your email password first, then the passwords for your other
   accounts. Turn on two-step sign-in where you can.
3. Remove the tool (Step 4), then run the checkup again: scammers often
   leave a second one.
4. Report it. In the US, report it to the FTC (reportfraud.ftc.gov). In the
   UK, report it to Action Fraud. In Canada, report it to the Canadian
   Anti-Fraud Centre.
