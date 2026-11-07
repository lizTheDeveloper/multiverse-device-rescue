# An infected computer you don't want on your network

**`infected_device`**: a scan that works with no network, and a 6-phase guide.

## Who this is for

You have a computer that's clearly infected. It may barely start, or not start
at all, and you don't want it anywhere near your Wi-Fi or your other devices.
That instinct is right. This page walks you through it in order:

1. [Keep it off the network](#1-keep-it-off-the-network)
2. [Work out how it's doing](#2-work-out-how-its-doing): it starts, it barely starts, or it won't start
3. [Save your files, carefully](#3-save-your-files-carefully)
4. [Check it offline with a Rescue Stick](#4-check-it-offline-with-a-rescue-stick)
5. [Erase and reinstall, when that's the honest answer](#5-erase-and-reinstall-when-thats-the-honest-answer)
6. [Fix your accounts from a different, clean device](#6-your-accounts-from-a-different-clean-device)

You can do all of this one step at a time. Nothing here is a race.

!!! warning "What Reclaim City can and can't do here"
    Reclaim City runs **inside** a computer's own system. That means:

    - It **can't check a computer that won't start.** For that one, this page
      is the help: recovery, copying files off, and reinstalling.
    - It **can't check one computer from another.** Running it on your laptop
      tells you about your laptop, not the infected one.
    - It **can** check the infected computer itself, offline, if that computer
      starts. You install it from a [USB Rescue Stick](../usb-rescue-stick.md),
      with no internet.
    - On a computer that's clearly infected, a clean result **lowers the odds**
      of a problem; it can't prove there's none. Malware can hide from programs
      running on the same system.

!!! danger "If someone you know may have done this"
    If a partner, ex, family member or housemate may have put monitoring
    software on this computer, removing it, or erasing the computer, can alert
    them. Talk to an advocate before you remove anything. In the US: National
    Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.
    Internationally: <https://stopstalkerware.org>.

## In the app

On the "What's worrying you?" screen, choose **A computer I don't want to turn
on or connect**. It doesn't start a scan, because the computer you're using
may be the clean one. It shows the short version of this page as a checklist,
one step at a time, with a link back here. At the end, **Check this computer**
runs the offline checkup, for when the app is on the infected computer itself.

From the command line:

```console
$ rescue guide infected_device                 # the walkthrough, with saved progress
$ rescue scan --profile infected_device        # the offline checkup (read-only)
```

---

## 1. Keep it off the network

Do this first, and do it **before** you turn the computer on if you can.
Malware that can't reach the internet can't send your files out, take orders
from whoever runs it, or spread to your other devices.

- **Unplug its network cable** (if it has one) before you turn it on, or right
  now if it's on.
- **Turn off its Wi-Fi** as soon as it starts, before it has time to join a
  network:

=== "macOS"

    Apple menu > **System Settings** > **Wi-Fi**, and turn Wi-Fi off.
    ([Apple: Wi-Fi settings on Mac](https://support.apple.com/guide/mac-help/wi-fi-settings-on-mac-mh11935/mac))

    Then forget saved networks so it can't rejoin on its own: in the same
    Wi-Fi settings, click **Advanced** to see the networks your Mac knows,
    and remove each one.
    ([Apple: forget a Wi-Fi network](https://support.apple.com/en-us/102480))

=== "Windows"

    **Settings** > **Network & internet** > **Airplane mode**, and turn it on.
    The network icon on the taskbar opens a quick panel with the same
    **Airplane mode** button.

    Then forget saved networks so it can't rejoin on its own: **Settings** >
    **Network & internet** > **Wi-Fi** > **Manage known networks**, select
    each network, and click **Forget**.
    ([Microsoft: fix Wi-Fi connection issues](https://support.microsoft.com/en-us/windows/fix-wi-fi-connection-issues-in-windows-9424a1f7-6a3b-65a6-4d78-7f07eee84d2c),
    which shows both settings)

If you can't get as far as forgetting networks, Wi-Fi off and the cable out is
enough for now.

**While you work on it:**

- **Don't plug in USB drives you care about.** Malware can copy itself onto
  them. Use a Rescue Stick, or a spare drive you're willing to erase afterwards.
- **Don't sign in to anything on it.** No email, no bank, no passwords typed on
  this computer. A keylogger records what you type. Your accounts get fixed
  later, from a different device (step 6).

## 2. Work out how it's doing

### It starts, but acts infected

Pop-ups, a home page you didn't choose, programs you didn't install, a fan
running hard while you do nothing. Keep it offline, [save your
files](#3-save-your-files-carefully), then [check it with a Rescue
Stick](#4-check-it-offline-with-a-rescue-stick).

### It barely starts

Very slow, crashing, or so many pop-ups you can't work. Start it in **safe
mode**: the computer starts with only what it needs, so most malware doesn't
load, and you get a calmer place to copy files from.

=== "Mac with Apple silicon"

    (Apple menu > **About This Mac** says "Chip: Apple M…".)

    1. Shut down the Mac. If it won't shut down, press and hold the power button
       for up to 10 seconds.
    2. Press and hold the power button until you see **Loading startup options**.
    3. Select your startup disk (usually **Macintosh HD**).
    4. Press and hold **Shift**, then click **Continue in Safe Mode**.

    The login window shows **Safe Boot** in red in the top-right corner when it
    worked. ([Apple: start up your Mac in safe mode](https://support.apple.com/en-us/116946))

=== "Intel Mac"

    (Apple menu > **About This Mac** says "Processor: … Intel".)

    Turn on or restart the Mac, then immediately press and hold **Shift**.
    Release it when the login window appears.

    The login window shows **Safe Boot** in red in the top-right corner when it
    worked. ([Apple: start up your Mac in safe mode](https://support.apple.com/en-us/116946))

=== "Windows"

    1. Open the **Windows Recovery Environment**. From Windows: **Settings** >
       **System** > **Recovery**, then **Restart now** next to **Advanced
       startup** (Windows 10: **Update & Security** > **Recovery**). Or hold
       **Shift** while you click **Power** > **Restart**.
    2. Choose **Troubleshoot** > **Advanced options** > **Startup Settings** >
       **Restart**.
    3. Press **4** for **Enable Safe Mode**. Don't press 5: "Safe Mode with
       Networking" turns the network back on.

    ([Microsoft: Windows startup settings](https://support.microsoft.com/en-us/windows/start-your-pc-in-safe-mode-in-windows-92c27cff-db89-8644-1ce4-b3e5e56fe234),
    [Windows Recovery Environment](https://support.microsoft.com/en-us/windows/windows-recovery-environment-0eb14733-6301-41cb-8d26-06a12b42770b))

    If the disk is encrypted with BitLocker, Windows may ask for its recovery
    key. It's often saved in the owner's Microsoft account: look it up from a
    different device.

### It won't start

Reclaim City can't check it in this state. Your options are the computer's own
recovery tools:

=== "Mac with Apple silicon"

    **macOS Recovery:** shut down, press and hold the power button until
    **Loading startup options** appears, click **Options**, then **Continue**.
    If asked, choose a user you know the password for.
    ([Apple: start up from macOS Recovery](https://support.apple.com/en-us/102518))

=== "Intel Mac"

    **macOS Recovery:** press and release the power button, then immediately
    press and hold **Command (⌘)-R** until you see an Apple logo or a spinning
    globe. If it asks you to choose a Wi-Fi network, skip that for now: you can
    copy files and erase the disk without one.
    ([Apple: start up from macOS Recovery](https://support.apple.com/en-us/102518))

=== "Windows"

    **Windows Recovery Environment** starts by itself after Windows fails to
    start correctly a few times. To force it: while Windows is starting, hold
    the power button to turn it off; do that twice, and on the third start you
    see **Automatic Repair**. From there, **Advanced options** leads to
    **Startup Repair**, **System Restore**, **Startup Settings** (safe mode) and
    **Reset this PC**.
    ([Microsoft: Windows Recovery Environment](https://support.microsoft.com/en-us/windows/windows-recovery-environment-0eb14733-6301-41cb-8d26-06a12b42770b))

From recovery you can usually [copy files off](#3-save-your-files-carefully)
and then [erase and reinstall](#5-erase-and-reinstall-when-thats-the-honest-answer).
If none of this works, take it to a repair shop or the maker's support, and
tell them it's infected and must stay offline.

## 3. Save your files, carefully

Use a **spare USB drive** you're willing to erase later, not a backup drive you
rely on. If there's a backup from before the trouble started, leave it
unplugged: it may be the cleanest copy you have.

| Safer to copy | Leave behind |
| --- | --- |
| Photos, videos, music | Programs and installers: `.app`, `.dmg`, `.pkg`, `.exe`, `.msi` |
| PDFs and plain text | Scripts: `.sh`, `.command`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js` |
| Your own documents and spreadsheets | Shortcuts (`.lnk`) and anything you don't recognize |

Office files with macros (`.docm`, `.xlsm`) can carry malware. Copy them only
if you need them, and don't turn on macros when you open them. Programs you
can download again later, from their real websites.

Before you open the copies on another computer, make sure that computer's own
protection is on and up to date, and don't open anything from the copy that you
didn't put there yourself.

## 4. Check it offline with a Rescue Stick

If the computer starts:

1. On a **clean** computer, build a [USB Rescue Stick](../usb-rescue-stick.md).
   It holds the released installers, checked against the release's checksums.
2. Plug it into the infected computer (still offline), open **START-HERE**, and
   install Reclaim City. No internet is needed.
3. Open Reclaim City, choose **A computer I don't want to turn on or connect**,
   go through the checklist, and choose **Check this computer**. (Command line:
   `rescue scan --profile infected_device`.)

**What runs.** The `infected_device` profile picks the checks that work with no
network: what starts on its own, what's running, known malware signs,
monitoring and remote-access software, browser add-ons and hijacked settings,
miners, whether the built-in protection is on, whether this start is safe mode,
and whether a backup exists. Network checks (your router, Wi-Fi neighbours,
speed, updates) are left out: they'd only report that there's no network.

**What doesn't.** The AI tools check needs a free helper, HackMyAgent, that's
downloaded the first time. This profile never downloads it. If a copy was saved
earlier, it runs; if not, the result says "couldn't check", and that's
expected. (If you run the full checkup on a computer with no internet, the same
check sees there's no connection and says so straight away.)

**Reading the result honestly.** "Couldn't check" means that check didn't run:
it isn't a clean result. A clean result lowers the odds of a problem, but on a
computer that was clearly infected it doesn't prove there's none. If the
computer stays slow, keeps showing pop-ups, or you found monitoring software,
go to step 5.

## 5. Erase and reinstall, when that's the honest answer

Erasing and reinstalling is the only fix that doesn't depend on finding every
piece of the infection. It's the honest answer when:

- the computer won't start normally, or barely does;
- the infection keeps coming back after you remove it;
- you found ransomware, or remote-access or monitoring software someone else
  controls (talk to an advocate first if that someone may be a person you know);
- you simply can't trust it any more.

[Copy your files off](#3-save-your-files-carefully) first: erasing deletes
everything.

=== "macOS"

    **Erase first, then reinstall.**

    - On macOS Monterey or later, on a Mac with Apple silicon or the Apple T2
      chip: Apple menu > **System Settings** > **General** > **Transfer or
      Reset** > **Erase All Content and Settings**.
      ([Apple: erase your Mac](https://support.apple.com/en-us/102664))
    - Otherwise, or if the Mac won't start: start
      [macOS Recovery](https://support.apple.com/en-us/102518), open **Disk
      Utility**, erase the startup disk, then choose **Reinstall macOS**.
      ([Apple: reinstall macOS](https://support.apple.com/en-us/102655))

    Reinstalling macOS downloads it, so the Mac needs the internet for this
    step. That's fine once the disk is erased: the infection was on the disk.
    Reinstalling **without** erasing keeps your apps and data, and so it can
    keep the infection too.

=== "Windows"

    - From Windows: **Settings** > **System** > **Recovery** > **Reset PC**
      (Windows 10: **Update & Security** > **Recovery** > **Get started**).
      From the Windows Recovery Environment: **Troubleshoot** > **Reset this PC**.
    - Choose **Remove everything**. "Keep my files" keeps files the malware may
      have touched.
    - **Local reinstall** uses files already on the PC and works offline.
      **Cloud download** gets a fresh copy of Windows and needs the internet.
      ([Microsoft: reset your PC](https://support.microsoft.com/en-us/windows/reset-your-pc-0ef73740-b927-549b-b7c9-e6f2b48d275e))

    For a PC you can't trust at all, the cleaner way is a fresh install from a
    USB drive made on a different, clean PC with Microsoft's media creation
    tool. It deletes everything on the disk.
    ([Microsoft: reinstall Windows with the installation media](https://support.microsoft.com/en-us/windows/reinstall-windows-d8369486-3e33-7d9c-dccc-859e2b022fc7))

After reinstalling, install updates before anything else, then put back your
copied files and download your programs again from their real websites.

## 6. Your accounts, from a different, clean device

Anything typed on the infected computer may have been recorded. Change your
passwords from a **different** device you trust (another computer, or your
phone), never from the infected one, even after it's been cleaned. Start with
your email, because it can reset everything else.

The full accounts walkthrough (passwords, two-step sign-in, signing out other
sessions) is the [Digital security reset](digital-security-reset.md). In the
app it's the worry **I think I've been hacked**; on the command line,
`rescue guide digital_security_reset`.

## Teaching notes

- **Isolation comes before diagnosis.** Most people's instinct is to "go
  online and look it up" on the infected computer. Look it up on another
  device instead.
- **"Couldn't check" isn't "clean", and "clean" isn't "proven clean".** Both
  matter more than usual on a computer that was clearly infected.
- **Safe mode is a calmer place, not a cure.** It's for copying files off and
  for running the checkup, not proof the problem is gone.
- **Reinstalling isn't failure.** For a computer that was clearly infected, it's
  often the most honest fix, and your files survive if you copied them first.
