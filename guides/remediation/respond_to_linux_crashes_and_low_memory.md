---
title: "Stop programs from crashing or running out of memory"
estimated_time: "20 minutes"
platforms: [linux]
remediates:
  - integrity.linux_journal_errors.oom_kill
  - integrity.linux_journal_errors.segfault
  - performance.linux_memory_pressure.memory_stall
  - performance.linux_memory_pressure.low_available_memory
  - performance.linux_memory_pressure.heavy_swap_use
  - performance.linux_memory_pressure.no_swap_configured
  - performance.linux_memory_pressure.memory_hog
steps_for:
  integrity.linux_journal_errors.segfault: [1, 2, 4]
  performance.linux_memory_pressure.heavy_swap_use: [1, 2]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

When a computer runs short of memory it slows down, and then it starts closing
programs to survive. That is why windows can vanish and work can be lost. A
program that crashes over and over is either broken or running on faulty
memory. None of this means someone has broken in. It means the computer is
short of something.

## Step 1: Close programs you aren't using

Open **System Monitor** (or "Task Manager") and sort the list by **Memory**.
Close the programs at the top that you don't need right now. Web browsers with
many tabs are the most common cause, followed by virtual machines and chat apps.

## Step 2: Restart your computer

A restart clears memory that has built up. If the problem comes back within a
day or two, carry on with the steps below.

## Step 3: Turn on swap if it's missing

Swap is a safety area on the drive that gives the computer a gentler option than
closing programs. If your system has none, many distributions offer **zram**
(compressed memory) as a setting or a small package; search for your
distribution's guide to "enable zram" or "add a swap file". Both are safe to do.

## Step 4: Fix programs that keep crashing

- If it is always the same program: update it, and if it keeps crashing,
  switch to an alternative.
- If many different programs crash, the memory may be faulty. Follow the
  memory test step in "Back up now: your drive or memory is reporting errors".
- If the computer is simply too small for what you do, adding more memory is the
  lasting fix.
