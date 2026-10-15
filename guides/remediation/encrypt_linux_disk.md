---
title: "Protect your files if the computer is lost or stolen"
estimated_time: "60 minutes"
platforms: [linux]
remediates:
  - security.linux_disk_encryption_check.root_not_encrypted
  - security.linux_disk_encryption_check.home_not_encrypted
  - security.linux_disk_encryption_check.encryption_undetermined
automatable_steps: []
human_only_steps: [1, 2, 3]
---

Your files are stored on the drive in a form anyone can read. If the computer
is lost or stolen, someone can take the drive out and read everything on it:
saved passwords, logged-in browser sessions and documents. Your login password
does not stop that. Encrypting the drive scrambles it, so only someone who
knows the disk passphrase can read it.

## Step 1: Back up your files first

Copy everything you care about to an external drive or cloud storage. Setting up
encryption changes how the whole drive is stored, and a power cut in the middle
can lose files.

## Step 2: Turn on encryption

On Linux, encryption is normally chosen when the system is installed, so the
usual way is a reinstall:

1. Make a fresh installation USB stick from your distribution's website.
2. During the installer, choose **Encrypt the new installation** (the wording
   varies slightly; it is often on the "Installation type" screen).
3. Choose a passphrase of four or five random words. Write it on paper and
   keep it somewhere safe at home. It cannot be recovered if you lose it.

Only your home folder is unencrypted? Your distribution may offer an encrypted
home folder (ecryptfs or systemd-homed) which you can set up instead; search
for your distribution's name plus "encrypt home folder".

## Step 3: Restore your files

After the install, copy your backed-up files back. If a new scan then shows
the drive as encrypted, you're done. If it says it could not tell, run the scan
again with administrator rights to get a definite answer.
