# Check an Android phone for spyware

This guide walks you through checking an Android phone for known
**stalkerware** (apps sold to secretly watch another person) and known
**mercenary spyware** (like Pegasus or Predator). It's written to be followed
step by step; you do **not** need to be technical.

Everything runs **on your own computer**. Nothing is uploaded anywhere.

---

## Read this first

- **Only check your own phone, or a phone whose owner has asked you to check
  it.** The tools used here (Amnesty International's AndroidQF and MVT) are
  licensed for use only with the explicit consent of the person whose data is
  being checked.
- **If you think a partner, ex, or someone you live with is monitoring your
  phone,** talk to an advocate before you start. This check needs you to turn
  on a hidden phone setting (Developer options), which someone who checks your
  phone might notice, and removing anything it finds can alert them. In the US,
  the National Domestic Violence Hotline is **1-800-799-7233**, or text
  **START** to **88788**. They help with tech safety.
- **A clean result does not prove the phone is safe.** It only means nothing
  on the *known, published* lists was found. New or custom spyware won't show
  up.

---

## What this does

1. **AndroidQF**, a free tool from Amnesty International, copies a snapshot of
   the phone's app list, settings and system logs onto your computer, over a
   USB cable. It saves one file, named like
   `3f2c9a1e-7b4d-4e8a-9c1f-2a6b8d0e5f13.zip`.
2. **Reclaim City** finds that file and checks it with **MVT**, Amnesty's
   scanner, against public lists of known stalkerware and spyware.

Reclaim City never connects to the phone itself. It unpacks the snapshot into
a private temporary folder for the scan and deletes that copy afterwards.

You need a **Mac or Linux computer**. (MVT doesn't run on Windows without
setting up Linux inside it, WSL, first.)

---

## Before you start: one-time setup on the computer

### 1. Install the scanner (MVT) and its lists

Open the **Terminal** app, paste this line, and press Return:

```
pip install mvt
```

If that command isn't found, install Python first (`python.org/downloads`),
then run the line again.

Then download the lists of known spyware and stalkerware. **Don't skip this:**
without the lists, MVT has nothing to compare against, and Reclaim City will
tell you it can't check rather than call the phone clean.

```
mvt-android download-iocs
```

### 2. Download AndroidQF

Go to <https://github.com/mvt-project/androidqf/releases/latest> and download
the file for your computer:

- **Mac:** the one ending in `macos_universal_..._signed`
- **Linux:** `linux_amd64` (most PCs) or `linux_arm64`

---

## Turn on USB debugging on the phone

This lets AndroidQF read the phone over the cable. You'll turn it off again at
the end.

1. Open **Settings → About phone**. (Samsung: **Settings → About phone →
   Software information**.)
2. Tap **Build number** seven times. The phone says *"You are now a
   developer"*. It may ask for your PIN.
3. Go back to **Settings → System → Developer options** (on Samsung,
   **Developer options** is at the bottom of Settings).
4. Turn on **USB debugging**.

The steps vary a little between phone makers. If you can't find **Build
number**, search Settings for it.

---

## Make the snapshot with AndroidQF

1. Plug the phone into the computer with a USB cable. Unlock the phone.
2. On the computer, open **Terminal** and run AndroidQF from your Downloads
   folder. On a Mac:

   ```
   cd ~/Downloads
   chmod +x androidqf_macos_universal_*
   ./androidqf_macos_universal_*
   ```

3. **On the phone**, a box asks *"Allow USB debugging?"*. Tick **Always allow
   from this computer** and tap **Allow**.
4. AndroidQF asks a few questions as it goes. Suggested answers:
   - **Backup:** *Only SMS* lets MVT check text messages for links to known
     spyware. You'll need to confirm the backup on the phone. *No backup* is
     fine too.
   - **Download copies of apps:** *No* (it isn't needed for this check, and it
     makes the file much bigger).
   - Anything else (intrusion logs, hashing files, browser history): *No*.
5. Wait until it says it's finished. You now have a file named like
   `3f2c9a1e-....zip` in your **Downloads** folder. Leave it there, or move it
   to your home folder or Desktop: Reclaim City looks in all three.

> If the file ends in **`.zip.age`**, AndroidQF found a `key.txt` file and
> encrypted the snapshot. Only the holder of the matching key can unlock it.
> Move `key.txt` out of the way and run AndroidQF again.

---

## Run the check

In Reclaim City, choose **"I'm worried about spyware on my Android phone"**.
Or, from the command line:

```
rescue --auto --profile android_spyware_check
```

The scan usually takes a few minutes.

---

## Reading the result

- **"No spyware indicators detected"**: nothing on the known lists was
  found. This is reassuring, not a guarantee.
- **"Signs of spyware found"** (shown in red): the scan matched an app,
  domain or other sign against a known stalkerware or spyware list. **Don't
  panic, and don't delete anything yet.** See *If something is found* below.
- **"Something an expert should look at"**: not a match against a list, but
  something spyware often needs or leaves behind, such as signs the phone has
  been **rooted**. It can have an innocent explanation (some people root their
  own phones). If you didn't do it, take it seriously.
- **"Lower-level notes"**: things like apps installed from outside the Play
  Store, an old security update, or settings changed for the scan itself (USB
  debugging). Read the list for anything you didn't do yourself.
- **"The spyware scanner has no spyware lists yet"**: run
  `mvt-android download-iocs`, then check again.
- **"The spyware scan didn't finish"** or **"encrypted"**: nothing was
  confirmed, so this is not a clean result. The message says what to do.
- **"No phone data found to check"**: Reclaim City couldn't find the
  AndroidQF file. Make sure it's in your home folder, Downloads or Desktop.

---

## If something is found

1. **Don't remove the app or reset the phone yet.** If someone close to you put
   it there, removing it can alert them, and the snapshot is evidence.
2. **Keep the AndroidQF file** somewhere safe.
3. **Get help.** For stalkerware: an advocate (US hotline above), or the
   [Coalition Against Stalkerware](https://stopstalkerware.org/) list of
   organisations. For mercenary spyware: Amnesty International's Security Lab
   helps for free: <https://securitylab.amnesty.org/get-help/>, as does Access
   Now's Digital Security Helpline: <https://www.accessnow.org/help/>.

---

## When you're done

1. **Turn off USB debugging and Developer options** on the phone: **Settings →
   System → Developer options**, switch the top toggle off.
2. **Delete the AndroidQF file** if nothing was found. It holds a list of your
   apps (and your text messages, if you chose the SMS backup), unprotected.
