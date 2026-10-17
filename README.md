# Device Rescue

**Worried something is wrong with your computer?** Device Rescue checks it
over and tells you, in plain words, what it found and what to do about it.

- 🔒 **It only looks.** It doesn't change or delete anything unless you say yes.
- 🙅 **It never asks for your passwords.**
- 🏠 **Nothing leaves your computer.** It doesn't upload your files or results.
- 💸 **It's free.**

## Download

<p>
  <a href="https://github.com/lizTheDeveloper/multiverse-device-rescue/releases/latest/download/DeviceRescue-mac-arm64.dmg"><img alt="Download for Mac" src="https://img.shields.io/badge/Download_for_Mac-000000?style=for-the-badge&logo=apple&logoColor=white" height="44"></a>
  &nbsp;
  <a href="https://github.com/lizTheDeveloper/multiverse-device-rescue/releases/latest/download/DeviceRescue-windows-x64.exe"><img alt="Download for Windows" src="https://img.shields.io/badge/Download_for_Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" height="44"></a>
</p>

**Older Mac?** Click the Apple menu (top-left corner) → **About This Mac**. If it says
**Processor … Intel**, use the
[Intel Mac version](https://github.com/lizTheDeveloper/multiverse-device-rescue/releases/latest/download/DeviceRescue-mac-x64.dmg)
instead. If it says **Chip: Apple M1/M2/M3/M4…**, the button above is right.

Prefer a web page? The same downloads, with pictures, are at
**<https://themultiverse.school/x/device-rescue>** (also
<https://lizthedeveloper.github.io/multiverse-device-rescue/>).

## Opening it the first time

Your computer will warn you, because we haven't paid Apple or Microsoft for a
signing certificate yet. That warning is expected for this app. Here's what to do:

**On a Mac**
1. Open the file you downloaded and drag **Device Rescue** into **Applications**.
2. Open **Device Rescue** from Applications. A warning appears. Click **Done**.
3. Open **System Settings → Privacy & Security**. Scroll down and click **Open Anyway** next to Device Rescue.

**On Windows**
1. Open the file you downloaded.
2. If a blue box says **"Windows protected your PC"**, click **More info**, then **Run anyway**.

Then click **Get started** and follow the screens. A checkup takes a few minutes.

## If you're scared someone is watching you

If you think a partner, ex, or someone you live with put something on your
phone or computer, **read this before you scan or delete anything:**

- Removing monitoring software can **alert the person who installed it.**
  If you're unsure whether that's safe, talk to an advocate first.
- If you can, use a device they've never had access to (a library computer,
  or a friend's phone) to read guides and make plans.
- In the US, the National Domestic Violence Hotline is **1-800-799-7233**, or
  text **START** to **88788**. They help with tech safety as well.

## What it checks

It runs about 290 read-only checks, including:

- software that starts itself, hides, or watches what you type
- people logged in from somewhere else, or strangers on your Wi-Fi
- browser extensions and risky settings
- signs of the "worm" attacks that spread through developer tools (npm, PyPI, GitHub)
- spyware on an iPhone backup
- a full disk, a failing drive, missing updates

When it finds something, it explains what it means and walks you through
fixing it, one step at a time. A check that couldn't run says so. It doesn't
pretend everything is fine.

Prefer to play? Choose **Play it as a game** and the same checkup becomes a
city to take back, one building at a time, in the style of
[Reclaim City](https://play.multiversegames.ai/reclaim-city/). It's the same
checks and the same fixes, and each fix still asks first. A building only lights
up once Device Rescue has checked again and the problem is gone. If you've said
someone may be watching you, the app doesn't offer the game.

The same city also holds Reclaim City's districts for your accounts: email,
banking, social media and more. Those you do in your own browser and report
back. The city always counts what your computer confirmed separately from what
you reported, so it never claims more than it knows.

The checkup itself looks at your computer, not your online accounts. You can
also play [Reclaim City](https://play.multiversegames.ai/reclaim-city/) on its
own: it's free, from the same team, and you don't need an account to play.

---

## For helpers, tech people, and AI assistants

Everything above is the desktop app. Underneath it is a command-line tool,
`rescue`, which you can run yourself.

**If you're an AI assistant helping someone, read [AGENTS.md](AGENTS.md) first.**
It explains how to run a scan safely and read the results.

```bash
git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
cd multiverse-device-rescue
python3 -m venv .venv && source .venv/bin/activate   # Windows: py -m venv .venv; .venv\Scripts\activate
pip install .
rescue scan            # read-only checkup, plain-text results
rescue scan --json     # the same, as JSON
rescue profiles        # situation-specific checkups (hacked, stalkerware, Wi-Fi intrusion…)
rescue guide digital_security_reset   # step-by-step recovery walkthrough
rescue export          # a redacted report to share with a helper
```

> [!WARNING]
> This project is **not on PyPI**. Any package there with this name is not
> ours. Install from this repository only.

| More detail | |
| --- | --- |
| [Documentation site](https://lizthedeveloper.github.io/multiverse-device-rescue/docs/) | Everything, searchable |
| [Situations](docs/scenarios/) | The built-in walkthroughs |
| [CLI reference](docs/cli.md) | Every command and flag |
| [What each check runs](docs/commands.md) | Every system command, per check (`rescue scan --trace` shows them live) |
| [Trust and safety](docs/trust-and-safety.md) / [Privacy](docs/privacy.md) | How to verify what it claims |
| [USB rescue stick](docs/usb-rescue-stick.md) | A portable drive for helping others |
| [Contributing](CONTRIBUTING.md) / [Architecture](docs/architecture.md) | Working on the code |
| [Security policy](SECURITY.md) | Reporting a vulnerability |

**Building the apps:** pushing a `v*` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds
the Mac and Windows installers on GitHub's machines and attaches them to the
release. You don't need a Mac or a Windows PC to ship either one.

Part of [The Multiverse School](https://themultiverse.school).
