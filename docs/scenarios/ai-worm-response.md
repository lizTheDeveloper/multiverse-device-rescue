# AI worm response

**`ai_worm_response`** — 12 modules, no guide.

## Who this is for

You are a developer or someone with a development machine, and you have reason
to think you pulled a compromised package, cloned something hostile, or were
hit by one of the self-propagating supply-chain worms that spread through
package registries and developer credentials — Shai Halud, Miasma,
SANDWORM_MODE, SesameOp.

The pattern these share: they land through a package or repository, harvest git
and SSH credentials, establish persistence, call home, and then use the
credentials they found to move to the next machine or the next registry
account. That is why this profile checks all five of those stages rather than
just scanning for files.

Also useful if you simply want a hard look at a development machine after a
dependency was found to be malicious.

## What to run

```console
$ rescue --auto --profile ai_worm_response
```

There is **no guide for this profile** — `rescue guide ai_worm_response` will
tell you `No guide content found`. It is scan-only. For remediation guidance,
each finding carries a code that maps to a walkthrough; see the
[remediation catalog](../REMEDIATION_CATALOG.md), and the
[threat map](../THREAT_REMEDIATION.md) for how this profile fits the broader
threat model.

## What the tool does

The worm checks run on all three platforms, configured at `sensitivity: elevated` for
this profile — the same modules run more conservatively elsewhere.

| Module | What it answers | Risk level |
| --- | --- | --- |
| `ai_worm_filesystem` | Filesystem artifacts of known worm families | moderate |
| `ai_worm_git_ssh` | Has git or SSH configuration been tampered with — hooks, keys, config | moderate |
| `ai_worm_persistence` | What has been arranged to run again | **destructive** |
| `ai_worm_network` | Command-and-control indicators in network state | moderate |
| `ai_worm_lateral` | Signs of movement toward other machines and accounts | moderate |
| `mvt_spyware_scan` | Mobile spyware indicators, if a device backup is present | safe |
| `ai_agent_audit` | What AI tools on the computer can reach | safe |
| `vulnerable_runtimes` | Copies of Node.js and PHP with a bug on CISA's Known Exploited Vulnerabilities list (Node2Shell, PHP2Shell), with the update step for each installer | safe |
| `endor_dependency_scan` | Whether your code projects can be checked for known-malicious and known-vulnerable packages with Endor Labs; the scan itself is off here (see below) | safe |

### Checking your projects' packages

A dependency that turned out to be malicious is how most of these worms
arrive. For that check we recommend Endor Labs' `endorctl`, which looks up
each package a project uses against Endor's lists of malicious packages and
known vulnerabilities. Disclosure: Endor Labs is one of Reclaim City's
sponsors.

This profile doesn't run it, because the scan sends each project's package
names and versions, git details (including commit authors' email addresses)
and basic facts about the computer to Endor Labs; source code and package
files stay local ([Privacy](../privacy.md#what-leaves-the-machine)). To run
it, install `endorctl`, sign in with `endorctl init` (at Endor's own sign-in
page), then:

```console
$ rescue scan --profile dependency_scan
```

Only JavaScript projects with a lock file are scanned: for anything else
endorctl runs the project's own install or build code, which is the code a
malicious package hides in.

!!! warning "This profile contains the tree's only DESTRUCTIVE module"
    `ai_worm_persistence` is `RiskLevel.DESTRUCTIVE` — the only module at that
    level in the whole catalog. That describes its `fix()`, not its `check()`;
    every check in this tool is read-only.

    A destructive module can **never** be auto-applied: the auto-mode gate
    requires `RiskLevel.SAFE` *and* `auto_apply = True`. `rescue --auto` will
    scan it and list it under "Skipped (requires confirmation)". The only ways
    to reach its `fix()` are `rescue run ai_worm_persistence` and answering
    `y`, or passing `--yes`. Read what it proposes before you agree.

The `sensitivity: elevated` setting means these modules flag more aggressively
here than in a general scan. Expect more findings, and expect some of them to
be things you installed on purpose. That trade is deliberate: for this threat,
a false positive costs you five minutes and a false negative costs you your
credentials.

## What stays human-led

Everything after the scan, and this is the profile where that matters most —
because the credentials are the payload.

- **Rotating every credential the machine had access to.** SSH keys, git
  tokens, package-registry tokens, cloud credentials, CI secrets. Assume
  anything readable on that machine is compromised.
- **Revoking sessions and tokens at each provider**, not just changing
  passwords.
- **Checking what was published from your accounts.** These worms propagate by
  publishing malicious versions of packages you maintain.
- **Auditing what the machine could reach** — other hosts, internal services,
  shared drives.
- **Notifying anyone downstream** of a package or repository you maintain.
- **Deciding whether to reinstall.** For a worm that had credential access and
  root, a clean reinstall is often faster than being sure.

The tool tells you what is observable. It cannot revoke a token at a registry,
and it will not pretend to.

## What it will never ask you for

Your git token, your SSH passphrase, your registry credentials, your cloud
keys, or any password. `ai_worm_git_ssh` inspects git and SSH *configuration*
and key *metadata* — it does not read private key material out to you or send
it anywhere. Every rotation happens at the provider, in your browser or their
CLI.

## Afterwards

```console
$ rescue export --profile ai_worm_response
```

If you are reporting this to a security team or a registry, the redacted case
is a good attachment. Read it first — redaction removes credential-shaped
strings and private-key blocks, but module output is free text and may contain
internal hostnames or repository names. See
[Privacy](../privacy.md#the-redacted-case-export).

For an active compromise with real stakes — a business, a widely-used package,
a high-risk individual — get professional incident response. This is a triage
tool.
