# Multiverse Device Rescue

Multiverse Device Rescue is a local diagnostic, maintenance, and guided
recovery toolkit for macOS, Windows, and Linux. It runs read-only checks by
default and clearly separates observations, manual guidance, and system
changes.

## Safe use

- Start with `rescue` to run checks interactively, or `rescue --auto` for
  eligible low-impact actions.
- Review every result before changing security settings or deleting data.
- Use a known-clean device and professional incident-response support when you
  suspect an active compromise.
- Do not enter account passwords, recovery codes, or API tokens into the tool.

## Installation

Install from a release artifact or from source with `pip install .`. The
installed package includes the module, profile, guide, and security metadata
needed at runtime.

## Support status

- macOS and Windows have the broadest diagnostic coverage.
- Linux supports profile collection and the modules that explicitly declare
  Linux support.
- Mobile-device steps are human-guided; there is no desktop-module support for
  Android or iOS.

See `docs/ROADMAP.md` for reliability, security, and capability work in
progress.

## Threat coverage

`docs/THREAT_REMEDIATION.md` maps common threats (AI worms, mobile spyware,
credential compromise, unwanted remote access, …) to the exact `rescue` command
that checks and remediates them. Regenerate it with `rescue threat-remediation`.
