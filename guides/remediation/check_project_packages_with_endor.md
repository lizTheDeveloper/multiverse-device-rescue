---
title: "Check your code projects' packages (Endor Labs)"
platforms: [macos, linux, windows]
remediates:
  - security.endor_dependency_scan.scan_available
  - security.endor_dependency_scan.could_not_check
  - security.endor_dependency_scan.malicious_dependency
  - security.endor_dependency_scan.vulnerable_dependencies
  - security.endor_dependency_scan.not_scanned
  - security.endor_dependency_scan.scan_summary
steps_for:
  security.endor_dependency_scan.scan_available: [1]
  security.endor_dependency_scan.could_not_check: [1]
  security.endor_dependency_scan.malicious_dependency: [2]
  security.endor_dependency_scan.vulnerable_dependencies: [3]
  security.endor_dependency_scan.not_scanned: [4]
  security.endor_dependency_scan.scan_summary: [5]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

Code projects use packages: code other people wrote, pulled in from npm, PyPI
and similar registries. Some packages are published to steal from the
computers that install them, and many have known security holes. Endor Labs
checks a project's packages against its lists of both. We recommend it for
developers. Disclosure: Endor Labs is one of Reclaim City's sponsors.

## Step 1: Set up Endor Labs' tool, if you want the scan

The scan is off unless you ask for it, because it sends information to Endor
Labs: the names and versions of each project's packages and where they're
listed, the project's git details (branch, latest commit, repository name and
web address, and the email addresses of people who made commits), and basic
facts about this computer. Your code and your package files stay on the
computer. Endor's page on what it receives:
https://docs.endorlabs.com/trust-compliance/sca-scan-data

1. Install endorctl from Endor's instructions:
   https://docs.endorlabs.com/endorctl/install-and-configure/
2. Sign in with `endorctl init` in a terminal. It opens Endor's sign-in page
   in your browser; you sign in there. Reclaim City never asks for or keeps
   your Endor key. Scanning from the command line needs an Endor Labs
   account with its own workspace (their paid plan):
   https://www.endorlabs.com/get-started
3. Run `rescue scan --profile dependency_scan`.

## Step 2: A known malicious package

Don't install or run the project's packages until it's removed. Remove the
package from the project and its lock file, and delete the project's
`node_modules` folder. If its packages were installed on this computer, the
package's code may have run: run the AI Worm & Spyware Response checkup, and
from another device change the passwords and keys this computer had (code
hosting, package registry, cloud accounts). If you didn't add the package
yourself, check the project's history (`git log -p -- package.json`) for who
did.

## Step 3: Packages with known security holes

Update each one to the fixed version Endor Labs lists, run the project's
tests, and scan again. Endor Labs' web app shows the details of each problem.

## Step 4: Projects that weren't checked

We only scan projects Endor's tool can read without building them:
JavaScript projects with a lock file. For other projects endorctl runs the
project's package manager or build tool, which runs the project's own code,
including any bad package's. If you trust a project, scan it yourself from its
folder with `endorctl scan --path . --dependencies`.

## Step 5: The summary

A scan only knows about problems that have been found and published. A clean
result lowers the odds of a bad package; it doesn't rule one out.
