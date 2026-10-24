# The photo record: a checkup report someone can photograph

Status: proposed (2026-10-23)

## Why

Someone worried about being watched needs what the checkup found as evidence, for an advocate, a lawyer, a
protective order or a police report. A file saved on this computer can be found by the person watching it, and
texting it to themselves leaves a trail on accounts that may also be watched. What people actually do is take
photos with their phone. So the checkup's findings need to come out as pages built to be photographed.

The owner's rule: when the person is gathering evidence, or worried about being watched, everything the checkup
gathered is evidence.

## When it's offered

One place: the help district (city mode, and standard mode through the warning's GO THERE). A button there,
**Make a photo record**, appears when any of these holds:

- city mode;
- the worry picked was "I think someone is watching me" (`safety: true`);
- the scan has any monitoring finding (`ALWAYS_SAFETY_MODULES`) or remote-access tool;
- the person answered "Someone else" or "Not sure" to "Who gets this program's reports?" (parental control), or
  "Mine" or "Not sure" to "Whose computer is this?" (employee monitoring: an exploitative employer or a
  trafficker can put "work" software on someone's own home computer). Who receives the reports decides who is being watched, not
  who installed it or why: monitoring often starts negotiated ("a child uses this device").

Those answers go in the record too, as "You said: someone else gets its reports", because how the monitoring
came to be there is evidence.

It is never offered on the normal mission screens, and it never opens by itself.

## What's in it

Everything the checkup gathered that is evidence, from the scan already in memory (no new scan, no engine
change):

- every held finding (monitoring software, remote-access tools), with its `heldRows` / `heldEvidence` facts;
- every warning and critical finding from the other checks (sharing settings, background tasks, permissions such
  as screen recording, camera, microphone and keyboard access, certificates, device management…), with the
  facts its evidence card shows;
- the "couldn't check" list: checks that didn't run or didn't finish (`supported: false`, `error`,
  `complete: false`), because evidence of what wasn't looked at matters too.

Info findings are left out (an inventory would bury the evidence), except held ones.

For each finding: what was found (the product or item name), the kind of thing it is, where it was found (the
**full** path, wrapped, never shortened), when it was added and when it was last used when the evidence has them,
whether it's running now, who made it and whether that was verified, and how the check knows. Missing evidence
says "Couldn't tell", never "no".

## The pages

- **Sized for a phone photo:** portrait, about 3:4, one finding per page (two short ones may share a page).
- **Readable in a photo:** large type, black on white whatever the app's theme, no gradients, no hover-only text,
  paths in a monospace face that wraps.
- **Each page stands alone:** a header on every page with "Checkup record", the date and time of the scan, the
  computer (model and system version from the scan), "Page 2 of 7", and the record's **fingerprint** in short
  form (below), shared by every page so they can be shown to belong together.
- **First page: how to use it.** "Take a photo of each page with your phone. Make sure the top line is in the
  picture. If someone may look through your phone, keep the photos somewhere they can't reach." Plus who can help
  (the help district's own note, in full).
- **Last page: what couldn't be checked**, and "a clear checkup lowers the odds of a problem; it doesn't rule one
  out."
- **Moving through:** Next / Back buttons and arrow keys; **Done** returns to the help district; Esc leaves at
  once, as everywhere in the help district.

## The fingerprint

The record has one fingerprint: the SHA-256 of its canonical form (the facts on its pages as JSON with sorted
keys, UTF-8, no whitespace, a `version` field first), computed on this computer with Web Crypto. Nothing is sent
anywhere to make it.

- **Every page header** shows the short form: the first 16 hex characters in groups of four (`3F9A 0C21 77DE
  B410`).
- **The last page** shows all 64 characters, in groups of four over four lines, in a large monospace face, under
  "Record fingerprint". It says what it proves, plainly: "If anything in this record changes, this number
  changes. It shows the pages belong together and haven't been edited since the checkup made them. It doesn't
  prove what the checkup found is true."
- **Same record, same fingerprint:** opening the photo record twice for the same scan gives the same number.
  The scan time is part of the record, so a new scan gives a new one.
- **Proving when:** the fingerprint alone proves nothing about time. That comes with the evidence escrow's
  public log (`docs/superpowers/proposals/2026-10-23-evidence-escrow.md`), which can record a fingerprint, and only the
  fingerprint, at the moment it's sent. Until then the page doesn't claim a time beyond the scan's own clock.

## Words

Facts in plain, neutral words. The product's own name and the kind of thing it is ("Parental control product",
"Remote-access tool") are evidence and stay. No "stalker", "abuser", "partner" or "ex" words, and the title is
"Checkup record", not "forensics": the photos will sit in a camera roll someone else may look through. City mode's
forbidden-words check applies to every page.

## What it never does

- It saves nothing: no file, no storage, no screenshot taken by the app. Pages are drawn from memory and gone when
  closed.
- It changes no finding, removes nothing and offers no fix. The removal warning stays on the findings.
- No points, no mission progress, nothing remembered.
- A file export stays where it is today (`rescue export`, which redacts), for helpers; the photo record doesn't
  add one.

## Testing

Desktop tests: offered exactly in the four cases above and not otherwise; contents (held findings, warning and
critical findings, couldn't-check list, info findings left out); full paths never shortened; every page has the
header, date, computer, page count and the same short fingerprint; the fingerprint is stable for the same
record, changes when any fact changes, matches a known SHA-256 for a fixed synthetic record, and nothing is sent
over the network to make it; "Couldn't tell" for missing evidence; nothing written
to storage, exports or the clipboard; city-mode forbidden words on every page; Esc and Done. Screenshots of each
page in both themes to confirm it reads the same (black on white).
