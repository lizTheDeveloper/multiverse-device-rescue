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
- **Before the pages: a screen that isn't one of them.** Shown first when the record opens, headed "Before you
  start", with "This screen isn't part of the record. You don't need to photograph it." It holds who can help (the
  help district's own list and note, in full), **Start the record** and **Done**. It has no "Checkup record"
  header, no fingerprint and no page frame (the district's own look, not black on white), and isn't counted in
  "Page N of M": a photo of the pages never puts the hotlines in a camera roll someone may look through.
- **First page: how to use it, only.** "Take a photo of each page with your phone. Make sure the top line is in
  the picture. If someone may look through your phone, keep the photos somewhere they can't reach."
- **Last page: what couldn't be checked**, and "a clear checkup lowers the odds of a problem; it doesn't rule one
  out."
- **Moving through:** Next / Back buttons and arrow keys; Back from the first page returns to the screen before
  the pages; **Done** returns to the help district; Esc leaves at once, as everywhere in the help district.

## The fingerprint

The record has one fingerprint: the SHA-256 of its canonical form, computed on this computer with Web Crypto.
Nothing is sent anywhere to make it.

**The canonical form covers exactly what the pages print, and nothing else**, so a set of photos can be checked
on its own: someone holding only the photos can retype the printed facts in a text editor, and `shasum -a 256`
gives the same number. It is one JSON object (version 2):

```jsonc
{
  "version": 2,                                   // the number 2: this form
  "computer": "MacBook Pro (Mac16,1), macOS 26.1 (25B78)",
                                                  // the header's computer line, as printed
  "findings": [                                   // one per finding page, in page order
    {
      "kind": "Parental control product",         // the line under the title, as printed
      "rows": [ ["Where", "/Applications/ExampleWatch.app"], ["Added", "March 3, 2026"] ],
                                                  // every row, top to bottom: [label, value], as printed
      "said": "You said: someone else gets its reports",
                                                  // the whole "You said: …" line; "" when the page has none
      "what": "ExampleWatch"                      // the page's title
    }
  ],
  "not_checked": [ ["Firewall", "Couldn't run"] ],
                                                  // the last page's list, top to bottom: [check, why]. Each item prints
                                                  // as "check: why"; split it at the last ": ". [] when the page says
                                                  // "Every check ran to the end."
  "when": "October 23, 2026, 9:17 AM (UTC-7)"     // the header's scan time, as printed
}
```

Left out: page numbers, "Checkup record", the how-to-use page, every fixed sentence, the fingerprint itself and
the buttons. The engine's evidence that no page shows (codes, severities, other `data` fields) isn't covered:
nobody holding the photos could check it.

**Normalizing every string** (the pages keep their typography; this is for hashing only), in this order:

1. Unicode NFC.
2. `‘` (U+2018) and `’` (U+2019) become `'`; `“` (U+201C) and `”` (U+201D) become `"`.
3. `−` (U+2212, minus), `–` (U+2013, en dash) and `—` (U+2014, em dash) become `-`.
4. Every run of whitespace becomes one space: tab, line feed, U+000B, U+000C, carriage return, space, U+00A0
   (no-break space), U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF (JavaScript's `\s`).
5. Spaces trimmed from both ends.

So a value retyped with a keyboard's straight apostrophes, or with an extra space, gives the same fingerprint.

**Serializing:** `version` first, then every other key, at every level, in sorted order (`computer`, `findings`,
`not_checked`, `when`; in a finding `kind`, `rows`, `said`, `what`); arrays in page order; no whitespace between
tokens; strings as JavaScript's `JSON.stringify` writes them (`"` and `\` escaped with a backslash, any other control
character as `\u00XX`, non-ASCII characters as themselves). Encoded as UTF-8, no newline at the end, hashed with SHA-256, written as 64 lowercase
hex characters.

**The printed text is the same on every computer:** the pages are in US English whatever the computer's
language, and every date is written by the app in that form ("March 3, 2026"). The header's scan time is
in this computer's time zone and says so, with the computer's own UTC offset at that instant: "October 23,
2026, 9:17 AM (UTC-7)", "(UTC+5:30)", "(UTC+0)". The same scan opened in another time zone prints another time,
so its pages have their own fingerprint; each set of pages matches its own.

**Worked example** (`desktop/test/photo-record.test.js` pins it, and checks the fingerprint against facts read
back out of the rendered pages alone): one parental control finding, one check that couldn't run, scanned at
2026-10-23T16:17:00Z on a computer in Los Angeles. Its canonical text, one line:

```
{"version":2,"computer":"MacBook Pro (Mac16,1), macOS 26.1 (25B78)","findings":[{"kind":"Parental control product","rows":[["Where","/Applications/ExampleWatch.app"],["Added","March 3, 2026"],["Last used","Couldn't tell"],["Running now","Couldn't tell"],["Made by","Example Family Co (not verified)"],["How the check knows","Found by the check \"Safety sweep\""]],"said":"You said: someone else gets its reports","what":"ExampleWatch"}],"not_checked":[["Firewall","Couldn't run"]],"when":"October 23, 2026, 9:17 AM (UTC-7)"}
```

Saved without a final newline (`printf '%s' '…' | shasum -a 256`), its SHA-256 is
`8298a3867b2a4e5f7f9bf82dbe163f67361346356076c28e65075ff33fb06e51`, and every page header shows
`8298 A386 7B2A 4E5F`.

- **Every page header** shows the short form: the first 16 hex characters in groups of four (`3F9A 0C21 77DE
  B410`).
- **The last page** shows all 64 characters, in groups of four over four lines, in a large monospace face, under
  "Record fingerprint". It says what it proves, plainly: "If anything in this record changes, this number
  changes. It shows the pages belong together and haven't been edited since the checkup made them. It doesn't
  prove what the checkup found is true."
- **Same record, same fingerprint:** opening the photo record twice for the same scan, on the same computer,
  gives the same number. The scan time is printed, so a new scan gives a new one.
- **Proving when:** the fingerprint alone proves nothing about time. That comes with the evidence escrow's
  public log (`docs/superpowers/proposals/2026-10-23-evidence-escrow.md`), which can record a fingerprint, and only the
  fingerprint, at the moment it's sent. Until then the page doesn't claim a time beyond the scan's own clock.

## Words

Facts in plain, neutral words. The product's own name and the kind of thing it is ("Parental control product",
"Remote-access tool") are evidence and stay. No "stalker", "abuser", "partner" or "ex" words, and the title is
"Checkup record", not "forensics": the photos will sit in a camera roll someone else may look through. City mode's
forbidden-words check applies to every page, and to the screen before them (all but the help district's own list).

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
record, changes when any printed fact changes and not when evidence no page shows does, matches a known SHA-256
for a fixed synthetic record, equals the SHA-256 of the facts read back out of the rendered pages alone, survives
retyping with straight quotes, is the same in two languages, and nothing is sent over the network to make it; "Couldn't tell" for missing evidence; nothing written
to storage, exports or the clipboard; city-mode forbidden words on every page and the screen before them; the
screen before the pages comes first, with no header or fingerprint, isn't counted, and is where Back from page 1
goes; no page carries who can help or a phone number; Esc and Done. Screenshots of each
page in both themes to confirm it reads the same (black on white).
