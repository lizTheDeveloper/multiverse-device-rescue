# Network analysis training: design

Status: approved-pending review, from conversation 2026-10-18. Builds on game mode
(`2026-10-16-game-mode-*.md`) and the command center
(`2026-10-18-command-center-signal-or-noise-design.md`: the deck, Signal or
Noise, drills, ranks). Read that spec first; this one reuses its vocabulary.
This track is piece 7 on the command center's roadmap.

### How it fits the command center

| Command center | Here |
|---|---|
| The deck | Home for everything here. Onboarding level (N1) sits on it; network signals arrive in INCOMING SIGNALS like any other. |
| Signal or Noise | Network signals get extra clues: where it's going, how often and how much, and who owns the address. |
| THREAT → threat board | The threat board **is** the Evidence Board. A threat card can be opened as a case. |
| Dossier (piece 4) | Extended from "who made this program" to "who owns this address or domain" (N4). One Dossier, two kinds of subject. |
| Places map (piece 2) | The Wires district is where network places live; the three visibility levels are its zoom levels. |
| Drill bank, DRILL RANGE | Network drills join the same bank, with the same rules. |
| Ranks, points, ops log | Shared. Case-file grades earn points. The ops log is the raw timeline a case file draws on. Instructor review is gated on rank. |
| Breach Protocol (piece 3) | Contain/recover steps from a case file run through it like any fix. |

## Why

Watching network activity is hard to learn, but Device Rescue is already a
personal secops tool with a game wrapped around it, which makes it a good place
to teach it. The goal, in Liz's words: someone who finishes can **evaluate
network traffic, see where it's all going, what it's carrying, which device
it's coming from, and figure out who those people are from OSINT.** The top of
the ladder is **writing up an incident like a junior analyst would**. The final
exam is writing up real incidents on their own machine.

Reclaim City (the vendored submodule, v5.1.6) doesn't teach any of this. Its
network content is three "go change a setting" missions in The Grid (secure the
router, an IoT guest network, encrypted DNS) plus "check your router's
connected-devices list" in `smart_appliances-recon-inventory`. Those missions
are reused as next steps. The analysis side is new.

## Who it's for

Three starting points, chosen at onboarding:

| Level | Who | What changes |
|---|---|---|
| **Help me** | Frightened, wants the bottom line | Plain results, one step at a time, no jargon. The network ladder is offered, never pushed. |
| **Curious** | Wants to understand their computer | Lessons and clues also show the real thing underneath: the actual command and its output. |
| **Learning security** | Wants to learn the craft, maybe as a career | Raw output, harder drills, the case-file track, and the review ladder. |

The existing worries still choose *what* gets scanned. The level chooses *how
deep* it's explained. Anyone can change level at any time, and moving up is
part of the game.

## Goals

- Teach the network analysis skills in order, each first on invented traffic
  (drills) and then on the person's own traffic.
- Give the scanner the network visibility those skills need, at three levels of
  access (below).
- Teach incident response as a named loop, ending in a written case file.
- Store case files and show them two ways: an **Evidence Board** (fun) and a
  **Casebook** (real).
- Review case files on a ladder: game check → AI review → instructor review.

## Non-goals

- Seeing or capturing other people's traffic. Nothing pulls another device's
  traffic through this computer (no ARP spoofing, no MITM, no promiscuous
  sniffing of others, no active scanning of other people's devices). Blue team
  only.
- Decrypting anything. "What it carried" is taught as what metadata reveals and
  what encryption hides.
- Live packet capture by the app (see piece N10).
- Replacing the plain results route. Everything here lives in game mode, so the
  existing monitoring gate covers all of it. "Learning security" is a level
  inside game mode, not a separate surface.

## Anti-goals (would be a failure even if it worked)

- **Becoming a free incident-response service for frightened people.** The
  instructor queue is for learners who have earned it, with no "ask anyway"
  button. Scared people get the bottom line, "Copy for any AI", and the
  hotlines and advocates already in the guides.
- **Teaching surveillance.** Any lesson or feature that would work as well for
  watching a partner, housemate, or employee as for defending your own network
  is out. The network-control check (N5) is the gate, and the reason for it is
  taught as a lesson.
- **Leaking the person's life.** A case file about real traffic holds the sites
  they visit and their device names. It never leaves the machine unredacted.
- **Breaking "look, don't touch"** (`AGENTS.md`). Every new check is read-only.
- **Heavy checks inside `check()`.** Per the existing lesson that heavy scans
  froze the Mac, anything that watches over time is opt-in, time-bounded, and
  cancellable, never part of a default scan.

## Three levels of network visibility

| Level | Sees | Unlocked by |
|---|---|---|
| **1. This computer** | Its connections and which app made them, listening ports, DNS lookups, bytes in/out, timing | Always, on any network |
| **2. Devices on my network** | Who's on the Wi-Fi, who made each device, what's new since last time | The device list itself shows on any network, as today. Device memory and per-device detail need the network-control check (N5) |
| **3. The whole house's traffic** | Destinations and DNS **for the person's own devices**, from what the router or their own DNS filter already records | The person can sign in to their router themselves |

### Bright lines: other people's devices

Decided: **no superstalkers.** Owning the router doesn't make a housemate's or
partner's traffic yours to read.

- Full detail (destinations, DNS, timing) is shown only for devices the person
  has **marked as theirs**. Every other device appears only as its maker plus a
  count ("a device made by Samsung", "3 other devices"). There are no
  destinations, no DNS, and no history beyond "new since last time".
- Existing checks stay as they are, on any network, for teaching: the passive
  device list (`lan_device_inventory`, `arp_spoof_check`) and test connections
  to the router (`router_security_audit`). Checking the router is allowed. The
  plain scan's behaviour doesn't change.
- **Clicking a device they haven't marked as theirs is a teaching moment.**
  Instead of detail, they get a short explanation of where the bright lines
  are: your devices vs. other people's, your network vs. a shared one, looking
  at your own traffic vs. watching someone else's. It also covers why those
  lines exist (law, network rules, and safety). This is the same content as the
  network-control lesson and doesn't cost points.
- Marking a device as theirs is the person's own choice and answer, the same as
  the existing "It's mine" step.

## Teaching incident response

The IR lifecycle is mostly a matter of naming steps the game already plays
(mockup: `.superpowers/brainstorm/83317-1792353773/content/casebook.html`):

| IR step | In the game |
|---|---|
| 1 Prepare: know normal | Onboarding, "mark as mine", device memory (N5), baselines (N3) |
| 2 Detect | Scout's sweep, a signal in the queue |
| 3 Analyze | The network ladder skills, Signal or Noise clues, the address dossier (N4) |
| 4 Contain | Mission steps, with the safety check first |
| 5 Recover | Building liberated; a re-check confirms |
| 6 Learn | The case file → reviewed → Casebook |

## The skill ladder

Each rung is a Training Grounds lesson plus a set of network drills (same rules
as command-center drills: DRILL stamp, invented, never counted in integrity,
accuracy-tested against cited sources). Each rung teaches one section of the
case-file template.

1. **Read a connection:** app, remote address, port, state. → *Evidence*
2. **Names and numbers:** DNS; who owns an address (RDAP/WHOIS, ASN, reverse
   DNS, certificate transparency). → *Who's on the other end*
3. **Normal vs. odd:** baselines, beaconing (regular check-ins), volume, time of
   day. → *What happened* (timeline)
4. **What encryption hides and what it doesn't:** TLS, SNI, DNS, sizes, timing;
   spotting plaintext. → *What it carried*
5. **Devices:** hardware vendor IDs, randomized MACs, new-device detection. →
   *Scope*
6. **The whole house:** reading router and DNS-filter records (level 3). →
   *Scope*
7. **Learning-security level only:** reading a packet capture of their own
   traffic (N10).
8. **Capstone:** a full training case file, then real ones.

## Case files

One template, used for training and real cases:

- **What happened**: a timeline
- **Evidence (indicators)**: addresses, domains, process, device, timing, volume
- **Who's on the other end**: the OSINT done, and a confidence level
- **What it carried**: what's visible, and what encryption hid
- **Scope and severity**
- **Next steps**: from `docs/REMEDIATION_CATALOG.md` and the Reclaim City
  missions, never improvised

Evidence is dragged in from scans or drills. "Nothing found, and here's what I
couldn't see" is a valid real case file. Couldn't-check modules must be listed
(rule 3 in `AGENTS.md`).

### Two views, same cases

- **Evidence Board:** the working view. Evidence cards are pinned and tied
  together with string; there is one board per case, and a drawer of closed
  cases.
- **Casebook:** the record. A plain ticket list of training and real cases with
  status and grade, like a security team's queue.

### Review ladder

1. **Game check:** training cases only. They are graded against the case's
   known answer (indicators found, attribution, severity, next step), and the
   grade feeds rank.
2. **Prepare for any AI:** extends the existing "Copy for any AI"
   (`desktop/ai-prompt.js`). It builds a redacted packet plus a senior-analyst
   review prompt for the person to paste into any AI themselves. Nothing is sent
   by the app.
3. **Instructor review:** unlocked only by earning the rank, with no way to
   request it before that. When they earn it, the app prompts them to email
   **liz@themultiverse.school** "for a surprise" (Liz's wording; the app
   doesn't say what the surprise is). The app uploads nothing. The person
   attaches their own redacted case file to the email if they want.
   *My call on the gate:* reaching **SYSOP** on the command-center ladder **and**
   the last five graded training case files at B or better. Liz asked that
   people "test into a rank consistently", which is why one lucky grade isn't
   enough.

### Network-aware redaction

Today's redaction drops network identifiers wholesale, which would delete the
evidence. Case-file redaction instead keeps **public infrastructure**: public
IPs, ASNs, the domains under investigation, and certificate names. It removes
anything that **identifies the person**: private and LAN addresses, MACs, the
Wi-Fi name, the computer name, account names, home public IP, and destinations
that are the person's own browsing rather than case evidence. Presidio
(installed in `~/src/infinite_generative_tunnel`, not here) is an **optional**
extra pass over free-text sections. It's not required, because it needs a
large dependency and a model download.

## Roadmap (each piece gets its own spec → plan → build)

| # | Piece | Depends on |
|---|---|---|
| N1 | **Onboarding level**: the three starting points, stored with progress, switchable | command center 1 |
| N2 | **Network findings wired in**: give `modules/network/*` finding codes and remediation entries so they reach the game, setting buttons, and lessons; fix `docs/commands.md` (it says `lan_device_inventory`/`arp_spoof_check` run no commands, but they run `arp`, `ip neigh`, `route`, and it omits `router_security_audit`'s socket connections) | none |
| N3 | **Level 1 scans**: opt-in, time-bounded **connection watch** (repeated per-process connection snapshots: destinations, counts, intervals, volume where the OS exposes it); **DNS lookup observation**; connection and port checks on **Windows and Linux** (today mac-only) | N2 |
| N4 | **Address dossier (OSINT)**: the command center's Dossier (piece 4) extended to addresses and domains. RDAP/WHOIS, ASN, reverse DNS, cert transparency, threat-intel reputation | N3, command center 4 |
| N5 | **Network-control check + level 2**: detect obvious "not yours" networks; the person proves control by doing something only an owner can; **device memory** (LAN inventory history, "new since last time") | N2 |
| N6 | **Level 3**: import what the router or the person's own DNS filter records (device lists, DNS logs, traffic stats) | N5 |
| N7 | **Ladder lessons + network drill bank** | N1, command center 3 |
| N8 | **Case files**, IR teaching, Evidence Board (the command center's threat board) and Casebook | N7, command center 1 |
| N9 | **Review ladder**: game check, Prepare for any AI with network-aware redaction, the rank gate and the email prompt | N8 |
| N10 | **Own packet captures** (learning-security level). The person captures with Wireshark/tcpdump themselves and imports the file; the app analyses it read-only | N8 |

## Constraints

- Read-only everywhere (`AGENTS.md` rule 1). No `--auto`/`--yes` paths.
- Never ask for a password, one-time code, or recovery code. For level 3 the
  person signs in to their router themselves and exports or reads back what's
  there.
- **Outbound lookups are disclosures.** An OSINT lookup tells the lookup
  service which address the person is curious about. Owner's decision
  (2026-10-19): the connection watch looks up who runs each address
  automatically, with an off switch (see
  `2026-10-19-n4-who-is-on-the-other-end-design.md`). Lookups are only for
  public addresses and domains (never private ranges or the person's own IP),
  and the services are named where the person starts them.
- Couldn't-check is never clean: unsupported platforms and failed watches show
  as fog / COULDN'T CHECK.
- Monitoring-software gate carries over: if stalkerware or monitoring appears,
  game mode (and so this whole track) is withdrawn, per the existing gate.
- No drills about stalkerware, monitoring apps, or being watched (command-center
  rule). The network-control lesson explains *why* watching others is out, but
  doesn't drill it.
- `rescue/*.py` changes need the integrity manifest regenerated.
- No time estimates in any follow-on doc.

## Calls made while writing this (check these)

- **"Help me" is the plain route.** Onboarding asks plain route vs. game mode as
  today; "Help me" is the plain route's level and gets no game or ladder. Game
  mode then asks **Curious** or **Learning security**. So lessons and clues need
  two depths of text, not three. The level lives in the progress store,
  changeable from the deck.
- **Level 3 sources, first version:** exports from DNS filters the person runs
  (Pi-hole, NextDNS, AdGuard Home), plus a device list the person copies by
  hand from their router's admin page. Consumer router pages have no standard
  export, so no screen-scraping per router. People with only an ISP router can
  still do rung 6 through the hand-copied device list and a lesson on what their
  router can't show.

## Left to the builder

- How DNS lookups are observed on each OS without root (or what's shown as
  COULDN'T CHECK where that's impossible).
- Watch duration defaults and caps, and how history is stored (the command
  center's rule applies: dates and counts, no names or paths, unless the person
  is building a case file).
- Which OSINT providers to use, and whether an offline IP-to-ASN dataset ships
  with the app.
- The exact network-control proof.
- Grading rubric details for the game check.
- Visual design of the board and casebook, within the game's existing style.
