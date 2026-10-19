# N4 (first part): who's on the other end, looked up automatically

Piece N4 of the network analysis track (parent:
`2026-10-18-network-analysis-training-design.md`), first part: the address
dossier for the connection watch. Also folds in two fixes the N3 screenshots
showed. Owner's direction (2026-10-19): "do dig automatically, search who they
are automatically". Calls marked **(my call)** are mine, made without a
question round at the owner's request.

## Decision that changes the parent spec

The parent spec said outbound lookups are "per-item and explicit". **The owner
overrode that: lookups run automatically after a watch.** What stays from the
old rule: only public addresses are ever looked up (never private, loopback,
link-local, multicast, CGNAT, reserved), the services are named where the
person starts the watch, and there is an off switch. The parent spec's
constraint line is updated to say so.

## What the person gets

After a watch, each destination an app talked to carries who runs it:

| Field | Source | Example |
|---|---|---|
| Hostname | reverse DNS through the computer's own resolver | `dns.google` |
| Network owner and AS number | RIPEstat prefix overview (`stat.ripe.net`) | `GOOGLE - Google LLC`, AS15169 |
| Registered network and registrant | RDAP via `rdap.org` (redirects to the registry: ARIN, RIPE, APNIC, LACNIC, AFRINIC) | `GOGL`, registrant `Google LLC`, country when the registry gives one |

**(my call)** RIPEstat and rdap.org because both are free, keyless, run by or
for the internet registries, and answer for every region. Threat-reputation
services need keys and send more; they're left for a later part.

## Fix 1: one watch signal, not twenty

A 1-minute watch on a real Mac made about 20 low-priority signals, one per
app. **(my call)** The game shows the watch as **one** signal, "Connection
watch: N apps talked to M places", and opening it shows the clue **WHERE THEY
WENT**: per app, its destinations with who runs each, busiest first. The
engine keeps its per-app findings (codes unchanged); only the game groups
them.

## Fix 2: show where, not just how many

An app's note said "connected to 2 places" and never which. The destination
list (address, port, and now who runs it) is shown in the WHERE THEY WENT clue,
and the engine's `watch_summary` description names the top destinations by
owner ("mostly Google LLC and Cloudflare").

Also **(my call)** a rollup line at the top of the clue: the organisations the
whole computer talked to, by number of apps, e.g. "Apple Inc. (9 apps), Google
LLC (4), Cloudflare (3)". That's the teaching hook for later lessons.

## Engine design

- `rescue/whois.py` (stdlib only): `is_lookupable(ip)`, `reverse_dns(ip)`,
  `ripe_overview(ip, fetch)`, `rdap(ip, fetch)`, and
  `look_up_all(ips, *, fetch, resolve, limit, workers, timeout, budget) ->
  {ip: who}`. `fetch` and `resolve` are injected so tests never touch the
  network.
- **Bounds (my call):** at most 150 distinct addresses per watch (busiest
  first), 6 at a time, 4 s per request, 60 s for the whole lookup step; past
  that, the rest are marked "not looked up" and `watch_incomplete` says why.
  Results are cached in memory for the run only: nothing about the person's
  destinations is written to disk.
- **HTTPS in the frozen engine (my call):** the context uses the platform's
  trust store. On macOS that means loading the system roots with `security
  find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain`
  (through `rescue.command.run`), because the bundled Python's default CA path
  may be empty. Windows and Linux use `ssl.create_default_context()`. A TLS or
  network failure is couldn't-check for that field, never an error for the
  watch.
- `User-Agent: ReclaimCity/<version>` and RIPEstat's `sourceapp=reclaim-city`.
- `rescue watch` looks up by default; `--no-lookups` turns it off. The JSON
  gains `data.who` on each destination and `data.lookup_sources` on
  `watch_summary`; `watch_incomplete` names lookups that failed, were skipped
  or were turned off.
- The `rescue watch` text and walkthrough say which services were asked.
  `docs/commands.md` lists the two HTTPS endpoints and reverse DNS as the
  watch's network use.

## Desktop design

- The watch panel gets a checkbox, on by default: **"Look up who runs each
  address (sends the addresses, not what was in them, to RIPE NCC and
  rdap.org)"**. Off → main passes `--no-lookups`. The idle sentence no longer
  says "Nothing leaves this computer" while lookups are on; it says what is
  sent and to whom.
- Main validates the flag as a boolean over IPC; nothing else crosses.
- The grouped watch signal, its WHERE THEY WENT clue and rollup line are pure
  view code (clues.js / signal view). Ask/Copy-for-AI stay hidden for watch
  findings.
- Plain view isn't touched (owner: plain view may be dropped).

## Non-goals

- Automatic lookups outside a watch, or any lookup of other devices' traffic.
  (`rescue lookup` is explicit: the person types each address.)
- Threat reputation, certificate transparency, geolocation databases.
- Storing lookup results between runs.

## Testing

- Engine: classification of every address range; parsing of real RIPEstat and
  RDAP responses saved as fixtures (Google 8.8.8.8, a RIPE-region address, an
  APNIC one, an RDAP 404, a malformed body); bounds (limit, budget, timeout),
  fetch failures → per-field couldn't-check; `--no-lookups`; nothing written to
  disk; the frozen engine can make one HTTPS request (release smoke step).
- Desktop: the checkbox reaches main as a boolean and becomes `--no-lookups`;
  one grouped signal per watch; the clue's lines and rollup; copy changes;
  escaping of every looked-up string (registry text is untrusted).
