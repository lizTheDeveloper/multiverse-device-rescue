# Proposal: evidence escrow — send the checkup record somewhere safe, claim it once

Status: proposal for review by an advocate and a lawyer before anything is built (2026-10-23)

## In plain words

Someone who may be watched runs Reclaim City and it finds monitoring software. Today they can photograph a
**photo record** of what was found (see `docs/superpowers/specs/2026-10-23-photo-record-design.md`). This
proposal adds an opt-in second way out:

1. On the watched computer, they press **Send it somewhere safe**. The record is locked (encrypted) on that
   computer before anything is sent. Reclaim City's server receives a locked box it cannot open.
2. They get a **claim ticket**: a link and a short code. They write it down or photograph it.
3. On a phone or computer the other person can't reach, they open the link and **claim** the record. Claiming
   ties it to that device (a passkey). From then on only that device can open it, and the link stops working
   for anyone else.
4. The first claim wins. If someone else saw the ticket and claimed it first, the person's claim fails and
   tells them when it was claimed. That tells them someone is watching closely, which is itself evidence, and
   their photos still exist.
5. Every time the record is opened, the time and the kind of device go into an **access log** only the owner
   sees.
6. The record's fingerprint goes into a **public log** that anyone can check but no one can rewrite, so the
   person can later show "this record existed, unchanged, at 3:14pm on October 23".

What it proves: when the record existed and that it hasn't changed since. What it doesn't prove: that what the
checkup found is true. The checkup runs on the person's own computer.

## Who it's for, and the risks to them

- **It's opt-in and never the default.** The photo record works without it.
- **Sending is visible.** Whoever runs the home network can see that this computer contacted Reclaim City, even
  though they can't see what was sent. The button says so before anything is sent, in the same spirit as the
  removal warning: "Sending this can show up on your network. If someone controls your Wi-Fi, they may see
  that something was sent."
- **The ticket is shown on the watched screen.** If the watcher records the screen, they can see it. The design
  makes a stolen ticket useless after the first claim, and makes a claim race noticeable. It can't make the
  screen secret.
- **No email, no text messages, no camera.** Codes sent by email or text can land in accounts the watcher
  reads; camera checks would put the person's face on a server. None of these are used.

## The design

### Pieces (all on Cloudflare)

- **A Worker** serving the upload, claim, view and log endpoints, and the claim page on the Reclaim City site.
- **A Durable Object per record**: the single place that decides claim-once and appends to that record's access
  log. Its storage is transactional, so two claims at once can't both win.
- **A Durable Object for the public log**: the append-only Merkle tree, the one writer that adds leaves and
  signs the tree head.
- **R2** for the encrypted records (small: a record is facts, never images; capped at 100 KB).

### The "contract": rules enforced by code, not a chain

The rules live in the Durable Objects and are published with the code. Anyone can check that the log follows
them, because the log is a Merkle tree with signed heads, as Certificate Transparency logs are:

1. **Append-only.** Leaves are only ever added. Each new signed tree head comes with a consistency proof that
   the old tree is a prefix of the new one. A log that rewrote history would be caught by anyone holding an
   older head.
2. **What a leaf may hold:** a record's fingerprint, the hash of its encrypted box, and the time; a claim event
   (record id hash, time); an access event (record id hash, time, device kind). Never content, never IP
   addresses, never names.
3. **Claim once.** A record moves `unclaimed → claimed(passkey)` exactly once. Every later claim fails and
   returns only the time of the first claim.
4. **Views need the passkey** registered at the claim, or a share link the owner made (below). Each view is
   logged before the box is sent.
5. **Delete is real.** The owner can delete the box; the server destroys it and logs a tombstone (see "Unknown"
   below: the platform keeps restore points for 30 days). The log keeps
   the fingerprint, so "a record existed" survives, but nothing readable does.
6. **Unclaimed records expire** and are destroyed after a set period (a retention choice for the review).
7. **Not just our word on time.** The log's signed head is periodically anchored with an independent timestamp
   (an RFC 3161 timestamp authority or OpenTimestamps), and can be cosigned by independent witnesses, so we
   can't quietly backdate or fork it.

### Keys

- The record is encrypted on the person's computer with a fresh random key (AES-256-GCM, Web Crypto).
- The key travels only in the claim ticket: in the link's `#fragment`, which browsers never send to a server,
  and as a short code to type if the link is copied by hand.
- Reclaim City's server never has the key. A breach, or a demand to hand over data, yields locked boxes, the
  public log, and the access logs' times and device kinds.

### Sharing with an advocate or lawyer

The owner can make a **share link** for one person. It's logged like a view, can be limited to one opening, and
can be revoked. The advocate's views appear in the owner's access log.

### What the person sees

- On the watched computer: **Send it somewhere safe** in the photo record, the network warning, then the ticket
  page (the link in large type, the code in groups of four, "Write this down or take a photo of it").
- On the safe device: the claim page (create a passkey), then the record's pages (the same pages as the photo
  record, with the fingerprint and "Recorded in the public log at …"), the access log, share links, and
  delete.

## Questions for the advocate and the lawyer

1. **Holding it at all:** what does holding encrypted evidence for people in danger expose the project to
   (subpoenas, preservation requests, discovery), given we can't read it? What should the terms say?
2. **Metadata:** the access log and public log hold times and device kinds. Could either harm someone (proving
   a person was preparing to leave, for instance)? Should the public log hold fingerprints only, with claims
   and views kept private to the owner?
3. **Retention:** how long should unclaimed records live? Should claimed ones expire?
4. **Courts:** what do courts and advocates need to accept a timestamped, unchanged record (the fingerprint,
   the log entry, the independent timestamp)? Is a printed verification page useful?
5. **Abuse of the service:** encrypted storage can be misused. Is a 100 KB cap on structured facts (no images,
   no files) enough, and what else is expected of us?
6. **Partners:** should this live with an advocacy organization instead of with Reclaim City? None of the
   evidence services found accepts records from another app (see below), so a partner would need to host it or
   take it over.
7. **Jurisdiction:** does anything change for users outside the US?

## Not in this proposal

Proving the findings true; images or files; any automatic sending; email or text notifications; camera or face
checks; device identifiers such as MAC addresses (reported by the app itself, easy to fake, and a privacy leak).

## Existing services and APIs

Checked 2026-10-23. Nothing runs this whole system for us, and no evidence vault accepts encrypted records from
another app: NNEDV's DocuSAFE shut down on 2023-10-01; VictimsVoice, Kulpa (UK), ARC (Australia), ProofMode,
eyeWitness to Atrocities and Truepic either have no public API or do something else (proving a photo came from a
camera). Most of the hard parts exist, though.

**Use off the shelf**

- **The log: Cloudflare's Azul** (github.com/cloudflare/azul, BSD-3, Rust on Workers). Built for exactly this
  shape: one sequencer Durable Object per log, tiles and checkpoints in R2. Its `generic_log_worker` is a tiled
  Merkle log that isn't tied to certificates, and `@cloudflare/tlog-tiles-wasm` / `@cloudflare/signed-note-wasm`
  (npm 0.3.0) can be called from a JavaScript Worker. Its README warns it depends on Durable Objects handling one
  request at a time, which is also what claim-once relies on.
- **The formats: C2SP** (tlog-tiles, tlog-checkpoint, signed-note, tlog-cosignature, tlog-witness), so any
  outside tool can check our log.
- **Independent time:** anchor each signed tree head (not each record, so no person's fingerprint goes to a third
  party) with **Sigstore's timestamp service** (RFC 3161; the only one found that a browser can call directly,
  tokens about 1.2 KB), **FreeTSA** as a backup called from the Worker, and **OpenTimestamps** (anchored in
  Bitcoin; checking it trusts no one; the proof completes after a few hours).
- **Witnesses:** witness-network.org (experimental) and Google's witnesses (not yet in production). Azul's
  `mirror_worker` can be a witness, but it only counts if someone independent runs it.
- **Claim-once: Durable Objects with SQLite.** One request at a time per object, replies held until the write is
  on disk, and `transactionSync()` rolls back on any error: "check unclaimed, mark claimed, append to the log" in
  one block can't be won twice. One object per record keeps each person's record separate. A 100 KB record fits
  in a Durable Object row, so R2 is optional for the boxes.
- **Passkeys: SimpleWebAuthn** (MIT), which lists Cloudflare Workers as supported; to be tested there.

**Build ourselves**

The escrow Worker (upload, claim-once burn, passkey binding, access-log entries written into the log), the
verification page the photo record points to, and the rules above as code.

**Don't use**

Sigstore Rekor or Sigsum for each record: every entry needs a signing key and is public forever, so a key reused
across one person's records would link them.

**Unknown, to settle before building**

1. **Deleting may not be immediate.** Durable Objects can be restored to any point in the last 30 days, so a
   deleted or burned record may be recoverable by the operator (or under a legal demand) for up to 30 days. The
   boxes are still encrypted with a key the server never has, but rule 5 should say "destroyed, and
   unrecoverable after 30 days" unless Cloudflare offers a way around it. This belongs in question 1 above.
2. Whether witness-network.org will list a log like this, and on what criteria.
3. The real limits and terms of Sigstore's and FreeTSA's free public services.
4. Whether Azul's generic log is meant for outside use (actively developed, but its own CT logs are described as
   test logs).
5. Cloudflare's view on hosting end-to-end-encrypted user content: its terms say nothing specific.
