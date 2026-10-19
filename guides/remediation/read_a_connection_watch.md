---
title: "Read a connection watch"
estimated_time: ""
platforms: [macos, windows, linux]
remediates:
  - network.connection_watch.watch_summary
  - network.connection_watch.regular_checkins
  - network.connection_watch.new_listener
  - network.connection_watch.upload_heavy
  - network.connection_watch.dns_lookups
  - network.connection_watch.dns_not_visible
  - network.connection_watch.watch_incomplete
steps_for:
  network.connection_watch.watch_summary: [1, 2, 3, 5, 9]
  network.connection_watch.regular_checkins: [1, 2, 3, 4, 9]
  network.connection_watch.new_listener: [1, 6]
  network.connection_watch.upload_heavy: [1, 3, 5, 9]
  network.connection_watch.dns_lookups: [1, 3, 7, 9]
  network.connection_watch.dns_not_visible: [1, 8]
  network.connection_watch.watch_incomplete: [1, 8, 9]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7, 8, 9]
monitoring_risk: false
---

This walkthrough covers the connection watch (`rescue watch`), which looks at
this computer's network connections again and again for a few minutes and
then summarises what each program did. Everything it reports is information,
not a warning: most of what it shows is ordinary app traffic. Nothing here
asks you to stop or remove anything.

## Step 1: Know what the watch is and what it isn't

The watch is a record of what the programs on this computer did while it was
running: where each one connected, how often, and, where the computer shows
it, how much data went each way. It only reads the list of connections your
computer already keeps, and it changes nothing. When it finishes, it looks up
who runs each internet address it saw (step 9 says what that sends, and to
whom), unless that was turned off.

It only sees this computer's own connections, never another device's
traffic. And it only saw the minutes it ran for. A quiet watch lowers the
odds of a problem without ruling one out, and anything it couldn't see is
listed as couldn't-check, which is not the same as clean.

## Step 2: Read a destination and its port

Each destination is an address, a port and a protocol (TCP or UDP), with how
many of the watch's looks saw it and when it was first and last seen.

- **The address** is the other end of the connection. An address on your own
  network (starting 10., 172.16 to 172.31, or 192.168.) is a device in your
  home or office, like a printer or another computer. Connections a program
  makes to this computer itself are counted, not listed.
- **The port** says which kind of service the program says it is talking to:
  443 is HTTPS (encrypted web traffic) and 80 is plain HTTP, 53 is DNS (name
  lookups), 993 and 587 are mail, 22 is SSH, and 5223 and 5228 are Apple and
  Google push notifications for chat and mail apps. Many legitimate apps use
  other ports for their own features. The program picks the port, so a port
  number does not prove who is using it.
- **How many looks saw it** tells you whether a connection stayed open the
  whole time or came and went.

The most useful question is usually about the program, not the address: do
you recognise it, and does talking to the internet fit what it does? If you
don't recognise a program, search for its name to see if it is a known app.

## Step 3: Know what encryption hides and what it doesn't

A connection on port 443 (HTTPS) is encrypted, and so are many on other
ports. Encryption hides what is inside: the pages you read, what you type,
your passwords and messages. Anyone along the way sees only scrambled data,
and the watch never sees what is inside either. (The exception is a rogue
root certificate: it lets whoever installed it read traffic that the padlock
says is encrypted. On a Mac, the full checkup looks for those.)

Encryption does not hide the outside of the conversation, and that is what
the watch shows: which address this computer talked to, on which port, when,
how often, and how much data went each way. The name of the site is usually
visible too. Name lookups (DNS) are often sent in plain text, and even an
encrypted connection usually announces the site's name as it starts (this is
called SNI). Encrypted DNS hides the lookups from your internet provider, but
the provider still sees which servers you connect to.

## Step 4: Know why apps check in

A steady check-in means a program opened a new connection to the same
internet address at least four times during the watch, at a gap that hardly
changed (by less than a fifth). Most apps do this: mail, chat, cloud storage
and updaters check for new messages and updates on a timer. On its own, a
regular check-in isn't a sign of a problem, which is why it is shown as a
pattern worth knowing about and not as a warning.

Unwanted software can check in on a timer too (people who study attacks call
this "beaconing"), so the rhythm alone can't tell the two apart. What tells
them apart is the program. If you recognise it and it is something that
would reasonably check for messages or updates, there is nothing to do. If
you don't recognise it, search for its name to see if it is a known app, and
run the full checkup, which looks at the programs themselves.

## Step 5: Read bytes in and out

Where the computer shows it, the watch adds up how much each program received
and sent while it ran. Most programs receive much more than they send:
reading web pages, streaming and downloading all bring data in.

A program that sent much more than it received (more than 10 MB, and more
than three times what it received) is pointed out separately. That is normal
for backups, cloud sync and video calls. If you don't recognise the program,
it's worth finding out what it is before anything else.

Not every computer shows these numbers to an ordinary account. A Mac shows
them for each program it can see. Linux shows them only for your own
programs. Windows doesn't show them per program without admin rights, so a
watch on Windows says it couldn't see them instead of showing zero.

## Step 6: Read a port that started listening

A program that starts listening is waiting for other devices to connect to
it. Apps do this for things like sharing, syncing and developer tools. The
finding says what the next full checkup would make of it: an ordinary
service it wouldn't raise, a port whose owner it couldn't confirm (mentioned
without a warning), or one it would point out so you can decide whether you
expected it.

If you don't recognise the program, see which program holds the port:

- **Mac:** in Terminal, `lsof -iTCP -sTCP:LISTEN -nP` lists every listening
  port and its program.
- **Linux:** in a terminal, `ss -tlnp` lists listening ports and their
  programs. Programs that belong to other accounts show only when an
  administrator runs `sudo ss -tlnp`.
- **Windows:** open Resource Monitor (type "Resource Monitor" in the Start
  menu), go to the Network tab and look under Listening Ports.

Then run the full checkup, which judges listening ports the same way and has
its own walkthrough for any it points out.

## Step 7: Read the names looked up (Windows)

On Windows, the watch also lists the names (like website addresses) this
computer looked up while it ran, with when each first appeared. Windows
doesn't record which program asked for each name, so a name can't be tied to
a particular app. The closest you can get is to line up when a name first
appeared with the connections that started around the same time.

A name in the list means something on this computer looked it up. It doesn't
say which program, or whether a connection followed.

## Step 8: When part of the watch couldn't be seen

The watch says plainly what was out of view, because couldn't-check is not
the same as clean. Things it may list:

- **Looked-up names.** A Mac shows an ordinary account no lookup names, and
  Linux needs admin rights to show them, so the watch says it couldn't see
  them. On Windows it says so if the list couldn't be read. A DNS filter that
  keeps a log can show them; that's part of a later level of the checkup.
- **Bytes in and out.** Windows doesn't show them per program without admin
  rights. Linux shows them only for your own programs.
- **Other accounts' programs.** A Mac shows connections only for programs
  running as you, and Linux shows which program owns a connection only for
  your own programs, unless the check runs as admin. On Linux, an
  administrator can see every owner with `sudo ss -tnap`.
- **Stopped early, or looks that failed.** The result covers only the time
  that was gathered.
- **Who runs an address.** If looking up was turned off, or some addresses
  couldn't be looked up, the watch says so (step 9 explains the lookups).
- **Too much to list.** The watch keeps at most 2,000 program-and-destination
  pairs and the timing of 200 connections per pair. Beyond that it keeps
  counting and says how many more there were.

If the watch gathered nothing, it says nothing about your connections either
way. Running it again for the full time, without stopping it early, gives the
fullest picture this computer allows.

## Step 9: Read who runs an address

After the watch, Reclaim City looks up who runs each internet address it
saw, so a destination reads as a company's name and not just a number. The
name comes from the internet registries, the organisations that hand out
addresses, and from the address's own name in DNS.

- **Most names are hosting and cloud companies.** A few companies (such as
  Amazon, Google, Microsoft, Cloudflare and Akamai) run the computers behind
  a large part of the internet, and many apps rent space from them. So the
  name says who runs the address, which is not necessarily who made the app.
  A chat app that talks to "Amazon.com, Inc." is usually just hosted there.
- **The name is the network's holder.** The name shown is the company whose
  network the address belongs to, as the registries list it, not every
  customer using it. Where that isn't known, it is the company registered for
  the address, or the address's own name in DNS, but only if that name leads
  back to the same address (anyone who runs an address can give it any name,
  even a famous one). A name you don't recognise is worth searching for; it
  isn't a sign of a problem on its own.
- **What was sent.** Only the addresses were sent, never what was in the
  connections, to these services: your computer's own name lookup (reverse
  DNS, which asks your DNS provider), RIPE NCC (stat.ripe.net) and rdap.org,
  which sends your computer on to the regional registry that holds the
  address (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC) to ask it directly.
  Addresses on your own network and other private addresses are never sent.
  Each service learns which addresses were asked about. Like any website,
  each also sees your computer's public internet address and that the
  question came from Reclaim City. The lookups keep no
  copy of their own: the answers are only part of this watch's result.
- **When a name is missing.** If the computer was offline, or a service
  didn't answer, the watch says how many addresses it couldn't look up, and
  how many it found out only part of. It looks up at most the 150 busiest
  addresses and stops looking after 60 seconds. If you stop the watch early,
  it still looks up what it gathered, for at most 10 seconds, and stopping
  again ends that at once. It says so when any of these cuts the lookups
  short. Couldn't-check is not the
  same as clean.

To turn the lookups off, untick "Look up who runs each address" before
starting the watch in the app, or run `rescue watch --no-lookups`. The watch
then shows addresses as numbers and says that looking up was turned off.

The program is still the better question: whether you recognise it, and
whether the pattern and the companies it talked to fit what it does.
