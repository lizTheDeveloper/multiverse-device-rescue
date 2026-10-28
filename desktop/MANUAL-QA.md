# Manual QA

Checks a person runs on a real Mac before a release. Run them from the
repository root, with the engine installed in `.venv` (see the README).
Start the app against that engine, not an old build in `desktop/engine/`:

```bash
cd desktop && RESCUE_ENGINE="$PWD/../.venv/bin/rescue" npm start
```

The first time a worry is picked on a clean slate, "One more question" appears
(see "The question and the two modes"). In every section except those two,
answer **No** to it, so the game runs in standard mode.

## Game mode, end to end

Set up a harmless test launch agent:

```bash
mkdir -p ~/Library/LaunchAgents ~/Library/Application\ Support/.dr-qa
printf '#!/bin/sh\nexit 0\n' > ~/Library/Application\ Support/.dr-qa/helper && chmod +x ~/Library/Application\ Support/.dr-qa/helper
cat > ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.devicerescue.qa.helper</string>
<key>ProgramArguments</key><array><string>/Users/USER/Library/Application Support/.dr-qa/helper</string></array></dict></plist>
EOF
sed -i '' "s#/Users/USER#$HOME#" ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist
```

Then run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start` and check:
1. Click **Play it as a game**, then **I'm not sure**. The checkup starts by itself on the sweep screen. When it finishes, the city appears with The Gatehouse dark, and DevTools' Console shows no CSP errors.
2. DevTools → Network, filtered to "All": every request is `app://rescue/…`. There is no `https://`.
3. Open The Gatehouse, then the `com.devicerescue.qa.helper` mission. Click **Fix it for me**, check that the panel text matches the list view's, and click **Yes, fix it**. "Checking again" appears, then **RECLAIMED**.
4. Clear a district: in The Gatehouse (or another district with no **COULDN'T CHECK** panel), fix or do every remaining mission until each re-check says **RECLAIMED** (marking one as yours also counts). After the last one, answer **How did that go?**. The button reads **SEE THE GATEHOUSE**, and it opens **DISTRICT TAKEN BACK** with every fixed mission listed under **FIXED AND CHECKED**. The district screen still lists them, each with a **RECLAIMED** badge, and the map card shows **N RECLAIMED**, not **NOTHING FOUND**. A district with a **COULDN'T CHECK** panel never offers this screen.
5. Click **LIST**. The finding is gone from the list view too. Click **See it as a city** to go back.
6. Go back into the city, to the RECLAIMED screen of that mission (do the fix again if needed), and click **Undo**. "Checking again" shows while it re-checks, then **PUT BACK** with "Put back. It’s showing again.", and the building is dark again on the map. Scout doesn't say "Something you fixed came back". Then run a full checkup from the list. The mission is still open, not reclaimed.
7. Start over, pick **I think someone is watching me**, and run the checkup. No question is asked. The checkup runs on the sweep screen, and the city opens with the generated district's tile on it (see "City mode" below).
8. Clean up: `rm ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist; rm -r ~/Library/Application\ Support/.dr-qa`.

## One city (Spec B)

Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start` and check:
1. Click **Play it as a game**, then **I think I've been hacked**. The checkup starts by itself; when it finishes, the map shows "YOUR COMPUTER" with the device districts, then "YOUR ACCOUNTS", and the view is scrolled to The Master Keys. The HUD reads CONFIRMED and YOU REPORTED, with no RECLAIMED, and there are no payment links anywhere.
2. Open The Master Keys. The survey ("Do you have a Gmail account?") toggles, and a toggled account appears or disappears.
3. Open a Gmail mission and click **GO DO IT**. The page opens in your browser, not in the app, and the app moves to the debrief. Answer it and **SUBMIT REPORT**. You land back on the district, and YOU REPORTED goes up by 1.
4. Open The Perimeter, then **Harden Your Computer**. Every step has a badge: CONFIRMED BY YOUR COMPUTER, PROBLEM FOUND, COULDN'T CHECK, FOR WINDOWS COMPUTERS, or YOURS TO CHECK. If FileVault is off, PROBLEM FOUND links to the device mission.
5. If every Mac step is confirmed, click **FINISH FROM THE CHECKUP**. CONFIRMED goes up by 1, not YOU REPORTED. Then, in DevTools, delete the `device-rescue.game.scan-confirmed.v1` key and reload. That mission now counts under YOU REPORTED.
6. Find a step whose link isn't https (the Firefox `about:preferences#privacy` step in a browser-privacy mission, for example **Harden Your Browser** in The Trail). Clicking it shows "This link can't be opened from here" and the URL to copy. Nothing opens.
7. A link to `#/quiz/phishing` (a Quick Quest or the phishing chapter, if one shows) lands on the one-city map. The address in DevTools (`location.hash`) doesn't change.
8. DevTools → Network: every request is `app://rescue/…`. The pages opened in step 3 open in the system browser, not as requests from the app.
9. Open a district's milestone (finish every mission in one). It lists missions under CONFIRMED BY YOUR COMPUTER and YOU REPORTED, and there is no share card.

## Training Grounds and the final boss

Set up the test launch agent from "Game mode, end to end" first. Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start`, with DevTools open, and check:
1. Click **Play it as a game**, then **Someone is on my Wi-Fi…**. The checkup starts at once on the sweep screen (THE SWEEP), with no Training Grounds first. "POP-UPS YOU MIGHT SEE" is listed above the districts, and any macOS permission pop-up that appears matches one of the tips.
2. While it runs: the bar moves and districts change from WAITING to SWEEPING to SWEPT. No district says safe or clear. The Gatehouse, The Wires and The Foundations each show **LEARN ▶**; The Engine Room and The Junkyard have no cue and do nothing when clicked. The district being swept has a bright border and "Scanning now — learn about it". With VoiceOver on, Tab reaches the districts, and each is read as "Learn about …", followed by its state. Focus stays on the district you're on as the sweep moves.
3. Click the district marked "Scanning now". Its lesson opens, with **BACK TO THE CHECKUP ▶** at the bottom. Answer question 1 wrongly: the feedback shows, the option is marked, and **NEXT QUESTION** appears. Click **BACK TO THE CHECKUP ▶**. That district still shows **LEARN ▶**.
4. Click **The Wires** and finish "Who's on your Wi-Fi". You're back on the sweep, and The Wires shows **DONE ✓**. Click **The Gatehouse**: "The tool that asks for your password" opens, the first unfinished Gatehouse lesson for this worry.
5. Click **ALL LESSONS** on the sweep. The Training Grounds lists every lesson, including "Spot the fake message" and "What “couldn’t check” means", which no district opens. The HUD reads `1/8 LESSONS`, and the bottom button is **BACK TO THE CHECKUP ▶**.
6. Open any lesson and answer one question. When the scan finishes, you stay on that question: the banner "Your checkup is done." appears, and the answer you picked is still shown. Click **SEE YOUR CITY ▶** and the city appears. A district where some checks couldn't run has a dashed grey border and a **COULDN'T CHECK** badge. It is never lit. (In System Settings → Accessibility → Display, with Reduce motion on, the sweep's moving light doesn't move.)
7. Click **TRAINING** in the HUD and finish "Things that start on their own". The banner offers **SEE YOUR CITY ▶**, and the bottom button reads **RUN THE CHECKUP AGAIN ▶**. Open The Gatehouse, then the `com.devicerescue.qa.helper` mission. The briefing shows "You learned about this in the Training Grounds" and links to the lesson.
8. With the test launch agent still in place, click **LIST** in the HUD, then **Start over**, then **Play it as a game** and **Someone is on my Wi-Fi…**. Click **PLAIN VIEW** on the sweep mid-scan. The plain scan screen shows live progress. When it finishes, the list results show, not the city.
9. Simulate a failed scan: quit, run with `RESCUE_ENGINE=/usr/bin/false`, click **Play it as a game** and pick a worry. You land in the Training Grounds with "THE CHECKUP STOPPED" and **START THE CHECKUP ▶**.
10. Start over and pick the iPhone worry after **Play it as a game**. The plain scan screen opens, waiting for **Run checkup**: no sweep, no lessons, and no checkup started for you.
11. Simulate monitoring software. Quit, save this as `/tmp/fake-rescue`, and run `chmod +x /tmp/fake-rescue`:
    ```sh
    #!/bin/sh
    echo '{"schema_version":1,"platform":"darwin","modules":[{"name":"stalkerware_scan","category":"security","status":"ok","error":null,"supported":true,"findings":[{"title":"Monitoring app found (test)","description":"Test only.","severity":"critical","category":"security","data":{}}]}]}'
    ```
    In DevTools' Console run `localStorage.setItem('device-rescue.display', 'standard')` and reload. Run with `RESCUE_ENGINE=/tmp/fake-rescue`, click **Play it as a game** and pick **I’m not sure — check everything**. When the sweep finishes, "We found something that can be used to watch a computer. Is that something you know about?" appears before anything else. Click **Yes, I know about it**: the city opens, and on the list (**LIST**) the card has one line, "Removing this can alert whoever installed it. Read this first.", which opens to the full note. Keep `/tmp/fake-rescue` for "City mode" below.
12. DevTools → Network: every request is `app://rescue/…`, including `rc/data/phishing.js`.
13. Clean up the test launch agent as in "Game mode, end to end", step 8.
14. Network findings. On a Mac with a proxy configured (System Settings → Network → your connection → Details → Proxies), run a checkup and open The Wires. The proxy mission shows walkthrough steps and an **Open in System Settings** button that opens Network › Proxies. A router, ARP or LAN mission has no such button. After upgrading from a build without network codes, any network mission previously marked "later" reopens once, because its saved progress was keyed by the old title-based identity. That is accepted, not migrated.
15. Router button. On your home network, run a checkup for "Someone's on my Wi-Fi". In the plain results, the router findings (an open admin service, UPnP, "Router settings that this check cannot see") and the device-list findings show **Open your router's settings**, with a line naming the router's address and your default browser ("in Safari"). Clicking it opens `http://<router address>/` in that browser and nothing else; the app never asks for the router password. In The Wires, the same missions show **OPEN YOUR ROUTER ▶**, and so does the "Where is the full list of devices on your network?" question in the "Who's on your Wi-Fi" lesson once the checkup has run. If the ARP check reported another device answering for your router, a fake-looking router ID or more than one router, there is no button anywhere; the text says to check the address on the router's label first.
16. Connection watch. The engine must be a build with `rescue watch` (rebuild `desktop/engine/rescue` if it's older). Click **Play it as a game**, then **I'm not sure**. Before the checkup finishes, nothing says WATCH CONNECTIONS. On the deck, under RANK, **WATCH CONNECTIONS** says it watches which apps connect where "for 5 minutes, then looks up who runs each address", and that results last until your next checkup. The checkbox "Look up who runs each address (sends the addresses, not what was in them, to RIPE NCC, rdap.org and the regional registry that holds each one, and asks your DNS provider for their names)" is ticked. The minute buttons are 1, 2, 5, 10, 15 and 30, with 5 pressed. Press **1**: the sentence says "for 1 minute" and the box stays ticked. Press **START THE WATCH ▶**. The line reads "Watching… 0 of 1 minute, N snapshots." ("1 snapshot" when there is one) and the snapshot count goes up every few seconds while you open a signal, tag it and close it again. VoiceOver reads the line, and focus moves to **STOP**. When the minute is up, the line reads "Looking up who runs each address… N of M." and N goes up to M. Then the instrument says "Watch finished. What it saw is in INCOMING SIGNALS." Open **LOW-PRIORITY SIGNALS**: the apps the watch saw are one row, "Connection watch: N apps talked to M places" (M counts distinct addresses; "M+ places" when an app talked to more than its list holds). Anything else the watch noted (regular check-ins, a new listener, a heavy upload, a gap in what it could see) keeps its own row. Open it and press **SCAN CLUE: WHERE THEY WENT ▶**. The first line starts "Talked to:" with company names and how many apps talked to each (for example "Apple Inc. (5 apps), Google LLC (3)"); then one line per app, busiest first, each place as "company (address:port)", a bare address where nobody could be named, or "name (unverified)" for a reverse name that didn't lead back to the address; at most 8 places an app, then "and N more". Then any gaps, and "Looked up with: …" naming reverse DNS, RIPE NCC and rdap.org. RANK points don't go up, and tagging it adds no points. Untick the box: the sentence goes back to "Nothing leaves this computer". Run a 1-minute watch: no "Looking up…" line appears, and WHERE THEY WENT shows addresses only and says "Not looked up (turned off)." once. In DevTools → Application → Local Storage → `device-rescue.game.v1`, nothing says `connection_watch` or an app's name from the watch. Start a 5-minute watch and press **STOP** after about a minute. The line at once reads "Stopping… finishing what was gathered." and stays that way until the watch ends early (the app waits up to 75 seconds before giving up on it); what it gathered still arrives in INCOMING SIGNALS. Start another watch and quit the app while it runs: the app closes within about 5 seconds, and Activity Monitor shows no `rescue` process left behind. Click **LIST**. The watch's findings are in the plain results with no **Ask about this** or **Copy for any AI** button; other findings keep theirs. While a watch runs, the top bar shows RE-SWEEP AFTER THE WATCH in place of **RE-SWEEP ⟳**; the button comes back when the watch ends. After a full checkup, the watch's row is gone and the instrument is back to its first sentence. With the fake monitoring engine from step 11, there's no deck and so no watch.

## Command center (the deck)

Set up the test launch agent from "Game mode, end to end" first. Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start`, with DevTools open, and check:
1. Click **Play it as a game**, then **I'm not sure**. When the sweep finishes, the deck appears: **INCOMING SIGNALS** on the left, the city in the middle, **CITY INTEGRITY**, **SIGNALS** and **RANK** on the right, and the **OPS LOG** at the bottom with a SWEEP line. The top bar shows RANK, LAST SWEEP with the check count, and **RE-SWEEP ⟳**. There is no separate HUD row.
2. Click **INVESTIGATE NEXT ▶**. The most important signal opens in a panel. Its clues are **SCAN CLUE** buttons, and each opens with a "How to read this" line. For the `com.devicerescue.qa.helper` signal, **WHERE IT LIVES** names its folder under Application Support, with the note "Where apps keep their own files. An unfamiliar name here is worth a look."
3. Tag it **THREAT**. Scout's read appears. It says whether the scan agrees and why, and never says you're wrong. Close the panel: the signal is on the **THREAT BOARD** with **SEE THE STEPS ▶** or **SEE THE FIX ▶**. In Terminal, `ls ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist` still finds the file, because a tag changes nothing.
4. Open it again and tag it **MINE**. **OPTIONAL: TELL RECLAIM CITY TOO** shows the "It's mine" button. Press it: its own confirmation question appears. Press **Cancel**. Nothing was marked.
5. Click **The Gatehouse** in the city. The queue shows only its signals, with **SHOW ALL** and **OPEN THE DISTRICT ▶**. Click **SHOW ALL**.
6. Open **LOW-PRIORITY SIGNALS (N)**. At most 50 show, plus "And N more" if there are more. Click **THESE ARE ALL FINE**. The row goes, SORTED goes up, and the points under RANK don't change.
7. If a **DRILL** row is in the queue, it has a hatched lime border and the DRILL stamp, and its panel says "Practice. This isn't on your computer." Answer it. A right answer adds points and a DRILL line in the log. A wrong one shows "The tell:" and adds nothing. CITY INTEGRITY doesn't move either way. A drill pays once ever: if you already got that drill right (on an earlier sweep or in the Drill Range), answering it again adds no points.
8. From the threat board, open the helper's steps, click **Fix it for me**, then **Yes, fix it**. After **RECLAIMED**, go back to the city. CONFIRMED reads 1, the log has a CONFIRMED line, and if nothing else was open in The Gatehouse, a **DISTRICT SECURED** banner shows once. Turn on System Settings → Accessibility → Display → Reduce motion and repeat with another fix: the banner appears without moving.
9. Click **RE-SWEEP ⟳**. The sweep screen runs the same checkup. Back on the deck, there's another SWEEP line, the sparkline has two points, and the sentence under it says "up from", "down from" or "the same as" last sweep. A finding you tagged that is still there keeps its tag. If one is gone, the log says "NO LONGER SEEN", and CONFIRMED doesn't go up for it.
10. Click **DRILL RANGE ▶**. A drill opens. **NEXT DRILL ▶** moves on, and **BACK TO THE DECK** returns. A drill you already got right can come round again to practise, and it adds no points. Then click **Start over**, **Play it as a game** and a worry, and click **ALL LESSONS** on the sweep: the Training Grounds offer **DRILL RANGE ▶** too, before the checkup has finished, and its back button reads **BACK TO THE TRAINING GROUNDS**.
11. Make the window narrow (about 700 px wide). The panels stack in this order: queue, city, instruments, log. The Signal panel fits the width with no sideways scrolling.
12. Keyboard and VoiceOver: Tab reaches each queue row as a button, Enter opens it, and focus stays put when a clue opens or a tag is set. VoiceOver reads the sentence under CITY INTEGRITY, for example "City integrity 50%, up from 0% last sweep."
13. DevTools → Application → Local Storage → `device-rescue.game.v1`: `version` is 3, `deck.sweeps` entries have only `at` and numbers, `deck.tags` keys look like `launch_agent_audit|…`, and nothing anywhere says `monitoringSeen`.
14. Monitoring software in a re-sweep. Quit, save this as `/tmp/fake-rescue`, and run `chmod +x /tmp/fake-rescue`:
    ```sh
    #!/bin/sh
    # The first scan is the real engine; every scan after that "finds" monitoring software.
    case " $* " in
      *" scan "*)
        if [ -f /tmp/fake-rescue.ran ]; then
          echo '{"schema_version":1,"platform":"darwin","modules":[{"name":"stalkerware_scan","category":"security","status":"ok","error":null,"supported":true,"findings":[{"title":"Monitoring app found (test)","description":"Test only.","severity":"critical","category":"security","data":{}}]}]}'
          exit 0
        fi
        touch /tmp/fake-rescue.ran ;;
    esac
    exec "$REAL_RESCUE" "$@"
    ```
    In DevTools' Console run `localStorage.setItem('device-rescue.display', 'standard')`. Run `rm -f /tmp/fake-rescue.ran; REAL_RESCUE="$PWD/.venv/bin/rescue" RESCUE_ENGINE=/tmp/fake-rescue npm --prefix desktop start`. Play it as a game with **I'm not sure**. When the deck appears, click **RE-SWEEP ⟳**. When it finishes, "We found something that can be used to watch a computer. Is that something you know about?" appears before anything else. Click **Yes, I know about it**: the deck comes back, the game isn't withdrawn, and **Start over** still offers **Play it as a game**. Quit, then delete `/tmp/fake-rescue` and `/tmp/fake-rescue.ran`.
15. On Windows or Linux (if available), the same deck appears, and there are no **OPEN IN SYSTEM SETTINGS** buttons.
16. Clean up the test launch agent as in "Game mode, end to end", step 8.

## Reclaim City: the name

1. Build with `cd desktop && npx electron-builder --mac --publish never -c.mac.identity=-`. `desktop/dist/` holds `ReclaimCity-mac-arm64.dmg` (or `-x64`). Its window title is "Reclaim City".
2. Install it from the dmg. The app is "Reclaim City" in Applications, the Dock, the menu bar and **Reclaim City → About Reclaim City**. If the owner has added `desktop/build/icon.png`, the Dock shows the game icon; otherwise Electron's default. Never a shield.
3. On a Mac that had Device Rescue with saved game progress: open Reclaim City. Lessons marked DONE and missions saved for LATER are still there. `~/Library/Application Support/Device Rescue/` is still the folder in use, and no `~/Library/Application Support/Reclaim City/` folder appears.
4. Search every screen you pass through below for "Device Rescue". It appears nowhere, except where the real folder path `~/Library/Application Support/Device Rescue/Quarantine` is printed in a background job's Undo steps.

## The question and the two modes

Start from a clean slate each time: in DevTools' Console run `localStorage.removeItem('device-rescue.display')` and reload.

1. **Get started**, pick **I think I’ve been hacked**. "One more question" appears with the question and three answers. The title of the question has keyboard focus (VoiceOver reads it first). Click **No**. The scan screen opens. Reload, go back to the worry screen: the question isn't asked again.
2. On the worry screen, click **Something changed?**. The question appears with a fourth choice, **Back — keep things as they are**. Click **Back**: you're on the worry screen and nothing changed (`device-rescue.display` has the same value).
3. Open **Something changed?** again and answer **Yes, that’s part of it**. You're back on the worry screen, and `device-rescue.display` now reads `city`.
4. With the mode on `city`, open **Something changed?** and click **I’d rather not say**. The mode is still `city`: only an explicit **No** leaves city mode. Open it once more and click **No**. The mode reads `standard`. (On the very first question, **I’d rather not say** gives `standard`.)
5. DevTools → Application → Local Storage → `app://rescue`. The only new keys are `device-rescue.display` (`city` or `standard`) and `device-rescue.city-seed` (a number). Search every value for "partner", "safety", "stalk", "watch", "advocate" and "hotline": none appear.
6. Standard mode, a normal checkup: no card, the scan screen or the "What to do next" box mentions a hotline or an advocate. Advice and "stop and read this" notes still show: standard mode quiets only the hotline and DV sentences.
7. Standard mode, "Copy everything for an AI" and one card's **Copy for any AI**: the text has no note about monitoring software.
8. Pick **I think someone is watching me**. No question is asked, and the mode reads `city`.

## City mode

Set `device-rescue.display` to `city` in DevTools' Console and quit and reopen the app.

1. It opens straight into the game (the Training Grounds before any sweep), with no welcome screen. Its heading reads "Take back the city", not a worry.
2. The generated district's tile is there. Note its name, look and wording. Quit, reopen: same name, same colours. On a second Mac (or after deleting `device-rescue.city-seed`), the name is usually different.
3. Open the district. QUIET FIRST STEPS, WHO CAN HELP, the Six Roses guide and "Leaving is the most dangerous time. Plan carefully with DV advocates." are there. The Six Roses note reads "The title looks like a recipe, but the page is a safety guide, so open it when you’re alone or on a device that’s yours…". Only **OPEN IT IN YOUR BROWSER** opens anything: it opens https://themultiverse.school/x/six-roses, which reads as a recipe.
4. Press **Esc**. You're back on the deck at once, with keyboard focus on the first district on the map. Open the district again and click **BACK TO THE GAME**: the same. Press **Esc** on the deck itself: nothing happens, and no other screen closes.
5. Click **OPEN IT IN YOUR BROWSER** and press **Esc** straight away. Back in the app, the deck shows no notice and no address.
6. Run with `RESCUE_ENGINE=/tmp/fake-rescue` (from "Training Grounds and the final boss", step 11) and start a sweep. When it finishes, the question "We found something that can be used to watch a computer…" is **not** asked (the mode is already `city`). The deck says "Something new in <the district>" and shows nothing named "Monitoring app found". The queue reads "Nothing to sort here right now. Something new in <the district>." and never shows a CLEAR BOARD while that is held. The district shows it under "Don’t remove it yet. Talk to an advocate first.", with how to keep a record of it. On **LIST**, its card has the same line and no **Fix it for me**, no **This is mine**, no step-by-step and no System Settings button (the list stays literal: the card still names what was found). **Copy for any AI** on that card ends with "Don’t suggest removing or disabling it; the person may be at risk if it’s removed. Suggest documenting it and talking to an advocate." Points, CONFIRMED, SORTED and CITY INTEGRITY on the deck didn't change for it, and no signal for it is in the queue.
7. The ops log reads "Visited <the district>" for each visit, and nothing else about it. The app never shows a notification or bounces the Dock icon.
8. **PLAIN VIEW**, **Start over**, **Get started**, **Someone is on my Wi-Fi…**: no question, and the checkup runs in the game.
9. Couldn't look, not clean: on a Mac with no iPhone backup, run the `iphone_spyware_check` module through a sweep (or use an engine that returns its "no backups found" finding). Its district shows **COULDN'T CHECK** with a dashed grey border, never lit and never RECLAIMED.
10. The carry flag, across a restart. Keep the monitoring-software `/tmp/fake-rescue` from step 6 and note the deck's points and CONFIRMED. Quit. Replace `/tmp/fake-rescue` with a script that finds nothing:
    ```sh
    #!/bin/sh
    echo '{"schema_version":1,"platform":"darwin","modules":[{"name":"stalkerware_scan","category":"security","status":"ok","error":null,"supported":true,"findings":[]}]}'
    ```
    Run with `RESCUE_ENGINE=/tmp/fake-rescue` again (the same profile, so saved progress is kept) and click **RE-SWEEP ⟳**. The held software is gone, but the points and CONFIRMED are the same as before, there is no CONFIRMED line or DISTRICT SECURED banner for it, and the log has no reward for it. A second clean re-sweep after this one can score as normal. DevTools → `device-rescue.game.v1`: the only trace is `deck.sweep.carry: true`, a bare boolean, with no title or name.
11. Hand the app to a "glance test". Open the deck in city mode with the monitoring software held (step 6), and have someone who doesn't know what the app is for look at the screen for a few seconds, then at the Dock and Cmd-Tab. They should see only a game: the window title "Reclaim City", the heading "Take back the city", a map of districts, the generated district's tile with a place-like name, the ops log (SWEEP and "Visited …" lines), and the signals and rank panels. They must not find the words partner, safety, stalking, stalkerware, monitoring, spyware, watching, advocate, hotline or DV on the deck, the map, the window title, the Dock label or Cmd-Tab. The map's note about the held software uses its neutral label ("Something the checkup found") with the rest closed, never the software's name. **Known limit:** the list view (**LIST**) is literal by design, and the district itself names help once opened; the Esc key is the way out.
12. Quit and delete `/tmp/fake-rescue`. In DevTools, `localStorage.removeItem('device-rescue.display')`.

## An infected computer, kept offline

1. **Get started** → **A computer I don’t want to turn on or connect**. No scan starts and no question is asked. The screen "Keep that computer off your network" shows Step 1 of 5, five unticked checkboxes, **Open the full guide**, **Check this computer** and **Back to the list**. The "Your worry" dot stays lit.
2. **Done** moves to Step 2 and ticks Step 1. Clicking a title in the list jumps to that step; ticking a box ticks only that step. Step 5 has **Open the accounts guide**, which opens the Digital security reset page in the browser. **Open the full guide** opens `…/docs/scenarios/infected-device/`.
3. **Back to the list**, then pick the worry again: the list starts fresh, nothing ticked.
4. **Check this computer**: plain view goes to the scan screen ("Checking for: A computer I don’t want to turn on or connect") and **Run checkup** runs `scan --json --profile infected_device --trace`. In city mode (`device-rescue.display` = `city`), it goes straight to the sweep with the same profile.
5. Offline for real: turn Wi-Fi off and unplug the cable, then run the check. It finishes (about a minute or two on a Mac), and the AI tools card says "This checkup is for a computer you’re keeping off the internet…" unless HackMyAgent was saved earlier. With the full checkup (**I’m not sure**) offline, the same card says "This computer isn’t connected to the internet…" within a second or two, not after a minute.

## Before publishing (the owner's steps, never an agent's)

Each of these is outward-facing. The plan prepares them; the owner does them. Nothing here has been done: nothing is published, tagged or pushed, and the `reclaim-city` branch is not merged.
1. Supply the game icon as `desktop/build/icon.png`, 1024×1024 (`app-identity.test.js` checks the size). There is no `desktop/build/icon.png` today, so a build uses Electron's default icon until it exists.
2. Confirm the name of the web version on the download page and the USB stick ("Reclaim City (Web)").
3. Choose the version in `desktop/package.json` and write the release notes (they begin "Reclaim City used to be called Device Rescue.").
4. Merge `reclaim-city` into `main` and push the `v*` release tag together. Merging deploys `site/` and the docs with the new `ReclaimCity-*` download links, and those links only work once the release exists. The merge is itself publishing.
5. Rebuild the `/x/` page with `python scripts/build-standalone-landing.py` (it writes `dist/reclaim-city-landing.html`) and seed it per `~/src/themultiverse.school/docs/AGENT_PUBLISHING_GUIDE.md` Part 2. Decide whether the slug stays `/x/device-rescue`. The Six Roses page that the help district opens is a separate `/x/` page (`/x/six-roses`) and should be live and checked before the release, or the district's link goes nowhere.
6. Windows: install the new `ReclaimCity-windows-x64.exe` over an existing Device Rescue install, and check that it updates in place (same appId) and keeps saved progress.
7. Optional, outside this repo: the Six Roses guide's figure cites NPR's 2014 survey now; the spec's suggested note about the removal warning is already addressed on the page.

Record anything that doesn't match as a bug and fix it before the release goes out.
