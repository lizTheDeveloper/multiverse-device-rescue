# Manual QA

Checks a person runs on a real Mac before a release. Run them from the
repository root, with the engine installed in `.venv` (see the README).
Start the app against that engine, not an old build in `desktop/engine/`:

```bash
cd desktop && RESCUE_ENGINE="$PWD/../.venv/bin/rescue" npm start
```

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
7. Start over, pick **I think someone is watching me**, and run the checkup. No city is offered anywhere.
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
10. Start over and pick **I think someone is watching me** after **Play it as a game**. The plain scan screen opens, waiting for **Run checkup**: no sweep, no lessons, and no checkup started for you. Do the same with the iPhone worry.
11. Simulate monitoring software. Quit, save this as `/tmp/fake-rescue`, and run `chmod +x /tmp/fake-rescue`:
    ```sh
    #!/bin/sh
    echo '{"schema_version":1,"platform":"darwin","modules":[{"name":"stalkerware_scan","category":"security","status":"ok","error":null,"supported":true,"findings":[{"title":"Monitoring app found (test)","description":"Test only.","severity":"critical","category":"security","data":{}}]}]}'
    ```
    Run with `RESCUE_ENGINE=/tmp/fake-rescue`, click **Play it as a game** and pick **I’m not sure — check everything**. The sweep runs, and when it finishes the list results show, not the city. Click **Start over**. The welcome screen no longer shows **Play it as a game**. Quit and delete `/tmp/fake-rescue` afterwards.
12. DevTools → Network: every request is `app://rescue/…`, including `rc/data/phishing.js`.
13. Clean up the test launch agent as in "Game mode, end to end", step 8.

Record anything that doesn't match as a bug and fix it before the release goes out.
