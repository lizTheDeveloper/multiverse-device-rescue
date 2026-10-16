# Manual QA

Checks a person runs on a real Mac before a release. Run them from the
repository root, with the engine installed in `.venv` (see the README).

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
1. Click **Play it as a game**, then **I'm not sure**, then **Run checkup**. The city appears with The Gatehouse dark, and DevTools' Console shows no CSP errors.
2. DevTools → Network, filtered to "All": every request is `app://rescue/…`. There is no `https://`.
3. Open The Gatehouse, then the `com.devicerescue.qa.helper` mission. Click **Fix it for me**, check that the panel text matches the list view's, and click **Yes, fix it**. "Checking again" appears, then **RECLAIMED**.
4. Clear a district: in The Gatehouse (or another district with no **COULDN'T CHECK** panel), fix or do every remaining mission until each re-check says **RECLAIMED** (marking one as yours also counts). After the last one, answer **How did that go?**. The button reads **SEE THE GATEHOUSE**, and it opens **DISTRICT TAKEN BACK** with every fixed mission listed under **FIXED AND CHECKED**. The district screen still lists them, each with a **RECLAIMED** badge, and the map card shows **N RECLAIMED**, not **NOTHING FOUND**. A district with a **COULDN'T CHECK** panel never offers this screen.
5. Click **LIST**. The finding is gone from the list view too. Click **See it as a city** to go back.
6. Go back into the city, to the RECLAIMED screen of that mission (do the fix again if needed), and click **Undo**. "Checking again" shows while it re-checks, then **PUT BACK** with "Put back. It’s showing again.", and the building is dark again on the map. Scout doesn't say "Something you fixed came back". Then run a full checkup from the list. The mission is still open, not reclaimed.
7. Start over, pick **I think someone is watching me**, and run the checkup. No city is offered anywhere.
8. Clean up: `rm ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist; rm -r ~/Library/Application\ Support/.dr-qa`.

Record anything that doesn't match as a bug and fix it before the release goes out.
