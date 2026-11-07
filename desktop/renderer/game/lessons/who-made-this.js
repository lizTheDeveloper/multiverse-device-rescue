export default {
  id: 'who-made-this',
  title: 'Who made this program?',
  recommendedFor: ['sketchy', 'hacked', 'unsure', 'helping'],
  modules: ['code_signature_audit', 'gatekeeper_quarantine_check', 'sip_gatekeeper'],
  districts: ['gatehouse'],
  sources: [
    'guides/remediation/check_app_signatures.md',
    'guides/remediation/verify_sip_gatekeeper.md',
    'modules/security/code_signature_audit/__init__.py',
    'modules/security/gatekeeper_quarantine_check/__init__.py',
    'modules/security/sip_gatekeeper/__init__.py',
    'desktop/renderer/app.js',
    'rescue/attribution.py',
  ],
  briefing: 'Software makers can put a digital seal, called a signature, on their programs. This lesson is about what that seal can tell you, and what it can’t.',
  whatTheScanLooksFor: 'On a Mac or a Windows computer, the checkup reads the signatures of installed apps, up to a set number, and says if it stopped before the end. It flags a seal that’s broken, and a missing seal on an app installed for everyone who uses the computer. On a Mac, it also checks that Gatekeeper is on. When a finding names a program, it says who made it and whether that could be verified.',
  questions: [
    {
      concept: 'signature-tells-who',
      teach: 'When a finding names a program, Reclaim City says who made it. A “verified signature” means the seal is real and names the maker. It tells you who made it, not that you wanted it or that it’s safe.',
      prompt: 'A finding says “Made by Google LLC (verified signature)”. What does that tell you?',
      options: [
        { text: 'Who made the program', correct: true,
          feedback: 'Right. The seal is real and names the maker. Whether you want that program here is still your call.' },
        { text: 'That the program is safe', correct: false,
          feedback: 'A signature can’t tell that. It tells you who made it, not what the program is doing.' },
        { text: 'That you installed it and want it', correct: false,
          feedback: 'A signature can’t tell who installed it. It tells you who made it, not that you wanted it.' },
      ],
      variants: [
        {
          prompt: 'A remote-control app you don’t remember installing has a verified signature from a real company. Does that settle it?',
          options: [
            { text: 'No. It says who made the app, not who put it here or who can use it', correct: true,
              feedback: 'Right. Real companies make remote-control and monitoring apps too. The question is who installed it and who can connect. If a partner, ex or housemate may be involved, removing it can alert them, so get help planning the safest order first.' },
            { text: 'Yes. Verified means it’s fine', correct: false,
              feedback: 'Verified means the maker is confirmed. It says nothing about whether you wanted it, or who can use it.' },
          ],
        },
        {
          prompt: 'Which question can a verified signature answer?',
          options: [
            { text: '“Who made this program?”', correct: true,
              feedback: 'Right. That’s the one thing a seal tells you.' },
            { text: '“Did I install this?”', correct: false,
              feedback: 'A seal can’t tell who installed a program, only who made it.' },
            { text: '“Is it safe to keep?”', correct: false,
              feedback: 'A seal can’t answer that. It tells you who made it, and the rest is up to you.' },
          ],
        },
      ],
    },
    {
      concept: 'unsigned-isnt-proof',
      teach: '“Not signed”, “only self-signed by whoever built it” or “signed with a developer’s test certificate, not a published one” all mean the maker couldn’t be confirmed. That’s worth a look, but it isn’t proof of harm. Plenty of free tools, open-source programs and older software are unsigned.',
      prompt: 'A finding says an app is “not signed”. What does that mean?',
      options: [
        { text: 'Nobody could confirm who made it, so it’s worth asking where it came from', correct: true,
          feedback: 'Right. It’s a reason to look, not proof of anything bad.' },
        { text: 'It’s harmful software', correct: false,
          feedback: 'Not necessarily. Many free tools, open-source programs and older apps are unsigned. It means the maker couldn’t be confirmed.' },
        { text: 'Nothing. Signatures don’t matter', correct: false,
          feedback: 'They do help: a seal names the maker. Without one, it’s worth knowing where the app came from.' },
      ],
      variants: [
        {
          prompt: 'A free drawing tool you downloaded from its maker’s own website is “not signed”. What’s the sensible read?',
          options: [
            { text: 'That’s common for free tools. If you know where it came from, it’s expected', correct: true,
              feedback: 'Right. A missing seal on a tool you chose, from its maker’s own site, is expected.' },
            { text: 'Delete it straight away, because unsigned means harmful', correct: false,
              feedback: 'Unsigned isn’t proof of harm. Many free tools ship that way. What matters is whether you know where it came from.' },
            { text: 'Switch off Gatekeeper so it stops getting flagged', correct: false,
              feedback: 'That would drop the check for every other app too. A tool you chose and trust can just stay as it is.' },
          ],
        },
        {
          prompt: 'An unsigned app you don’t recognise is installed for everyone who uses the computer. What’s a good first step?',
          options: [
            { text: 'Note its name and ask where it came from before removing anything', correct: true,
              feedback: 'Right. Write down the name, and ask a trusted technical person or an advocate to help you identify it. If someone close to you may have installed it, removing it can alert them.' },
            { text: 'Delete it straight away', correct: false,
              feedback: 'Look before you remove anything. If someone close to you installed it to monitor you, removing it can alert them.' },
            { text: 'Ignore it. Unsigned apps are always fine', correct: false,
              feedback: 'Many are, but not always. If you don’t recognise it, it’s worth finding out where it came from.' },
          ],
        },
      ],
    },
    {
      concept: 'broken-seal-is-the-warning',
      teach: 'A broken seal is different from a missing one. The app has a signature, but the file no longer matches it, so it was changed after the maker signed it. Real updates are signed again by the maker, so this is a strong sign the app isn’t what it claims to be.',
      prompt: 'Which of these is the strongest warning sign?',
      options: [
        { text: 'The app was changed after it was signed', correct: true,
          feedback: 'Right. There’s no normal reason for a broken seal. Real updates are signed again by the maker.' },
        { text: 'The app is not signed', correct: false,
          feedback: 'That’s worth a look, but many free tools are unsigned. A broken seal is the stronger sign.' },
        { text: 'The app has a verified signature from a company you know', correct: false,
          feedback: 'That’s the least worrying of these. The seal is real and names the maker.' },
      ],
      variants: [
        {
          prompt: 'The checkup says an app “was changed after it was signed”. What’s the safe fix?',
          options: [
            { text: 'Don’t open it, and get a fresh copy from the maker’s own website or the App Store', correct: true,
              feedback: 'Right. Never use a link from an ad or an email. If you don’t recognise the app at all, and someone close to you may have installed it, get help before removing it.' },
            { text: 'Keep using it. Updates change apps all the time', correct: false,
              feedback: 'Real updates are signed again by the maker, so they don’t break the seal. Get a fresh copy from the maker’s own website or the App Store.' },
          ],
        },
        {
          teach: 'Anyone can write a company’s name into a program. Reclaim City only says “verified” when the seal checks out. Otherwise it shows the name the program claims, followed by “but it cannot be verified”.',
          prompt: 'A finding says “Made by Acme, but it cannot be verified”. What does that mean?',
          options: [
            { text: 'The program names Acme, but its seal didn’t confirm that, so don’t go by the name alone', correct: true,
              feedback: 'Right. A claimed name is just text. Check where the program came from before you trust it.' },
            { text: 'Acme made it, and that’s confirmed', correct: false,
              feedback: 'Confirmed would say “verified”. Here the name is only what the program claims.' },
            { text: 'It’s definitely a fake', correct: false,
              feedback: 'Not necessarily. Sometimes the check simply couldn’t finish. It means the name isn’t confirmed, so look at where it came from.' },
          ],
        },
      ],
    },
    {
      concept: 'gatekeeper-checks-new-apps',
      teach: 'On a Mac, Gatekeeper checks apps from the internet before they run. If it’s off, your Mac won’t warn you before running new apps. That doesn’t mean anyone has broken in, but if you didn’t switch it off, turn it back on in System Settings > Privacy & Security.',
      prompt: 'The checkup says Gatekeeper is off. What does that mean?',
      options: [
        { text: 'The Mac won’t warn you before running new apps from the internet', correct: true,
          feedback: 'Right. It makes it easier for bad software to get in, but it isn’t a sign of a break-in on its own.' },
        { text: 'Someone has broken into the Mac', correct: false,
          feedback: 'Not on its own. It means the Mac isn’t checking new apps. If you didn’t switch it off, turn it back on.' },
        { text: 'Nothing. It only matters for App Store apps', correct: false,
          feedback: 'It’s the other way round. Gatekeeper matters most for apps from the internet.' },
      ],
      variants: [
        {
          prompt: 'Your Mac won’t open an app you downloaded from a small developer’s website. What’s most likely?',
          options: [
            { text: 'Apple hasn’t approved that app, which is common outside the App Store', correct: true,
              feedback: 'Right. If you trust where it came from, you can leave it. If you aren’t sure, get the current version from the maker’s own website.' },
            { text: 'The app is definitely harmful', correct: false,
              feedback: 'Not necessarily. This is common for smaller developers and older apps. Check where you got it.' },
            { text: 'You should switch Gatekeeper off so it opens', correct: false,
              feedback: 'That drops the check for every app. If you need one app, allowing just that one is better than switching Gatekeeper off.' },
          ],
        },
        {
          prompt: 'You never switched Gatekeeper off, but the checkup says it’s off. What’s sensible?',
          options: [
            { text: 'Switch it back on, in System Settings > Privacy & Security', correct: true,
              feedback: 'Right. If you didn’t switch it off, it’s worth turning back on. Reclaim City shows the steps and doesn’t change it for you.' },
            { text: 'Leave it. It doesn’t do much', correct: false,
              feedback: 'It checks new apps before they run. If you didn’t switch it off, turn it back on.' },
          ],
        },
      ],
    },
  ],
};
