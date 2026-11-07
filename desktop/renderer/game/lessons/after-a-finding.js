export default {
  id: 'after-a-finding',
  title: 'After the checkup finds something',
  recommendedFor: ['unsure', 'hacked', 'watched', 'sketchy', 'helping'],
  modules: [],
  districts: [],
  sources: [
    'README.md',
    'AGENTS.md',
    'docs/trust-and-safety.md',
    'desktop/renderer/app.js',
    'desktop/renderer/mark-flow.js',
    'desktop/renderer/fix-flow.js',
  ],
  briefing: 'Most checkups find something. A finding is a place to look, and there’s a calm order for what to do next.',
  whatTheScanLooksFor: 'Each finding says what was seen, where, and how much it matters: “Needs attention now”, “Worth a look” or “Good to know”. When it names a program, it also says who made it and whether that could be verified.',
  questions: [
    {
      concept: 'read-the-evidence',
      teach: 'Before you act, read what the finding shows: the program’s name, where it lives, and who made it. “Made by … (verified signature)” means the maker was checked. “Unknown maker” means nobody vouched for it, which is a reason to be careful, not proof of anything bad.',
      prompt: 'A finding names a program you don’t recognise. What do you do first?',
      options: [
        { text: 'Read its name, where it lives, and who made it', correct: true,
          feedback: 'Right. That evidence often tells you what it is. A familiar maker with a verified signature is a very different case from an unknown one in a temporary folder.' },
        { text: 'Remove it before anything else happens', correct: false,
          feedback: 'Look first. Many unfamiliar names turn out to be parts of apps you use, and the evidence usually shows that.' },
        { text: 'Ignore it, since you don’t know what it is', correct: false,
          feedback: 'Not knowing is the reason to look. The finding shows who made it and where it lives, which helps you decide.' },
      ],
      variants: [
        {
          prompt: 'A finding says “Unknown maker” next to a program. What does that mean?',
          options: [
            { text: 'Nobody vouched for it, so look more carefully', correct: true,
              feedback: 'Right. It isn’t proof of anything bad. It means the maker couldn’t be checked, so the other evidence matters more.' },
            { text: 'It is definitely harmful', correct: false,
              feedback: 'No. Plenty of ordinary scripts and small tools aren’t signed. It’s a reason for care, not a verdict.' },
          ],
        },
        {
          prompt: 'A program is “Made by Google LLC (verified signature)”. What does that settle?',
          options: [
            { text: 'Who made it, but not whether you want it running', correct: true,
              feedback: 'Right. A verified signature tells you who made it. Whether it belongs on this computer is still your call.' },
            { text: 'That it’s safe and you can stop looking', correct: false,
              feedback: 'Not quite. It tells you the maker is real. A real maker’s program can still be something you didn’t want.' },
          ],
        },
      ],
    },
    {
      concept: 'warning-is-not-proof',
      teach: '“Needs attention now” and “Worth a look” mean a finding deserves a closer look. They aren’t proof that anyone got in. “Good to know” findings are mostly background details, and most checkups have plenty.',
      prompt: 'Your checkup shows one finding marked “Worth a look”. What does it mean?',
      options: [
        { text: 'Something worth reviewing, not proof of a break-in', correct: true,
          feedback: 'Right. Read what it shows and decide. Many turn out to be things you set up yourself.' },
        { text: 'Someone has broken in', correct: false,
          feedback: 'A finding can’t say that on its own. It points at something to look at, and the evidence tells you more.' },
      ],
      variants: [
        {
          prompt: 'The checkup lists a long row of “Good to know” findings. How worried should you be?',
          options: [
            { text: 'Not much. They’re mostly normal background details.', correct: true,
              feedback: 'Right. Start with “Needs attention now”, then “Worth a look”. The “Good to know” ones are usually reassurance-level notes.' },
            { text: 'Very. A long list means lots of problems.', correct: false,
              feedback: 'No. Most real checkups have many “Good to know” findings. Length isn’t danger.' },
          ],
        },
        {
          prompt: 'Which findings should you look at first?',
          options: [
            { text: '“Needs attention now”, then “Worth a look”', correct: true,
              feedback: 'Right. Those are the ones that deserve a closer look. Even so, each one is a thing to check, not proof of being hacked.' },
            { text: '“Good to know”, because there are the most of them', correct: false,
              feedback: 'Those are mostly background details. Start with the ones marked as needing attention.' },
            { text: 'None. Findings are just noise.', correct: false,
              feedback: 'The important ones are worth reading. They tell you what to look at, even if most turn out to be fine.' },
          ],
        },
      ],
    },
    {
      concept: 'mine-or-fix',
      teach: 'If a finding is something you set up and want, “It’s mine” remembers that. Nothing on the computer changes, and it’s listed as “marked as yours” next time. If you don’t want it, a fix shows “This will:” and “To undo later:” first, and waits for your yes.',
      prompt: 'A finding is a file-sharing setting you turned on yourself, on purpose. What fits?',
      options: [
        { text: 'Mark it as yours. Nothing on the computer changes.', correct: true,
          feedback: 'Right. From your next checkup it will be listed as “marked as yours” instead of being flagged. You can undo that with “Stop treating this as mine”.' },
        { text: 'Use the fix to switch it off', correct: false,
          feedback: 'You want it, so switching it off isn’t the goal. Marking it as yours records that, without changing anything.' },
      ],
      variants: [
        {
          prompt: 'You press “Fix it for me”. What happens before anything changes?',
          options: [
            { text: 'It shows what will change and how to undo it, then waits for “Yes, fix it”', correct: true,
              feedback: 'Right. You can still press “Cancel”. Nothing else on your computer is changed.' },
            { text: 'The change happens right away', correct: false,
              feedback: 'No. Every fix shows what it will do and asks first.' },
          ],
        },
        {
          prompt: 'You don’t recognise a background item, and you’re not sure it’s yours. What fits best?',
          options: [
            { text: 'Don’t mark it as yours; look into it, or use a fix you can undo', correct: true,
              feedback: 'Right. Only mark something as yours if you set it up yourself. For a flagged background job on a Mac, the fix moves it aside, nothing is deleted, and there’s an Undo button.' },
            { text: 'Mark it as yours so the warning goes away', correct: false,
              feedback: 'Only do that if you set it up yourself. If you’re not sure, leave it as it is.' },
            { text: 'Delete its files by hand', correct: false,
              feedback: 'Deleting can’t be undone. Moving it aside in a way you can undo is safer while you find out what it is.' },
          ],
        },
      ],
    },
    {
      concept: 'monitoring-safe-order',
      teach: 'Removing monitoring software can alert the person who installed it. If a partner, ex or housemate might be involved, talk to an advocate before removing anything. “I set it up” doesn’t settle it: what matters is who gets what it records.',
      prompt: 'The checkup finds monitoring software, and you think an ex installed it. What’s the safest next step?',
      options: [
        { text: 'Talk to an advocate first to plan the safest order', correct: true,
          feedback: 'Right. Removing it can alert whoever installed it. A plan comes first. In the US, the National Domestic Violence Hotline helps with tech safety.' },
        { text: 'Remove it straight away', correct: false,
          feedback: 'That can alert the person who installed it. If you’re not sure removal is safe for you, get help planning first.' },
      ],
      variants: [
        {
          prompt: 'Someone says the monitoring app on your laptop is fine because they set it up for you. What decides whether it’s a problem?',
          options: [
            { text: 'Who gets what it records', correct: true,
              feedback: 'Right. Who set it up, or a good-sounding reason, doesn’t settle it. If reports go to someone else, it can watch you.' },
            { text: 'Whether they had a good reason', correct: false,
              feedback: 'A reason doesn’t change what the software does. Ask who receives what it records.' },
            { text: 'Nothing. If they set it up, it’s fine.', correct: false,
              feedback: '“I set it up” never clears monitoring software. What matters is who gets the reports.' },
          ],
        },
        {
          prompt: 'Why doesn’t Reclaim City offer “It’s mine” on monitoring software findings?',
          options: [
            { text: 'Because who set it up doesn’t settle whether it watches you', correct: true,
              feedback: 'Right. Those findings stay visible, so the question of who gets the reports isn’t hidden away.' },
            { text: 'Because it deletes monitoring software automatically', correct: false,
              feedback: 'No. Nothing is removed without your yes, and removal can alert whoever installed it.' },
          ],
        },
      ],
    },
  ],
};
