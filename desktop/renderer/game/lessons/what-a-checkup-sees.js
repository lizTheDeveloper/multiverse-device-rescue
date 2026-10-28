export default {
  id: 'what-a-checkup-sees',
  title: 'What a checkup can and can’t see',
  recommendedFor: ['unsure', 'hacked', 'identity', 'phone', 'helping'],
  modules: [],
  districts: [],
  sources: [
    'README.md',
    'AGENTS.md',
    'docs/trust-and-safety.md',
    'desktop/renderer/permissions-content.json',
    'desktop/renderer/fix-flow.js',
    'modules/security/mvt_spyware_scan/__init__.py',
  ],
  briefing: 'A checkup is a careful look at this one computer. Knowing what it can and can’t see helps you read what it tells you.',
  whatTheScanLooksFor: 'The checkup reads how this computer is set up: what runs, what starts on its own, what it’s connected to, and its settings. It doesn’t open your documents or photos, read your browser history, or open a password manager.',
  questions: [
    {
      concept: 'checkup-only-reads',
      teach: 'A checkup only looks. It doesn’t remove, switch off or change anything by itself. A fix happens only when you choose it and press “Yes, fix it”.',
      prompt: 'The checkup is running. What is it doing to your computer?',
      options: [
        { text: 'Looking, and changing nothing', correct: true,
          feedback: 'Right. The checks only read. Anything that would change something waits for you to say yes.' },
        { text: 'Removing anything it doesn’t like as it goes', correct: false,
          feedback: 'No. A checkup removes nothing. Fixes come afterwards, one at a time, and only if you agree.' },
        { text: 'Switching off risky settings to keep you safe', correct: false,
          feedback: 'It doesn’t switch anything off on its own. It tells you what it found, and you decide.' },
      ],
      variants: [
        {
          prompt: 'The checkup finds something it can fix. What happens next?',
          options: [
            { text: 'It tells you what the fix will change and waits for your yes', correct: true,
              feedback: 'Right. Before any fix, Reclaim City shows “This will:” and how to undo it, then waits for “Yes, fix it” or “Cancel”.' },
            { text: 'It fixes it straight away, then tells you', correct: false,
              feedback: 'No. Nothing changes on your computer until you say yes to that fix.' },
          ],
        },
        {
          prompt: 'A friend worries that running a checkup could mess up their computer. What can you tell them?',
          options: [
            { text: 'The checkup only reads; changes happen only if they say yes to a fix', correct: true,
              feedback: 'Right. Looking is safe to do. Each fix is a separate choice, made after reading what it will change.' },
            { text: 'It might, so they should back everything up first', correct: false,
              feedback: 'The checkup itself only reads, so it isn’t what changes things. Fixes are separate and ask first.' },
            { text: 'It will tidy their settings, but that’s a good thing', correct: false,
              feedback: 'It doesn’t tidy anything on its own. It reports, and the person decides what to change.' },
          ],
        },
      ],
    },
    {
      concept: 'this-computer-only',
      teach: 'The checkup sees this computer only. It can’t see inside your online accounts, like email or banking, and it can’t see your phone or other devices. Account problems are fixed by you, on the company’s own website.',
      prompt: 'You’re worried someone got into your email account. Can the checkup look inside it?',
      options: [
        { text: 'No. Account fixes happen on the email company’s own website.', correct: true,
          feedback: 'Right. The checkup can look at this computer. Changing a password or signing out other sessions is done by you, at the provider’s website.' },
        { text: 'Yes, it checks all your accounts as part of the scan', correct: false,
          feedback: 'No. It can’t see inside your online accounts. Those are fixed at the provider’s website.' },
        { text: 'Yes, if you type your email password into Reclaim City', correct: false,
          feedback: 'Never. Reclaim City never asks for a password, and it can’t check your accounts with one.' },
      ],
      variants: [
        {
          prompt: 'You ran a checkup on your laptop. What does it tell you about your phone?',
          options: [
            { text: 'Nothing. It only looked at this laptop.', correct: true,
              feedback: 'Right. The iPhone check is separate: it reads a backup of the phone saved on this computer, so it needs one first.' },
            { text: 'Your phone was checked too, since they share an account', correct: false,
              feedback: 'No. Sharing an account doesn’t let the checkup see the phone. It sees this computer only.' },
          ],
        },
        {
          prompt: 'Which of these can a checkup on this computer look at?',
          options: [
            { text: 'Programs that start on their own on this computer', correct: true,
              feedback: 'Right. That’s on this computer, so the checkup can look at it.' },
            { text: 'Who has signed in to your online banking', correct: false,
              feedback: 'That lives in your bank account, not on this computer. Check it on the bank’s own website.' },
            { text: 'Apps on your partner’s phone', correct: false,
              feedback: 'No. The checkup sees this computer only, not other people’s devices.' },
          ],
        },
      ],
    },
    {
      concept: 'clean-lowers-odds',
      teach: 'When a checkup finds nothing worrying, the odds of a problem are lower. It still can’t rule one out, because no tool knows every kind of unwanted software.',
      prompt: 'Your checkup shows nothing that needs attention. What’s the honest way to say it?',
      options: [
        { text: 'The odds of a problem are lower, but it isn’t a guarantee', correct: true,
          feedback: 'Right. A clean checkup is good news. It lowers the odds without ruling a problem out.' },
        { text: 'This computer is now proven safe', correct: false,
          feedback: 'No tool can prove that. A clean result lowers the odds; it doesn’t rule a problem out.' },
      ],
      variants: [
        {
          prompt: 'The checkup was clean, but strange things keep happening. What makes sense?',
          options: [
            { text: 'Trust what you notice, and keep looking into it', correct: true,
              feedback: 'Right. A clean checkup lowers the odds, but it isn’t the last word. What you see still counts.' },
            { text: 'Ignore it. The checkup says everything is fine.', correct: false,
              feedback: 'A clean result doesn’t rule a problem out. If something still seems wrong, it’s worth following up.' },
          ],
        },
        {
          prompt: 'The iPhone check found no known spyware. What does that mean?',
          options: [
            { text: 'Nothing matched the known signs; new or unknown spyware can’t be ruled out', correct: true,
              feedback: 'Right. That check can only spot spyware that has already been described publicly. It lowers the odds, not to zero.' },
            { text: 'The phone has no spyware at all', correct: false,
              feedback: 'It can’t promise that. It only knows spyware that has already been published.' },
            { text: 'The check failed', correct: false,
              feedback: 'Not necessarily. It may have run fine and found no match. That lowers the odds without ruling spyware out.' },
          ],
        },
      ],
    },
    {
      concept: 'permission-to-look',
      teach: 'Some checks need your permission to look in protected places. On a Mac that’s Full Disk Access, in System Settings → Privacy & Security → Full Disk Access. Without it, those checks can’t look, so they checked nothing.',
      prompt: 'You didn’t turn on Full Disk Access for Reclaim City. What happens to the checks that need it?',
      options: [
        { text: 'They can’t look, so they checked nothing', correct: true,
          feedback: 'Right. A check that couldn’t look isn’t clean. It just wasn’t checked. You can turn the access on and run the checkup again.' },
        { text: 'They pass, because nothing bad was found', correct: false,
          feedback: 'No. They couldn’t look, so “nothing found” would mean nothing at all here.' },
      ],
      variants: [
        {
          prompt: 'Where do you give Reclaim City Full Disk Access on a Mac?',
          options: [
            { text: 'System Settings → Privacy & Security → Full Disk Access', correct: true,
              feedback: 'Right. Turn on the toggle for Reclaim City there. macOS may ask you to quit and reopen the app.' },
            { text: 'By typing your Mac password into Reclaim City', correct: false,
              feedback: 'No. Reclaim City never asks for a password. If your Mac asks, it does so in its own window.' },
          ],
        },
        {
          prompt: 'Why would a checkup ask for Full Disk Access at all?',
          options: [
            { text: 'Some checks need to read protected places, like other apps’ data or iPhone backups', correct: true,
              feedback: 'Right. macOS keeps those places locked until you allow it, so without the access those checks can’t look.' },
            { text: 'So it can delete files without asking', correct: false,
              feedback: 'No. The checks only read. Any change is a separate fix that asks you first.' },
            { text: 'It means something was found', correct: false,
              feedback: 'No. Asking for access isn’t a finding. It’s just what some checks need in order to look.' },
          ],
        },
      ],
    },
  ],
};
