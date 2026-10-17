export default {
  id: 'starts-on-its-own',
  title: 'Things that start on their own',
  recommendedFor: ['hacked', 'sketchy', 'helping', 'unsure'],
  modules: ['launch_agent_audit', 'launchd_persistence_audit', 'win_autoruns_audit'],
  sources: [
    'guides/remediation/review_launch_persistence.md',
    'guides/remediation/audit_windows_autoruns.md',
    'rescue/app_fixes.json',
    'desktop/renderer/app.js',
    'desktop/renderer/fix-flow.js',
  ],
  briefing: 'Some programs set themselves up to start every time you log in. On a Mac these include launch agents. On Windows they sit in Run keys and the Startup folders. Lots of ordinary apps do this, like sync clients and VPN helpers. Unwanted software does it too, so it keeps coming back. When a finding names a program, Device Rescue says who made it and whether that could be checked: for example a “verified signature”, or “not signed”.',
  whatTheScanLooksFor: 'On a Mac, the checkup lists background items that aren’t part of macOS, and flags ones that run from /tmp, /var/tmp or a hidden folder. On Windows, it lists every startup entry, and flags ones that run from a Temp or Downloads folder.',
  questions: [
    {
      prompt: 'Which of these is a warning sign in something that starts on its own?',
      options: [
        { text: 'It’s made by a company you know, with a verified signature', correct: false,
          feedback: 'That’s the less worrying case. A verified signature tells you who made it, not that you wanted it.' },
        { text: 'It runs a program from a hidden folder or a temporary folder', correct: true,
          feedback: 'Right. On Windows, installed software runs from Program Files or its own install folder, not a temporary or download folder. On a Mac, a program in a temporary or hidden folder is one of the strongest warning signs the checkup looks for.' },
        { text: 'It’s a sync app you use all the time', correct: false,
          feedback: 'Sync clients and VPN helpers start on their own on purpose. That’s a normal pattern.' },
      ],
    },
    {
      prompt: 'You don’t recognise a background item. What’s the safest first move?',
      options: [
        { text: 'Delete it straight away', correct: false,
          feedback: 'Look before you remove anything, and move it aside rather than deleting it, so it can be looked at again or put back.' },
        { text: 'Check who made it, then switch it off in a way you can undo', correct: true,
          feedback: 'Right. On a Mac, for a flagged background job, Device Rescue’s “Fix it for me” stops the job and moves its settings file to a quarantine folder. Nothing is deleted, and you can undo it.' },
        { text: 'Leave it. Everything on a computer starts on its own.', correct: false,
          feedback: 'Some things do, on purpose. It’s still worth knowing what each one is, because unwanted software uses the same trick.' },
      ],
    },
  ],
};
