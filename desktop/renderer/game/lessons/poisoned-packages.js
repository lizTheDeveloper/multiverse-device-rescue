export default {
  id: 'poisoned-packages',
  title: 'Poisoned packages',
  recommendedFor: ['sketchy'],
  modules: ['ai_worm_filesystem', 'ai_worm_git_ssh', 'ai_worm_persistence', 'ai_worm_network', 'ai_worm_lateral'],
  sources: [
    'README.md',
    'guides/remediation/clean_ai_worm_filesystem.md',
    'guides/remediation/cut_ai_worm_c2.md',
    'guides/remediation/secure_git_ssh_after_worm.md',
  ],
  briefing: 'This one is mostly for people who write code. Some “worm” attacks spread through developer tools like npm, PyPI and GitHub. These worms can drop scripts into hidden or temporary folders, talk to the attacker’s servers, and change your git settings so that every project you clone or create quietly picks up a malicious hook. If you don’t use developer tools, you can skip this lesson.',
  whatTheScanLooksFor: 'The checkup looks for files these worms are known to drop, connections to their known servers, changed git settings, and anything set to start them again.',
  questions: [
    {
      prompt: 'The checkup flags a script a worm is known to drop. What do the guides say to do with it?',
      options: [
        { text: 'Read it first, then move it to a quarantine folder instead of deleting it', correct: true,
          feedback: 'Right. Inspect before moving anything, and quarantine rather than delete, so it can be looked at later.' },
        { text: 'Delete it straight away', correct: false,
          feedback: 'Read it first, then quarantine it rather than deleting it. What it does tells you which passwords and keys to change afterwards.' },
        { text: 'Run it to see what it does', correct: false,
          feedback: 'Never run it. Read it, don’t execute it.' },
      ],
    },
    {
      prompt: 'A program is talking to a known worm server. Is blocking that address enough?',
      options: [
        { text: 'No. The program itself is the problem; the connection is only the symptom.', correct: true,
          feedback: 'Right. Stop the program and find what keeps starting it.' },
        { text: 'Yes. Block it and carry on.', correct: false,
          feedback: 'The program would still be running. The connection is only the part you happened to see.' },
      ],
    },
  ],
};
