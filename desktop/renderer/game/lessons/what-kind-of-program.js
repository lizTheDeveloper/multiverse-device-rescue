// What the kind labels on a signal, a mission and the YOURS inventory mean
// (program-kinds.js PROGRAM_KINDS). Taught here once, so the cards only need
// the short label.
export default {
  id: 'what-kind-of-program',
  title: 'What kind of program is it?',
  recommendedFor: [],
  modules: ['startup_optimizer', 'launch_agent_audit', 'cron_jobs_audit', 'open_ports_scan', 'browser_extension_audit'],
  districts: ['gatehouse'],
  sources: [
    'modules/performance/startup_optimizer/__init__.py',
    'guides/remediation/review_launch_persistence.md',
    'guides/remediation/review_cron_jobs.md',
    'guides/remediation/review_open_ports.md',
    'guides/remediation/review_browser_extensions.md',
    'desktop/renderer/game/program-kinds.js',
  ],
  briefing: 'Reclaim City labels the programs it finds by what they do. One program can have more than one label, like “Starts on its own · Running now”.',
  whatTheScanLooksFor: 'On a Mac, the startup report reads each background item’s settings: whether it starts at login or at startup, is kept running, runs on a timer or a calendar, or only when needed. Other checks list running programs, programs listening on the network, and browser extensions.',
  questions: [
    {
      teach: '“Starts on its own” means it is set to start every time you log in or the computer starts up, or to be kept running. “Runs on a schedule” means it starts on a timer or on a calendar instead, and then stops again.',
      prompt: 'A program is labelled “Runs on a schedule”, not “Starts on its own”. What does that tell you?',
      options: [
        { text: 'It starts on a timer or calendar, not every time you log in', correct: true,
          feedback: 'Right. Something on a schedule comes and goes. Something that starts on its own is there from the moment you log in.' },
        { text: 'It is running right now', correct: false,
          feedback: 'Not from that label. “Running now” is its own label, and it’s only there when the checkup saw it running.' },
        { text: 'It was installed on a schedule', correct: false,
          feedback: 'The label is about when it runs, not when it was installed.' },
      ],
    },
    {
      teach: '“Background item” means it is set up to run in the background, but the checkup couldn’t tell when: it may only run when something asks for it. “Running now” means the checkup saw it running while it looked.',
      prompt: 'A program is labelled “Background item” with no other label. What do you know about it?',
      options: [
        { text: 'It’s set up to run in the background; when it runs wasn’t reported', correct: true,
          feedback: 'Right. It might run only when needed. If the startup report had seen a login or timer setting, the label would say so.' },
        { text: 'It starts every time you log in', correct: false,
          feedback: 'That would be labelled “Starts on its own”. A plain background item only tells you it’s set up to run in the background.' },
      ],
    },
    {
      teach: '“Listens on the network” means a program is waiting for other computers to connect to it. A “Browser extension” is an add-on inside your web browser, which can often read the pages you visit.',
      prompt: 'Which label means other computers can try to connect to the program?',
      options: [
        { text: 'Listens on the network', correct: true,
          feedback: 'Right. A listening program has a door open for connections. Plenty of ordinary apps do; it’s worth knowing which.' },
        { text: 'Browser extension', correct: false,
          feedback: 'An extension lives inside your browser and works on the pages you visit. That’s a different kind of access.' },
        { text: 'Runs on a schedule', correct: false,
          feedback: 'That’s about when a program runs, not whether it accepts connections.' },
      ],
    },
  ],
};
