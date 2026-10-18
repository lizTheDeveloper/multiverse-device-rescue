// Practice signals for The Engine Room. Invented: none of this is on the person's computer.
export default [
  {
    id: 'busy-miner',
    district: 'engine-room',
    severity: 'critical',
    modules: ['resource_hog_identifier'],
    title: 'Something keeps your processor busy all the time',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'unsigned' },
      path: '/var/tmp/kworkerd',
      what: 'A program named kworkerd that uses most of your processor, even when you aren’t doing anything.',
      when: null,
    },
    answer: 'threat',
    why: 'It runs from /var/tmp, a temporary folder, with no signature, and it keeps the processor busy for no reason you know of. Those are signs of a hidden cryptocurrency miner.',
    sources: ['guides/remediation/remove_cryptominer.md', 'rescue/attribution.py'],
  },
  {
    id: 'busy-video-export',
    district: 'engine-room',
    severity: 'info',
    modules: ['resource_hog_identifier'],
    title: 'A video app is using a lot of the processor',
    setup: 'Practice setup: you’re exporting a video in iMovie right now.',
    clues: {
      maker: { name: 'Apple', verified: true, how: 'Mac App Store signature' },
      path: '/Applications/iMovie.app',
      what: 'iMovie is using most of the processor.',
      when: null,
    },
    answer: 'mine',
    why: 'It’s signed, installed where Mac apps go, and you’re using it right now. A busy processor while you export a video is normal.',
    sources: ['guides/remediation/investigate_keylogger_indicators.md', 'desktop/renderer/app.js'],
  },
];
