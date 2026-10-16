export default {
  id: 'couldnt-check',
  title: 'What “couldn’t check” means',
  recommendedFor: ['unsure'],
  modules: [],
  sources: [
    'README.md',
    'AGENTS.md',
    'desktop/renderer/index.html',
    'desktop/renderer/app.js',
    'desktop/renderer/game/findings-to-city.js',
  ],
  briefing: 'Not every check can run on every computer. Often it just means a permission or a tool is missing. A check that couldn’t run checked nothing, so it isn’t a clean bill of health. Device Rescue says so instead of pretending everything is fine. In the city, those places show as fog. Even a checkup that finds nothing lowers the odds of a problem without ruling one out.',
  whatTheScanLooksFor: 'After the checkup, anything that couldn’t run is listed by name, so you know exactly what wasn’t looked at.',
  questions: [
    {
      prompt: 'A district on your map is covered in fog. What does that mean?',
      options: [
        { text: 'Those checks couldn’t run, so nothing there was looked at', correct: true,
          feedback: 'Right. Often it just means a permission or a tool is missing.' },
        { text: 'Everything there is safe', correct: false,
          feedback: 'No. Fog means nothing was checked there, so it isn’t a clean bill of health.' },
        { text: 'Something bad is hiding there', correct: false,
          feedback: 'Fog doesn’t mean danger either. It means a check couldn’t look.' },
      ],
    },
    {
      prompt: 'The checkup found nothing at all. What can you say?',
      options: [
        { text: 'The odds of a problem are lower, but it isn’t a guarantee', correct: true,
          feedback: 'Right. A clean checkup lowers the odds without ruling a problem out.' },
        { text: 'This computer is definitely clean', correct: false,
          feedback: 'A checkup can’t promise that. It lowers the odds; it doesn’t rule a problem out.' },
      ],
    },
  ],
};
