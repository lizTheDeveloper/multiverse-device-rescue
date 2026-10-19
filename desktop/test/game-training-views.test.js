const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/training.js')),
  ...(await import('../renderer/game/views/lesson.js')),
  ...(await import('../renderer/game/views/boss.js')),
  ...(await import('../renderer/game/views/briefing.js')),
  ...(await import('../renderer/game/boss.js')),
});
const LESSON = {
  id: 'l1', title: 'Lesson one', recommendedFor: [], modules: [], sources: ['README.md'],
  briefing: 'Open `chrome://extensions/` to see them.', whatTheScanLooksFor: 'Extensions.',
  questions: [
    { prompt: 'Q1?', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'Not quite.' }] },
    { teach: 'Second `fact` here.', prompt: 'Q2?', options: [{ text: 'A', correct: false, feedback: 'Nope.' }, { text: 'B', correct: true, feedback: 'Yes.' }] },
  ],
};
const idle = { running: false, index: 0, total: 0, error: null };
const running = { running: true, index: 12, total: 290, error: null };
const failed = { running: false, index: 0, total: 0, error: 'The engine stopped.' };
const ordered = { recommended: [LESSON], other: [] };

test('the way to the checkup is on every Training Grounds and lesson state', async () => {
  const v = await views();
  const states = [];
  for (const scan of [idle, running, failed]) {
    for (const pendingCity of [false, true]) {
      states.push(v.renderTraining({ ordered, progress: { lessons: {} }, worryTitle: 'x', scan, scout, pendingCity }));
      for (const [qIndex, picked] of [[0, null], [0, 1], [1, 1]]) {
        states.push(v.renderLesson({ lesson: LESSON, qIndex, picked, scan, scout, pendingCity }));
      }
    }
  }
  states.push(v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} }, scan: idle, scout }));
  states.push(v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} }, scan: idle, scout, lessonsLoaded: true }));
  states.push(v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, scanFinished: true }));
  states.push(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: null, scan: idle, scout, scanFinished: true }));
  for (const html of states) assert.match(html, /data-act="start-checkup"|data-go="boss"/);
});

test('while a scan runs, the button goes back to the checkup instead of starting another', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered, progress: { lessons: {} }, scan: running, scout });
  assert.match(html, /data-go="boss"/);
  assert.doesNotMatch(html, /data-act="start-checkup"/);
  assert.match(html, /12 of 290/);
});

test('a failed scan shows the error in plain words and offers to start again', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered, progress: { lessons: {} }, scan: failed, scout });
  assert.match(html, /stopped before it finished/);
  assert.doesNotMatch(html, /The engine stopped\./, 'never the engine’s own words');
  assert.match(html, /Nothing on your computer was changed/);
  assert.match(html, /START THE CHECKUP/);
});

test('mid-lesson, a finished scan shows a banner and keeps the picked answer', async () => {
  const v = await views();
  const html = v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 0, scan: idle, scout, pendingCity: true });
  assert.match(html, /Your checkup is done/);
  assert.match(html, /data-go="city"/);
  assert.match(html, /class="opt right"/);
  assert.match(html, /Right\./);
});

test('a lesson: briefing with code, feedback after answering, next then finish', async () => {
  const v = await views();
  const q1 = v.renderLesson({ lesson: LESSON, qIndex: 0, picked: null, scan: idle, scout });
  assert.match(q1, /<code>chrome:\/\/extensions\/<\/code>/);
  assert.doesNotMatch(q1, /class="feedback"/);
  assert.match(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 1, scan: idle, scout }), /data-act="next-question"/);
  const last = v.renderLesson({ lesson: LESSON, qIndex: 1, picked: 1, scan: idle, scout });
  assert.match(last, /data-act="finish-lesson"/);
  assert.match(last, /Extensions\./);
  assert.match(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 1, scan: idle, scout }), /class="opt wrong"/);
});

test('Reclaim City message text is escaped in the phishing lesson', async () => {
  const v = await views();
  const lesson = { ...LESSON, type: 'phishing', questions: [{ prompt: 'Real or fake?', message: { type: 'email', from: EVIL, subject: EVIL, body: EVIL },
    options: [{ text: 'Fake', correct: true, feedback: EVIL }, { text: 'Real', correct: false, feedback: 'x' }] }] };
  const html = v.renderLesson({ lesson, qIndex: 0, picked: 0, scan: idle, scout });
  assert.ok(!html.includes('<img src=x'));
  assert.match(html, /&lt;img src=x/);
});

test('the boss screen: sweep states, progress, a way to the lessons, escaped tips, and no verdicts', async () => {
  const v = await views();
  let b = v.bossInit();
  b = v.bossApply(b, { type: 'progress', phase: 'done', index: 1, total: 4, category: 'security', findings: 3 });
  b = v.bossApply(b, { type: 'progress', phase: 'start', index: 2, total: 4, category: 'network' });
  const html = v.renderBoss({ boss: b, scout, tips: [{ title: EVIL, body: 'Click Allow.' }] });
  assert.match(html, /SWEEPING/);
  assert.match(html, /SWEPT/);
  assert.match(html, /WAITING/);
  assert.match(html, /1 \/ 4 CHECKS/);
  assert.match(html, /3 THINGS NOTED SO FAR/);
  assert.match(html, /data-go="training"/);
  assert.match(html, /aria-valuenow="25"/);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html.replace(/<[^>]+>/g, ' '), /\b(safe|clear|nothing found|infected|hacked)\b/i);
});

test('the briefing links back to a finished lesson only when given one', async () => {
  const v = await views();
  const mission = { id: 'm1', districtId: 'gatehouse', severity: 'warning', title: 'T', description: 'D', steps: [{ number: 1, title: 'S', body: '' }],
    walkthroughTitle: null, safetyNote: null, findings: [{}], primary: {} };
  const base = { mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false };
  assert.doesNotMatch(v.renderBriefing(base), /Training Grounds/);
  const html = v.renderBriefing({ ...base, learned: { id: 'starts-on-its-own', title: EVIL } });
  assert.match(html, /data-go="lesson:starts-on-its-own"/);
  assert.match(html, /You learned about this in the Training Grounds/);
  assert.ok(!html.includes('<img src=x'));
});

test('the city HUD links back to the Training Grounds', async () => {
  const { renderHud } = await import('../renderer/game/views/hud.js');
  const html = renderHud({ title: 'T', city: { districts: [], totals: { critical: 0, warning: 0, fog: 0 } }, progress: { missions: {} } });
  assert.match(html, /data-go="training"/);
  assert.match(html, /data-act="list"/);
});

test('a call or text has no subject line, and never prints null', async () => {
  const v = await views();
  const lesson = { ...LESSON, type: 'phishing', questions: [{ prompt: 'Real or fake?', message: { type: 'text', from: '+1 555 0100', subject: null, body: 'Your parcel is waiting.' },
    options: [{ text: 'Fake', correct: true, feedback: 'Right.' }, { text: 'Real', correct: false, feedback: 'x' }] }] };
  const html = v.renderLesson({ lesson, qIndex: 0, picked: null, scan: idle, scout });
  assert.doesNotMatch(html, /null|undefined/);
  assert.doesNotMatch(html, /<strong>/);
  assert.match(html, /TEXT/);
  assert.match(html, /Your parcel is waiting\./);
});

test('lesson titles, prompts and feedback with HTML render as text', async () => {
  const v = await views();
  const lesson = { ...LESSON, title: EVIL, briefing: EVIL + ' `' + EVIL + '`',
    questions: [{ teach: EVIL, prompt: EVIL, options: [{ text: EVIL, correct: true, feedback: EVIL }, { text: 'No', correct: false, feedback: 'x' }] }] };
  const lessonHtml = v.renderLesson({ lesson, qIndex: 0, picked: 0, scan: idle, scout });
  const trainHtml = v.renderTraining({ ordered: { recommended: [lesson], other: [] }, progress: { lessons: {} }, worryTitle: EVIL, scan: { ...failed, error: EVIL }, scout });
  for (const html of [lessonHtml, trainHtml]) {
    assert.ok(!html.includes('<img src=x'));
    assert.match(html, /&lt;img src=x/);
  }
  assert.match(lessonHtml, /<code>&lt;img src=x/);
});

test('the Training Grounds and boss screens offer the plain view', async () => {
  const v = await views();
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout }), /data-act="leave"/);
  assert.match(v.renderBoss({ boss: v.bossInit(), scout, tips: [] }), /data-act="leave"/);
});

test('the boss screen never uses time words or says you are safe', async () => {
  const v = await views();
  let b = v.bossInit();
  b = v.bossApply(b, { type: 'progress', phase: 'start', index: 0, total: 4, category: 'security' });
  for (const boss of [v.bossInit(), b]) {
    const text = v.renderBoss({ boss, scout, tips: [] }).replace(/<[^>]+>/g, ' ');
    assert.doesNotMatch(text, /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i);
    assert.doesNotMatch(text, /you(’|')re safe|you are safe|unsafe/i);
    assert.doesNotMatch(text, /score/i);
  }
});

test('reduced motion also stops the sweep, which is drawn on ::after', () => {
  const css = require('node:fs').readFileSync(require('node:path').join(__dirname, '../renderer/game/game.css'), 'utf8');
  const rule = css.match(/@media \(prefers-reduced-motion: reduce\) \{([^{]*)\{[^}]*animation: none/);
  assert.ok(rule, 'reduced-motion rule found');
  assert.match(rule[1], /\*::after/);
  assert.match(rule[1], /\*::before/);
  assert.match(css, /\.district\.sweeping \.skyline::after \{[^}]*animation: sweep/);
});

test('a finished lesson is marked DONE without the safe styling', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered, progress: { lessons: { l1: { completedAt: 1 } } }, scan: idle, scout });
  assert.match(html, /class="badge cyan">DONE</);
  assert.doesNotMatch(html, /badge safe/);
});

test('before the lessons arrive, a neutral line; only a finished load with none says they couldn’t load', async () => {
  const v = await views();
  const none = { recommended: [], other: [] };
  const loading = v.renderTraining({ ordered: none, progress: { lessons: {} }, scan: idle, scout });
  assert.doesNotMatch(loading, /couldn’t load/);
  assert.match(loading, /Getting the lessons ready/);
  const empty = v.renderTraining({ ordered: none, progress: { lessons: {} }, scan: idle, scout, lessonsLoaded: true });
  assert.match(empty, /The lessons couldn’t load\. The checkup still works\./);
  const some = v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, lessonsLoaded: true });
  assert.doesNotMatch(some, /couldn’t load|Getting the lessons ready/);
});

test('after this worry’s checkup finished, the button runs it again rather than skipping to it', async () => {
  const v = await views();
  const again = /data-act="start-checkup"[^>]*>RE-SWEEP ⟳/;
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, scanFinished: true }), again);
  assert.match(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: null, scan: idle, scout, scanFinished: true }), again);
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout }), /SKIP TO THE CHECKUP ▶/);
  // A failed later run says START, and a running one goes back to it.
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: failed, scout, scanFinished: true }), /START THE CHECKUP ▶/);
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: running, scout, scanFinished: true }), /data-go="boss"/);
});

test('lesson tiles carry a start cue; the first not-done lesson is the primary one; skip is quiet', async () => {
  const v = await views();
  const two = { recommended: [LESSON, { ...LESSON, id: 'l2' }], other: [] };
  const html = v.renderTraining({ ordered: two, progress: { lessons: { l1: { completedAt: 1 } } }, scan: idle, scout });
  assert.match(html, /AGAIN ▶<\/span>/);
  assert.match(html, /START ▶<\/span>/);
  assert.equal((html.match(/class="lesson[^"]*\bnext\b/g) || []).length, 1);
  assert.match(html, /class="btn-s quiet" data-act="start-checkup"/);
  assert.match(v.renderTraining({ ordered, progress: { lessons: {} }, scan: running, scout }), /class="btn-s lime" data-go="boss"/);
});

test('the lesson intro shows on question 1; each question’s own what-to-know shows above it', async () => {
  const v = await views();
  const q1 = v.renderLesson({ lesson: LESSON, qIndex: 0, picked: null, scan: idle, scout });
  const q2 = v.renderLesson({ lesson: LESSON, qIndex: 1, picked: null, scan: idle, scout });
  assert.doesNotMatch(q1, /Second/);
  assert.doesNotMatch(q2, /chrome:\/\/extensions/);
  assert.match(q2, /WHAT TO KNOW<\/div><p class="intel">Second <code>fact<\/code> here\.<\/p>/);
  assert.ok(q2.indexOf('Second') < q2.indexOf('Q2?'));
  const bare = { ...LESSON, briefing: '', questions: [LESSON.questions[0]] };
  assert.doesNotMatch(v.renderLesson({ lesson: bare, qIndex: 0, picked: null, scan: idle, scout }), /WHAT TO KNOW/);
});

test('a visit renders the items it was given, counts them, and hides the what-to-know when told to', async () => {
  const v = await import('../renderer/game/views/lesson.js');
  const lesson = { id: 'l', title: 'L', briefing: 'Intro here.', questions: [{ teach: 'Q teach', prompt: 'Q one', options: [{ text: 'A', correct: true, feedback: 'ok' }, { text: 'B', correct: false, feedback: 'no' }] }] };
  const items = [
    { key: 'x-2', teach: 'Family teach', prompt: 'Variant prompt', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'No.' }] },
    { key: 'y', teach: 'Other teach', prompt: 'Second item', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'No.' }] },
  ];
  const scout = () => '';
  const idle = { running: false, index: 0, total: 0, error: null };
  const first = v.renderLesson({ lesson, items, qIndex: 0, picked: null, scan: idle, scout });
  assert.ok(first.includes('Variant prompt') && first.includes('QUESTION 1 OF 2') && first.includes('Family teach'));
  assert.ok(!first.includes('Q one'));
  const hidden = v.renderLesson({ lesson, items, qIndex: 1, picked: null, showTeach: false, scan: idle, scout });
  assert.ok(hidden.includes('Second item') && !hidden.includes('Other teach'));
  assert.match(v.renderLesson({ lesson, items, qIndex: 1, picked: 0, scan: idle, scout }), /data-act="finish-lesson"/);
});
