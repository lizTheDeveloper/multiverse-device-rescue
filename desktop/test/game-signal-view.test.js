const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/signal.js')),
  ...(await import('../renderer/game/clues.js')),
  ...(await import('../renderer/game/views/training.js')),
});
const FINDING = { title: 'Helper', description: 'Starts at login.', data: { program: '/tmp/x' }, made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] };
const real = (extra = {}) => ({ id: 'm|c|program=/tmp/x', kind: 'real', severity: 'critical', title: 'Helper', districtId: 'gatehouse',
  finding: FINDING, missionId: 'm|c|program=/tmp/x', fixable: true, marked: false, stale: false, changed: false, tag: null, ...extra });
const DRILL = { id: 'x', district: 'gatehouse', severity: 'warning', title: 'Practice thing', setup: 'Practice setup: you use it.',
  clues: { maker: null, path: '/tmp/y', what: 'Runs.', when: null }, answer: 'threat', why: 'Because.' };
const drillSig = { id: 'drill:x', kind: 'drill', severity: 'warning', title: DRILL.title, districtId: 'gatehouse', drill: DRILL, missionId: null, tag: null };
async function panel(over = {}) {
  const v = await views();
  const signal = over.signal || real();
  const clues = signal.kind === 'drill' ? v.drillClues(signal.drill) : signal.kind === 'real' ? v.cluesFor(signal.finding) : [];
  return v.renderSignalPanel({ signal, districtName: 'The Gatehouse', clues, opened: [], tagged: null, right: false, read: '', points: 0,
    scout, mineHtml: '', range: null, ...over });
}

test('clues are locked until SCAN CLUE, then show with their how-to-read line', async () => {
  const shut = await panel();
  assert.match(shut, /role="region" aria-labelledby="sig-title"/);
  assert.match(shut, /CRITICAL[\s\S]*The Gatehouse[\s\S]*id="sig-title"[^>]*>Helper/);
  for (const k of ['maker', 'where', 'what']) assert.match(shut, new RegExp(`data-act="clue:${k}"`));
  assert.doesNotMatch(shut, /How to read this/);
  assert.match(shut, /data-act="tag:mine"[\s\S]*data-act="tag:closer"[\s\S]*data-act="tag:threat"/);
  assert.match(shut, /They change nothing on your computer/);
  const open = await panel({ opened: ['maker', 'where'] });
  assert.match(open, /WHO MADE IT[\s\S]*Unknown maker, not verified \(unsigned\)[\s\S]*<summary>How to read this<\/summary><p>Not verified/);
  assert.match(open, /WHERE IT LIVES[\s\S]*\/tmp\/x[\s\S]*temporary folder/);
  assert.match(open, /data-act="clue:what"/);
});

test('engine text is escaped everywhere in the panel', async () => {
  const evil = { title: EVIL, description: EVIL, data: { program: `/tmp/${EVIL}` }, made_by: [{ name: EVIL, verified: false, how: EVIL }] };
  const html = await panel({ signal: real({ title: EVIL, finding: evil }), opened: ['maker', 'where', 'what'], tagged: 'threat', read: EVIL });
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x/);
});

test('a couldn’t-check signal can only be NOTED, and links the lesson', async () => {
  const html = await panel({ signal: { id: 'couldnt|m', kind: 'couldnt', severity: 'couldnt', title: 'A check couldn’t run here',
    description: 'Needs permission.', districtId: 'wires', finding: null, missionId: null, tag: null } });
  assert.match(html, /COULDN’T CHECK/);
  assert.match(html, /Needs permission\./);
  assert.match(html, /That doesn’t mean it’s safe/);
  assert.match(html, /data-act="tag:noted"[^>]*>NOTED/);
  assert.match(html, /data-go="lesson:couldnt-check"/);
  assert.doesNotMatch(html, /data-act="tag:(mine|threat|closer)"|SCAN CLUE/);
});

test('a drill: stamped, practice-only, its setup shown, and never the real “It’s mine” step', async () => {
  const html = await panel({ signal: drillSig, mineHtml: '<b>MARK</b>' });
  assert.match(html, /class="sig-panel drill"/);
  assert.match(html, /DRILL<\/span> Practice\. This isn’t on your computer\./);
  assert.match(html, /Practice setup: you use it\./);
  assert.match(html, /data-act="clue:where"/);
  assert.doesNotMatch(html, /data-act="clue:maker"/, 'no maker in this drill, so no maker clue');
  const after = await panel({ signal: drillSig, tagged: 'mine', right: false, read: 'Not this time, and it costs you nothing. The tell: Because.', mineHtml: '<b>MARK</b>' });
  assert.doesNotMatch(after, /<b>MARK<\/b>/);
  assert.match(after, /The tell: Because\./);
  assert.match(after, /aria-disabled="true" disabled/, 'a drill takes one answer, and the keyboard cannot re-answer');
  assert.doesNotMatch(after, /POINTS/, 'a wrong answer scores nothing');
});

test('after tagging: Scout’s read, the points, and each tag’s next step', async () => {
  const mine = await panel({ tagged: 'mine', read: 'The checkup marked this critical.', points: 20, mineHtml: '<div data-mark-card>MARK IT</div>' });
  assert.match(mine, /The checkup marked this critical\./);
  assert.match(mine, /\+20 POINTS for the clues you checked/);
  assert.match(mine, /OPTIONAL: TELL RECLAIM CITY TOO[\s\S]*It asks first, and you can undo it\.[\s\S]*MARK IT/);
  assert.match(mine, /data-act="tag:mine" aria-pressed="true"/);
  const threat = await panel({ tagged: 'threat', read: 'r' });
  assert.match(threat, /ON YOUR THREAT BOARD[\s\S]*data-go="mission:m\|c\|program=\/tmp\/x"[^>]*>SEE THE FIX ▶/);
  assert.doesNotMatch(threat, /MARK IT/);
  assert.doesNotMatch(threat, /POINTS/);
  assert.match(await panel({ tagged: 'closer', read: 'r' }), /It stays in your queue/);
});

// Review Focus 2.
test('a finding with no clues says so, and can still be tagged', async () => {
  const html = await panel({ signal: real({ finding: { title: 'x', description: '', data: {} } }) });
  assert.match(html, /recorded no clues for this one/);
  assert.match(html, /data-act="tag:threat"/);
});

test('marked, changed since marking, and changed since tagging each say so', async () => {
  assert.match(await panel({ signal: real({ marked: true, tag: 'mine' }) }), /MARKED<\/span> You told Reclaim City this is yours\. It stays listed\./);
  assert.match(await panel({ signal: real({ stale: true }) }), /CHANGED SINCE YOU MARKED IT/);
  assert.match(await panel({ signal: real({ changed: true }) }), /CHANGED SINCE YOU TAGGED IT/);
});

test('the drill range: getting ready, nothing loaded, and a drill with next and back', async () => {
  const v = await views();
  assert.match(v.renderRange({ loaded: false, panelHtml: '', hasCity: false }), /THE DRILL RANGE[\s\S]*Getting the drills ready/);
  const empty = v.renderRange({ loaded: true, panelHtml: '', hasCity: true });
  assert.match(empty, /The drills couldn’t load/);
  assert.match(empty, /data-act="leave-range">BACK TO THE DECK/);
  const html = v.renderRange({ loaded: true, panelHtml: await panel({ signal: drillSig, range: { hasCity: false } }), hasCity: false });
  assert.match(html, /None of this is on your computer/);
  assert.match(html, /data-act="next-drill"[^>]*>NEXT DRILL ▶/);
  assert.match(html, /data-act="leave-range"[^>]*>BACK TO THE TRAINING GROUNDS/);
  assert.doesNotMatch(html, /data-act="close-signal"/);
});

test('the Training Grounds offer the DRILL RANGE, with or without a scan', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} },
    scan: { running: false, index: 0, total: 0, error: null }, scout, lessonsLoaded: true });
  assert.match(html, /data-go="range"[^>]*>DRILL RANGE ▶/);
  assert.match(html, /Nothing in the range touches your computer/);
});

test('a mark that couldn’t be checked says so, and never that it changed', async () => {
  const html = await panel({ signal: real({ unchecked: true }) });
  assert.match(html, /NOT CHECKED THIS TIME[\s\S]*We couldn’t check this one this time, so its warning is back\. That doesn’t mean it changed\./);
  assert.doesNotMatch(html, /CHANGED SINCE YOU MARKED IT/);
});

test('an offer is one line with two answers, after Scout’s read', async () => {
  const { renderSignalPanel } = await import('../renderer/game/views/signal.js');
  const sig = { id: 'drill:x', kind: 'drill', severity: 'warning', title: 'A drill', districtId: 'gatehouse', drill: { setup: '' } };
  const html = renderSignalPanel({ signal: sig, tagged: 'mine', read: 'Not this time.', scout: () => '', offer: { id: 'where-it-lives', title: 'Where it lives' } });
  assert.match(html, /Want the 2 questions on Where it lives\?/);
  assert.match(html, /data-act="offer-yes:where-it-lives"/);
  assert.match(html, /data-act="offer-no:where-it-lives"[^>]*>STILL KNOW IT/);
  assert.ok(html.indexOf('Not this time.') < html.indexOf('Want the 2 questions'));
  assert.doesNotMatch(renderSignalPanel({ signal: sig, tagged: 'mine', read: 'r', scout: () => '' }), /offer-yes/);
});
