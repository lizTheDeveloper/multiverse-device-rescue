const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/deck.js')),
  ...(await import('../renderer/game/views/instruments.js')),
  ...(await import('../renderer/game/views/map.js')),
  ...(await import('../renderer/game/views/one-city-map.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/progress.js')),
  ...(await import('../renderer/game/ledger.js')),
});
const sig = (id, severity, extra = {}) => ({ id, kind: 'real', severity, title: `T ${id}`, districtId: 'gatehouse', missionId: null,
  tag: null, marked: false, stale: false, changed: false, count: 1, ...extra });
async function deck(over = {}) {
  const v = await views();
  return v.renderDeck({ title: 'YOUR COMPUTER', rank: v.rankOf(v.emptyDeck()), lastSweep: { at: '2026-10-18T12:00:00Z', checks: 290 },
    items: [], low: [], lowOpen: false, threats: [], known: [], filter: null, cityHtml: '<div id="city"></div>',
    instrumentsHtml: '<div id="inst"></div>', log: [], moment: null, panelHtml: '', nothingChecked: false, scanRunning: false,
    districtName: () => 'The Gatehouse', ...over });
}

test('the deck: top bar, queue, city, instruments, log; engine text is escaped', async () => {
  const html = await deck({ items: [sig('a', 'critical', { title: EVIL }), sig('b', 'warning')],
    log: [{ at: '2026-10-18T12:00:00Z', kind: 'TAG', text: EVIL }] });
  assert.match(html, /RANK<\/small> ROOKIE/);
  assert.match(html, /290 CHECKS/);
  assert.match(html, /data-act="resweep"[^>]*>RE-SWEEP ⟳/);
  assert.match(html, /data-go="training"/);
  assert.match(html, /data-act="list"/);
  assert.match(html, /INCOMING SIGNALS[\s\S]*data-act="investigate-next"[\s\S]*data-go="signal:a"[\s\S]*data-go="signal:b"/);
  assert.match(html, /<div class="deck-city"><div id="city"><\/div><\/div>/);
  assert.match(html, /<div id="inst"><\/div>/);
  assert.match(html, /OPS LOG[\s\S]*TAG/);
  assert.match(html, /<button type="button" class="sig sev-critical"/, 'each signal is a real button');
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x/);
  assert.match(await deck({ scanRunning: true }), /SWEEPING/);
  assert.doesNotMatch(await deck({ scanRunning: true }), /data-act="resweep"/);
});

// Review Focus 5.
test('hundreds of info signals stay folded: one row; opened, at most 50 and a count; the batch line', async () => {
  const v = await views();
  const low = Array.from({ length: 300 }, (_, i) => sig(`n${i}`, 'info'));
  const shut = await deck({ low });
  assert.match(shut, /data-act="toggle-low" aria-expanded="false">LOW-PRIORITY SIGNALS \(300\)/);
  assert.strictEqual((shut.match(/data-go="signal:n/g) || []).length, 0);
  const open = await deck({ low, lowOpen: true });
  assert.match(open, /aria-expanded="true"/);
  assert.strictEqual((open.match(/data-go="signal:n/g) || []).length, v.LOW_SHOWN);
  assert.match(open, /And 250 more/);
  assert.match(open, /data-act="batch-fine"[^>]*>THESE ARE ALL FINE/);
  assert.match(open, /earns no points/);
  const known = await deck({ known: low.map((x) => ({ ...x, tag: 'mine' })) });
  assert.match(known, /KNOWN AND NOTED \(300\)/);
  assert.strictEqual((known.match(/data-go="signal:n/g) || []).length, v.LOW_SHOWN, 'the known pile is capped too');
});

// Review Focus 1.
test('an empty board offers the drill range; nothing checked never says clear', async () => {
  const clear = await deck();
  assert.match(clear, /CLEAR BOARD/);
  assert.match(clear, /lowers the odds of a problem; it doesn’t rule one out/);
  assert.match(clear, /data-go="range"[^>]*>DRILL RANGE ▶/);
  assert.doesNotMatch(clear, /investigate-next/);
  const fog = await deck({ nothingChecked: true, items: [sig('couldnt|a', 'couldnt', { kind: 'couldnt', title: 'A check couldn’t run here' })] });
  assert.match(fog, /NOTHING COULD BE CHECKED/);
  assert.match(fog, /That doesn’t mean it’s safe/);
  assert.doesNotMatch(fog, /CLEAR BOARD/);
  assert.match(fog, /COULDN’T CHECK/);
});

test('rows say what they are: DRILL, LOOK CLOSER, MARKED, changed; the threat board has next moves', async () => {
  const html = await deck({
    items: [sig('drill:x', 'warning', { kind: 'drill' }), sig('c', 'warning', { tag: 'closer' }), sig('s', 'warning', { stale: true }), sig('g', 'warning', { changed: true })],
    threats: [sig('t1', 'critical', { tag: 'threat', missionId: 't1', fixable: true }), sig('t2', 'info', { tag: 'threat' })],
    known: [sig('k', 'warning', { tag: 'mine', marked: true })] });
  assert.match(html, /class="sig sev-warning drill"[\s\S]*?DRILL/);
  assert.match(html, /data-go="signal:c"[\s\S]*?LOOK CLOSER/);
  assert.match(html, /CHANGED SINCE YOU MARKED IT/);
  assert.match(html, /CHANGED SINCE YOU TAGGED IT/);
  assert.match(html, /THREAT BOARD \(2\)[\s\S]*data-go="mission:t1"[^>]*>SEE THE FIX ▶[\s\S]*data-act="list"[^>]*>SEE IT IN THE LIST ▶/);
  assert.match(html, /Tagging changes nothing on your computer/);
  assert.match(html, /KNOWN AND NOTED \(1\)[\s\S]*MARKED/);
});

test('a moment is a banner with a role; a filter shows its district with a way back', async () => {
  const html = await deck({ moment: { kind: 'clean', title: 'CLEAN SWEEP', text: 'No open signals.' }, filter: { id: 'wires', name: 'The Wires' } });
  assert.match(html, /<div class="moment moment-clean" role="status"><b>CLEAN SWEEP<\/b> No open signals\.<\/div>/);
  assert.match(html, /SHOWING THE WIRES[\s\S]*data-go="filter:all"[\s\S]*data-go="district:wires"/);
  assert.doesNotMatch(html, /CLEAR BOARD/, 'an empty filter isn’t a clear board');
  assert.match(html, /Nothing to sort here/);
});

test('instruments: integrity with a text equivalent, a hidden sparkline, confirmed and reported apart, rank progress', async () => {
  const v = await views();
  assert.strictEqual(v.integrityText(72, 61), 'City integrity 72%, up from 61% last sweep.');
  assert.strictEqual(v.integrityText(50, 61), 'City integrity 50%, down from 61% last sweep.');
  assert.strictEqual(v.integrityText(50, 50), 'City integrity 50%, the same as last sweep.');
  assert.strictEqual(v.integrityText(50, null), 'City integrity 50%.');
  assert.match(v.integrityText(null, 80), /no reading/);
  assert.strictEqual(v.sparklineSvg([50]), '', 'one point is not a line');
  assert.match(v.sparklineSvg([20, null, 80]), /<svg class="spark"[^>]*aria-hidden="true"[^>]*>[\s\S]*<polyline points="0\.0,[\d.]+ 100\.0,[\d.]+"/);
  const html = v.renderInstruments({ integrity: 72, previous: 61, history: [61, 72], bars: { sorted: 4, confirmed: 2, reported: 3 },
    rank: v.rankOf({ ...v.emptyDeck(), points: 40 }) });
  assert.match(html, /<b>72%<\/b>/);
  assert.match(html, /City integrity 72%, up from 61% last sweep\./);
  assert.match(html, /<b>4<\/b> <small>SORTED<\/small>[\s\S]*<b>2<\/b> <small>CONFIRMED<\/small>[\s\S]*<b>3<\/b> <small>YOU REPORTED<\/small>/);
  assert.doesNotMatch(html, /<b>5<\/b>/, 'confirmed and reported are never summed');
  assert.match(html, /ROOKIE[\s\S]*40 POINTS[\s\S]*aria-valuenow="40"[\s\S]*60 points to SIGNAL ANALYST/);
  const none = v.renderInstruments({ integrity: null, previous: null, history: [null], bars: {}, rank: v.rankOf(v.emptyDeck()) });
  assert.match(none, /<b>—<\/b>/);
  assert.doesNotMatch(none, /<b>\d+%<\/b>/);
});

test('the city in the middle: districts filter the queue, glow by heat, and fog is never clear', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [
    { name: 'a', category: 'security', status: 'ok', supported: true, findings: [{ title: 'x', severity: 'critical', data: {} }] },
    { name: 'b', category: 'network', status: 'error', error: 'no', findings: [] },
  ] });
  const opts = { goFor: (d) => `filter:${d.id}`, heat: { gatehouse: 'hot' }, selected: 'gatehouse' };
  const html = v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout, ...opts });
  assert.match(html, /class="district hot heat-hot" data-go="filter:gatehouse" aria-current="true"/);
  assert.match(html, /class="district fog" data-go="filter:wires"/);
  assert.match(html, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  assert.match(v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout }), /class="district hot" data-go="district:gatehouse">/, 'the default is unchanged');
  const one = v.renderOneCityMap({ city, progress: v.emptyProgress(), accountCards: [], focus: 'computer', cameBack: [], scout, ...opts });
  assert.match(one, /class="district hot heat-hot" data-go="filter:gatehouse" aria-current="true"/);
});

test('the deck stacks queue, city, instruments, log when narrow; drills are hatched; moments animate unless motion is reduced', () => {
  const css = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');
  assert.match(css, /@media \(max-width: 900px\) \{ \.deck \{[^}]*grid-template-areas: "queue" "city" "instruments" "log"/);
  assert.match(css, /\.sig\.drill, \.sig-panel\.drill \{[^}]*border: 2px solid var\(--lime\)[^}]*repeating-linear-gradient/);
  assert.match(css, /\.moment \{[^}]*animation: moment-in/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ \*, \*::before, \*::after \{ animation: none !important/);
});
