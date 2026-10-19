// UX round 2, Plain view: the Evidence block on every card with the prose it
// repeats cut, the couldn't-check box by cause, and one card for the same
// finding from several checks.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const app = require('../renderer/app.js');
const { page } = require('./page-harness.js');

const mod = (name, findings, extra = {}) => Object.assign({ name, category: 'security', status: 'ok', supported: true, findings }, extra);

// The round-1 screenshot's card, as the engine sends it.
const LABEL = 'ai.hermes.gateway-deflock';
const PROGRAM = '/Users/ann/.hermes/hermes-agent/venv/bin/python';
const PLIST = `/Users/ann/Library/LaunchAgents/${LABEL}.plist`;
const launchAgent = (title) => ({
  title,
  severity: 'warning',
  category: 'security',
  code: 'security.launch_agent_audit.hidden_folder',
  same_key: `task:${LABEL}:hidden_folder`,
  description: `The background task '${LABEL}' runs a program from ${PROGRAM}, which is inside a hidden folder. Hidden folders are often used by developers, but they can also be used to hide unwanted software.\n\nThis is not automatically dangerous, but you should verify that you installed this app.\n\nIf you think someone close to you set this up to monitor you, removing it can alert them.\n\nWhat to do: Open System Settings > General > Login Items & Extensions. Turn it off if you don't recognise it.`,
  data: { label: LABEL, program: PROGRAM, plist: PLIST },
  made_by: [{ subject: PROGRAM, name: 'Unknown maker', verified: false, how: 'ad-hoc signed', location_note: '' }],
  remediation: { steps: [{ title: 'Step 1: Remove high-risk background tasks', body: 'Run `launchctl bootout gui/501 <path-to-plist>`.' }] },
});

test('a card’s prose: no sentence the evidence, the warning box, the steps or a lesson already says', () => {
  const f = launchAgent(`Background task '${LABEL}' runs from a hidden folder`);
  const withSteps = app.cardProse(f.description, f, { steps: 1, alertShown: true });
  assert.strictEqual(withSteps.why, '', 'the path sentence is the evidence; the rest is a lesson or the warning box');
  assert.strictEqual(withSteps.todo, '', 'the steps say what to do');
  const noSteps = app.cardProse(f.description, f, { steps: 0, alertShown: true });
  assert.match(noSteps.todo, /^Open System Settings/);
  const noBox = app.cardProse(f.description, f, { steps: 1, alertShown: false });
  assert.match(noBox.why, /removing it can alert them/, 'the warning stays in the prose when no box shows it');
  const crash = { data: { app_name: 'chrome_crashpad_handler', crash_count: 50 } };
  const p = app.cardProse("The app 'chrome_crashpad_handler' has stopped working 50 times.\n\nThis usually means the app is buggy. Or not compatible. Or worse.\n\nWhat to do: update it.", crash);
  assert.strictEqual(p.why, 'This usually means the app is buggy. Or not compatible.', 'two sentences at most');
});

test('the same finding from several checks is one card that says which checks saw it', () => {
  const sleep = (m) => ({ module: m, title: 'Your Mac is set to never sleep', severity: 'warning', same_key: 'display:never_off', data: { setting: 'sleep', value: 0 } });
  const a = { module: 'launch_agent_audit', ...launchAgent(`Background task '${LABEL}' runs from a hidden folder`) };
  const b = { module: 'launchd_persistence_audit', ...launchAgent(`Background task runs from a hidden folder: ${LABEL}`) };
  const other = { module: 'launch_agent_audit', ...launchAgent('Background task \'other\' runs from a hidden folder'), same_key: 'task:other:hidden_folder', data: { label: 'other' } };
  const sameCheck = [{ module: 'login_items', title: 'Login item: Amical', severity: 'info' }, { module: 'login_items', title: 'Login item: Amical', severity: 'info' }];
  const mon = [{ module: 'stalkerware_scan', title: 'mSpy', severity: 'critical' }, { module: 'keylogger_indicators', title: 'mSpy', severity: 'critical' }];
  // Plain's cards are NotChecked.displayItems' items (app.plainCards), in the checkup's order.
  const asDoc = (findings) => ({ modules: findings.map(({ module, ...f }) => ({ name: module, category: 'security', status: 'ok', findings: [f] })) });
  const cardsOf = (findings) => { const g = app.plainCards(asDoc(findings), 'standard'); return [...g.critical, ...g.warning, ...g.info]; };
  const merged = cardsOf([sleep('energy_saver_check'), a, sleep('energy_settings'), b, other, sleep('power_settings'), ...sameCheck, ...mon]);
  assert.deepStrictEqual(merged.map((f) => f.title), ['mSpy', 'mSpy', 'Your Mac is set to never sleep', a.title, other.title, 'Login item: Amical']);
  assert.deepStrictEqual(merged[2].seen_in, ['energy_saver_check', 'energy_settings', 'power_settings']);
  assert.deepStrictEqual(merged[3].seen_in, ['launch_agent_audit', 'launchd_persistence_audit']);
  // A to-do never merges with a note.
  assert.strictEqual(cardsOf([sleep('a'), { ...sleep('b'), severity: 'info' }]).length, 2);

  const doc = { modules: [{ name: 'energy_saver_check', check_name: 'Energy saver' }] };
  const rows = app.cardEvidenceRows(merged[2], { mode: 'standard', doc, commands: new Map([['energy_settings', [['pmset', '-g']]]]) });
  const seen = rows.find((r) => r.label === 'Seen by');
  assert.strictEqual(seen.value, 'Energy saver, Energy settings, Power settings');
  assert.ok(!rows.some((r) => r.label === 'Check'), 'one line names the checks');
  assert.match(rows.find((r) => r.label === 'Checked with').value, /pmset -g/);
});

test('the couldn’t-check box: one line per cause, check names inline, the engine’s error_kind first', () => {
  const doc = { modules: [
    mod('launch_agent_audit', [], { status: 'error', error: 'PermissionError: [Errno 1] Operation not permitted', check_name: 'Background tasks' }),
    mod('stalkerware_scan', [], { status: 'error', error: 'boom', error_kind: 'permission' }),
    mod('time_machine_check', [], { status: 'error', error: null, error_kind: 'permission' }),
    mod('code_signature_audit', [], { status: 'error', error: 'This check took too long (timed out after 60.0s)' }),
    mod('keylogger_indicators', [], { status: 'error', error: 'x', error_kind: 'timeout' }),
  ] };
  const g = app.groupFindingsBySeverity(doc);
  const items = app.couldntCheckItems(g.erroredModules, g.unfinishedModules, 'standard', g.partlyChecked, doc);
  const { groups, raw } = app.couldntCheckGroups(items);
  assert.deepStrictEqual(groups.map((x) => x.line), [
    '3 checks need Full Disk Access: Background tasks, Stalkerware scan and Time machine check.',
    '2 checks took too long: Code signature audit and Keylogger indicators.',
  ]);
  assert.match(raw, /^Background tasks: PermissionError/m);
  // City mode never says why a monitoring check couldn't run.
  const city = app.couldntCheckGroups(app.couldntCheckItems(g.erroredModules, [], 'city', [], doc));
  assert.ok(city.groups.find((x) => x.kind === 'failed').line.includes('A check'));
  assert.doesNotMatch(JSON.stringify(city), /stalkerware|keylogger/i);
});

async function results(doc) {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  return p;
}

test('the card: title, Evidence, warning, actions; steps, help and technical details folded', async () => {
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('launch_agent_audit', [launchAgent(`Background task '${LABEL}' runs from a hidden folder`)], { check_name: 'Background tasks' }),
    mod('launchd_persistence_audit', [launchAgent(`Background task runs from a hidden folder: ${LABEL}`)]),
    mod('a', [], { status: 'error', error: 'Operation not permitted' }),
    mod('b', [], { status: 'error', error: 'Operation not permitted' }),
    mod('c', [], { status: 'error', error: 'timed out after 60s' }),
  ] });
  const html = p.byId('results-groups').innerHTML.replace(/<wbr>/g, ''); // break chances (evidence.js breakable)
  const cards = html.split('<li class="finding-card').slice(1);
  assert.strictEqual(cards.length, 1, 'one card for the task both checks saw');
  const card = cards[0];
  assert.match(card, /data-evidence/);
  assert.match(card, /Seen by<\/dt><dd><span>Background tasks, Launchd persistence audit/);
  assert.match(card, /evidence-mono">~\/\.hermes\/hermes-agent\/venv\/bin\/python/);
  assert.doesNotMatch(card, /made-by__line/, 'the maker is an Evidence row now');
  assert.doesNotMatch(card, /next-steps/, 'no short “What to do” list beside the steps');
  const face = card.split('<details class="tech-details">')[0];
  assert.doesNotMatch(face, /<strong>What to do:<\/strong>/, 'the steps say it');
  assert.doesNotMatch(face, /Hidden folders are often used|not automatically dangerous|set this up to monitor you/,
    'generic prose and the second warning are off the card’s face');
  assert.match(card, /data-lesson-link="background">What does this mean\?/);
  assert.match(card.split('<details class="tech-details">')[1], /Hidden folders are often used/, 'the whole description is kept for a helper');
  assert.strictEqual((card.match(/Removing this can alert whoever installed it\./g) || []).length, 1, 'the warning once');
  const order = ['data-evidence', 'Removing this can alert', 'Or fix it yourself, step by step (1)', 'Get help with this', 'Technical details'].map((s) => card.indexOf(s));
  assert.ok(order.every((at, i) => at >= 0 && (i === 0 || at > order[i - 1])), `card order: ${order}`);

  const box = p.byId('results-errors-list').innerHTML;
  assert.strictEqual((box.match(/Open the setting/g) || []).length, 1);
  assert.match(box, /2 checks need Full Disk Access: A and B\./);
  assert.match(box, /1 check took too long: C\./);
  assert.doesNotMatch(box, /For tech helpers/, 'one for the whole box, outside the list');
  assert.strictEqual(p.byId('results-errors-tech').hidden, false);
  assert.match(p.byId('results-errors-raw').textContent, /A: Operation not permitted/);
});

test('the step dots are hidden while the city shows', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'app.js'), 'utf8');
  assert.match(src, /stepsBar\.hidden = name === 'city'/);
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  assert.match(html, /<ol class="steps"/);
  assert.match(html, /<script src="evidence\.js"><\/script>\s*<script src="app\.js">/);
  for (const id of ['lesson-background', 'lesson-makers', 'lesson-evidence']) assert.match(html, new RegExp(`id="${id}"`));
});
