const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Q = require('../renderer/quiet-notes.js');
const { page, monitoring } = require('./page-harness.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const DV = /799-7233|88788|advocate|domestic\s+violence/i;
const REPO = path.join(__dirname, '..', '..');

test('standard mode: one line on monitoring software, nothing on anything else', () => {
  for (const mode of ['standard', null]) {
    for (const module of ['stalkerware_scan', 'keylogger_indicators', 'mvt_spyware_scan']) assert.strictEqual(Q.noteFor(mode, { module }), 'line', module);
    assert.strictEqual(Q.noteFor(mode, { module: 'remote_login_check' }), 'none');
  }
});

test('a hotline paragraph comes out of a description; the rest stays', () => {
  const text = 'Screen Sharing is on.\n\nIf you think someone close to you set this up, call 1-800-799-7233.\n\nWhat to do: turn it off.';
  assert.strictEqual(Q.quiet(text), 'Screen Sharing is on.\n\nWhat to do: turn it off.');
  assert.strictEqual(Q.quiet(''), '');
  assert.strictEqual(Q.quiet(null), '');
});

test('in a list, only the item that carries it comes out', () => {
  const body = '- If this is a work computer, call security.\n- If another person may be involved, talk to a domestic violence advocate before\n  you remove anything: 1-800-799-7233.\n- For everyone else, go ahead.';
  assert.strictEqual(Q.quiet(body), '- If this is a work computer, call security.\n- For everyone else, go ahead.');
});

test('a card for anything else has no such text, in its description or its steps', () => {
  const finding = { module: 'remote_login_check', description: 'Remote Login is on.\n\nTalk to an advocate first (1-800-799-7233).',
    remediation: { safety_note: 'Talk to an advocate.', steps: [{ number: 1, title: 'Turn it off', body: 'Open System Settings.\n\nCall 1-800-799-7233 first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'none');
  assert.doesNotMatch(card.description + card.steps.map((s) => s.body).join(' '), DV);
  assert.match(card.description, /Remote Login is on/);
  assert.match(card.steps[0].body, /Open System Settings/);
  assert.strictEqual(Q.lineHtml(card, esc), '');
});

test('monitoring software: one line with the full note behind it, and its own steps kept', () => {
  const finding = { module: 'stalkerware_scan', description: 'An app that records what you type.\n\nIf a partner set this up, call 1-800-799-7233.',
    remediation: { safety_note: 'Before you remove or turn anything off: talk to an advocate first.', steps: [{ number: 1, title: 'Decide', body: 'Talk to a domestic violence advocate first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'line');
  assert.doesNotMatch(card.description, DV);
  assert.deepStrictEqual(card.steps, finding.remediation.steps);
  const html = Q.lineHtml(card, esc);
  assert.match(html, /^<details class="finding-card__note"><summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  assert.match(html, /talk to an advocate first/);
  assert.match(html, /799-7233/);
  // With nothing of its own to say, the note still says it.
  assert.match(Q.lineHtml(Q.cardText('standard', { module: 'keylogger_indicators', description: 'x' }), esc), /799-7233/);
});

test('quietDoc quiets every finding but monitoring software, and leaves the scan alone', () => {
  const doc = { modules: [
    { name: 'remote_login_check', findings: [{ description: 'On.\n\nCall 1-800-799-7233.', remediation: { safety_note: 'n', steps: [{ title: 't', body: 'Call 88788.' }] } }] },
    { name: 'stalkerware_scan', findings: [{ description: 'Found.\n\nCall 1-800-799-7233.' }] },
  ] };
  const out = Q.quietDoc(doc);
  assert.strictEqual(out.modules[0].findings[0].description, 'On.');
  assert.strictEqual(out.modules[0].findings[0].remediation.steps[0].body, '');
  assert.ok(!('safety_note' in out.modules[0].findings[0].remediation));
  assert.strictEqual(out.modules[1], doc.modules[1], 'monitoring software is the game’s to hold (Task 7)');
  assert.match(doc.modules[0].findings[0].description, /799-7233/, 'the scan itself is untouched');
  assert.strictEqual(Q.quietDoc(null), null);
});

test('every remediation guide reads cleanly in standard mode, and keeps its other lines', () => {
  const dir = path.join(REPO, 'guides', 'remediation');
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.md'))) {
    if (file === 'respond_to_monitoring_software.md') continue; // monitoring software keeps its steps
    const body = fs.readFileSync(path.join(dir, file), 'utf8').replace(/^---[\s\S]*?---\n/, '');
    const quiet = Q.quiet(body);
    assert.doesNotMatch(quiet, DV, file);
    const kept = body.split('\n').filter((l) => l.trim() && !DV.test(l)).length;
    if (kept) assert.ok(quiet.trim().length > 0, `${file}: nothing left`);
  }
});

test('the scan screen and the results never carry the banner or the reminder any more', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  assert.doesNotMatch(html, /scan-safety|results-next-safety|799-7233/);
});

test('the list in standard mode: no hotline text except the one line on monitoring software', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [
    { name: 'remote_login_check', category: 'security', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 'Remote Login is on',
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.', category: 'security', data: {} }] },
    ...monitoring.modules,
  ] });
  p.answer('known'); // the follow-up (Task 5)
  const html = p.byId('results-groups').innerHTML;
  assert.strictEqual(html.split('Removing this can alert whoever installed it. Read this first.').length, 2, 'the one line, once');
  assert.doesNotMatch(html.replace(/<details class="finding-card__note">[\s\S]*?<\/details>/g, ''), DV);
});

test('the game’s mission screens read the same quiet text', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const ctl = createController({ win, storage: null, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  const doc = { schema_version: 1, platform: 'darwin', modules: [{ name: 'remote_login_check', category: 'security', status: 'ok', supported: true,
    findings: [{ title: 'Remote Login is on', severity: 'warning', category: 'security', data: {},
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.' }] }] };
  ctl.show(doc, { id: 'unsure' });
  const id = findingsToCity(doc).districts[0].missions[0].id;
  const el = { getAttribute: (k) => (k === 'data-go' ? `mission:${id}` : null) };
  clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  assert.match(frame.innerHTML, /Remote Login is on/);
  assert.doesNotMatch(frame.innerHTML, /799-7233/);
});

test('the monitoring checks are the same three app.js names', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'app.js'), 'utf8');
  const m = /const ALWAYS_SAFETY_MODULES = new Set\(\[([^\]]*)\]\)/.exec(src);
  assert.ok(m, 'ALWAYS_SAFETY_MODULES is still in app.js');
  const names = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]).sort();
  assert.deepStrictEqual(names, [...Q.MONITORING_MODULES].sort());
});
