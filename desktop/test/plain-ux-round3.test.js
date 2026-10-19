// UX round 3, Plain view: held items in city mode get no clipboard or AI
// export, cards in order of importance, near-duplicates merged, the iPhone
// backup scan as "not started" with a Start that asks first, the stopped
// checkup kept, Good to know grouped by check, and the per-app "mine" list.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const app = require('../renderer/app.js');
const MarkFlow = require('../renderer/mark-flow.js');
const { technicalReportText } = require('../renderer/copy-ai.js');
const { buildAiPrompt } = require('../ai-prompt.js');
const { page, tick } = require('./page-harness.js');

// The owner's own Mac, fresh scan (warnings, criticals and the iPhone line; home renamed).
const FRESH = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'fresh-round3.json'), 'utf8'));
const mod = (name, findings, extra = {}) => Object.assign({ name, category: 'security', status: 'ok', supported: true, findings }, extra);
const cardsOf = (html) => html.split('<li class="finding-card').slice(1);

async function results(doc, mode = 'standard') {
  const p = page({ store: { 'device-rescue.display': mode } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  if (mode !== 'city') p.byId('btn-run-scan').click();
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  return p;
}

// ---------------------------------------------------------------------------
// P1-2: city mode, held items: nothing to the clipboard or a website.
// ---------------------------------------------------------------------------
const SPY = { title: 'mSpy is on this computer (app)', severity: 'critical', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found', description: 'mSpy records what you type.',
  data: { stalkerware_name: 'mSpy', location: '/Library/Application Support/mSpyAgent' } };
const KEYLOG = { title: 'An app can read your keyboard', severity: 'warning', category: 'security',
  code: 'security.keylogger_indicators.suspicious_input_monitoring', description: 'x', data: { apps: ['com.x.keylogger'] } };
const heldDoc = () => ({ schema_version: 1, platform: 'darwin', modules: [
  mod('stalkerware_scan', [SPY]),
  mod('keylogger_indicators', [KEYLOG]),
  mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', category: 'security', description: 'On.', data: {} }]),
] });

test('P1-2: in city mode a held card has no Get help, no Copy for any AI and no Ask about this', async () => {
  const p = await results(heldDoc(), 'city');
  const cards = cardsOf(p.byId('results-groups').innerHTML);
  const spy = cards.find((c) => c.includes('mSpy'));
  assert.ok(spy);
  assert.doesNotMatch(spy, /data-copy-ai|data-ask-id|Get help with this|Copy for any AI|Ask about this|data-evidence-copy/);
  const keylog = cards.find((c) => c.includes('read your keyboard'));
  assert.doesNotMatch(keylog, /data-copy-ai|data-ask-id/, 'any monitoring check, held or not');
  const remote = cards.find((c) => c.includes('Remote Login is on'));
  assert.match(remote, /data-copy-ai/, 'other cards keep theirs');
});

test('P1-2: "Copy everything for an AI" in city mode leaves held items out entirely: no names, no check ids', async () => {
  const p = await results(heldDoc(), 'city');
  const report = JSON.parse(p.run('JSON.stringify(copyAiReport)'));
  assert.deepStrictEqual(report.findings.map((f) => f.title), ['Remote Login is on']);
  const text = buildAiPrompt(report, { home: '/Users/x', user: 'x', hostnames: [] });
  assert.doesNotMatch(text, /stalkerware|mSpy|keylogger|keyboard/i);
  // The technical report copy leaves the monitoring checks out too, in city mode only.
  assert.doesNotMatch(technicalReportText(heldDoc(), { cover: true }), /stalkerware|mSpy|keylogger/i);
  assert.match(technicalReportText(heldDoc()), /stalkerware_scan/);
  // Standard mode is unchanged: the card has its help.
  const s = await results(heldDoc(), 'standard');
  assert.match(cardsOf(s.byId('results-groups').innerHTML).find((c) => c.includes('mSpy')), /data-copy-ai/);
});

// ---------------------------------------------------------------------------
// P1-4: order by importance; the audit's security items on the first page.
// ---------------------------------------------------------------------------
test('P1-4: on the fresh scan, criticals first, then the fixes and the signs someone got in, all in the first 10', async () => {
  const p = await results(FRESH);
  const html = p.byId('results-groups').innerHTML;
  const groups = html.split('data-results-group="');
  const warn = groups.find((g) => g.startsWith('warning'));
  const shown = cardsOf(warn).filter((c) => !/data-card-more hidden/.test(c.split('>')[0]));
  assert.strictEqual(shown.length, 10, 'one page of cards');
  const first = shown.map((c) => /<h3[^>]*>([^<]*)</.exec(c)[1]).join('\n');
  for (const want of [/gateway-deflock' runs from a hidden folder/, /gateway-multiverse-games' runs from a hidden/,
    /saved key could let another computer log in/, /website name is being redirected/, /router&#39;s SSH is open|router's SSH is open/,
    /DNS servers we don(&#39;|')t recognize/, /new listening ports/]) {
    assert.match(first, want, `${want} on the first page:\n${first}`);
  }
  assert.doesNotMatch(first, /volume|Time Machine|font|chrome_crashpad/i, 'not the housekeeping');
  // Criticals stay above every warning.
  assert.ok(html.indexOf('data-results-group="critical"') < html.indexOf('data-results-group="warning"'));
});

test('P1-4: sortByImportance: fixable, then signals, then security lists, security, network, the rest; stable', () => {
  const f = (module, category, extra = {}) => Object.assign({ module, category, title: module }, extra);
  const sorted = app.sortByImportance([
    f('font_issues', 'integrity'), f('router_security_audit', 'network'), f('chrome_extensions', 'security'),
    f('vpn_leak_check', 'network'), f('app_permissions', 'security', { markable: { id: 'x' } }),
    f('hosts_file_check', 'security'), f('launch_agent_audit', 'security', { fixable: { will_change: 'x' } }),
  ]).map((x) => x.module);
  assert.deepStrictEqual(sorted, ['launch_agent_audit', 'hosts_file_check', 'router_security_audit', 'app_permissions',
    'chrome_extensions', 'vpn_leak_check', 'font_issues']);
});

test('P1-4: near-duplicates from different checks merge by what the data says (crash, volume, swap, backups, screensaver)', async () => {
  const p = await results(FRESH);
  const titles = cardsOf(p.byId('results-groups').innerHTML).map((c) => /<h3[^>]*>([^<]*)</.exec(c)[1]);
  const count = (re) => titles.filter((t) => re.test(t)).length;
  assert.strictEqual(count(/chrome_crashpad_handler/), 1);
  assert.strictEqual(count(/volume is set|volume is set to zero/i), 1);
  assert.strictEqual(count(/swap/i), 1);
  assert.strictEqual(count(/Time Machine|backing up your files|backup drive/i), 1);
  assert.strictEqual(count(/[Ss]creensaver waits 60/), 1);
  assert.strictEqual(count(/control your Mac/), 2, 'the 14 merge; the 11 unrecognised stay their own list');
  // The merged card keeps the one with controls (the markable list) and says who saw it.
  const merged = app.mergeAcrossChecks([
    { module: 'accessibility_permissions', severity: 'warning', title: 'Many apps can control your Mac (14)', data: { check: 'excessive_accessibility', count: 14 } },
    { module: 'app_permissions', severity: 'warning', title: '14 apps can control your Mac', markable: { id: 'a' }, data: { check: 'accessibility_access', apps: new Array(14).fill('x') } },
  ]);
  assert.strictEqual(merged.length, 1);
  assert.strictEqual(merged[0].module, 'app_permissions');
  assert.deepStrictEqual(merged[0].seen_in, ['app_permissions', 'accessibility_permissions']);
});

// ---------------------------------------------------------------------------
// P2-12: the iPhone backup scan isn't "couldn't run"; Start asks first.
// ---------------------------------------------------------------------------
test('P2-12: an iPhone backup that can be scanned is "not started", never "couldn’t run", and Start asks first', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [
    mod('mvt_spyware_scan', [{ title: '1 device backup found (scan available)', severity: 'info', category: 'security',
      code: 'security.mvt_spyware_scan.mvt_scan_available', data: { check: 'mvt_scan_available', backups_found: 1 } }], { check_name: 'iPhone backup spyware scan' }),
    mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }]),
  ] };
  assert.deepStrictEqual(app.plainNotChecked(doc).notStarted, ['mvt_spyware_scan']);
  assert.strictEqual(app.plainNotChecked(doc).summary.count, 0);
  const p = await results(doc);
  assert.strictEqual(p.byId('results-errors').hidden, true, 'not in the couldn’t-check box');
  assert.strictEqual(p.byId('results-waiting').hidden, false);
  assert.strictEqual(p.byId('results-waiting-line').textContent, 'Not started — your iPhone backup can be checked for spyware. This is a long scan.');
  assert.strictEqual(p.byId('btn-phone-start').hidden, false);
  // Start only asks: no scan runs until "Yes, start it".
  const before = p.calls.scans.length;
  p.byId('btn-phone-start').click();
  assert.strictEqual(p.byId('phone-start-confirm').hidden, false);
  assert.strictEqual(p.calls.scans.length, before, 'nothing ran yet');
  p.byId('btn-phone-start-yes').click();
  assert.deepStrictEqual(p.calls.scans.slice(before), ['iphone_spyware_check']);
  // Its result joins the checkup: the other findings stay.
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [mod('mvt_spyware_scan', [{ title: 'No known spyware found in the backup',
    severity: 'info', category: 'security', code: 'security.mvt_spyware_scan.mvt_clean_scan', data: {} }])] });
  assert.deepStrictEqual(p.shown(), ['results']);
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /Remote Login is on/);
  assert.match(html, /No known spyware found in the backup/);
  assert.strictEqual(p.byId('results-waiting').hidden, true);
  // City mode names nothing and offers no Start.
  const c = await results(doc, 'city');
  assert.doesNotMatch(c.byId('results-waiting-line').textContent, /iPhone|spyware/);
  assert.strictEqual(c.byId('btn-phone-start').hidden, true);
});

test('mergeModules: the extra checks replace their own entries, the rest stays', () => {
  const a = { platform: 'darwin', modules: [{ name: 'x', findings: [1] }, { name: 'mvt_spyware_scan', findings: [2] }] };
  const out = app.mergeModules(a, { modules: [{ name: 'mvt_spyware_scan', findings: [3] }] });
  assert.deepStrictEqual(out.modules.map((m) => m.findings[0]), [1, 3]);
  assert.strictEqual(out.platform, 'darwin');
});

// ---------------------------------------------------------------------------
// P1-1 (Plain side): a checkup that stops keeps what it found, plainly.
// ---------------------------------------------------------------------------
test('P1-1: a stopped checkup says so in one plain line, keeps the raw text for tech helpers, and offers what it found so far', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  p.emit({ type: 'plan', total: 3, modules: [] });
  p.emit({ type: 'progress', phase: 'done', index: 1, total: 3, module: 'remote_login_check', findings: 1 });
  p.emit({ type: 'module', result: mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }]) });
  await p.fail('engine exited 1: Traceback (most recent call last): /Users/ann/x.py TypeError');
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-error').hidden, false);
  assert.match(p.byId('scan-error-text').textContent, /Traceback/, 'the raw text, under For tech helpers');
  assert.strictEqual(p.byId('scan-error-tech').hidden, false);
  assert.strictEqual(p.byId('btn-scan-sofar').hidden, false);
  p.byId('btn-scan-sofar').click();
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.match(p.byId('results-title').textContent, /before it stopped/);
  assert.match(p.byId('results-running-text').textContent, /stopped before it finished: 1 of 3 checks done/);
  assert.match(p.byId('results-summary').innerHTML, /in the part that ran\. The rest wasn’t checked/);
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /Remote Login is on/);
  assert.ok(!html.includes('[FIX IT]') && !html.includes('[IT IS MINE]'), 'nothing to act on in a partial checkup');
  await tick();
});

// ---------------------------------------------------------------------------
// P2-7: Good to know, grouped by check.
// ---------------------------------------------------------------------------
test('P2-7: Good to know is one box per check with its count, each note one line until opened', async () => {
  const note = (t) => ({ title: t, severity: 'info', category: 'integrity', description: 'x', data: { path: '/tmp/x' } });
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('font_issues', [note('Font A'), note('Font B'), note('Font C')], { check_name: 'Fonts' }),
    mod('login_items', [note('Login item: Amical')], { check_name: 'Login items' }),
  ] });
  const html = p.byId('results-groups').innerHTML;
  const info = html.split('data-results-group="info"')[1];
  assert.match(info, /<span class="info-check__name">Fonts<\/span> <span class="results-group__count">3<\/span>/);
  assert.match(info, /<span class="info-check__name">Login items<\/span> <span class="results-group__count">1<\/span>/);
  assert.match(info, /<details class="finding-note"><summary class="finding-note__summary">[\s\S]*?<h3[^>]*>Font A<\/h3><\/summary>/,
    'the title is the line; its evidence opens with it');
  assert.doesNotMatch(info, /data-show-more/);
});

// ---------------------------------------------------------------------------
// P2-6: the per-app list never says "couldn't check who made this one" next to a maker.
// ---------------------------------------------------------------------------
test('P2-6: an app with a verified maker shown is never "we couldn’t check who made this one"', () => {
  const f = FRESH.modules.find((m) => m.name === 'app_permissions').findings.find((x) => x.markable);
  const html = MarkFlow.markControlsHtml(Object.assign({ module: 'app_permissions' }, f));
  const rows = html.split('mark-apps__maker').length;
  assert.ok(rows > 1);
  // Dropbox: verified maker, no id from the engine this time.
  const dropbox = /Dropbox[\s\S]*?(?=<\/li>|<li)/.exec(html.split('Tick the apps you know and use')[1])[0];
  assert.match(dropbox, /Made by Dropbox, Inc\. \(verified\)/);
  assert.doesNotMatch(dropbox, /couldn’t check who made this one/);
  assert.match(dropbox, /can only be marked with the whole list/);
});

// ---------------------------------------------------------------------------
// P2-2, P3-1, P3-2: the card face.
// ---------------------------------------------------------------------------
test('P2-2: a path with spaces in it is shown in the evidence, so the why line doesn’t repeat it', () => {
  const f = { data: { path: '/Applications/Baba Is You.app' } };
  const p = app.cardProse('/Applications/Baba Is You.app has a digital signature, but it no longer matches the file. This means the app was modified after the maker signed it.', f);
  assert.strictEqual(p.why, 'This means the app was modified after the maker signed it.');
});

test('P3-2: the partly-checked line isn’t said twice', async () => {
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('usb_devices_check', [{ title: 'We couldn’t list your USB devices', severity: 'info', description: 'x', data: {} }]),
  ] });
  const list = p.byId('results-errors-list').innerHTML;
  assert.match(list, /See what was only partly checked \(1\)/);
  assert.doesNotMatch(list, /<summary>1 thing was only partly checked/);
});

test('Ask about this sends the evidence, not only the prose', async () => {
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('hosts_file_check', [{ title: '1 website name is being redirected', severity: 'warning', description: 'A website is redirected.',
      data: { path: '/etc/hosts', entries: ['1.2.3.4 example.com'] } }], { check_name: 'Hosts file' }),
  ] });
  const asks = JSON.parse(p.run('JSON.stringify(askRegistry)'));
  assert.match(asks[0].description, /^Evidence:\n/);
  assert.match(asks[0].description, /\/etc\/hosts/);
});

test('P2-14: Your progress counts the list’s own answers', async () => {
  const { plainCountsLine } = await import('../renderer/game/profile/plain-panel.js');
  assert.strictEqual(plainCountsLine({ fixed: 1, marked: 2, did: 0 }), 'On this checkup: 1 fixed · 2 marked as yours · 0 you said you did');
  assert.strictEqual(plainCountsLine(null), '');
});

// ---------------------------------------------------------------------------
// Integration: stopped scans by stage, dns_profile marks, one set of counts.
// ---------------------------------------------------------------------------
async function stoppedPage(stage, done, total) {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  p.emit({ type: 'plan', total, modules: [] });
  await p.finish({ schema_version: 1, platform: 'darwin',
    modules: [mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }])],
    stopped: { stage, reason: 'exit', exit_code: 1, done, total }, partial: { done, total, stopped: stage } });
  assert.strictEqual(p.byId('btn-scan-sofar').hidden, false);
  p.byId('btn-scan-sofar').click();
  return p;
}
test('a stopped scan after every check ran says the report could not be put together, and not the other line', async () => {
  const p = await stoppedPage('assembly', 3, 3);
  const text = p.byId('results-running-text').textContent;
  assert.strictEqual(text, 'All 3 checks ran, but the report couldn\u2019t be put together. This is what they found.');
  assert.ok(!/stopped before it finished/.test(text));
  await tick();
});
test('a stopped scan that ended early says how many checks were done, and not the other line', async () => {
  const p = await stoppedPage('early', 1, 3);
  const text = p.byId('results-running-text').textContent;
  assert.strictEqual(text, 'The checkup stopped before it finished: 1 of 3 checks done. This is only what they found.');
  assert.ok(!/put together/.test(text));
  await tick();
});
test('a DNS filtering-profile warning can be marked as mine', () => {
  const html = MarkFlow.markControlsHtml({ module: 'm', markable: { kind: 'dns_profile', monitoring: false,
    items: [], id: 'abc' } });
  assert.ok(MarkFlow.BUTTON.dns_profile);
  assert.ok(MarkFlow.WATCH_KINDS ? MarkFlow.WATCH_KINDS.has('dns_profile') : true);
  assert.strictEqual(typeof html, 'string');
});
