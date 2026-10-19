// UX round 1, now on the city's LIST (Plain view is retired): honesty at the
// top, the safety line before a fix (in the flows the city's missions use),
// and engine wording mapped for people.
const test = require('node:test');
const assert = require('node:assert');
const app = require('../renderer/app.js');
const FixFlow = require('../renderer/fix-flow.js');
const MarkFlow = require('../renderer/mark-flow.js');
const QuietNotes = require('../renderer/quiet-notes.js');
const { page } = require('./page-harness.js');

const mod = (name, findings, extra = {}) => Object.assign({ name, category: 'security', status: 'ok', supported: true, findings }, extra);
const info = (title, data = {}) => ({ title, description: 'd', severity: 'info', category: 'integrity', data });

test('notes that say part of a check couldn’t look are counted with the checks that couldn’t run', () => {
  assert.ok(app.isPartlyChecked(info('We couldn’t list your USB devices')));
  assert.ok(app.isPartlyChecked(info("Couldn't check whether Location Services are on")));
  assert.ok(app.isPartlyChecked(info('Could not read your Mail account list')));
  assert.ok(app.isPartlyChecked(info('Checked 16 of 110 app signatures', { incomplete: 10 })));
  assert.ok(!app.isPartlyChecked(info('Checked 16 of 110 app signatures')), 'only when the engine says it is incomplete');
  assert.ok(!app.isPartlyChecked({ ...info('We couldn’t check your backup'), severity: 'warning' }), 'a warning stays on the list');
  const doc = { modules: [
    mod('usb_devices_check', [info('We couldn’t list your USB devices'), info('2 USB devices')]),
    mod('stalkerware_scan', [], { status: 'error', error: 'timed out after 60.0s' }),
    mod('update_checker', [], { complete: false }),
    mod('disk_space', []),
  ] };
  const g = app.groupFindingsBySeverity(doc);
  assert.deepStrictEqual(g.groups.info.map((f) => f.title), ['2 USB devices']);
  assert.deepStrictEqual(g.partlyChecked, [{ name: 'usb_devices_check', title: 'We couldn’t list your USB devices' }]);
  const sum = app.notCheckedSummary(doc);
  assert.deepStrictEqual(sum, { checks: 4, couldntRun: 1, notReached: 0, unfinished: 1, notStarted: 0, partly: 1, count: 3 });
  assert.strictEqual(app.notCheckedLine(sum),
    '2 checks couldn’t run or didn’t finish, and 1 thing was only partly checked, so this isn’t a clean bill of health.');
  assert.strictEqual(app.notCheckedLine({ couldntRun: 6 }), '6 checks couldn’t run, so this isn’t a clean bill of health.');
  assert.strictEqual(app.notCheckedLine({}), '');
});

test('only security and network findings can be “Needs attention now”', () => {
  assert.strictEqual(app.shownSeverity({ severity: 'critical', category: 'security' }), 'critical');
  assert.strictEqual(app.shownSeverity({ severity: 'critical', category: 'network' }), 'critical');
  assert.strictEqual(app.shownSeverity({ severity: 'critical', category: 'performance' }), 'warning');
  assert.strictEqual(app.shownSeverity({ severity: 'critical', category: 'integrity' }), 'warning');
  assert.strictEqual(app.shownSeverity({ severity: 'odd' }), 'info');
});

test('the couldn’t-check list says what went wrong in words, with the raw text kept for a tech helper', () => {
  assert.strictEqual(app.errorKind("PermissionError: [Errno 1] Operation not permitted: '/Library/LaunchDaemons'"), 'permission');
  assert.strictEqual(app.errorKind('(timed out after 60.0s)'), 'slow');
  assert.strictEqual(app.errorKind('boom'), 'failed');
  const [perm, slow, part] = app.couldntCheckItems(
    [{ name: 'launch_agent_audit', error: 'PermissionError: [Errno 1] Operation not permitted' }, { name: 'code_signature_audit', error: 'timed out after 60.0s' }],
    [], 'standard', [{ name: 'usb_devices_check', title: 'We couldn’t list your USB devices' }]);
  assert.deepStrictEqual([perm.reason, perm.kind], ['Needs permission (Full Disk Access).', 'permission']);
  assert.match(perm.raw, /PermissionError/);
  assert.strictEqual(slow.reason, 'Took too long.');
  assert.deepStrictEqual([part.name, part.reason], ['Usb devices check', 'We couldn’t list your USB devices']);
});

test('walkthrough placeholders are filled from what the scan found, paths single-quoted', () => {
  const data = { plist: '/Users/a/Library/LaunchAgents/x y.plist', label: 'ai.hermes.gateway-deflock', pid: 61084 };
  const mac = { platform: 'darwin' };
  assert.strictEqual(app.fillPlaceholders('launchctl bootout gui/$(id -u) <path-to-plist>', data, mac),
    "launchctl bootout gui/$(id -u) '/Users/a/Library/LaunchAgents/x y.plist'");
  assert.strictEqual(app.fillPlaceholders('launchctl bootout gui/$(id -u) "<path-to-plist>"', data, mac),
    "launchctl bootout gui/$(id -u) '/Users/a/Library/LaunchAgents/x y.plist'", 'the template’s quotes are replaced, never doubled');
  assert.strictEqual(app.fillPlaceholders('kill <pid> for <label>, <unknown>', data, mac), "kill 61084 for 'ai.hermes.gateway-deflock', <unknown>");
  assert.strictEqual(app.fillPlaceholders('<path>', {}, mac), '<path>', 'unknown values stay as written');
  assert.strictEqual(app.fillPlaceholders('rm <path>', { path: '/x' }), 'rm <path>', 'an unknown platform is never filled');
  assert.strictEqual(app.fillPlaceholders('rm <path>', { path: '/x' }, { platform: 'win32' }), 'rm <path>', 'Windows walkthroughs are never filled');
});

test('scan data never reaches a step as a shell payload or as markup', () => {
  const { renderMiniMarkdown } = app;
  const evil = [
    '/tmp/$(touch x).plist', '/tmp/`id`.plist', '/tmp/a"; rm -rf ~; ".plist', "/tmp/a'; rm -rf ~; '.plist",
    '/tmp/a\nrm -rf ~', '/tmp/[click](http://evil)', '/tmp/![x](http://evil/i.png)', '/tmp/<img src=x onerror=alert(1)>',
    '/tmp/**bold**', '/tmp/a\\b', '/tmp/a;b', '/tmp/a|b', '/tmp/a&b', 'relative/path', '-rf',
  ];
  for (const v of evil) {
    for (const name of ['path-to-plist', 'path', 'program']) {
      const filled = app.fillPlaceholders(`launchctl bootout gui/501 <${name}>`, { plist: v, path: v, location: v, program: v }, { platform: 'darwin' });
      assert.strictEqual(filled, `launchctl bootout gui/501 <${name}>`, `${JSON.stringify(v)} is not filled into <${name}>`);
    }
    for (const name of ['label', 'bundle-id']) {
      assert.strictEqual(app.fillPlaceholders(`<${name}>`, { label: v, bundle_id: v }, { platform: 'darwin' }), `<${name}>`, JSON.stringify(v));
    }
  }
  for (const pid of ['1; rm -rf ~', '$(id)', '12a', -1, 1.5, '']) {
    assert.strictEqual(app.fillPlaceholders('kill <pid>', { pid }, { platform: 'darwin' }), 'kill <pid>', JSON.stringify(pid));
  }
  for (const label of ['$(id)', 'a b', '`id`', '<img src=x onerror=alert(1)>', '[x](http://evil)', '-rf', 'a\nb']) {
    assert.strictEqual(app.fillPlaceholders('<label>', { label }, { platform: 'darwin' }), '<label>', JSON.stringify(label));
  }
  // What does pass is rendered as text: no tag, no link, no image.
  const html = renderMiniMarkdown(app.fillPlaceholders('Run `launchctl bootout gui/501 <path-to-plist>`', { plist: '/Users/a/My App/x.plist' }, { platform: 'darwin' }));
  assert.strictEqual(html, "<p>Run <code>launchctl bootout gui/501 &#39;/Users/a/My App/x.plist&#39;</code></p>".replace(/&#39;/g, "'"));
  assert.doesNotMatch(html, /<img|<a |onerror/);
});

test('the scan screen never shows a check id', () => {
  const p = app.describeProgress({ phase: 'start', index: 60, total: 196, module: 'smcreset_guide', category: 'integrity' });
  assert.strictEqual(p.detail, 'Check 60 of 196');
});

test('the worry screen has no time estimate', () => {
  const unsure = app.SITUATIONS.find((s) => s.id === 'unsure');
  assert.doesNotMatch(`${unsure.title} ${unsure.sub}`, /minute|longer|hour|second/i);
});

test('confirm panels say Reclaim City, keep real paths, and put command-line lines under “For tech helpers”', () => {
  const html = FixFlow.fixControlsHtml({ module: 'launch_agent_audit', fixable: {
    will_change: "Moves its settings file to Device Rescue's quarantine folder.",
    how_to_undo: ['Open Device Rescue and choose Undo', 'Or move it from ~/Library/Application Support/Device Rescue/Quarantine', 'If you use the command line: rescue undo <id>'],
  } }, { safety: QuietNotes.LINE_SHORT });
  assert.match(html, /Reclaim City&#39;s quarantine folder/);
  assert.match(html, /Open Reclaim City and choose Undo/);
  assert.match(html, /Application Support\/Device Rescue\/Quarantine/, 'the real folder name');
  assert.match(html, /<summary>For tech helpers<\/summary><p>If you use the command line: rescue undo &lt;id&gt;<\/p>/);
  assert.ok(html.indexOf('data-fix-safety') < html.indexOf('data-fix-confirm'), 'the warning comes before “Yes, fix it”');
  const mark = MarkFlow.markControlsHtml({ module: 'launch_agent_audit', markable: { kind: 'background_task', id: '0123456789ab',
    label: 'x', program: '/usr/bin/x', plist: '/L/x.plist', will_change: 'Remembers this.',
    how_to_undo: ['Choose "Stop treating this as mine" on the item in this app', 'If you use the command line: rescue known remove <id> (rescue known list shows the id)'] } });
  const undo = /<ol class="fix-undo">[\s\S]*?<\/ol>/.exec(mark)[0];
  assert.doesNotMatch(undo, /command line/);
  assert.match(mark, /For tech helpers<\/summary><p>If you use the command line/);
});

test('a note that points at steps the card doesn’t show loses that sentence', () => {
  const card = QuietNotes.cardText('standard', { module: 'stalkerware_scan', code: 'security.stalkerware_scan.found', severity: 'critical',
    description: 'mSpy is on this computer. The steps below cover removal for when it’s safe.' });
  assert.strictEqual(card.steps.length, 0);
  assert.doesNotMatch(card.description, /steps below/);
  assert.match(card.description, /mSpy is on this computer\./);
});

// The LIST, as the city's LIST tab opens it after the sweep.
async function results(doc, store) {
  const p = page(store ? { store } : undefined);
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  p.sandbox.RescueHost.showList();
  return p;
}

const warning = (title, extra = {}) => Object.assign({ title, description: 'What to do: do it.', severity: 'warning', category: 'security', data: {} }, extra);

test('the LIST: every card on show (it is literal), Good to know folded, no checkboxes, and the honesty line at the top', async () => {
  const many = Array.from({ length: 23 }, (_, i) => warning(`Warning ${i}`));
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('a', many), mod('b', [info('A note'), info('We couldn’t list your USB devices')]),
    mod('c', [], { status: 'error', error: 'timed out after 60.0s' }),
  ] });
  const html = p.byId('results-groups').innerHTML;
  for (let i = 0; i < 23; i += 1) assert.ok(html.includes(`>Warning ${i}<`), `card ${i} on show`);
  assert.doesNotMatch(html, /data-card-more|data-show-more/, 'nothing behind “Show more”');
  assert.match(html, /<details class="results-group__fold">\s*<summary><span class="chip chip--info">Good to know/);
  assert.doesNotMatch(html, /data-card-pick|data-bulk|type="checkbox"/, 'nothing to tick: the LIST changes nothing');
  assert.match(p.byId('results-errors-line').textContent, /^1 check couldn’t run, and 1 thing was only partly checked/);
  assert.doesNotMatch(html, /We couldn’t list your USB devices/, 'the partly-checked note moved to the top list');
});

test('Start over asks first', async () => {
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [mod('a', [warning('W')])] });
  p.byId('btn-start-over').click();
  assert.deepStrictEqual(p.shown(), ['results'], 'nothing thrown away yet');
  assert.strictEqual(p.byId('start-over-confirm').hidden, false);
  p.byId('btn-start-over-no').click();
  assert.strictEqual(p.byId('start-over-confirm').hidden, true);
  p.byId('btn-start-over').click();
  p.byId('btn-start-over-yes').click();
  assert.deepStrictEqual(p.shown(), ['welcome']);
});

test('the LIST offers no “I did this”, fix or mark on any card, monitoring software or not', async () => {
  const p = await results({ schema_version: 1, platform: 'darwin', modules: [
    mod('stalkerware_scan', [warning('mSpy is on this computer', { code: 'security.stalkerware_scan.found' })]),
    mod('other', [warning('Something else', { fixable: { will_change: 'x' }, markable: { kind: 'background_task', id: 'a' } })]),
  ] });
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /mSpy is on this computer/);
  assert.match(html, /Something else/);
  assert.doesNotMatch(html, /data-clear-did|\[FIX IT\]|\[IT IS MINE\]|data-fix|data-mark/);
});
