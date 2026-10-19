// UX round 1, city side (group B): the fixes the audit asked for.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const game = (f) => import(`../renderer/game/${f}`);
const CSS = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');

test('P1-1: [hidden] wins over component display rules inside the city', () => {
  // .fix-panel { display: grid } used to beat the attribute, so both confirm boxes showed.
  assert.match(CSS, /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/);
  const FixFlow = require('../renderer/fix-flow.js');
  const html = FixFlow.fixControlsHtml({ module: 'firewall_check', title: 't',
    fixable: { will_change: 'Turns on the firewall.', how_to_undo: ['Open System Settings.'] } }, {});
  assert.ok(html.includes('data-fix-confirm'));
  // The confirm button sits inside the panel, which is drawn hidden.
  assert.ok(html.indexOf('data-fix-panel hidden') >= 0 && html.indexOf('data-fix-panel') < html.indexOf('data-fix-confirm'));
});

test('P1-9: steps get the scan’s values, words for check ids, real Markdown, and commands behind FOR TECH HELPERS', async () => {
  const { stepsHtml, fillPlaceholders, wordsForModules, descriptionHtml } = await game('views/steps.js');
  const data = { label: 'ai.hermes.gateway', plist: '/Users/a/Library/LaunchAgents/ai.hermes.gateway.plist', program: '/Users/a/.hermes/py' };
  assert.strictEqual(fillPlaceholders('cat <path-to-plist> | grep <label>', data, 'darwin'),
    "cat '/Users/a/Library/LaunchAgents/ai.hermes.gateway.plist' | grep 'ai.hermes.gateway'");
  assert.strictEqual(fillPlaceholders('file "<path>"', { path: '/Applications/My App.app' }, 'darwin'), "file '/Applications/My App.app'", 'the template’s quotes give way to ours');
  assert.strictEqual(fillPlaceholders('kill <pid> <unknown>', {}), 'kill <pid> <unknown>', 'unknown values stay as they were');
  assert.strictEqual(wordsForModules('findings from `launchd_persistence_audit` and `my_check`', ['my_check']),
    'findings from the startup-task check and this checkup');
  assert.strictEqual(wordsForModules('a `program` path, snake_case words'), 'a `program` path, snake_case words');
  const body = 'These are from `launchd_persistence_audit`.\n\nFor each flagged label:\n\n1. Inspect: `cat <path-to-plist>`\n2. Unload it.';
  const html = stepsHtml([{ number: 1, title: 'Remove **high-risk** tasks', body },
    { number: 2, title: 'Open settings', body: 'Go to **Settings > Apps** and look.' }], { data, modules: [], platform: 'darwin' });
  assert.doesNotMatch(html, /launchd_persistence_audit|<path-to-plist>|&lt;path-to-plist&gt;|\*\*/);
  assert.match(html, /Remove high-risk tasks/);
  assert.match(html, /<details class="tech"><summary>FOR TECH HELPERS<\/summary>[\s\S]*For each flagged label:[\s\S]*<code>cat &#39;\/Users\/a\/Library\/LaunchAgents\/ai.hermes.gateway.plist&#39;<\/code>/);
  assert.match(html, /<strong>Settings &gt; Apps<\/strong>/, 'plain guidance shows, with bold drawn');
  const evil = stepsHtml([{ number: 1, title: '<img src=x>', body: '<script>x</script> `<b>`' }]);
  assert.doesNotMatch(evil, /<img|<script|<b>/);
  assert.match(descriptionHtml('It runs. What to do: Open **Settings**.'), /<p class="intel">It runs\.<\/p><p class="intel todo"><strong>What to do:<\/strong> Open <strong>Settings<\/strong>\.<\/p>/);
});

test('P1-9: a code span wrapped across a list item’s lines stays one span', async () => {
  const { miniMarkdown } = await game('views/steps.js');
  assert.strictEqual(miniMarkdown('1. Move it: `mkdir -p x &&\n   mv y z/`.\n2. Done.'), '<ol><li>Move it: <code>mkdir -p x &amp;&amp; mv y z/</code>.</li><li>Done.</li></ol>');
});

test('steps never paste scan data into a shell command where it could run', async () => {
  const { fillPlaceholders, stepsHtml, shellSafe } = await game('views/steps.js');
  // Drawn steps keep the placeholder too.
  assert.match(stepsHtml([{ number: 1, title: 't', body: '`cat <path>`' }], { data: { path: '$(touch x)' }, platform: 'darwin' }), /cat &lt;path&gt;/);
  const BAD = ['$(touch x)', '`id`', '"; rm -rf ~; "', "'; rm -rf ~; '", 'a\nrm -rf ~', 'a\rb', 'x\u0000y', '\u201c; id; \u201d', '\u2018$(id)\u2019',
    'a;b', 'a&b', 'a|b', 'a>b', 'a<b', 'a\\b', '*', '?', '-rf', ' lead', 'a{b}', 'a!b', 'a#b'];
  const TEMPLATES = ['cat <path>', 'cat "<path>"', "cat '<path>'", 'cat \u201c<path>\u201d', 'launchctl bootout gui/$(id -u) <path-to-plist>'];
  for (const v of BAD) {
    assert.strictEqual(shellSafe(v), false, JSON.stringify(v));
    for (const t of TEMPLATES) {
      for (const platform of ['darwin', 'linux', 'win32', null]) {
        for (const key of ['path', 'plist', 'program', 'label']) {
          const out = fillPlaceholders(t, { [key]: v }, platform);
          assert.strictEqual(out, t, `${platform} ${JSON.stringify(v)} in ${t}`);
        }
      }
    }
  }
  // Windows (PowerShell) and an unknown platform fill nothing, even a safe value.
  for (const platform of ['win32', null, undefined, 'freebsd']) {
    assert.strictEqual(fillPlaceholders('Remove-Item "<path>"', { path: 'C:/Apps/x.exe' }, platform), 'Remove-Item "<path>"');
  }
  // A safe value is always single-quoted, in every template context.
  for (const t of TEMPLATES.slice(0, 4)) assert.strictEqual(fillPlaceholders(t, { path: '/Applications/Ö App.app' }, 'darwin'), "cat '/Applications/Ö App.app'");
});

test('P1-4: the queue is a few little missions: 5 rows, AND N MORE, same titles merged, filters, Scout up top', async () => {
  const { renderDeck, QUEUE_SHOWN } = await game('views/deck.js');
  const { mergeSame, severityCounts } = await game('signals.js');
  const { rankOf } = await game('ledger.js');
  const { emptyDeck } = await game('progress.js');
  const sig = (id, severity, title = `T ${id}`) => ({ id, kind: 'real', severity, title, districtId: 'gatehouse', tag: null, count: 1 });
  const all = [sig('a', 'critical'), ...Array.from({ length: 3 }, (_, i) => sig(`n${i}`, 'warning', 'Your Mac is set to never sleep')),
    ...Array.from({ length: 12 }, (_, i) => sig(`w${i}`, 'warning'))];
  const rows = mergeSame(all);
  assert.strictEqual(rows.length, 14);
  assert.strictEqual(rows[1].same, 3);
  const deck = (over) => renderDeck({ title: 'X', rank: rankOf(emptyDeck()), lastSweep: null, items: rows, sevCounts: severityCounts(all),
    scoutHtml: '<p class="say">Start with The Gatehouse.</p>', districtName: () => 'The Gatehouse',
    districtChips: [{ id: 'gatehouse', name: 'The Gatehouse', count: 16 }, { id: 'wires', name: 'The Wires', count: 2 }], ...over });
  const html = deck({});
  const q = html.split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.strictEqual((q.match(/data-go="signal:/g) || []).length, QUEUE_SHOWN);
  assert.match(q, /AND 9 MORE ▶/);
  assert.match(q, /Your Mac is set to never sleep <span class="same"[^>]*>×3<\/span>/);
  assert.ok(q.indexOf('Start with The Gatehouse') < q.indexOf('investigate-next'), 'Scout’s read under the header');
  assert.match(q, /data-act="sev:critical"[^>]*>CRITICAL 1</);
  assert.match(q, /data-act="sev:warning"[^>]*>WARNING 15</);
  assert.match(q, /data-go="filter:wires"/);
  const open = deck({ queueOpen: true }).split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.strictEqual((open.match(/data-go="signal:/g) || []).length, 14);
  assert.match(open, /SHOW FEWER/);
});

test('P1-4: the deck controller filters by kind, opens the rest, and a district card opens the district', async () => {
  const { createController } = await game('controller.js');
  let html = '';
  const clicks = [];
  const frame = { set innerHTML(v) { html = v; }, get innerHTML() { return html; }, addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const Q = require('../renderer/quiet-notes.js');
  const win = { document: { getElementById: () => ({ attachShadow: () => shadow }) }, QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' }, MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => 'city', citySeed: () => 1, showList() {}, docChanged: () => true, wantsSafety: () => false, scanTips: async () => [], leaveGame() {} },
    rescue: {} };
  const ctl = createController({ win, storage: { getItem: () => null, setItem() {}, removeItem() {} }, scoutSprite: () => '',
    loadGame: () => new Promise(() => {}), loadTraining: async () => [], loadDrillBank: async () => [] });
  const f = (title, severity, i) => ({ title, severity, description: '', category: 'security', code: `c.${i}`, data: { path: `/p${i}` } });
  const findings = [f('Crit', 'critical', 0), ...Array.from({ length: 8 }, (_, i) => f(`Warn ${i}`, 'warning', i + 1))];
  ctl.show({ schema_version: 1, platform: 'darwin', modules: [{ name: 'some_check', category: 'security', status: 'ok', supported: true, findings }] }, { id: 'city' });
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; clicks.forEach((fn) => fn({ target: { closest: () => el } })); };
  const q = () => html.split('INCOMING SIGNALS')[1].split('deck-city')[0];
  const rows = () => (q().match(/data-go="signal:/g) || []).length;
  assert.strictEqual(rows(), 5);
  click({ 'data-act': 'toggle-queue' });
  assert.strictEqual(rows(), 9);
  click({ 'data-act': 'sev:critical' });
  assert.strictEqual(rows(), 1);
  assert.match(q(), /data-act="sev:critical" aria-pressed="true"/);
  click({ 'data-act': 'sev:all' });
  assert.strictEqual(rows(), 5);
  assert.match(html, /class="district [^"]*" data-go="district:gatehouse"/);
});

test('P1-11: only verified, known programs with keyboard access leave the help district; everything else stays held', async () => {
  const { splitHeld, heldOnly, familiarVerified } = await game('held.js');
  const KB = 'security.keylogger_indicators.suspicious_input_monitoring';
  const VS = { subject: 'com.microsoft.VSCode', name: 'Microsoft Corporation', verified: true, what: 'Visual Studio Code: Microsoft’s code editor.' };
  const ST = { subject: 'com.valvesoftware.steam', name: 'Valve Corporation (Steam)', verified: true, what: 'Steam: Valve’s game store.' };
  const kb = (severity, made_by, apps = ['com.microsoft.VSCode', 'com.valvesoftware.steam'], check = 'claimed_vendor_input_monitoring') =>
    ({ title: 'Keyboard access: 2 app(s) with familiar names', severity, code: KB, data: { check, apps }, made_by });
  const doc = (f, name = 'keylogger_indicators') => ({ modules: [{ name, category: 'security', status: 'ok', supported: true, findings: [f] }] });
  assert.strictEqual(familiarVerified(kb('info', [VS, ST]), 'keylogger_indicators'), true);
  assert.strictEqual(familiarVerified(kb('info', [VS, ST]), 'stalkerware_scan'), false);
  let r = splitHeld(doc(kb('info', [VS, ST])));
  assert.deepStrictEqual(r.held, []);
  assert.strictEqual(r.doc.modules[0].findings.length, 1, 'kept as an ordinary note');
  assert.deepStrictEqual(heldOnly(doc(kb('info', [VS, ST]))).modules[0].findings, []);
  const unknownSigned = { subject: 'com.evil.keys', name: 'Evil Keys Ltd', verified: true };
  const held = [
    ['signed but unknown maker (no what)', doc(kb('info', [VS, unknownSigned], ['com.microsoft.VSCode', 'com.evil.keys']))],
    ['one unknown app mixed in, with no made_by entry', doc(kb('info', [VS, ST], ['com.microsoft.VSCode', 'com.valvesoftware.steam', 'com.evil.keys']))],
    ['one maker not verified', doc(kb('info', [VS, { ...ST, verified: false }]))],
    ['no makers', doc(kb('info', []))],
    ['warning', doc(kb('warning', [VS, ST]))],
    ['critical', doc(kb('critical', [VS, ST]))],
    ['the suspicious-apps check, same code', doc(kb('info', [VS, ST], undefined, 'suspicious_input_monitoring'))],
    ['stalkerware_scan at info with verified, known makers', doc({ title: 'TeamViewer is on this computer (app)', severity: 'info',
      code: 'security.stalkerware_scan.monitoring_software_found', data: { check: 'claimed_vendor_input_monitoring', apps: ['com.microsoft.VSCode'] }, made_by: [VS] }, 'stalkerware_scan')],
    ['mvt_spyware_scan with the familiar code', doc(kb('info', [VS, ST]), 'mvt_spyware_scan')],
  ];
  for (const [why, d] of held) {
    r = splitHeld(d);
    assert.strictEqual(r.held.length, 1, why);
    assert.deepStrictEqual(r.doc.modules[0].findings, [], why);
  }
});

test('P1-11: each held item shows what to write down (name, where, how, maker, date) with COPY TO WRITE DOWN', async () => {
  const { splitHeld } = await game('held.js');
  const { renderSide, heldText } = await game('views/side-district.js');
  const { pickDistrict } = await game('district-names.js');
  const mspy = { title: 'mSpy is on this computer (app)', severity: 'critical', code: 'security.stalkerware_scan.monitoring_software_found',
    data: { stalkerware_name: 'mSpy', detected_as: 'app', location: '/Applications/<b>mSpy.app' },
    made_by: [{ subject: '/Applications/mSpy.app', name: 'Unknown maker', verified: false }] };
  const { held } = splitHeld({ modules: [{ name: 'stalkerware_scan', status: 'ok', findings: [mspy] }] });
  assert.deepStrictEqual(held, [{ module: 'stalkerware_scan', title: mspy.title, name: 'mSpy', where: '/Applications/<b>mSpy.app', how: 'app', maker: 'Unknown maker (not verified)' }]);
  const html = renderSide({ district: pickDistrict(1), held, date: '18 October 2026' });
  assert.match(html, /<dt>Name<\/dt><dd>mSpy<\/dd>/);
  assert.match(html, /<dt>Where found<\/dt><dd class="mono">\/Applications\/&lt;b&gt;mSpy.app<\/dd>/);
  assert.match(html, /<dt>Made by<\/dt><dd>Unknown maker \(not verified\)<\/dd>/);
  assert.match(html, /<dt>Date<\/dt><dd>18 October 2026<\/dd>/);
  assert.match(html, /data-act="side-copy:0"/);
  assert.strictEqual(heldText(held[0], '18 October 2026'),
    'Name: mSpy\nWhere found: /Applications/<b>mSpy.app\nFound as: app\nMade by: Unknown maker (not verified)\nDate: 18 October 2026');
  assert.match(html, /<h3 class="side-h">/);
  assert.match(renderSide({ district: pickDistrict(1), held, date: 'd', copied: 0 }), /role="status">Copied\./);
  assert.match(renderSide({ district: pickDistrict(1), held, date: 'd', copied: -1 }), /couldn’t be copied/);
  assert.match(fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8'), /\.side-steps \{ list-style-position: inside;/);
});

test('P1-6 / P2-29: every check counted, couldn’t-check named with why, partly checked notes folded in, one top line', async () => {
  const { notCheckedSummary, notCheckedLine, foldPartly, couldntTitle } = await game('signals.js');
  const { sweepChecks } = await game('views/deck.js');
  const doc = { modules: [
    { name: 'code_signature_audit', status: 'ok', findings: [{ title: 'Checked 16 of 110 app signatures', severity: 'info', data: { incomplete: true } }, { title: 'X', severity: 'warning' }] },
    { name: 'usb_audit', status: 'ok', findings: [{ title: 'We couldn’t list your USB devices', severity: 'info' }] },
    { name: 'a', status: 'error', error: 'timed out after 60.0s' },
    { name: 'b', status: 'ok', supported: false, unsupported_reason: 'PermissionError: [Errno 1] Operation not permitted' },
    { name: 'stalkerware_scan', status: 'error', error: 'x' },
    { name: 'c', status: 'ok', complete: false, findings: [] },
    { name: 'd', status: 'ok', findings: [{ title: 'Fine', severity: 'info' }] },
  ] };
  const sum = notCheckedSummary(doc);
  assert.deepStrictEqual(sum, { checks: 7, couldntRun: 3, unfinished: 1, partly: 2, count: 6 });
  assert.strictEqual(notCheckedLine(sum), '4 checks couldn’t run or didn’t finish, and 2 things were only partly checked, so this isn’t a clean bill of health.');
  assert.strictEqual(notCheckedLine(notCheckedSummary({ modules: [{ name: 'd', status: 'ok', findings: [] }] })), '');
  const f = foldPartly(doc);
  assert.deepStrictEqual(f.doc.modules[0].findings.map((x) => x.title), ['X']);
  assert.strictEqual(f.doc.modules[0].complete, false);
  assert.deepStrictEqual(f.partly.get('usb_audit'), ['We couldn’t list your USB devices']);
  assert.strictEqual(doc.modules[0].findings.length, 2, 'the scan is unchanged');
  assert.strictEqual(couldntTitle({ module: 'code_signature_audit', reason: 'timed out after 60.0s' }), 'Code signature audit took too long');
  assert.strictEqual(couldntTitle({ module: 'b', reason: 'PermissionError: Operation not permitted' }), 'B needed a permission');
  assert.strictEqual(couldntTitle({ module: 'c', reason: 'Not on Windows' }), 'C couldn’t run here');
  assert.strictEqual(sweepChecks({ checks: 5, fog: 6 }), '11 CHECKS, 6 COULDN’T RUN');
  assert.strictEqual(sweepChecks({ checks: 1, fog: 0 }), '1 CHECK');
});
