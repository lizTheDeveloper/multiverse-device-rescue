'use strict';
// The photo record (docs/superpowers/specs/2026-10-23-photo-record-design.md): pages built to be photographed,
// from the scan in memory, with one SHA-256 fingerprint. game/photo-record.js; synthetic data only.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');
require('../renderer/evidence.js');

const load = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'photo-record.js')).href);
const CITY_FORBIDDEN = (() => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js'), 'utf8');
  const m = /export const CITY_FORBIDDEN = \/(.+)\/([a-z]*);/.exec(src);
  return new RegExp(m[1], m[2]);
})();

const LONG = '/Users/someone/Library/Application Support/Example Family Helper With A Long Folder Name/Agents/helper/bin/example-helper';
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const WATCH = { title: 'ExampleWatch is on this computer', description: 'd', severity: 'critical', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found',
  data: { check: 'monitoring_software_found', stalkerware_name: 'ExampleWatch', stalkerware_category: 'parental_control', location: LONG, detected_as: 'installed application' },
  made_by: [{ subject: LONG, name: 'Example Family Co', verified: false, how: 'claims to be', location_note: '' }] };
const DESK = { title: 'DeskTool can let someone control this computer', description: 'd', severity: 'warning', category: 'security',
  code: 'security.remote_access_tools.tool_found', removal_alert: true,
  data: { check: 'tool_found', tool: 'DeskTool', tool_id: 'desktool', path: '/Applications/DeskTool.app', added_on: '2026-03-03',
    lets_in_unattended: true, unattended_via: 'com.example.desktool.service', running_now: false, last_incoming: '2026-03-12', incoming_count: 4 } };
const QUIET_TOOL = { title: 'HelpDesk can let someone control this computer', description: 'd', severity: 'info', category: 'security',
  code: 'security.remote_access_tools.tool_found', data: { check: 'tool_found', tool: 'HelpDesk', path: '/Users/someone/Downloads/HelpDesk.app',
    added_on: null, lets_in_unattended: null, running_now: null, last_incoming: null, incoming_count: null } };
const SHARE = { title: 'Screen Sharing is on', description: 'd', severity: 'warning', category: 'security', code: 'security.sharing_services.screen_sharing',
  data: { service: 'Screen Sharing', enabled: true } };
const NOTE = { title: 'Battery is fine', description: 'd', severity: 'info', category: 'integrity', data: { cycles: 12 } };
const VERSION = { title: 'macOS version', description: 'd', severity: 'info', category: 'integrity',
  data: { check: 'version_info', version: '26.1', build: '25B78', model: 'Mac16,1', model_name: 'MacBook Pro', architecture: 'arm64' } };
function doc() {
  return { schema_version: 1, platform: 'darwin', modules: [
    mod('stalkerware_scan', [WATCH]),
    mod('remote_access_tools', [DESK, QUIET_TOOL]),
    mod('sharing_services', [SHARE], { check_name: 'Sharing settings' }),
    mod('battery_health', [NOTE], { category: 'integrity' }),
    mod('macos_version_support', [VERSION], { category: 'integrity' }),
    mod('firewall_audit', [], { status: 'error', error: 'boom' }),
    mod('kernel_extensions_audit', [], { supported: false, unsupported_reason: 'Not on this system' }),
    mod('network_connections', [], { complete: false }),
  ] };
}
const AT = '2026-10-23T16:17:00.000Z';
const ctx = (extra = {}) => ({ doc: doc(), scanAt: AT, dualUse: {}, ...extra });
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/&#39;/g, '\'').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/\s+/g, ' ');

test('offered in exactly the four cases', async () => {
  const P = await load();
  const plain = { schema_version: 1, platform: 'darwin', modules: [mod('sharing_services', [SHARE])] };
  const unsure = { id: 'unsure' };
  assert.strictEqual(P.offerRecord({ mode: 'standard', situation: unsure, doc: plain, dualUse: {} }), false, 'nothing that calls for it');
  assert.strictEqual(P.offerRecord({ mode: 'city', situation: unsure, doc: plain, dualUse: {} }), true, 'city mode');
  assert.strictEqual(P.offerRecord({ mode: 'standard', situation: { id: 'watched', safety: true }, doc: plain, dualUse: {} }), true, 'the watched worry');
  for (const m of [mod('stalkerware_scan', [WATCH]), mod('remote_access_tools', [QUIET_TOOL])]) {
    assert.strictEqual(P.offerRecord({ mode: 'standard', situation: unsure, doc: { ...plain, modules: [m] }, dualUse: {} }), true, m.name);
  }
  // A monitoring check that found nothing is not a finding.
  const clean = mod('mvt_spyware_scan', [{ title: 'No backups', severity: 'info', code: 'security.mvt_spyware_scan.no_backups_found', data: {} }]);
  assert.strictEqual(P.offerRecord({ mode: 'standard', situation: unsure, doc: { ...plain, modules: [clean] }, dualUse: {} }), false);
  const yes = [{ parental_control: 'someone' }, { parental_control: 'notsure' }, { employee_monitoring: 'mine' }, { employee_monitoring: 'notsure' }];
  const no = [{ parental_control: 'me' }, { employee_monitoring: 'employer' }, {}, null];
  for (const a of yes) assert.strictEqual(P.offerRecord({ mode: 'standard', situation: unsure, doc: plain, dualUse: a }), true, JSON.stringify(a));
  for (const a of no) assert.strictEqual(P.offerRecord({ mode: 'standard', situation: unsure, doc: plain, dualUse: a }), false, JSON.stringify(a));
});

test('contents: held findings, warning and critical findings, the couldn’t-check list; info left out unless held', async () => {
  const P = await load();
  const raw = P.buildRecord(ctx());
  const r = P.recordView(raw);
  const whats = r.findings.map((f) => f.what);
  assert.deepStrictEqual(whats.slice(0, 3).sort(), ['DeskTool', 'ExampleWatch', 'HelpDesk'], 'held first, the info-level tool too');
  assert.ok(whats.includes('Screen Sharing is on'), 'a warning from another check');
  assert.ok(!whats.some((w) => /Battery|macOS version/.test(w)), 'info findings left out');
  assert.deepStrictEqual(r.not_checked.map((x) => x.why), ['Couldn’t run', 'Couldn’t run', 'Didn’t finish']);
  assert.strictEqual(r.not_checked.length, 3);
  assert.strictEqual(r.computer, 'MacBook Pro (Mac16,1), macOS 26.1 (25B78)');
  // The record itself (what the fingerprint covers) holds raw values only: never the page's words.
  assert.strictEqual(raw.scanned_at, AT);
  assert.deepStrictEqual(raw.computer, { platform: 'darwin', model_name: 'MacBook Pro', model: 'Mac16,1', os_version: '26.1', build: '25B78' });
  assert.deepStrictEqual(raw.not_checked.map((x) => x.why), ['couldnt_run', 'couldnt_run', 'unfinished']);
  const rawWatch = raw.findings.find((f) => f.module === 'stalkerware_scan');
  assert.strictEqual(rawWatch.kind, 'parental_control');
  assert.strictEqual(rawWatch.data.location, LONG);
  assert.deepStrictEqual(rawWatch.made_by, [{ subject: LONG, name: 'Example Family Co', verified: false }]);
  assert.strictEqual(rawWatch.said, null);
  const rawDesk = raw.findings.find((f) => f.data.tool === 'DeskTool');
  assert.strictEqual(rawDesk.kind, 'remote_access_tool');
  assert.strictEqual(rawDesk.data.added_on, '2026-03-03', 'the engine’s own ISO day, not "March 3, 2026"');
  assert.strictEqual(rawDesk.data.running_now, false);
  assert.strictEqual(raw.findings.find((f) => f.data.tool === 'HelpDesk').data.running_now, null, '"Couldn’t tell" is null in the record');
  assert.doesNotMatch(P.canonicalJson(raw), /Couldn’t tell|March|October|Remote-access tool|Parental control product|Found by/);
  const watch = r.findings.find((f) => f.what === 'ExampleWatch');
  assert.strictEqual(watch.kind, 'Parental control product');
  const row = (f, l) => (f.rows.find((x) => x[0] === l) || [])[1];
  assert.strictEqual(row(watch, 'Where'), LONG, 'the full path, never shortened');
  assert.strictEqual(row(watch, 'Made by'), 'Example Family Co (not verified)');
  assert.strictEqual(row(watch, 'Added'), 'Couldn’t tell');
  assert.strictEqual(row(watch, 'Running now'), 'Couldn’t tell');
  const desk = r.findings.find((f) => f.what === 'DeskTool');
  assert.strictEqual(desk.kind, 'Remote-access tool');
  assert.strictEqual(row(desk, 'Added'), 'March 3, 2026');
  assert.strictEqual(row(desk, 'Last let someone in'), 'March 12, 2026 (4 times)');
  assert.strictEqual(row(desk, 'Running now'), 'No');
  assert.strictEqual(row(desk, 'Can let someone in without a click'), 'Yes');
  assert.strictEqual(row(desk, 'Made by'), 'Couldn’t tell');
  const quiet = r.findings.find((f) => f.what === 'HelpDesk');
  for (const l of ['Added', 'Last let someone in', 'Running now', 'Can let someone in without a click']) assert.strictEqual(row(quiet, l), 'Couldn’t tell', l);
});

test('"You said": the dual-use answer that led to the record is in it', async () => {
  const P = await load();
  const raw = P.buildRecord(ctx({ dualUse: { parental_control: 'someone' } }));
  assert.strictEqual(raw.findings.find((f) => f.module === 'stalkerware_scan').said, 'parental_control:someone', 'the answer as its key');
  const r = P.recordView(raw);
  assert.strictEqual(r.findings.find((f) => f.what === 'ExampleWatch').said, 'someone else gets its reports');
  const html = P.renderRecordPage({ record: raw, fp: 'a'.repeat(64), index: P.recordPages(raw).findIndex((p) => p.finding && p.finding.what === 'ExampleWatch') });
  assert.match(text(html), /You said: someone else gets its reports/);
  const work = { ...WATCH, data: { ...WATCH.data, stalkerware_category: 'employee_monitoring' } };
  const r2 = P.recordView(P.buildRecord(ctx({ doc: { ...doc(), modules: [mod('stalkerware_scan', [work])] }, dualUse: { employee_monitoring: 'mine' } })));
  assert.strictEqual(r2.findings[0].said, 'it’s your computer');
  assert.strictEqual(r2.findings[0].kind, 'Employee monitoring product');
  assert.strictEqual(P.recordView(P.buildRecord(ctx())).findings.find((f) => f.what === 'ExampleWatch').said, '', 'no answer, no line');
});

// The fixed synthetic record and its canonical form: pinned, so a change to either is seen. Raw values only
// (docs/superpowers/specs/2026-10-23-photo-record-design.md, "The fingerprint").
const FIXED = { version: 1, scanned_at: '2026-10-23T16:17:00.000Z',
  computer: { platform: 'darwin', model_name: 'MacBook Pro', model: 'Mac16,1', os_version: '26.1', build: '25B78' },
  findings: [{ module: 'stalkerware_scan', check_name: null, code: 'security.stalkerware_scan.monitoring_software_found', severity: 'critical',
    kind: 'parental_control', title: 'ExampleWatch is on this computer',
    data: { check: 'monitoring_software_found', stalkerware_name: 'ExampleWatch', stalkerware_category: 'parental_control',
      location: '/Applications/ExampleWatch.app', added_on: '2026-03-03', running_now: null },
    made_by: [{ subject: '/Applications/ExampleWatch.app', name: 'Example Family Co', verified: false }], said: 'parental_control:someone' }],
  not_checked: [{ module: 'firewall_audit', check_name: 'Firewall', why: 'couldnt_run' }] };
const FIXED_JSON = '{"version":1,"computer":{"build":"25B78","model":"Mac16,1","model_name":"MacBook Pro","os_version":"26.1","platform":"darwin"},'
  + '"findings":[{"check_name":null,"code":"security.stalkerware_scan.monitoring_software_found","data":{"added_on":"2026-03-03","check":"monitoring_software_found",'
  + '"location":"/Applications/ExampleWatch.app","running_now":null,"stalkerware_category":"parental_control","stalkerware_name":"ExampleWatch"},'
  + '"kind":"parental_control","made_by":[{"name":"Example Family Co","subject":"/Applications/ExampleWatch.app","verified":false}],'
  + '"module":"stalkerware_scan","said":"parental_control:someone","severity":"critical","title":"ExampleWatch is on this computer"}],'
  + '"not_checked":[{"check_name":"Firewall","module":"firewall_audit","why":"couldnt_run"}],"scanned_at":"2026-10-23T16:17:00.000Z"}';
const FIXED_SHA = crypto.createHash('sha256').update(FIXED_JSON, 'utf8').digest('hex');

test('the fingerprint: SHA-256 of the canonical JSON (version first, keys sorted, no whitespace), pinned', async () => {
  const P = await load();
  assert.strictEqual(P.canonicalJson(FIXED), FIXED_JSON);
  const fp = await P.fingerprint(FIXED);
  assert.strictEqual(fp, FIXED_SHA);
  assert.strictEqual(fp, PINNED, 'the pinned value');
  assert.strictEqual(P.shortPrint(fp), fp.slice(0, 16).toUpperCase().match(/.{4}/g).join(' '));
  assert.deepStrictEqual(P.fullPrintLines(fp), fp.toUpperCase().match(/.{16}/g).map((l) => l.match(/.{4}/g).join(' ')));
  // Same record, same number; any fact changed, a new one.
  const built = P.buildRecord(ctx());
  assert.strictEqual(await P.fingerprint(built), await P.fingerprint(P.buildRecord(ctx())));
  const moved = P.buildRecord(ctx({ scanAt: '2026-10-23T16:18:00.000Z' }));
  assert.notStrictEqual(await P.fingerprint(moved), await P.fingerprint(built));
  const edited = JSON.parse(JSON.stringify(FIXED)); edited.findings[0].data.location += 'x';
  assert.notStrictEqual(await P.fingerprint(edited), fp);
});
const PINNED = 'ee35c2170b5a5dd357ae9237c14b5a6b4281c41948fa0e62eeae87f09fd124bf';

test('no network: nothing is fetched or sent to build, fingerprint or draw the record', async () => {
  const P = await load();
  const calls = [];
  const saved = { fetch: globalThis.fetch, XMLHttpRequest: globalThis.XMLHttpRequest, WebSocket: globalThis.WebSocket };
  globalThis.fetch = (...a) => { calls.push(['fetch', a]); throw new Error('no network'); };
  globalThis.XMLHttpRequest = function XHR() { calls.push(['xhr']); throw new Error('no network'); };
  globalThis.WebSocket = function WS() { calls.push(['ws']); throw new Error('no network'); };
  try {
    const r = P.buildRecord(ctx({ dualUse: { parental_control: 'someone' } }));
    const fp = await P.fingerprint(r);
    P.recordPages(r).forEach((_, i) => P.renderRecordPage({ record: r, fp, index: i }));
  } finally { Object.assign(globalThis, saved); }
  assert.deepStrictEqual(calls, []);
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'photo-record.js'), 'utf8');
  assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|openLookup|openGuide|rescue\./, 'no way out in the source');
});

test('every page: the header, date, computer, page count and the same short fingerprint; black on white; city words', async () => {
  const P = await load();
  const r = P.buildRecord(ctx({ dualUse: { parental_control: 'someone' } }));
  const fp = await P.fingerprint(r);
  const pages = P.recordPages(r);
  assert.strictEqual(pages[0].kind, 'intro');
  assert.strictEqual(pages[pages.length - 1].kind, 'end');
  assert.strictEqual(pages.filter((p) => p.kind === 'finding').length, r.findings.length);
  const short = P.shortPrint(fp);
  for (let i = 0; i < pages.length; i += 1) {
    const html = P.renderRecordPage({ record: r, fp, index: i });
    const page = /<article class="pr-page[\s\S]*?<\/article>/.exec(html)[0];
    const head = /<header class="pr-head"[\s\S]*?<\/header>/.exec(page)[0];
    assert.match(head, /Checkup record/, `page ${i + 1}`);
    assert.ok(head.includes(P.scanWhen(AT)), `page ${i + 1}: the scan's date and time`);
    assert.ok(text(head).includes('MacBook Pro (Mac16,1), macOS 26.1 (25B78)'), `page ${i + 1}: the computer`);
    assert.ok(head.includes(`Page ${i + 1} of ${pages.length}`), `page ${i + 1}`);
    assert.ok(head.includes(short), `page ${i + 1}: the short fingerprint`);
    // City mode's forbidden words: every page, except the help district's own note, quoted in full on the first.
    const own = page.replace(/<section class="pr-help"[\s\S]*?<\/section>/, '');
    assert.doesNotMatch(text(own), CITY_FORBIDDEN, `page ${i + 1}: ${(text(own).match(CITY_FORBIDDEN) || [])[0]}`);
    assert.match(html, /data-act="record-done"/, 'Done on every page');
  }
  const first = P.renderRecordPage({ record: r, fp, index: 0 });
  assert.match(text(first), /Take a photo of each page with your phone\. Make sure the top line is in the picture\. If someone may look through your phone, keep the photos somewhere they can’t reach\./);
  const SD = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'side-district.js')).href);
  for (const h of SD.HELP) assert.ok(text(first).includes(h.text.replace(/&/g, '&')), `who can help: ${h.id}`);
  assert.ok(text(first).includes(SD.OPEN_NOTE.text));
  assert.doesNotMatch(first, /data-act="record-back"/, 'no Back on the first page');
  const last = P.renderRecordPage({ record: r, fp, index: pages.length - 1 });
  assert.doesNotMatch(last, /data-act="record-next"/, 'no Next on the last page');
  assert.match(text(last), /Record fingerprint/);
  for (const line of P.fullPrintLines(fp)) assert.ok(last.includes(line), line);
  assert.match(text(last), /If anything in this record changes, this number changes\. It shows the pages belong together and haven’t been edited since the checkup made them\. It doesn’t prove what the checkup found is true\./);
  assert.match(text(last), /A clear checkup lowers the odds of a problem; it doesn’t rule one out\./);
  for (const n of P.recordView(r).not_checked) assert.ok(text(last).includes(n.check), n.check);
  // A finding page: its facts, full path, wrapped in a monospace face.
  const wi = pages.findIndex((p) => p.finding && p.finding.what === 'ExampleWatch');
  const w = P.renderRecordPage({ record: r, fp, index: wi });
  assert.match(w, /<code class="pr-mono">\/Users\/someone\/Library\/Application Support\/Example Family Helper With A Long Folder Name\/Agents\/helper\/bin\/example-helper<\/code>/);
  assert.doesNotMatch(w, /…/);
  // Black on white whatever the theme: the page's colours are its own, never the theme's variables.
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'game.css'), 'utf8');
  const block = /\.pr-page \{[^}]*\}/.exec(css)[0];
  assert.match(block, /background: #fff;/);
  assert.match(block, /color: #000;/);
  assert.doesNotMatch(block, /var\(|gradient/);
});

test('hostile values stay inert on every page', async () => {
  const P = await load();
  const C = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js')).href);
  for (const h of C.HOSTILE) {
    const bad = { ...WATCH, title: h, data: { ...WATCH.data, stalkerware_name: h, location: h } };
    const r = P.buildRecord(ctx({ doc: { ...doc(), modules: [mod('stalkerware_scan', [bad]), mod(h.slice(0, 20) || 'x', [], { status: 'error' })] } }));
    const fp = await P.fingerprint(r);
    P.recordPages(r).forEach((_, i) => {
      assert.deepStrictEqual(C.checkInert(P.renderRecordPage({ record: r, fp, index: i })).filter((p) => !/control\/bidi/.test(p)), []);
    });
  }
});

test('a finding page doesn’t repeat its Where under another label, and every path is in the monospace face', async () => {
  const P = await load();
  const agent = { title: 'Odd agent', description: 'd', severity: 'critical', category: 'security', code: 'security.launch_agent_audit.unsigned',
    data: { plist: '/Library/LaunchAgents/com.example.qa.plist', program: '/opt/example/bin/run' } };
  const r = P.buildRecord(ctx({ doc: { schema_version: 1, platform: 'darwin', modules: [mod('launch_agent_audit', [agent])] } }));
  const f = P.recordView(r).findings[0];
  const values = f.rows.map(([, v]) => v);
  assert.strictEqual(values.filter((v) => v === '/Library/LaunchAgents/com.example.qa.plist').length, 1, JSON.stringify(f.rows));
  assert.ok(values.includes('/opt/example/bin/run'), 'other paths stay');
  const html = P.renderRecordPage({ record: r, fp: 'b'.repeat(64), index: 1 });
  assert.match(html, /<code class="pr-mono">\/opt\/example\/bin\/run<\/code>/);
  // The help district's addresses wrap as words, not letter by letter.
  assert.match(P.renderRecordPage({ record: r, fp: 'b'.repeat(64), index: 0 }), /<code class="pr-url">https:\/\/techsafety\.org<\/code>/);
});


test('the same scan gives the same fingerprint in any language and time zone; only the pages’ words change', () => {
  const { execFileSync } = require('child_process');
  const script = `
    require(${JSON.stringify(path.join(__dirname, '..', 'renderer', 'not-checked.js'))});
    require(${JSON.stringify(path.join(__dirname, '..', 'renderer', 'evidence.js'))});
    const T = { doc: () => (${JSON.stringify(doc())}), AT: ${JSON.stringify(AT)} };
    import(${JSON.stringify(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'photo-record.js')).href)}).then(async (P) => {
      const r = P.buildRecord({ doc: T.doc(), scanAt: T.AT, dualUse: { parental_control: 'someone' } });
      const fp = await P.fingerprint(r);
      const page = P.renderRecordPage({ record: r, fp, index: 2 });
      process.stdout.write(JSON.stringify({ fp, head: /<header[\\s\\S]*?<\\/header>/.exec(page)[0], body: page }));
    });`;
  const run = (env) => JSON.parse(execFileSync(process.execPath, ['-e', script], { env: { ...process.env, ...env, NODE_TEST_CONTEXT: '' } }).toString());
  const us = run({ LC_ALL: 'en_US.UTF-8', LANG: 'en_US.UTF-8', TZ: 'America/Los_Angeles' });
  const de = run({ LC_ALL: 'de_DE.UTF-8', LANG: 'de_DE.UTF-8', TZ: 'Asia/Tokyo' });
  assert.notStrictEqual(us.head, de.head, 'the two runs really did show the date differently');
  assert.strictEqual(us.fp, de.fp);
});
