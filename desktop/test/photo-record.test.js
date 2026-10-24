'use strict';
// The photo record (docs/superpowers/specs/2026-10-23-photo-record-design.md): pages built to be photographed,
// from the scan in memory, with one SHA-256 fingerprint of what they print. game/photo-record.js; synthetic data only.
// The printed scan time carries this computer's time zone, so the pinned hash needs a fixed one.
process.env.TZ = 'America/Los_Angeles';
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
  // The fingerprint covers the pages' words, normalized, never the raw values behind them.
  assert.match(P.canonicalJson(raw), /"Couldn't tell"/);
  assert.match(P.canonicalJson(raw), /"March 3, 2026"/);
  assert.doesNotMatch(P.canonicalJson(raw), /2026-03-03|couldnt_run|parental_control|"data"|"module"|’/);
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

// The fixed synthetic record and the canonical text of what its pages print: pinned, so a change to either is seen
// (docs/superpowers/specs/2026-10-23-photo-record-design.md, "The fingerprint", which quotes both).
const FIXED = { version: 2, scanned_at: '2026-10-23T16:17:00.000Z',
  computer: { platform: 'darwin', model_name: 'MacBook Pro', model: 'Mac16,1', os_version: '26.1', build: '25B78' },
  findings: [{ module: 'stalkerware_scan', check_name: null, code: 'security.stalkerware_scan.monitoring_software_found', severity: 'critical',
    kind: 'parental_control', title: 'ExampleWatch is on this computer',
    data: { check: 'monitoring_software_found', stalkerware_name: 'ExampleWatch', stalkerware_category: 'parental_control',
      location: '/Applications/ExampleWatch.app', added_on: '2026-03-03', running_now: null },
    made_by: [{ subject: '/Applications/ExampleWatch.app', name: 'Example Family Co', verified: false }], said: 'parental_control:someone' }],
  not_checked: [{ module: 'firewall_audit', check_name: 'Firewall', why: 'couldnt_run' }] };
const FIXED_JSON = '{"version":2,"computer":"MacBook Pro (Mac16,1), macOS 26.1 (25B78)","findings":[{"kind":"Parental control product",'
  + '"rows":[["Where","/Applications/ExampleWatch.app"],["Added","March 3, 2026"],["Last used","Couldn\'t tell"],["Running now","Couldn\'t tell"],'
  + '["Made by","Example Family Co (not verified)"],["How the check knows","Found by the check \\"Safety sweep\\""]],'
  + '"said":"You said: someone else gets its reports","what":"ExampleWatch"}],"not_checked":[["Firewall","Couldn\'t run"]],'
  + '"when":"October 23, 2026, 9:17 AM (UTC-7)"}';
const FIXED_SHA = crypto.createHash('sha256').update(FIXED_JSON, 'utf8').digest('hex');
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// A verifier holding only the photos, written from the spec and not from photo-record.js: the printed facts,
// normalized, in the canonical object's sorted key order, as JSON with no whitespace.
const retype = (v) => String(v).normalize('NFC').replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"')
  .replace(/[\u2212\u2013\u2014]/g, '-').replace(/[\t\n\v\f\r \u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]+/g, ' ').trim();
const canonicalText = (facts) => JSON.stringify({ version: 2, computer: retype(facts.computer),
  findings: facts.findings.map((f) => ({ kind: retype(f.kind), rows: f.rows.map(([l, v]) => [retype(l), retype(v)]), said: retype(f.said), what: retype(f.what) })),
  not_checked: facts.not_checked.map(([c, w]) => [retype(c), retype(w)]), when: retype(facts.when) });
// What the pages print, read back out of their HTML only.
const unhtml = (h) => h.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, '\'').replace(/&amp;/g, '&');
function readPages(pages) {
  const one = (re, h) => { const m = re.exec(h); return m ? unhtml(m[1]) : ''; };
  const heads = pages.map((h) => [...(/<header class="pr-head">([\s\S]*?)<\/header>/.exec(h) || ['', ''])[1].matchAll(/<span>([\s\S]*?)<\/span>/g)].map((m) => unhtml(m[1])));
  const facts = { when: heads[0][0], computer: heads[0][1], findings: [], not_checked: [] };
  for (const h of pages) {
    if (/class="pr-page pr-finding"/.test(h)) {
      facts.findings.push({ what: one(/<h2 class="pr-title">([\s\S]*?)<\/h2>/, h), kind: one(/<p class="pr-kind">([\s\S]*?)<\/p>/, h),
        rows: [...h.matchAll(/<dt>([\s\S]*?)<\/dt><dd>([\s\S]*?)<\/dd>/g)].map((m) => [unhtml(m[1]), unhtml(m[2])]),
        said: one(/<p class="pr-said">([\s\S]*?)<\/p>/, h) });
    }
    if (/class="pr-page pr-end"/.test(h)) {
      // "check: why"; the why is one of a few fixed words, so the last ": " splits them.
      facts.not_checked = [...h.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((m) => { const t = unhtml(m[1]); const at = t.lastIndexOf(': '); return [t.slice(0, at), t.slice(at + 2)]; });
    }
  }
  return { heads, facts };
}

test('the fingerprint: SHA-256 of the printed facts’ canonical JSON (version first, keys sorted, no whitespace), pinned', async () => {
  const P = await load();
  assert.strictEqual(P.canonicalJson(FIXED), FIXED_JSON);
  const fp = await P.fingerprint(FIXED);
  assert.strictEqual(fp, FIXED_SHA);
  assert.strictEqual(fp, PINNED, 'the pinned value');
  assert.strictEqual(P.shortPrint(fp), fp.slice(0, 16).toUpperCase().match(/.{4}/g).join(' '));
  assert.deepStrictEqual(P.fullPrintLines(fp), fp.toUpperCase().match(/.{16}/g).map((l) => l.match(/.{4}/g).join(' ')));
  // Same record, same number; any printed fact changed, a new one.
  const built = P.buildRecord(ctx());
  assert.strictEqual(await P.fingerprint(built), await P.fingerprint(P.buildRecord(ctx())));
  const moved = P.buildRecord(ctx({ scanAt: '2026-10-23T16:18:00.000Z' }));
  assert.notStrictEqual(await P.fingerprint(moved), await P.fingerprint(built));
  const edited = JSON.parse(JSON.stringify(FIXED)); edited.findings[0].data.location += 'x';
  assert.notStrictEqual(await P.fingerprint(edited), fp);
  // The engine's evidence that no page shows isn't covered: nobody holding the photos could check it.
  const unseen = JSON.parse(JSON.stringify(FIXED));
  Object.assign(unseen.findings[0], { code: 'security.other', severity: 'warning' });
  Object.assign(unseen.findings[0].data, { check: 'other', internal_id: 'x-17', bundle_size: 12345 });
  unseen.findings[0].made_by[0].subject = '/elsewhere';
  assert.strictEqual(P.canonicalJson(unseen), FIXED_JSON);
  assert.strictEqual(await P.fingerprint(unseen), fp);
});
const PINNED = '8298a3867b2a4e5f7f9bf82dbe163f67361346356076c28e65075ff33fb06e51';

test('normalizing for retyping: quotes, dashes and spaces as a keyboard types them; NFC; trimmed', async () => {
  const P = await load();
  assert.strictEqual(P.normalizeForPrint('  Couldn\u2019t \u2018x\u2019 \u201Cy\u201D a\u2212b c\u2013d e\u2014f\u00A0g\u202Fh\u2003i \n\t j  '), 'Couldn\'t \'x\' "y" a-b c-d e-f g h i j');
  assert.strictEqual(P.normalizeForPrint('Cafe\u0301'), 'Caf\u00E9');
  for (const s of ['Couldn’t tell', 'a\u2212b\u00A0 c', ' x ', 'Cafe\u0301 “q”']) assert.strictEqual(P.normalizeForPrint(s), retype(s), s);
});

test('the photos verify themselves: the hash is SHA-256 of the facts read back out of the rendered pages', async () => {
  const P = await load();
  const r = P.buildRecord(ctx({ dualUse: { parental_control: 'someone' } }));
  const fp = await P.fingerprint(r);
  const pages = P.recordPages(r).map((_, i) => P.renderRecordPage({ record: r, fp, index: i }));
  const { heads, facts } = readPages(pages);
  for (const h of heads) assert.deepStrictEqual([h[0], h[1]], [heads[0][0], heads[0][1]], 'every header prints the same time and computer');
  assert.match(facts.when, /^October 23, 2026, 9:17 AM \(UTC-7\)$/);
  assert.strictEqual(facts.findings.length, r.findings.length);
  assert.ok(facts.findings.some((f) => f.said === 'You said: someone else gets its reports'));
  assert.ok(facts.not_checked.length >= 3);
  assert.strictEqual(sha(canonicalText(facts)), fp);
  assert.strictEqual(canonicalText(facts), P.canonicalJson(r));
  // Retyped with a keyboard's straight apostrophes and quotes, and loose spacing: the same number.
  const typed = JSON.parse(JSON.stringify(facts));
  typed.findings.forEach((f) => { f.rows = f.rows.map(([l, v]) => [l, ` ${v.replace(/’/g, "'").replace(/[“”]/g, '"')}  `]); });
  typed.not_checked = typed.not_checked.map(([c, w]) => [c, w.replace(/’/g, "'")]);
  assert.ok(JSON.stringify(facts).includes('’'), 'there were curly apostrophes to retype');
  assert.strictEqual(sha(canonicalText(typed)), fp);
  // Any printed value changed, a different number: every row of every finding page.
  facts.findings.forEach((f, i) => f.rows.forEach((_, j) => {
    const changed = JSON.parse(JSON.stringify(facts));
    changed.findings[i].rows[j][1] += '1';
    assert.notStrictEqual(sha(canonicalText(changed)), fp, `${f.what}: ${f.rows[j][0]}`);
  }));
  for (const k of ['when', 'computer']) assert.notStrictEqual(sha(canonicalText({ ...facts, [k]: `${facts[k]}1` })), fp, k);
});

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
    // City mode's forbidden words: every page, all of it.
    assert.doesNotMatch(text(html), CITY_FORBIDDEN, `page ${i + 1}: ${(text(html).match(CITY_FORBIDDEN) || [])[0]}`);
    assert.match(html, /data-act="record-done"/, 'Done on every page');
    assert.match(html, /data-act="record-back"/, 'Back on every page (from the first, to the screen before the pages)');
  }
  const first = P.renderRecordPage({ record: r, fp, index: 0 });
  assert.match(text(first), /How to use these pages/);
  assert.match(text(first), /Take a photo of each page with your phone\. Make sure the top line is in the picture\. If someone may look through your phone, keep the photos somewhere they can’t reach\./);
  assert.doesNotMatch(first, /Who can help/);
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

test('who can help is on a screen before the pages, never on one: no header, count, fingerprint or page frame', async () => {
  const P = await load();
  const SD = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'side-district.js')).href);
  const start = P.renderRecordStart({ look: 'garden' });
  assert.match(text(start), /Before you start/);
  assert.match(text(start), /This screen isn’t part of the record\. You don’t need to photograph it\./);
  for (const h of SD.HELP) assert.ok(text(start).includes(h.text), `who can help: ${h.id}`);
  assert.ok(text(start).includes(SD.OPEN_NOTE.text));
  assert.match(start, /data-act="record-start"[^>]*>START THE RECORD/);
  assert.match(start, /data-act="record-done"[^>]*>DONE</);
  assert.doesNotMatch(start, /pr-page|pr-head|photo-record|Checkup record|Page \d|pr-fp|record-back|record-next/);
  assert.match(start, /class="side record-start look-garden"/, 'the district’s own look');
  // City mode's forbidden words: all of it but the help district's own list, quoted in full.
  const own = start.replace(/<div class="panel record-help">[\s\S]*?<\/div>/, '');
  assert.ok(own.length < start.length);
  assert.doesNotMatch(text(own), CITY_FORBIDDEN, (text(own).match(CITY_FORBIDDEN) || [])[0]);
  // And none of it on any record page, which may end up in a camera roll.
  const r = P.buildRecord(ctx({ dualUse: { parental_control: 'someone' } }));
  const fp = await P.fingerprint(r);
  const PHONE = /\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b|\b(?:911|88788|233733)\b/;
  P.recordPages(r).forEach((_, i) => {
    const page = text(P.renderRecordPage({ record: r, fp, index: i }));
    assert.doesNotMatch(page, PHONE, `page ${i + 1}`);
    for (const h of [...SD.HELP, SD.OPEN_NOTE]) assert.ok(!page.includes(h.text) && !(h.url && page.includes(h.url)), `page ${i + 1}: ${h.id || 'note'}`);
    assert.doesNotMatch(page, /Who can help|Before you start/);
  });
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
  // The help district's addresses (on the screen before the pages) wrap as words, not letter by letter.
  assert.match(P.renderRecordStart(), /<code class="pr-url">https:\/\/techsafety\.org<\/code>/);
});


// Two runs of the same scan in fresh processes: the language and time zone come from the environment.
function inProcess(env) {
  const { execFileSync } = require('child_process');
  const script = `
    require(${JSON.stringify(path.join(__dirname, '..', 'renderer', 'not-checked.js'))});
    require(${JSON.stringify(path.join(__dirname, '..', 'renderer', 'evidence.js'))});
    const T = { doc: () => (${JSON.stringify(doc())}), AT: ${JSON.stringify(AT)} };
    import(${JSON.stringify(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'photo-record.js')).href)}).then(async (P) => {
      const r = P.buildRecord({ doc: T.doc(), scanAt: T.AT, dualUse: { parental_control: 'someone' } });
      const fp = await P.fingerprint(r);
      const pages = P.recordPages(r).map((_, i) => P.renderRecordPage({ record: r, fp, index: i }));
      const local = new Date(2026, 2, 3).toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' });
      process.stdout.write(JSON.stringify({ fp, pages, local }));
    });`;
  return JSON.parse(execFileSync(process.execPath, ['-e', script], { env: { ...process.env, ...env, NODE_TEST_CONTEXT: '' } }).toString());
}

test('the same scan in two languages, same time zone: the same pages and the same fingerprint', () => {
  const us = inProcess({ LC_ALL: 'en_US.UTF-8', LANG: 'en_US.UTF-8', TZ: 'America/Los_Angeles' });
  const de = inProcess({ LC_ALL: 'de_DE.UTF-8', LANG: 'de_DE.UTF-8', TZ: 'America/Los_Angeles' });
  assert.notStrictEqual(us.local, de.local, 'the two runs really did have different languages');
  assert.deepStrictEqual(de.pages, us.pages);
  assert.strictEqual(de.fp, us.fp);
  // Another time zone prints another time, so its pages have their own fingerprint, and say which zone.
  const jp = inProcess({ LC_ALL: 'en_US.UTF-8', LANG: 'en_US.UTF-8', TZ: 'Asia/Tokyo' });
  assert.ok(jp.pages[0].includes('October 24, 2026, 1:17 AM (UTC+9)'), 'the zone is printed');
  assert.ok(us.pages[0].includes('October 23, 2026, 9:17 AM (UTC-7)'));
  assert.notStrictEqual(jp.fp, us.fp);
  assert.ok(inProcess({ TZ: 'Asia/Kolkata' }).pages[0].includes('October 23, 2026, 9:47 PM (UTC+5:30)'), 'a half-hour offset');
  assert.ok(inProcess({ TZ: 'UTC' }).pages[0].includes('October 23, 2026, 4:17 PM (UTC+0)'));
});

test('every printed date is written by hand: with the computer’s date formatting broken, the same pages and fingerprint', async () => {
  const P = await load();
  const dated = () => {
    const d = doc();
    d.modules[0] = mod('stalkerware_scan', [{ ...WATCH, data: { ...WATCH.data, added_on: '2025-11-20', last_used: '2026-10-01T08:00:00Z' } }]);
    return d;
  };
  const run = async () => {
    const r = P.buildRecord({ doc: dated(), scanAt: AT, dualUse: { parental_control: 'someone' } });
    const fp = await P.fingerprint(r);
    return { fp, pages: P.recordPages(r).map((_, i) => P.renderRecordPage({ record: r, fp, index: i })), fixed: await P.fingerprint(FIXED),
      offered: P.offerRecord({ mode: 'standard', situation: { id: 'unsure' }, doc: dated(), dualUse: {} }) };
  };
  const before = await run();
  const all = before.pages.join('\n');
  for (const s of ['March 3, 2026', 'March 12, 2026', 'November 20, 2025', 'October 1, 2026', 'October 23, 2026, 9:17 AM (UTC-7)']) {
    assert.ok(all.includes(s), s);
  }
  const saved = { ld: Date.prototype.toLocaleDateString, ls: Date.prototype.toLocaleString, lt: Date.prototype.toLocaleTimeString, dtf: Intl.DateTimeFormat };
  const runs = [];
  for (const how of ['throw', 'garbage']) {
    const bad = how === 'throw' ? () => { throw new Error('date formatting was used'); } : () => 'Zzz 99, 0000 GARBAGE';
    try {
      Date.prototype.toLocaleDateString = bad;
      Date.prototype.toLocaleString = bad;
      Date.prototype.toLocaleTimeString = bad;
      Intl.DateTimeFormat = function DateTimeFormat() { if (how === 'throw') throw new Error('Intl was used'); return { format: bad, formatToParts: () => [], resolvedOptions: () => ({}) }; };
      runs.push([how, await run()]);
    } finally {
      Date.prototype.toLocaleDateString = saved.ld;
      Date.prototype.toLocaleString = saved.ls;
      Date.prototype.toLocaleTimeString = saved.lt;
      Intl.DateTimeFormat = saved.dtf;
    }
  }
  for (const [how, after] of runs) {
    assert.deepStrictEqual(after.pages, before.pages, how);
    assert.strictEqual(after.fp, before.fp, how);
    assert.strictEqual(after.fixed, PINNED, how);
  }
});
