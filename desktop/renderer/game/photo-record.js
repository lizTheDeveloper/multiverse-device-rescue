// The photo record (docs/superpowers/specs/2026-10-23-photo-record-design.md): what the checkup found, as pages
// built to be photographed with a phone, offered only in the help district. Drawn from the scan already in
// memory; nothing is saved, copied, exported or sent, and nothing here scores. One fingerprint, the SHA-256 of
// the facts the pages print, made on this computer with Web Crypto, ties the pages together: someone holding
// only the photos can retype those facts and get the same number.
//
//   offerRecord({ mode, situation, doc, dualUse }) -> boolean     the four cases in the spec
//   buildRecord({ doc, scanAt, dualUse }) -> record               raw values: what the pages are made from
//   recordView(record) -> the pages' words (US English, whatever the computer's language: they're hashed)
//   normalizeForPrint(s) -> string                                a printed fact as a verifier would retype it
//   printedFacts(view) -> the canonical object                    the printed facts, normalized, in page order
//   canonicalJson(record) -> string                               version first, every other key sorted, no whitespace
//   fingerprint(record, subtle?) -> Promise<hex>                  64 lowercase hex
//   shortPrint(hex) / fullPrintLines(hex)                         'AAAA BBBB CCCC DDDD' / four such lines of the whole
//   recordPages(record) -> [{ kind: 'intro' | 'finding' | 'end', finding? }]
//   renderRecordStart({ look }) -> HTML                           the screen before the pages: who can help, never photographed
//   renderRecordPage({ record, fp, index }) -> HTML               one page and its Back / Next / Done
//   scanWhen(iso) -> the scan's date, time and UTC offset, as the header shows it
import { esc } from './escape.js';
import { splitHeld, heldEvidence, REMOTE_TOOLS } from './held.js';
import { HELP, OPEN_NOTE } from './side-district.js';
import { remoteFacts } from '../missions/remote-facts.js';
import { dayWords } from '../missions/day.js';
import * as evidenceModule from '../evidence.js';

const EV = globalThis.Evidence || evidenceModule.default;
const NC = globalThis.NotChecked;

export const RECORD_VERSION = 2;
const LOCALE = 'en-US'; // the app's words are English; a printed date must not depend on the computer's language
const COULDNT = 'Couldn’t tell';
const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : '');

// ---- When it's offered ----

// The dual-use answers that mean someone else may be the one watching (dual-use.js): who gets a parental
// tool's reports, and whose computer has the work tool. Who receives the reports decides who is watched.
const WATCHED_ANSWERS = { parental_control: new Set(['someone', 'notsure']), employee_monitoring: new Set(['mine', 'notsure']) };
const SAID = {
  parental_control: { me: 'only you get its reports', someone: 'someone else gets its reports', notsure: 'you’re not sure who gets its reports' },
  employee_monitoring: { employer: 'it’s your employer’s computer', mine: 'it’s your computer', notsure: 'you’re not sure whose computer this is' },
};

export function offerRecord({ mode, situation, doc, dualUse } = {}) {
  if (mode === 'city') return true;
  if (situation && situation.safety === true) return true;
  if (splitHeld(doc, { mode: 'city' }).held.length > 0) return true;
  const a = isObj(dualUse) ? dualUse : {};
  return Object.entries(WATCHED_ANSWERS).some(([cat, yes]) => yes.has(a[cat]));
}

// ---- What's in it ----
//
// The record is raw values: the scan's ISO time, the engine's own data for each finding, booleans as true / false /
// null (null: couldn't tell), kinds and answers as stable keys. The pages' words are made from it by recordView;
// the fingerprint covers those words, not this (see the spec's "The fingerprint").

function kindKey(module, f, held) {
  const d = isObj(f.data) ? f.data : {};
  if (module === REMOTE_TOOLS) return d.check === 'several_tools' ? 'remote_access_tools' : 'remote_access_tool';
  if (module === 'stalkerware_scan') return d.stalkerware_category === 'parental_control' || d.stalkerware_category === 'employee_monitoring'
    ? d.stalkerware_category : 'monitoring_product';
  if (module === 'keylogger_indicators') return 'keyboard_access';
  if (module === 'mvt_spyware_scan') return 'phone_backup';
  return held ? 'program' : 'finding';
}
const nul = (v) => (v === undefined ? null : v);
// JSON values only (the engine's data is JSON already; this drops anything that isn't).
const plain = (v) => (v === undefined ? null : JSON.parse(JSON.stringify(v)));

function rawFinding(module, f, doc, held, answers) {
  const d = isObj(f.data) ? f.data : {};
  const cat = d.stalkerware_category;
  const answer = typeof cat === 'string' && answers[cat] && SAID[cat] && SAID[cat][answers[cat]] ? `${cat}:${answers[cat]}` : null;
  const mod = (doc && Array.isArray(doc.modules) ? doc.modules : []).find((m) => m && m.name === module);
  return {
    module, check_name: mod && typeof mod.check_name === 'string' && mod.check_name ? mod.check_name : null,
    code: nul(f.code), severity: nul(f.severity), kind: kindKey(module, f, held), title: typeof f.title === 'string' ? f.title : null,
    data: plain(d),
    made_by: (Array.isArray(f.made_by) ? f.made_by.filter(isObj) : [])
      .map((m) => ({ subject: nul(m.subject), name: nul(m.name), verified: m.verified === true ? true : m.verified === false ? false : null })),
    said: answer,
  };
}

function rawComputer(doc) {
  const out = { platform: nul(doc && doc.platform), model_name: null, model: null, os_version: null, build: null };
  for (const m of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    for (const f of (m && Array.isArray(m.findings) ? m.findings : [])) {
      const d = f && isObj(f.data) ? f.data : null;
      if (!d || d.check !== 'version_info') continue;
      return { ...out, model_name: nul(d.model_name), model: nul(d.model), os_version: nul(d.version), build: nul(d.build) };
    }
  }
  return out;
}

function rawNotChecked(doc) {
  const parts = NC.notCheckedParts(doc);
  const names = new Map((doc && Array.isArray(doc.modules) ? doc.modules : []).filter(Boolean)
    .map((m) => [m.name, typeof m.check_name === 'string' && m.check_name ? m.check_name : null]));
  const out = [];
  const add = (list, why) => { for (const x of list || []) out.push({ module: x.name, check_name: names.get(x.name) || null, why }); };
  add(parts.couldntRun, 'couldnt_run');
  add(parts.notReached, 'not_reached');
  add(parts.notStarted, 'not_started');
  add(parts.unfinished, 'unfinished');
  return out;
}

export function buildRecord({ doc, scanAt, dualUse } = {}) {
  const answers = isObj(dualUse) ? dualUse : {};
  const split = splitHeld(doc, { mode: 'city' });
  const findings = split.held.map((h) => rawFinding(h.module, h.finding || {}, doc, true, answers));
  // Every warning and critical finding from the other checks (info left out: an inventory would bury the evidence).
  const list = NC.displayItems(split.doc, { mode: 'standard' });
  for (const item of [...list.critical, ...list.warning]) {
    const f = item.finding || {};
    const module = f.module || (item.seen_in || [])[0] || '';
    findings.push(rawFinding(module, { ...f, severity: item.severity || f.severity }, doc, false, answers));
  }
  const t = new Date(String(scanAt || ''));
  return { version: RECORD_VERSION, scanned_at: Number.isNaN(t.getTime()) ? null : t.toISOString(), computer: rawComputer(doc),
    findings, not_checked: rawNotChecked(doc) };
}

// ---- What the pages say (US English everywhere: the fingerprint covers it) ----

const KIND_WORDS = { parental_control: 'Parental control product', employee_monitoring: 'Employee monitoring product',
  monitoring_product: 'Monitoring product', keyboard_access: 'Program with keyboard access', phone_backup: 'Finding in a phone backup',
  remote_access_tool: 'Remote-access tool', remote_access_tools: 'Remote-access tools', program: 'Program' };
const kindWords = (rf) => KIND_WORDS[rf.kind] || (rf.severity === 'critical' ? 'Critical finding' : 'Warning finding');
const WHY_WORDS = { couldnt_run: 'Couldn’t run', not_reached: 'Not reached', not_started: 'Not started', unfinished: 'Didn’t finish' };

// A check's name as the city may say it (never a watching word).
const checkName = (module, name) => EV.cityCheckName(name || EV.checkLabel(module, null), module);

const day = (v) => (typeof v === 'string' ? (dayWords(v, { year: true, locale: LOCALE }) || str(v)) : '');
const first = (d, keys) => { for (const k of keys) if (d[k] != null && d[k] !== '') return d[k]; return null; };
const yesNo = (v) => (v === true ? 'Yes' : v === false ? 'No' : COULDNT);

function whereOf(d) {
  const p = first(d, ['location', 'path', 'plist', 'program', 'binary', 'file']);
  if (typeof p === 'string' && p.trim()) return p;
  const apps = Array.isArray(d.apps) ? d.apps.filter((x) => typeof x === 'string' && x.trim()) : [];
  return apps.length ? apps.join(', ') : COULDNT;
}
function makerOf(rf) {
  const out = rf.made_by.map((m) => `${str(m.name) || 'Unknown maker'} (${m.verified === true ? 'verified' : 'not verified'})`)
    .filter((x, i, a) => a.indexOf(x) === i);
  return out.length ? out.join('; ') : COULDNT;
}
function howOf(rf) {
  const d = isObj(rf.data) ? rf.data : {};
  const by = `the check “${checkName(rf.module, rf.check_name)}”`;
  if (str(d.detected_as)) return `Found as ${str(d.detected_as)}, by ${by}`;
  if (rf.module === 'keylogger_indicators') return `Has keyboard access, found by ${by}`;
  return `Found by ${by}`;
}
const HELD_KINDS = new Set(Object.keys(KIND_WORDS));

// The facts on one finding's page, as [label, value] pairs. Missing evidence says "Couldn't tell", never "no".
function rowsOf(rf) {
  const d = isObj(rf.data) ? rf.data : {};
  const held = HELD_KINDS.has(rf.kind);
  const rows = [['Where', whereOf(d)]];
  if (rf.kind === 'remote_access_tool') {
    const r = Object.fromEntries(remoteFacts(d, { year: true, locale: LOCALE }).rows.map((x) => [x.label, x.value]));
    rows.push(['Added', r.Added], ['Last let someone in', r['Last let someone in']],
      ['Can let someone in without a click', r['Can let someone in without a click']], ['Running now', r['Running now']]);
  } else {
    rows.push(['Added', day(first(d, ['added_on', 'installed_on', 'install_date', 'installed_at', 'created_at', 'first_seen'])) || COULDNT],
      ['Last used', day(first(d, ['last_used', 'last_seen', 'last_run', 'last_opened'])) || COULDNT],
      ['Running now', yesNo(first(d, ['running_now', 'running', 'is_running']))]);
  }
  rows.push(['Made by', makerOf(rf)], ['How the check knows', howOf(rf)]);
  if (!held) {
    // The rest of what its evidence card shows, every path whole.
    const have = new Set(rows.map(([l]) => l));
    const skip = new Set(['Check', 'When', 'Seen', 'Command', 'Commands', 'Made by', 'Where', 'Name']);
    const f = { module: rf.module, title: rf.title, severity: rf.severity, code: rf.code, data: d };
    for (const r of EV.evidenceRows(f, { mode: 'standard', held: false, checkName: checkName(rf.module, rf.check_name), commands: [], fullPaths: true })) {
      const value = String(r && (r.copy || r.value));
      if (!r || have.has(r.label) || skip.has(r.label) || r.tech || value === rows[0][1]) continue;
      rows.push([String(r.label), value]);
      have.add(r.label);
    }
  }
  return rows.map(([l, v]) => [l, v == null || v === '' ? COULDNT : String(v)]);
}

function whatOf(rf) {
  const d = isObj(rf.data) ? rf.data : {};
  if (rf.kind === 'remote_access_tools' && Array.isArray(d.tools)) {
    const names = d.tools.filter((x) => typeof x === 'string' && x.trim()).join(', ');
    if (names) return names;
  }
  if (HELD_KINDS.has(rf.kind)) return heldEvidence({ data: d, made_by: rf.made_by }, rf.module).name || str(rf.title) || COULDNT;
  return str(rf.title) || COULDNT;
}

function computerWords(c) {
  const x = isObj(c) ? c : {};
  const model = [str(x.model_name), str(x.model) ? `(${str(x.model)})` : ''].filter(Boolean).join(' ');
  const system = str(x.os_version) ? `macOS ${str(x.os_version)}${str(x.build) ? ` (${str(x.build)})` : ''}` : '';
  const out = [model, system].filter(Boolean).join(', ');
  if (out) return out;
  if (x.platform === 'darwin') return 'A Mac (model and system version: couldn’t tell)';
  if (x.platform === 'win32') return 'A Windows PC (model and system version: couldn’t tell)';
  return COULDNT;
}

// The record in the pages' words: { when, computer, findings: [{ what, kind, rows, said }], not_checked: [{ check, why }] }.
export function recordView(record) {
  const r = isObj(record) ? record : {};
  return {
    when: scanWhen(r.scanned_at),
    computer: computerWords(r.computer),
    findings: (Array.isArray(r.findings) ? r.findings : []).map((rf) => {
      const [cat, ans] = typeof rf.said === 'string' ? rf.said.split(':') : [];
      return { what: whatOf(rf), kind: kindWords(rf), rows: rowsOf(rf), said: (SAID[cat] && SAID[cat][ans]) || '' };
    }),
    not_checked: (Array.isArray(r.not_checked) ? r.not_checked : []).map((x) => ({ check: checkName(x.module, x.check_name), why: WHY_WORDS[x.why] || COULDNT })),
  };
}

// ---- The fingerprint ----

// For hashing only (the pages keep their typography): what someone retyping a photo would type. NFC; curly
// quotes straight; minus, en and em dash a hyphen; every kind of space (\s) one space; trimmed.
export const normalizeForPrint = (v) => String(v == null ? '' : v).normalize('NFC')
  .replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"').replace(/[\u2212\u2013\u2014]/g, '-')
  .replace(/\s+/g, ' ').trim();

// The facts as the pages print them, in page order: the header's scan time and computer; each finding page's
// title, kind line, rows and "You said" line ('' when there's none); the couldn't-check list. Nothing else: no
// page numbers, instructions, fixed sentences, fingerprint or buttons.
export function printedFacts(view) {
  const v = isObj(view) ? view : {};
  const n = normalizeForPrint;
  return {
    version: RECORD_VERSION, when: n(v.when), computer: n(v.computer),
    findings: (Array.isArray(v.findings) ? v.findings : []).map((f) => ({ what: n(f.what), kind: n(f.kind),
      rows: (f.rows || []).map(([l, x]) => [n(l), n(x)]), said: f.said ? n(`You said: ${f.said}`) : '' })),
    not_checked: (Array.isArray(v.not_checked) ? v.not_checked : []).map((x) => [n(x.check), n(x.why)]),
  };
}

function sorted(v) {
  if (Array.isArray(v)) return v.map(sorted);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => [k, sorted(v[k])]));
  return v;
}
export function canonicalJson(record) {
  const r = printedFacts(recordView(record));
  const rest = sorted(Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'version')));
  return JSON.stringify({ version: r.version, ...rest });
}
export async function fingerprint(record, subtle = globalThis.crypto && globalThis.crypto.subtle) {
  const bytes = new TextEncoder().encode(canonicalJson(record));
  const digest = await subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const groups = (s) => (s.match(/.{1,4}/g) || []).join(' ');
export const shortPrint = (hex) => groups(String(hex || '').slice(0, 16).toUpperCase());
export const fullPrintLines = (hex) => (String(hex || '').toUpperCase().match(/.{1,16}/g) || []).map(groups);

// ---- The pages ----

export function recordPages(record) {
  const fs = recordView(record).findings;
  return [{ kind: 'intro' }, ...fs.map((finding) => ({ kind: 'finding', finding })), { kind: 'end' }];
}

// "October 23, 2026, 9:17 AM (UTC-7)": US English by hand (ICU versions differ on " at " and the space before AM),
// in this computer's time zone with its offset at that instant, so the printed time is unambiguous.
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
export function scanWhen(iso) {
  const t = new Date(String(iso || ''));
  if (Number.isNaN(t.getTime())) return COULDNT;
  const h = t.getHours();
  const off = -t.getTimezoneOffset();
  const zone = `UTC${off < 0 ? '-' : '+'}${Math.floor(Math.abs(off) / 60)}${Math.abs(off) % 60 ? `:${String(Math.abs(off) % 60).padStart(2, '0')}` : ''}`;
  return `${MONTHS[t.getMonth()]} ${t.getDate()}, ${t.getFullYear()}, ${h % 12 || 12}:${String(t.getMinutes()).padStart(2, '0')} ${h < 12 ? 'AM' : 'PM'} (${zone})`;
}

const looksLikePath = (s) => /^(~|\/|[A-Za-z]:\\)/.test(s);

// Before the pages, and not one of them: who can help, in the district's own look (no page frame, header,
// count or fingerprint), so a photo of the pages never puts the hotlines in a camera roll someone may look through.
export function renderRecordStart({ look = '' } = {}) {
  return `<section class="side record-start${look ? ` look-${esc(look)}` : ''}" aria-labelledby="record-start-title">
    <header class="hud side-top"><h2 class="hud-title" id="record-start-title" tabindex="-1">${esc('Before you start')}</h2></header>
    <div class="panel"><p class="intel"><b>${esc('This screen isn’t part of the record. You don’t need to photograph it.')}</b></p></div>
    <div class="panel record-help"><h3 class="side-h">Who can help</h3><ul class="notes">${HELP.map((h) => `<li>${esc(h.text)}${h.url ? ` <code class="pr-url">${esc(h.url)}</code>` : ''}</li>`).join('')}</ul>
      <p class="intel">${esc(OPEN_NOTE.text)}</p></div>
    <nav class="pr-nav" aria-label="Record"><button type="button" class="btn-p" data-act="record-start">START THE RECORD ▶</button>
      <button type="button" class="btn-s" data-act="record-done">DONE</button></nav>
  </section>`;
}

function introHtml(record) {
  const n = record.findings.length;
  return `<h2 class="pr-title">How to use these pages</h2>
    <p class="pr-lead">Take a photo of each page with your phone. Make sure the top line is in the picture. If someone may look through your phone, keep the photos somewhere they can’t reach.</p>
    <p>${esc(`This record has ${n} ${n === 1 ? 'page' : 'pages'} of what the checkup found, then a page of what it couldn’t check. Use Next to go through them.`)}</p>`;
}

function findingHtml(f) {
  const rows = f.rows.map(([l, v]) => `<dt>${esc(l)}</dt><dd>${looksLikePath(v)
    ? `<code class="pr-mono">${esc(v)}</code>` : esc(v)}</dd>`).join('');
  return `<h2 class="pr-title">${esc(f.what)}</h2><p class="pr-kind">${esc(f.kind)}</p><dl class="pr-rows">${rows}</dl>`
    + (f.said ? `<p class="pr-said">${esc(`You said: ${f.said}`)}</p>` : '');
}

function endHtml(record, fp) {
  const nc = record.not_checked;
  const list = nc.length ? `<ul class="pr-list">${nc.map((x) => `<li>${esc(`${x.check}: ${x.why}`)}</li>`).join('')}</ul>`
    : '<p>Every check ran to the end.</p>';
  return `<h2 class="pr-title">What couldn’t be checked</h2>${list}
    <p>A clear checkup lowers the odds of a problem; it doesn’t rule one out.</p>
    <h3 class="pr-fp-head">Record fingerprint</h3>
    <pre class="pr-fp-full">${fullPrintLines(fp).map(esc).join('\n')}</pre>
    <p>If anything in this record changes, this number changes. It shows the pages belong together and haven’t been edited since the checkup made them. It doesn’t prove what the checkup found is true.</p>`;
}

export function renderRecordPage({ record, fp = '', index = 0 } = {}) {
  const view = recordView(record);
  const pages = recordPages(record);
  const i = Math.max(0, Math.min(pages.length - 1, Number(index) || 0));
  const p = pages[i];
  const head = `<header class="pr-head"><b>Checkup record</b><span>${esc(view.when)}</span><span>${esc(view.computer)}</span>`
    + `<span>${esc(`Page ${i + 1} of ${pages.length}`)}</span><span class="pr-fp">${esc(shortPrint(fp))}</span></header>`;
  const body = p.kind === 'intro' ? introHtml(view) : p.kind === 'end' ? endHtml(view, fp) : findingHtml(p.finding);
  // Back on every page: from the first, to the screen before the pages.
  const nav = '<nav class="pr-nav" aria-label="Record pages"><button type="button" class="btn-s" data-act="record-back">◀ BACK</button>'
    + `${i < pages.length - 1 ? '<button type="button" class="btn-p" data-act="record-next">NEXT ▶</button>' : ''}`
    + '<button type="button" class="btn-s" data-act="record-done">DONE</button></nav>';
  return `<section class="photo-record" aria-label="Checkup record"><article class="pr-page pr-${p.kind}" tabindex="-1">${head}<div class="pr-body">${body}</div></article>${nav}</section>`;
}

