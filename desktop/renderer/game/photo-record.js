// The photo record (docs/superpowers/specs/2026-10-23-photo-record-design.md): what the checkup found, as pages
// built to be photographed with a phone, offered only in the help district. Drawn from the scan already in
// memory; nothing is saved, copied, exported or sent, and nothing here scores. One fingerprint, the SHA-256 of
// the record's canonical JSON, made on this computer with Web Crypto, ties the pages together.
//
//   offerRecord({ mode, situation, doc, dualUse }) -> boolean     the four cases in the spec
//   buildRecord({ doc, scanAt, dualUse }) -> record               { version, scanned_at, computer, findings, not_checked }
//   canonicalJson(record) -> string                               version first, every other key sorted, no whitespace
//   fingerprint(record, subtle?) -> Promise<hex>                  64 lowercase hex
//   shortPrint(hex) / fullPrintLines(hex)                         'AAAA BBBB CCCC DDDD' / four such lines of the whole
//   recordPages(record) -> [{ kind: 'intro' | 'finding' | 'end', finding? }]
//   renderRecordPage({ record, fp, index }) -> HTML               one page and its Back / Next / Done
//   scanWhen(iso) -> the scan's date and time, as the header shows it
import { esc } from './escape.js';
import { splitHeld, heldEvidence, REMOTE_TOOLS } from './held.js';
import { HELP, OPEN_NOTE } from './side-district.js';
import { remoteFacts } from '../missions/remote-facts.js';
import { dayWords } from '../missions/day.js';
import * as evidenceModule from '../evidence.js';

const EV = globalThis.Evidence || evidenceModule.default;
const NC = globalThis.NotChecked;

export const RECORD_VERSION = 1;
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

const KIND = { parental_control: 'Parental control product', employee_monitoring: 'Employee monitoring product' };
function kindOf(module, f, held) {
  const d = isObj(f.data) ? f.data : {};
  if (module === REMOTE_TOOLS) return d.check === 'several_tools' ? 'Remote-access tools' : 'Remote-access tool';
  if (module === 'stalkerware_scan') return KIND[d.stalkerware_category] || 'Monitoring product';
  if (module === 'keylogger_indicators') return 'Program with keyboard access';
  if (module === 'mvt_spyware_scan') return 'Finding in a phone backup';
  if (held) return 'Program';
  return f.severity === 'critical' ? 'Critical finding' : 'Warning finding';
}

// A check's name as the city may say it (never a watching word).
const checkName = (module, doc) => EV.cityCheckName(EV.checkLabel(module, doc), module);

const day = (v) => (typeof v === 'string' ? (dayWords(v, { year: true }) || str(v)) : '');
const first = (d, keys) => { for (const k of keys) if (d[k] != null && d[k] !== '') return d[k]; return null; };
const yesNo = (v) => (v === true ? 'Yes' : v === false ? 'No' : COULDNT);

function whereOf(d) {
  const p = first(d, ['location', 'path', 'plist', 'program', 'binary', 'file']);
  if (typeof p === 'string' && p.trim()) return p;
  const apps = Array.isArray(d.apps) ? d.apps.filter((x) => typeof x === 'string' && x.trim()) : [];
  return apps.length ? apps.join(', ') : COULDNT;
}
function makerOf(f) {
  const mb = Array.isArray(f.made_by) ? f.made_by.filter(isObj) : [];
  const out = mb.map((m) => `${str(m.name) || 'Unknown maker'} (${m.verified === true ? 'verified' : 'not verified'})`)
    .filter((x, i, a) => a.indexOf(x) === i);
  return out.length ? out.join('; ') : COULDNT;
}
function howOf(module, f, doc) {
  const d = isObj(f.data) ? f.data : {};
  const by = `the check “${checkName(module, doc)}”`;
  if (str(d.detected_as)) return `Found as ${str(d.detected_as)}, by ${by}`;
  if (module === 'keylogger_indicators') return `Has keyboard access, found by ${by}`;
  return `Found by ${by}`;
}

// The facts on one finding's page, as [label, value] pairs. Missing evidence says "Couldn't tell", never "no".
function rowsOf(module, f, doc, held) {
  const d = isObj(f.data) ? f.data : {};
  const rows = [['Where', whereOf(d)]];
  if (module === REMOTE_TOOLS && d.check !== 'several_tools') {
    const r = Object.fromEntries(remoteFacts(d, { year: true }).rows.map((x) => [x.label, x.value]));
    rows.push(['Added', r.Added], ['Last let someone in', r['Last let someone in']],
      ['Can let someone in without a click', r['Can let someone in without a click']], ['Running now', r['Running now']]);
  } else {
    rows.push(['Added', day(first(d, ['added_on', 'installed_on', 'install_date', 'installed_at', 'created_at', 'first_seen'])) || COULDNT],
      ['Last used', day(first(d, ['last_used', 'last_seen', 'last_run', 'last_opened'])) || COULDNT],
      ['Running now', yesNo(first(d, ['running_now', 'running', 'is_running']))]);
  }
  rows.push(['Made by', makerOf(f)], ['How the check knows', howOf(module, f, doc)]);
  if (!held) {
    // The rest of what its evidence card shows, every path whole.
    const have = new Set(rows.map(([l]) => l));
    const skip = new Set(['Check', 'When', 'Seen', 'Command', 'Commands', 'Made by', 'Where', 'Name']);
    for (const r of EV.evidenceRows({ ...f, module }, { mode: 'standard', held: false, checkName: checkName(module, doc), commands: [], fullPaths: true })) {
      if (!r || have.has(r.label) || skip.has(r.label) || r.tech) continue;
      rows.push([String(r.label), String(r.copy || r.value)]);
      have.add(r.label);
    }
  }
  return rows.map(([l, v]) => [l, v == null || v === '' ? COULDNT : String(v)]);
}

function computerOf(doc) {
  for (const m of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    for (const f of (m && Array.isArray(m.findings) ? m.findings : [])) {
      const d = f && isObj(f.data) ? f.data : null;
      if (!d || d.check !== 'version_info') continue;
      const model = [str(d.model_name), str(d.model) ? `(${str(d.model)})` : ''].filter(Boolean).join(' ');
      const system = str(d.version) ? `macOS ${str(d.version)}${str(d.build) ? ` (${str(d.build)})` : ''}` : '';
      const out = [model, system].filter(Boolean).join(', ');
      if (out) return out;
    }
  }
  const p = doc && doc.platform;
  if (p === 'darwin') return 'A Mac (model and system version: couldn’t tell)';
  if (p === 'win32') return 'A Windows PC (model and system version: couldn’t tell)';
  return COULDNT;
}

function notCheckedOf(doc) {
  const parts = NC.notCheckedParts(doc);
  const out = [];
  const add = (list, why) => { for (const x of list || []) out.push({ check: checkName(x.name, doc), why }); };
  add(parts.couldntRun, 'Couldn’t run');
  add(parts.notReached, 'Not reached');
  add(parts.notStarted, 'Not started');
  add(parts.unfinished, 'Didn’t finish');
  return out;
}

export function buildRecord({ doc, scanAt, dualUse } = {}) {
  const answers = isObj(dualUse) ? dualUse : {};
  const split = splitHeld(doc, { mode: 'city' });
  const findings = [];
  const said = (f) => {
    const cat = f && isObj(f.data) ? f.data.stalkerware_category : null;
    return cat && SAID[cat] && SAID[cat][answers[cat]] ? SAID[cat][answers[cat]] : undefined;
  };
  for (const h of split.held) {
    const f = h.finding || {};
    const d = isObj(f.data) ? f.data : {};
    const what = (d.check === 'several_tools' && Array.isArray(d.tools) ? d.tools.filter((x) => typeof x === 'string').join(', ') : '')
      || heldEvidence(f, h.module).name || str(f.title) || COULDNT;
    const entry = { what, kind: kindOf(h.module, f, true), rows: rowsOf(h.module, f, doc, true) };
    const s = said(f);
    if (s) entry.said = s;
    findings.push(entry);
  }
  // Every warning and critical finding from the other checks (info left out: an inventory would bury the evidence).
  const list = NC.displayItems(split.doc, { mode: 'standard' });
  for (const item of [...list.critical, ...list.warning]) {
    const f = item.finding || {};
    const module = f.module || (item.seen_in || [])[0] || '';
    findings.push({ what: str(f.title) || COULDNT, kind: kindOf(module, { ...f, severity: item.severity || f.severity }, false), rows: rowsOf(module, f, doc, false) });
  }
  return { version: RECORD_VERSION, scanned_at: String(scanAt || ''), computer: computerOf(doc), findings, not_checked: notCheckedOf(doc) };
}

// ---- The fingerprint ----

function sorted(v) {
  if (Array.isArray(v)) return v.map(sorted);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => [k, sorted(v[k])]));
  return v;
}
export function canonicalJson(record) {
  const r = isObj(record) ? record : {};
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
  const fs = record && Array.isArray(record.findings) ? record.findings : [];
  return [{ kind: 'intro' }, ...fs.map((finding) => ({ kind: 'finding', finding })), { kind: 'end' }];
}

export function scanWhen(iso) {
  const t = new Date(String(iso || ''));
  return Number.isNaN(t.getTime()) ? COULDNT : t.toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' });
}

const looksLikePath = (s) => /^(~|\/|[A-Za-z]:\\)/.test(s);

function introHtml(record) {
  const n = record.findings.length;
  return `<h2 class="pr-title">How to use these pages</h2>
    <p class="pr-lead">Take a photo of each page with your phone. Make sure the top line is in the picture. If someone may look through your phone, keep the photos somewhere they can’t reach.</p>
    <p>${esc(`This record has ${n} ${n === 1 ? 'page' : 'pages'} of what the checkup found, then a page of what it couldn’t check. Use Next to go through them.`)}</p>
    <section class="pr-help"><h3>Who can help</h3><ul>${HELP.map((h) => `<li>${esc(h.text)}${h.url ? ` <code class="pr-mono">${esc(h.url)}</code>` : ''}</li>`).join('')}</ul>
      <p>${esc(OPEN_NOTE.text)}</p></section>`;
}

function findingHtml(f) {
  const rows = f.rows.map(([l, v]) => `<dt>${esc(l)}</dt><dd>${l === 'Where' && looksLikePath(v)
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
  const pages = recordPages(record);
  const i = Math.max(0, Math.min(pages.length - 1, Number(index) || 0));
  const p = pages[i];
  const head = `<header class="pr-head"><b>Checkup record</b><span>${esc(scanWhen(record.scanned_at))}</span><span>${esc(record.computer)}</span>`
    + `<span>${esc(`Page ${i + 1} of ${pages.length}`)}</span><span class="pr-fp">${esc(shortPrint(fp))}</span></header>`;
  const body = p.kind === 'intro' ? introHtml(record) : p.kind === 'end' ? endHtml(record, fp) : findingHtml(p.finding);
  const nav = `<nav class="pr-nav" aria-label="Record pages">${i > 0 ? '<button type="button" class="btn-s" data-act="record-back">◀ BACK</button>' : ''}`
    + `${i < pages.length - 1 ? '<button type="button" class="btn-p" data-act="record-next">NEXT ▶</button>' : ''}`
    + '<button type="button" class="btn-s" data-act="record-done">DONE</button></nav>';
  return `<section class="photo-record" aria-label="Checkup record"><article class="pr-page pr-${p.kind}" tabindex="-1">${head}<div class="pr-body">${body}</div></article>${nav}</section>`;
}

