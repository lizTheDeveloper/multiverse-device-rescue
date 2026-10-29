// The triage queue's drawing: the top bar, the filters, and one dense row
// per case with its own verdict buttons at the row's right edge, in the same
// column on every row, so a mouse never crosses the screen. Pure; every
// string from the engine is escaped. The keys are shown once, small, at the
// foot, and in full behind "?".
import { esc } from '../escape.js';
import { PROGRAM_KINDS, KIND_ORDER } from '../program-kinds.js';
import { CASE_TYPES, CASE_STATUSES } from '../case-file.js';
import { OWN_CATEGORIES } from '../own-categories.js';
import { DISTRICTS, OUTSKIRTS } from '../findings-to-city.js';
import { TYPE_IDS, SORTS, GROUPS, districtLabel, groupMineable } from '../triage.js';

const CAT = Object.fromEntries(OWN_CATEGORIES.map((c, i) => [c.id, { ...c, n: i + 1 }]));
const SORT_LABEL = { case: 'CASE', name: 'NAME', maker: 'MAKER', district: 'DISTRICT', kind: 'KIND' };
const GROUP_LABEL = { none: 'NONE', maker: 'MAKER', kind: 'KIND', district: 'DISTRICT' };
const PRI = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

// Priority first, in the case file's words: a lead's is the risk if it isn't
// theirs, never the engine's severity. Then its type and where it stands.
function caseCell(c, status, held = false) {
  // Held: SAFETY FIRST and nothing else; "yours" never applies to it.
  if (held) return `<b class="tri-pri">${esc(status)}</b>`;
  const pri = c.type === 'lead' ? `${PRI[c.priority]} RISK IF NOT YOURS` : `${PRI[c.priority]}`;
  return `<b class="tri-pri">${esc(pri)}</b><small>${esc(CASE_TYPES[c.type].label)} · ${esc(status)}</small>`;
}

export const KEYS_LINE = 'j/k move · Enter evidence · m mine · 1–9 what it is · t threat · l closer · c check again · x select · u undo · / filter · ? keys';
export const KEYS_HELP = [
  ['j / k, ↓ / ↑', 'Move. Shift extends the selection.'],
  ['Enter', 'Show the evidence under the row. Looking is what earns XP.'],
  ['m', 'Mine (KEEP for a setting). A lead asks what it is: the suggestion is picked, Enter takes it.'],
  ['1–9', 'Mine, as that kind of thing.'],
  ['t / l', 'Threat / look closer.'],
  ['n', 'Noted (a check that couldn’t run).'],
  ['c', 'Check again: re-runs that one check, read-only.'],
  ['x / X', 'Select / select from the last one to here.'],
  ['u', 'Undo the last verdict.'],
  ['/', 'Search. Enter or Esc goes back to the list.'],
  ['g / o', 'Group by maker, kind or district / change the sort.'],
  ['y', 'Yes, to the question on screen.'],
  ['Esc', 'Close the question, the selection or this help.'],
];

const DISTRICT_OPTS = [...DISTRICTS, OUTSKIRTS];

function makerCell(r) {
  if (!r.maker) return '<span class="tri-mk none">—</span>';
  return r.verified ? `<span class="tri-mk ok" title="Verified signature">✓ ${esc(r.maker.name)}</span>`
    : `<span class="tri-mk unv" title="Couldn’t verify">? ${esc(r.maker.name)}</span>`;
}

function kindCell(r) {
  return r.kinds.map((k) => `<span class="tri-kind" title="${esc(PROGRAM_KINDS[k].label)}">${esc(PROGRAM_KINDS[k].icon)}</span>`).join('');
}

const btn = (act, label, aria, cls = 'btn-t') => `<button type="button" class="${cls}" data-act="${act}" aria-label="${esc(aria)}">${label}</button>`;

// The row's own verdicts: MINE (as the suggestion), the nine kinds, THREAT,
// CLOSER, CHECK AGAIN. Always the same slots, so they line up down the list.
function actionsCell(r, i, { canCheck }) {
  if (r.held) return '<span class="tri-acts held-note">Not sorted here</span>';
  const name = r.name;
  if (r.couldnt) {
    return `<span class="tri-acts">${btn(`tri-tag:noted:${i}`, 'NOTED', `Noted: ${name}`, 'btn-t tri-v')}</span>`;
  }
  if (r.marked) return `<span class="tri-acts"><span class="badge yours">IN YOURS</span>${canCheck ? btn(`tri-check:${i}`, '⟳', `Check again: ${name}`, 'btn-t tri-v tri-chk') : ''}</span>`;
  const lead = r.case.type === 'lead';
  const sug = lead && r.suggest ? CAT[r.suggest] : null;
  const mine = lead ? `MINE${sug ? ` <small>${esc(sug.icon)}</small>` : ''}` : 'KEEP';
  const chips = lead ? `<span class="tri-cats" role="group" aria-label="${esc(`Mine, as: ${name}`)}">${OWN_CATEGORIES.map((c) => `<button type="button" class="tri-cat${r.suggest === c.id ? ' sug' : ''}" data-act="tri-cat:${c.id}:${i}" title="${esc(`${CAT[c.id].n} ${c.label}`)}" aria-label="${esc(`Mine, ${c.label}: ${name}`)}">${esc(c.icon)}</button>`).join('')}</span>`
    : '<span class="tri-cats"></span>';
  return `<span class="tri-acts">
    ${btn(`tri-tag:mine:${i}`, mine, `${lead ? 'Mine' : 'Keep'}: ${name}`, `btn-t tri-v tri-mine${r.tag === 'mine' ? ' on' : ''}`)}${chips}
    ${btn(`tri-tag:threat:${i}`, 'THREAT', `Threat: ${name}`, `btn-t tri-v tri-threat${r.tag === 'threat' ? ' on' : ''}`)}
    ${btn(`tri-tag:closer:${i}`, 'CLOSER', `Look closer: ${name}`, `btn-t tri-v tri-closer${r.tag === 'closer' ? ' on' : ''}`)}
    ${canCheck ? btn(`tri-check:${i}`, '⟳', `Check again: ${name}`, 'btn-t tri-v tri-chk') : ''}</span>`;
}

// One case. `i` is its place in the list as drawn.
export function rowHtml(r, i, { cur = false, sel = false, open = false, canCheck = false } = {}) {
  const c = r.case;
  const status = CASE_STATUSES[c.status].label;
  const cls = `tri-row pr-${esc(c.priority)} st-${esc(c.status)}${r.held ? ' held' : ''}${cur ? ' cur' : ''}${sel ? ' sel' : ''}${open ? ' open' : ''}`;
  const pick = r.held ? '<span class="tri-pick"></span>'
    : `<span class="tri-pick"><input type="checkbox" data-act="tri-pick:${i}"${sel ? ' checked' : ''} aria-label="${esc(`Select: ${r.name}`)}"></span>`;
  const name = r.held
    ? `<span class="tri-name"><b>${esc(r.name)}</b> ${r.go ? `<button type="button" class="btn-s" data-go="${esc(r.go)}">READ THIS FIRST ▶</button>`
      : `<button type="button" class="btn-s" data-act="${esc(r.act || 'list')}">READ THIS FIRST ▶</button>`}</span>`
    : `<span class="tri-name"><button type="button" class="tri-open" data-act="tri-open:${i}" aria-expanded="${open ? 'true' : 'false'}">${esc(r.name)}</button>${r.also.length ? ` <small class="tri-also">×${r.also.length + 1}</small>` : ''}${r.changed ? ' <span class="badge warn">CHANGED</span>' : ''}${r.pending ? ' <small class="tri-pend">saving…</small>' : ''}${r.tag === 'mine' && r.markable && !r.marked ? ' <small class="tri-pend">tag only</small>' : ''}</span>`;
  return `<div class="${cls}" role="row" data-tid="${i}" id="tri-r-${i}" aria-selected="${sel ? 'true' : 'false'}">
    ${pick}
    <span class="tri-case" role="gridcell">${caseCell(c, status, r.held)}</span>
    <span class="tri-where" role="gridcell">${r.held ? '' : esc(districtLabel(r.district))} ${kindCell(r)}</span>
    ${name}
    <span class="tri-maker" role="gridcell">${r.held ? '' : makerCell(r)}</span>
    <span class="tri-path" role="gridcell">${r.path ? `<code>${esc(r.path)}</code>` : ''}</span>
    <span class="tri-evid" role="gridcell">${esc(r.evidence)}</span>
    ${actionsCell(r, i, { canCheck })}
  </div>`;
}

// A group's head, with its own bulk verdict. A maker group says whether the
// maker was verified, and only a verified one offers MINE for all of it.
export function headHtml(g, i, { cur = false } = {}) {
  const n = g.rows.length;
  const mine = groupMineable(g);
  return `<div class="tri-head${cur ? ' cur' : ''}" role="row" data-tid="${i}" id="tri-r-${i}">
    <span class="tri-head-label"><b>${esc(g.label)}</b> <small>${esc(n)} ${n === 1 ? 'ITEM' : 'ITEMS'}</small></span>
    <span class="tri-acts">${btn(`tri-gsel:${i}`, `SELECT ${esc(n)}`, `Select all ${n}: ${g.label}`, 'btn-t tri-v')}
      ${mine ? btn(`tri-gmine:${i}`, `MINE ✓ ${esc(n)}…`, `Mine, all ${n}: ${g.label}`, 'btn-s lime tri-v') : ''}</span></div>`;
}

// The question under a row (or a group, or the selection). `ask`:
// {kind: 'identify'|'critical'|'confirm'|'bulk', cat, count, looked, critical, skipped, watch}.
export function askHtml(ask) {
  const lead = ask.lead !== false;
  const cats = lead ? `<span class="tri-cats big" role="group" aria-label="What is it?">${OWN_CATEGORIES.map((c) => `<button type="button" class="tri-cat${ask.cat === c.id ? ' sug' : ''}" data-act="tri-askcat:${c.id}" aria-pressed="${ask.cat === c.id ? 'true' : 'false'}"><kbd>${CAT[c.id].n}</kbd> ${esc(c.icon)} ${esc(c.label)}</button>`).join('')}</span>` : '';
  let q;
  if (ask.kind === 'bulk') {
    const xp = ask.looked === ask.count ? 'XP for all of them: you looked at each.'
      : ask.looked ? `XP only for the ${ask.looked} you opened; the rest land in YOURS without it.`
        : 'No XP: none of these were opened. They still land in YOURS.';
    const left = ask.skipped ? ` ${ask.skipped} left out (criticals and anything held need their own look).` : '';
    q = `<b>Mark ${esc(ask.count)} as yours${lead && ask.cat ? `, as ${esc(CAT[ask.cat].label)}` : ''}?</b> Only if you set these up yourself. ${esc(xp)}${esc(left)}`;
  } else if (ask.kind === 'critical') {
    q = `<b>This one is critical.</b> Mark it as yours only if you set it up yourself and know what it does. Press y to confirm.`;
  } else if (ask.kind === 'confirm') {
    q = `<b>Mark this as yours?</b> Only if you set it up yourself.${ask.watch ? ' Something like this can be used to watch or get into a computer.' : ''}`;
  } else {
    q = `<b>What is it?</b> ${ask.cat ? `Enter: ${esc(CAT[ask.cat].label)}.` : 'Pick one.'}`;
  }
  const yes = ask.kind === 'identify' ? 'MINE ✓' : 'YES, MINE';
  return `<div class="tri-ask" role="group" aria-label="A question before it moves">
    <p>${q}</p>${cats}
    <span class="row">${btn('tri-yes', `${yes} <kbd>${ask.kind === 'identify' ? 'Enter' : 'y'}</kbd>`, yes, 'btn-p')}${btn('tri-no', 'CANCEL <kbd>Esc</kbd>', 'Cancel')}</span></div>`;
}

// The selection's own bar, drawn right under the selected rows.
export function bulkHtml(count) {
  return `<div class="tri-bulk" role="group" aria-label="Selected"><b>${esc(count)} SELECTED</b>
    ${btn('tri-bulk:mine', 'MINE ✓ <kbd>m</kbd>', `Mine, all ${count}`, 'btn-s lime')}
    ${btn('tri-bulk:threat', 'THREAT <kbd>t</kbd>', `Threat, all ${count}`)}
    ${btn('tri-bulk:closer', 'CLOSER <kbd>l</kbd>', `Look closer, all ${count}`)}
    ${btn('tri-bulk:none', 'CLEAR <kbd>Esc</kbd>', 'Clear the selection')}</div>`;
}

export function toastHtml(t) {
  if (!t) return '';
  return `<div class="tri-toast${t.tone === 'error' ? ' error' : ''}" role="status">${esc(t.text)}${t.undo ? ` ${btn('tri-undo', 'UNDO <kbd>u</kbd>', 'Undo')}` : ''}</div>`;
}

// The list's rows: each item, then (where they belong) its evidence, its
// question, the selection's bar.
export function bodyHtml({ items, cursor, selected, expanded, ask, evidence, canCheck, bulkAt }) {
  const out = [];
  items.forEach((it, i) => {
    const cur = i === cursor;
    if (it.head) out.push(headHtml(it, i, { cur }));
    else out.push(rowHtml(it, i, { cur, sel: selected.has(it.id), open: expanded.has(it.id), canCheck: canCheck && !it.held }));
    if (!it.head && expanded.has(it.id)) out.push(`<div class="tri-ev" role="row">${evidence(it)}</div>`);
    if (ask && ask.at === it.id) out.push(askHtml(ask));
    if (bulkAt === it.id && !(ask && ask.kind === 'bulk')) out.push(bulkHtml(selected.size));
  });
  if (!items.length) out.push('<p class="intel tri-empty">Nothing here with these filters.</p>');
  return out.join('');
}

function chip(act, label, on, aria = label) {
  return `<button type="button" class="tri-chip${on ? ' on' : ''}" data-act="${act}" aria-pressed="${on ? 'true' : 'false'}" aria-label="${esc(aria)}">${label}</button>`;
}
function select(act, label, value, opts) {
  return `<label class="tri-sel"><span>${esc(label)}</span><select data-act="${act}">${opts.map(([v, t]) => `<option value="${esc(v)}"${v === value ? ' selected' : ''}>${esc(t)}</option>`).join('')}</select></label>`;
}

export function filtersHtml(f, { sort, group }) {
  const types = TYPE_IDS.map((t) => chip(`tri-type:${t}`, esc(CASE_TYPES[t].label), f.types.has(t), `Show ${CASE_TYPES[t].label}`)).join('');
  return `<div class="tri-filters" role="toolbar" aria-label="Filters">
    <span class="tri-chips">${types}${chip('tri-openonly', 'OPEN ONLY', f.open)}</span>
    ${select('tri-maker', 'MAKER', f.maker || '', [['', 'any'], ['verified', 'verified'], ['unverified', 'not verified']])}
    ${select('tri-kind', 'KIND', f.kind || '', [['', 'any'], ...KIND_ORDER.map((k) => [k, PROGRAM_KINDS[k].label])])}
    ${select('tri-district', 'DISTRICT', f.district || '', [['', 'any'], ...DISTRICT_OPTS.map((d) => [d.id, districtLabel(d.id)])])}
    ${select('tri-priority', 'PRIORITY', f.priority || '', [['', 'any'], ['high', 'high'], ['medium', 'medium'], ['low', 'low']])}
    <label class="tri-search"><span class="sr-only">Search</span><input type="search" id="tri-q" data-act="tri-q" value="${esc(f.text)}" placeholder="/ search name, path, maker" autocomplete="off" spellcheck="false"></label>
    ${select('tri-group', 'GROUP', group, GROUPS.map((g) => [g, GROUP_LABEL[g]]))}
    ${select('tri-sort', 'SORT', sort, SORTS.map((s) => [s, SORT_LABEL[s]]))}
  </div>`;
}

export function statsHtml({ report, scanning, boss, shown, total }) {
  const live = scanning ? `<span class="stat cyan"><b>${esc(boss.index)}/${esc(boss.total || '?')}</b> <small>CHECKS · LIVE</small></span>` : '<span class="stat grey"><small>SWEEP DONE</small></span>';
  return `${live}
    <span class="stat amb"><b>${esc(report.unidentified)}</b> <small>UNIDENTIFIED</small></span>
    <span class="stat mag"><b>${esc(report.doorsOpen)}</b> <small>OPEN DOORS</small></span>
    ${report.threats ? `<span class="stat mag"><b>${esc(report.threats)}</b> <small>THREATS</small></span>` : ''}
    <span class="stat lime"><b>${esc(report.closed)}</b> <small>SORTED</small></span>
    <span class="stat grey"><small>SHOWING</small> <b>${esc(shown)}</b>/${esc(total)}</span>`;
}

export function helpHtml() {
  return `<div class="panel tri-help" role="dialog" aria-label="Keys"><div class="row"><span class="label">KEYS</span>${btn('tri-help', 'CLOSE <kbd>Esc</kbd>', 'Close')}</div>
    <dl>${KEYS_HELP.map(([k, v]) => `<dt><kbd>${esc(k)}</kbd></dt><dd>${esc(v)}</dd>`).join('')}</dl>
    <p class="intel faint">Nothing here changes the computer except MINE on a background task, which saves it as yours (Undo takes it back). Anything held, and anything critical, asks first.</p></div>`;
}

export function renderTriage({ statsHtml: stats, filters, sort, group, body, toast, help, back }) {
  return `
  <section class="triage" aria-labelledby="tri-title">
    <header class="hud deck-top tri-top"><h1 class="hud-title" id="tri-title" tabindex="-1">TRIAGE</h1>
      <span id="tri-stats" class="tri-stats">${stats}</span>
      <span class="switch">${btn('tri-help', '? KEYS', 'Keys')}${btn('tri-back', esc(back), back)}</span></header>
    ${filtersHtml(filters, { sort, group })}
    <div class="tri-colhead" aria-hidden="true"><span></span><span>CASE</span><span>WHERE</span><span>NAME</span><span>MAKER</span><span>PATH</span><span>EVIDENCE</span><span>VERDICT</span></div>
    <div class="tri-list" id="tri-list" tabindex="0" role="grid" aria-label="Cases" aria-activedescendant="">
      <div id="tri-body">${body}</div>
    </div>
    <div id="tri-toast">${toastHtml(toast)}</div>
    <p class="tri-keys faint">${esc(KEYS_LINE)}</p>
    <div id="tri-helpbox">${help ? helpHtml() : ''}</div>
  </section>`;
}
