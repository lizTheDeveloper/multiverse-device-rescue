// The triage queue's state, keys, clicks and drawing, kept apart from
// controller.js, which only routes to it. Technical level only. Everything a
// verdict changes goes where the deck's own verdicts go: tags in the deck
// (ledger setTag, with what a MINE item is for), watch tags in memory, real
// marks through mark-desk.js, points through the ledger's keys, lines in the
// ops log. Nothing here is stored on its own; the live sweep's findings and
// the cursor are memory only.
//
// Moving, opening and selecting patch the list in place; only a verdict
// redraws the list's rows, and nothing here redraws the whole frame.
import { setTag, sessionTag, isWatchKey } from './ledger.js';
import { buildSignals } from './signals.js';
import { caseReport } from './case-file.js';
import { programContext } from './program-kinds.js';
import { OWN_CATEGORY_IDS } from './own-categories.js';
import { liveCity, rowsOf, heldRow, viewOf, keyAction, rangeIds, selectable, planTag, groupCategory,
  restoreTags, restoreWatchTags, defaultFilters, groupMineable, SKIP_WHY, SORTS, GROUPS, UNDO_KEEP, TYPE_IDS } from './triage.js';
import { renderTriage, bodyHtml, statsHtml, toastHtml, helpHtml } from './views/triage.js';

const TAG_WORD = { mine: 'MINE', threat: 'THREAT', closer: 'LOOK CLOSER', noted: 'NOTED' };
const PAGE = 15;
const LIVE_DELAY = 120; // ms: progress lines come in bursts; one redraw per burst

// `frame`: the city's frame (its clicks and keys arrive through the controller;
// selects and the search box are listened to here). See controller.js for the rest.
export function createTriageScreen({ frame, now, scanning, boss, signals, live = () => null, quiet, platform, tagsDeck, changed, ctx, desk, held, heldSpec,
  closedIds, deck, commitDeck, firstSort = () => {}, watchTags, setWatchTags, clearChanged, award, opened, cluesOf, log, evidence, recheck, render, back,
  timer = (f, ms) => setTimeout(f, ms) }) {
  const st = { cursorId: null, cursorAt: 0, anchor: null, selected: new Set(), expanded: new Set(), ask: null,
    toast: null, help: false, filters: defaultFilters(), sort: 'case', group: 'none', undo: [] };
  let view = { items: [], count: 0, total: 0, report: caseReport([]) };
  let liveTimer = null;

  // --- Rows -------------------------------------------------------------------
  // While sweeping, the controller's live findings (live.js: `rescue scan --live`).
  // Once a monitoring check holds something, nothing more arrives: the held row alone.
  function liveParts() {
    const l = scanning() ? live() : null;
    if (!l) return null;
    if (l.held) return { sigs: [], held: [{ module: 'held' }], ctx: null };
    if (!l.modules.length) return null;
    const { city, held: h } = liveCity(l.modules, platform(), quiet);
    return { sigs: buildSignals(city, tagsDeck(), changed()), held: h, ctx: programContext({ modules: l.modules }) };
  }
  function compute() {
    const live = liveParts();
    const sigs = live ? live.sigs : signals() || [];
    // Main marks only what its last finished scan offered: no real marks mid-sweep.
    const qmOf = live ? () => null : (x) => desk.qmOf(x);
    const rows = rowsOf(sigs, { ctx: live ? live.ctx : ctx(), qmOf, closedIds: closedIds() });
    const h = live ? live.held : held();
    const hr = h && h.length ? heldRow({ ...heldSpec(), count: h.length }) : null;
    const v = viewOf(rows, { filters: st.filters, sort: st.sort, group: st.group, held: hr });
    view = { ...v, total: rows.length, report: caseReport(rows), rows };
    // The cursor stays on its case; when that case left the list, the next one moves up under it.
    let at = view.items.findIndex((x) => x.id === st.cursorId);
    if (at < 0) at = Math.min(st.cursorAt, Math.max(0, view.items.length - 1));
    st.cursorAt = at;
    st.cursorId = view.items[at] ? view.items[at].id : null;
    // A selection only holds what's still shown and still selectable.
    const ids = new Set(view.items.filter(selectable).map((x) => x.id));
    for (const id of [...st.selected]) if (!ids.has(id)) st.selected.delete(id);
    return view;
  }
  const cur = () => view.items[st.cursorAt] || null;
  const rowsUnder = (g) => (g && g.head ? g.rows : g ? [g] : []);
  const echoes = (rows) => rows.flatMap((r) => [r, ...(r.also || [])]);

  // --- Drawing ------------------------------------------------------------------
  const canCheck = () => !scanning();
  function bulkAt() {
    if (!st.selected.size) return null;
    let last = null;
    for (const it of view.items) if (st.selected.has(it.id)) last = it.id;
    return last;
  }
  const body = () => bodyHtml({ items: view.items, cursor: st.cursorAt, selected: st.selected, expanded: st.expanded, ask: st.ask,
    evidence: (r) => evidence(r.sig), canCheck: canCheck(), bulkAt: bulkAt() });
  const stats = () => statsHtml({ report: view.report, scanning: scanning(), boss: boss(), shown: view.count, total: view.total });
  const q = (sel) => (frame && typeof frame.querySelector === 'function' ? frame.querySelector(sel) : null);

  function html() {
    compute();
    timer(mounted, 0);
    return renderTriage({ statsHtml: stats(), filters: st.filters, sort: st.sort, group: st.group, body: body(), toast: st.toast,
      help: st.help, back: scanning() ? 'SWEEP' : 'DECK' });
  }
  // After a full draw: focus the list (unless the search box has it) and show the cursor.
  function mounted() {
    const list = q('#tri-list');
    if (!list) return;
    const active = frame.getRootNode && frame.getRootNode().activeElement;
    if (!active || active === frame || !frame.contains(active) || active.tagName === 'BODY') list.focus({ preventScroll: true });
    // The queue fills the window; the page itself doesn't scroll under it.
    const sec = q('.triage');
    if (sec && typeof sec.scrollIntoView === 'function') sec.scrollIntoView({ block: 'start' });
    showCursor();
  }
  function showCursor() {
    const list = q('#tri-list');
    const el = q(`#tri-r-${st.cursorAt}`);
    if (list) list.setAttribute('aria-activedescendant', el ? el.id : '');
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' });
  }
  // The rows, the numbers and the toast, in place.
  function refresh() {
    compute();
    const b = q('#tri-body');
    if (!b) return false;
    b.innerHTML = body();
    const s = q('#tri-stats');
    if (s) s.innerHTML = stats();
    const t = q('#tri-toast');
    if (t) t.innerHTML = toastHtml(st.toast);
    showCursor();
    return true;
  }
  function moveTo(at) {
    if (!view.items.length) return;
    const next = Math.max(0, Math.min(view.items.length - 1, at));
    const old = q(`#tri-r-${st.cursorAt}`);
    if (old) old.classList.remove('cur');
    st.cursorAt = next;
    st.cursorId = view.items[next].id;
    const el = q(`#tri-r-${next}`);
    if (el) el.classList.add('cur');
    showCursor();
  }

  // --- Looking ------------------------------------------------------------------
  // Opening a row's evidence counts as looking, the same way the signal panel
  // does: each clue once per finding per sweep, by the ledger's own keys.
  function look(r) {
    if (!r || r.held || r.head || !r.sig || r.sig.kind !== 'real') return;
    const seen = opened(r.id);
    for (const c of cluesOf(r.sig)) {
      if (seen.includes(c.kind)) continue;
      seen.push(c.kind);
      award('clue', `${r.id}#${c.kind}`);
    }
    if (!seen.length) seen.push('evidence'); // nothing to pay for, but it was looked at
  }
  const looked = (r) => opened(r.id).length > 0;

  // --- Verdicts -------------------------------------------------------------------
  function recOf(id) {
    if (isWatchKey(id)) return { id, watch: true, rec: (watchTags() || {})[id] || null };
    return { id, watch: false, rec: (deck().tags || {})[id] || null };
  }
  // Game tags for `rows` (and their echoes), in one deck write. XP only for
  // rows that were looked at: the tag bonus after two clues, and `identify`
  // for saying what a lead marked MINE is. Never for which verdict it was.
  function applyTags(rows, tag, cat) {
    const all = echoes(rows);
    const prev = all.map((r) => recOf(r.id));
    // A first sort (not just LOOK CLOSER) counts toward the same totals as the deck's.
    for (const r of rows) if (r.sig.kind === 'real' && (!r.tag || r.tag === 'closer') && tag !== 'closer') firstSort(r.sig);
    let d = deck();
    let w = watchTags();
    const at = now();
    for (const r of all) {
      const c = tag === 'mine' && r.case.type === 'lead' && OWN_CATEGORY_IDS.has(cat) ? cat : null;
      if (isWatchKey(r.id)) w = sessionTag(w, r.id, tag, r.sig.fp, at);
      else d = setTag(d, r.id, tag, r.sig.fp, at, c);
      clearChanged(r.id);
    }
    commitDeck(d);
    setWatchTags(w);
    let xp = 0;
    for (const r of rows) {
      if (r.sig.kind !== 'real' || !looked(r)) continue;
      if (opened(r.id).length >= 2) xp += award('tagBonus', r.id);
      if (tag === 'mine' && r.case.type === 'lead' && OWN_CATEGORY_IDS.has(cat)) xp += award('identify', r.id);
    }
    log('TAG', rows.length === 1 ? `${TAG_WORD[tag]}: ${rows[0].title}` : `${TAG_WORD[tag]}: ${rows.length} from triage`);
    return { prev, xp };
  }

  // The engine's own mark for the rows that have one (after the sweep). The
  // desk asks its own question where yours.js says so; ours was already
  // answered, so its yes follows.
  async function markReal(rows) {
    const ids = rows.filter((r) => r.markable && !r.marked).map((r) => r.id);
    if (!ids.length) return [];
    desk.pickNone();
    if (ids.length === 1) {
      await desk.ask(ids[0]);
      if (desk.confirm && desk.confirm.target === ids[0]) await desk.yes(ids[0]);
    } else {
      ids.forEach((id) => desk.pick(id));
      await desk.askPicked();
      if (desk.confirm && desk.confirm.target === '*') await desk.yes('*');
    }
    const shown = desk.overlay(signals() || []);
    return ids.filter((id) => (shown.find((x) => x.id === id) || {}).marked);
  }

  function pushUndo(entry) {
    st.undo = [...st.undo, entry].slice(-UNDO_KEEP);
  }

  async function verdict(rows, tag, cat = null) {
    if (!rows.length) return;
    const { prev, xp } = applyTags(rows, tag, cat);
    const entry = { prev, marks: [], count: rows.length, tag };
    pushUndo(entry);
    st.ask = null;
    st.selected.clear();
    const word = tag === 'mine' && rows.every((r) => r.case.type !== 'lead') ? 'KEEP' : TAG_WORD[tag];
    st.toast = { text: `${rows.length === 1 ? rows[0].name : `${rows.length} cases`} → ${word}${xp ? ` · +${xp} XP` : ''}`, undo: true };
    refresh();
    if (tag === 'mine' && !scanning()) {
      entry.marks = await markReal(rows);
      if (entry.marks.length) st.toast = { ...st.toast, text: `${st.toast.text} · ${entry.marks.length} saved to YOURS` };
      refresh();
    }
  }

  async function undo() {
    const e = st.undo.pop();
    if (!e) { st.toast = { text: 'Nothing to undo.' }; refresh(); return; }
    commitDeck(restoreTags(deck(), e.prev));
    setWatchTags(restoreWatchTags(watchTags(), e.prev));
    log('UNDO', `${e.count === 1 ? '1 verdict' : `${e.count} verdicts`} taken back`);
    st.toast = { text: `Undone: ${e.count === 1 ? '1 verdict' : `${e.count} verdicts`}${e.marks.length ? ', and out of YOURS' : ''}.` };
    refresh();
    if (e.marks.length) { await desk.unmine(e.marks); refresh(); }
  }

  // One verdict from a key or a button. `targets`: the selection, a group, or the row.
  function decide(tag, targets, { bulk, cat = null, at }) {
    const plan = planTag(targets, tag, { bulk });
    const why = plan.skip.length ? SKIP_WHY[plan.skip[0].why] : '';
    if (!plan.go.length && !plan.ask.length) { st.toast = { text: why || 'Nothing to do here.' }; refresh(); return; }
    if (tag !== 'mine') { verdict(plan.go, tag); if (why) st.toast = { ...st.toast, text: `${st.toast.text} (${plan.skip.length} skipped: ${why})` }; refresh(); return; }
    if (bulk) {
      const leads = plan.go.filter((r) => r.case.type === 'lead');
      st.ask = { kind: 'bulk', rows: plan.go, at, count: plan.go.length, looked: plan.go.filter(looked).length, skipped: plan.skip.length,
        lead: leads.length > 0, cat: leads.length ? (OWN_CATEGORY_IDS.has(cat) ? cat : groupCategory(leads)) : null };
      refresh();
      return;
    }
    const r = plan.ask[0] || plan.go[0];
    const lead = r.case.type === 'lead';
    // A lead says what it is first; a critical, or anything the desk asks about, then its own yes.
    if (lead && !OWN_CATEGORY_IDS.has(cat)) { st.ask = { kind: 'identify', rows: [r], at: r.id, cat: r.suggest || null, lead: true }; refresh(); return; }
    if (r.critical) { st.ask = { kind: 'critical', rows: [r], at: r.id, cat, lead }; refresh(); return; }
    if (r.markable && r.confirm) { st.ask = { kind: 'confirm', rows: [r], at: r.id, cat, lead, watch: desk.isWatch(r.sig) }; refresh(); return; }
    verdict([r], 'mine', cat);
  }

  // The question's yes: on to the next question for that row, or the verdict.
  function yes(catPicked = null) {
    const a = st.ask;
    if (!a) return;
    const cat = OWN_CATEGORY_IDS.has(catPicked) ? catPicked : a.cat;
    if (a.kind === 'bulk') { verdict(a.rows, 'mine', cat); return; }
    const r = a.rows[0];
    if (a.kind === 'identify') {
      if (!OWN_CATEGORY_IDS.has(cat)) return; // pick one first
      if (r.critical) { st.ask = { ...a, kind: 'critical', cat }; refresh(); return; }
      if (r.markable && r.confirm) { st.ask = { ...a, kind: 'confirm', cat, watch: desk.isWatch(r.sig) }; refresh(); return; }
      verdict([r], 'mine', cat);
      return;
    }
    if (a.kind === 'critical' && r.markable && r.confirm) { st.ask = { ...a, kind: 'confirm', watch: desk.isWatch(r.sig) }; refresh(); return; }
    verdict([r], 'mine', a.cat);
  }

  // What a verdict key acts on: the selection when there is one, else the row
  // (or the group) under the cursor.
  function targetsNow() {
    if (st.selected.size) {
      const rows = view.items.filter((x) => st.selected.has(x.id));
      return { rows, bulk: rows.length > 1, at: bulkAt() };
    }
    const c = cur();
    if (!c) return { rows: [], bulk: false, at: null };
    return { rows: rowsUnder(c), bulk: !!c.head, at: c.id, head: c.head ? c : null };
  }

  async function checkAgain(r) {
    if (!r || r.held || r.head || !r.sig || r.sig.kind !== 'real' || !r.sig.module || scanning()) return;
    st.toast = { text: `Checking ${r.name} again…` };
    refresh();
    const out = await recheck(r.sig);
    if (!out) return; // the app took over
    st.toast = { text: !out.ran ? 'That check couldn’t run just now, so nothing changed.'
      : out.still ? `Checked again: still there. ${r.name}` : `Checked again: gone. ${r.name}${out.paid ? ` · +${out.paid} XP` : ''}` };
    refresh();
  }

  function toggleSelect(id) {
    if (st.selected.has(id)) st.selected.delete(id);
    else st.selected.add(id);
    st.anchor = id;
  }

  // --- Keys -----------------------------------------------------------------------
  function key(e) {
    const t = e.target;
    const tag = t && t.tagName;
    if (tag === 'SELECT' && e.key !== 'Escape') return false;
    // Enter and Space on a button are that button's.
    if (tag === 'BUTTON' && (e.key === 'Enter' || e.key === ' ')) return false;
    const inInput = tag === 'INPUT' && t.type !== 'checkbox';
    const a = keyAction({ key: e.key, shiftKey: e.shiftKey, ctrlKey: e.ctrlKey, metaKey: e.metaKey, altKey: e.altKey, inInput });
    if (!a) return false;
    if (typeof e.preventDefault === 'function') e.preventDefault();
    act(a);
    return true;
  }

  function act(a) {
    const c = cur();
    if (a === 'filter-done') { const l = q('#tri-list'); if (l) l.focus(); return; }
    if (a === 'escape') {
      if (st.help) { st.help = false; const h = q('#tri-helpbox'); if (h) h.innerHTML = ''; return; }
      if (st.ask) { st.ask = null; refresh(); return; }
      if (st.selected.size) { st.selected.clear(); refresh(); return; }
      return;
    }
    if (a === 'help') { st.help = !st.help; const h = q('#tri-helpbox'); if (h) h.innerHTML = st.help ? helpHtml() : ''; return; }
    if (a === 'filter') { const i = q('#tri-q'); if (i) { i.focus(); i.select(); } return; }
    // Moving on leaves a question unanswered: nothing moved, and nothing waits behind the cursor.
    const MOVES = { down: 1, up: -1, 'page-down': PAGE, 'page-up': -PAGE };
    if (a in MOVES || a === 'top' || a === 'bottom') {
      if (st.ask) { st.ask = null; refresh(); }
      moveTo(a === 'top' ? 0 : a === 'bottom' ? view.items.length - 1 : st.cursorAt + MOVES[a]);
      return;
    }
    if (a === 'down-select' || a === 'up-select') {
      if (selectable(c) && !st.selected.has(c.id)) toggleSelect(c.id);
      moveTo(st.cursorAt + (a === 'down-select' ? 1 : -1));
      const n = cur();
      if (selectable(n)) { st.selected.add(n.id); st.anchor = n.id; }
      refresh();
      return;
    }
    if (a === 'select') { if (selectable(c)) { toggleSelect(c.id); refresh(); } return; }
    if (a === 'select-range') {
      if (!selectable(c)) return;
      for (const id of rangeIds(view.items, st.anchor, c.id)) st.selected.add(id);
      st.anchor = c.id;
      refresh();
      return;
    }
    if (a === 'undo') { undo(); return; }
    if (a === 'group' || a === 'sort') {
      if (a === 'group') st.group = GROUPS[(GROUPS.indexOf(st.group) + 1) % GROUPS.length];
      else st.sort = SORTS[(SORTS.indexOf(st.sort) + 1) % SORTS.length];
      render();
      return;
    }
    if (a === 'yes') { yes(); return; }
    if (a.startsWith('cat:')) {
      const cat = a.slice(4);
      if (st.ask) {
        if (st.ask.kind === 'identify' || st.ask.kind === 'bulk') { st.ask = { ...st.ask, cat }; yes(cat); return; }
        st.toast = { text: 'This one asks first: y to confirm, Esc (or j/k) to leave it.' };
        refresh();
        return;
      }
      const tg = targetsNow();
      if (tg.head && !groupMineable(tg.head)) { st.toast = { text: 'Only a verified maker’s group can be marked at once. x selects rows to sort.' }; refresh(); return; }
      decide('mine', tg.rows, { bulk: tg.bulk, cat, at: tg.at });
      return;
    }
    if (a === 'expand') {
      if (st.ask) { if (st.ask.kind === 'identify' || st.ask.kind === 'bulk') yes(); return; }
      if (!c) return;
      if (c.held) { const b = q(`#tri-r-${st.cursorAt} .tri-name button`); if (b) b.click(); return; }
      if (c.head) { for (const r of c.rows) st.selected.add(r.id); refresh(); return; }
      if (st.expanded.has(c.id)) st.expanded.delete(c.id); else { st.expanded.add(c.id); look(c); }
      refresh();
      return;
    }
    if (a === 'check') { checkAgain(c); return; }
    if (a === 'mine' || a === 'threat' || a === 'closer' || a === 'noted') {
      if (st.ask && a === 'mine' && st.ask.kind === 'identify') { yes(); return; }
      if (st.ask) return; // a question is open: y, a number, or Esc
      const tg = targetsNow();
      // On a group's head: MINE only for a verified maker; anything else selects the group first.
      if (tg.head && a === 'mine' && !groupMineable(tg.head)) { st.toast = { text: 'Only a verified maker’s group can be marked at once. x selects rows to sort.' }; refresh(); return; }
      decide(a, tg.rows, { bulk: tg.bulk, at: tg.at });
    }
  }

  // --- Clicks ---------------------------------------------------------------------
  const itemAt = (i) => view.items[Number(i)] || null;
  function click(actName, el) {
    const parts = actName.split(':');
    const head = parts[0];
    const it = itemAt(parts[parts.length - 1]);
    const point = () => { const i = Number(parts[parts.length - 1]); if (Number.isInteger(i)) moveTo(i); };
    if (head === 'tri-back') { back(); return; }
    if (head === 'tri-help') { act('help'); return; }
    if (head === 'tri-undo') { undo(); return; }
    if (head === 'tri-yes') { yes(); return; }
    if (head === 'tri-no') { st.ask = null; refresh(); return; }
    if (head === 'tri-askcat') { if (st.ask) { st.ask = { ...st.ask, cat: parts[1] }; refresh(); } return; }
    if (head === 'tri-type') {
      const t = parts[1];
      if (TYPE_IDS.includes(t)) { if (st.filters.types.has(t)) st.filters.types.delete(t); else st.filters.types.add(t); }
      render();
      return;
    }
    if (head === 'tri-openonly') { st.filters.open = !st.filters.open; render(); return; }
    if (head === 'tri-bulk') {
      if (parts[1] === 'none') { st.selected.clear(); refresh(); return; }
      const tg = targetsNow();
      decide(parts[1], tg.rows, { bulk: true, at: tg.at });
      return;
    }
    if (!it) return;
    point();
    if (head === 'tri-open') { act('expand'); return; }
    if (head === 'tri-pick') { if (selectable(it)) { toggleSelect(it.id); refresh(); } return; }
    if (head === 'tri-check') { checkAgain(it); return; }
    if (head === 'tri-gsel') { for (const r of it.rows || []) st.selected.add(r.id); refresh(); return; }
    if (head === 'tri-gmine') { if (!groupMineable(it)) return; decide('mine', it.rows || [], { bulk: true, at: it.id }); return; }
    if (head === 'tri-cat') { decide('mine', [it], { bulk: false, cat: parts[1], at: it.id }); return; }
    if (head === 'tri-tag') { decide(parts[1], [it], { bulk: false, at: it.id }); }
  }

  // The selects and the search box, here: the controller only routes clicks.
  if (frame && typeof frame.addEventListener === 'function') {
    const onField = (e) => {
      const t = e.target;
      const a = t && typeof t.getAttribute === 'function' ? t.getAttribute('data-act') : null;
      if (!a || !a.startsWith('tri-') || !q('#tri-body')) return;
      const v = String(t.value || '');
      if (a === 'tri-q') { st.filters.text = v.slice(0, 200); refresh(); return; }
      if (e.type !== 'change') return;
      if (a === 'tri-maker') st.filters.maker = v || null;
      else if (a === 'tri-kind') st.filters.kind = v || null;
      else if (a === 'tri-district') st.filters.district = v || null;
      else if (a === 'tri-priority') st.filters.priority = v || null;
      else if (a === 'tri-group' && GROUPS.includes(v)) st.group = v;
      else if (a === 'tri-sort' && SORTS.includes(v)) st.sort = v;
      else return;
      refresh();
    };
    frame.addEventListener('input', onField);
    frame.addEventListener('change', onField);
  }

  return {
    html,
    key,
    click,
    act,
    refresh,
    // A redraw of the rows for the live sweep, at most once per burst.
    live() {
      if (liveTimer) return;
      liveTimer = timer(() => { liveTimer = null; refresh(); }, LIVE_DELAY);
    },
    // A new sweep: the verdicts are in the deck; the rest starts again.
    reset() { st.ask = null; st.selected.clear(); st.expanded.clear(); st.undo = []; st.toast = null; },
    // The count for TRIAGE ▶: open cases (held included).
    openCount() { compute(); return view.report.open + (view.items[0] && view.items[0].held ? 1 : 0); },
    state: st,
    view: () => view,
  };
}

