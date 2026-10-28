// "This is mine" on the deck: the state and the steps. The controller gives it
// the signals, the engine bridge and a way to redraw; nothing here touches the
// DOM. Every mark and unmark is the engine's, through main's mark policy (only
// the engine's mark id crosses IPC). Marks pay no points (ledger noteMarked).
//
// After a mark the item is out of the queue at once (withPending) and a quiet
// re-check of its checks follows, with no change of screen; once that's back,
// the scan itself says it's marked. If the engine refused, nothing moves.
import { quickMarkOf, withPending, nameOf } from './yours.js';

const MARK_ID = /^[0-9a-f]{12}$/;

export function createMarkDesk({ api, MarkFlow, signals, opts, docChanged, rebuild, render, log = () => {}, noteMarked = () => {},
  modulesFor = () => [] }) {
  const pending = new Map(); // signal id -> { markIds, back? }
  const desk = { picked: new Set(), ypicked: new Set(), confirm: null, saving: new Set(), toast: null, bump: false };
  let chain = Promise.resolve();

  const raw = () => (typeof signals === 'function' ? signals() || [] : []);
  const shown = () => withPending(raw(), pending);
  const find = (id) => shown().find((x) => x.id === id) || null;
  const qmOf = (sig) => (sig && sig.kind === 'real' && !sig.marked ? quickMarkOf(sig.finding, { MarkFlow, ...opts() }) : null);
  const markable = (id) => { const s = find(id); return s && qmOf(s) ? s : null; };
  const watchKind = (sig) => { const q = qmOf(sig); return !!q && q.kind !== 'background_task'; };
  const draw = () => { try { render(); } catch (_) { /* the controller shows its own fallback */ } };

  // Re-check the checks these marks covered, one at a time, in the background.
  function recheck(ids, modules) {
    chain = chain.then(async () => {
      let ok = true;
      for (const name of modules) {
        let r = null;
        try { r = await api.recheckModule(name); } catch (_) { r = null; }
        if (!r || !r.ok) { ok = false; continue; }
        if (!docChanged(r.doc)) return; // the app's gate took over (it showed the list)
        rebuild(r.doc);
      }
      // A check that couldn't re-run keeps the engine's word for this session.
      if (!ok) return;
      for (const id of ids) {
        const p = pending.get(id);
        pending.delete(id);
        const now = raw().find((x) => x.id === id);
        if (p && !p.back && now && !now.marked) {
          desk.toast = { tone: 'error', text: `${nameOf(now.finding || {})} is still being flagged after the re-check.` };
          log('NOT MARKED', now.title);
        }
      }
      draw();
    }).catch(() => {});
    return chain;
  }

  async function markNow(ids) {
    const sigs = ids.map(markable).filter(Boolean);
    if (!sigs.length) return;
    desk.confirm = null;
    sigs.forEach((s) => desk.saving.add(s.id));
    draw();
    const done = [];
    let refused = null;
    for (const s of sigs) {
      const q = qmOf(s);
      let r = null;
      try { r = await api.markMine(q.id); } catch (_) { r = null; }
      desk.saving.delete(s.id);
      if (r && (r.status === 'marked' || r.status === 'already_marked')) {
        const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x)) : [];
        pending.set(s.id, { markIds: saved.length ? saved : [q.id] });
        desk.picked.delete(s.id);
        done.push(s);
        log('MINE', nameOf(s.finding));
      } else {
        refused = { s, message: r && typeof r.message === 'string' ? r.message : 'That didn’t go through. Nothing was changed.' };
      }
    }
    if (done.length) {
      noteMarked();
      desk.bump = true;
      const left = shown().filter((x) => qmOf(x) && x.severity !== 'info').length;
      desk.toast = { text: done.length === 1 ? `Sorted into YOURS: ${nameOf(done[0].finding)}` : `${done.length} sorted into YOURS`,
        undo: done.map((s) => s.id), allDone: left === 0 };
      if (desk.toast.allDone) desk.toast.text += '. All sorted.';
    }
    if (refused) desk.toast = { tone: 'error', text: `${nameOf(refused.s.finding)}: ${refused.message}` };
    draw();
    desk.bump = false;
    if (done.length) recheck(done.map((s) => s.id), [...new Set(done.flatMap((s) => modulesFor(markIdsOf(s))))]);
  }

  function markIdsOf(s) {
    const p = pending.get(s.id);
    if (p && p.markIds) return p.markIds;
    const id = s.finding && s.finding.data && s.finding.data.known_item_id;
    return MARK_ID.test(String(id || '')) ? [id] : [];
  }

  async function unmine(ids) {
    const sigs = ids.map(find).filter((s) => s && s.marked);
    const back = [];
    for (const s of sigs) {
      const markIds = markIdsOf(s);
      if (!markIds.length) continue;
      let r = null;
      try { r = await api.unmarkMine(markIds[0]); } catch (_) { r = null; }
      if (r && r.status === 'removed') {
        pending.set(s.id, { back: true, markIds });
        desk.ypicked.delete(s.id);
        back.push({ s, markIds });
        log('NOT MINE', nameOf(s.finding));
      } else {
        desk.toast = { tone: 'error', text: `${nameOf(s.finding)}: ${r && r.message ? r.message : 'That didn’t go through. Nothing was changed.'}` };
      }
    }
    if (back.length) {
      desk.toast = { text: back.length === 1 ? `Back in your queue: ${nameOf(back[0].s.finding)}` : `${back.length} back in your queue` };
    }
    draw();
    if (back.length) recheck(back.map((b) => b.s.id), [...new Set(back.flatMap((b) => modulesFor(b.markIds)))]);
  }

  return Object.assign(desk, {
    overlay: (sigs) => withPending(sigs, pending),
    qmOf,
    isWatch: watchKind,
    // MINE ✓ on one signal: at once, or after the one inline question.
    async ask(id) {
      const s = markable(id);
      if (!s) return;
      if (qmOf(s).confirm) { desk.confirm = { target: id, watch: watchKind(s) }; draw(); return; }
      await markNow([id]);
    },
    async askPicked() {
      const ids = [...desk.picked].filter((id) => markable(id));
      if (!ids.length) return;
      const sigs = ids.map(find);
      if (sigs.some((s) => qmOf(s).confirm)) { desk.confirm = { target: '*', watch: sigs.some(watchKind), count: ids.length }; draw(); return; }
      await markNow(ids);
    },
    async yes(target) {
      if (!desk.confirm || desk.confirm.target !== target) return;
      await markNow(target === '*' ? [...desk.picked] : [target]);
    },
    no() { desk.confirm = null; draw(); },
    pick(id) {
      if (desk.picked.has(id)) desk.picked.delete(id);
      else if (markable(id)) desk.picked.add(id);
    },
    pickNone() { desk.picked.clear(); desk.confirm = null; },
    ypick(id) { if (desk.ypicked.has(id)) desk.ypicked.delete(id); else if ((find(id) || {}).marked) desk.ypicked.add(id); },
    async undo() {
      const ids = desk.toast && desk.toast.undo;
      if (!ids) return;
      desk.toast = null;
      await unmine(ids);
    },
    unmine,
    // A redraw for something else: the toast has had its moment.
    settle() { desk.toast = null; },
  });
}
