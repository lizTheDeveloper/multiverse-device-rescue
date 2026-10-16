'use strict';

/*
 * "This is mine — stop flagging it": the button, the in-page confirmation,
 * and the result. Also "Stop treating this as mine" on a marked item.
 *
 * Nothing is saved until the person presses "Yes, it's mine". Only the
 * engine's mark id is sent back, so what is saved is what the scan showed. A marked item is
 * never hidden: the engine keeps listing it as "marked as yours". Everything
 * that comes from the engine is HTML-escaped before it is shown.
 *
 * Loaded as a plain script in the renderer (global `MarkFlow`) and required
 * from Node by the tests.
 */
const MarkFlow = (function () {
  const MARK_ID = /^[0-9a-f]{12}$/;
  const ONLY_IF_YOURS = 'Only do this if you set this up yourself. If you’re not sure, leave it as it is.';

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function clean(s, max) {
    return typeof s === 'string' && s.length > 0 && s.length < (max || 1024) && !s.includes('\0');
  }

  // The engine's `markable` block, or null if missing or malformed.
  function markableOf(finding) {
    const m = finding && finding.markable;
    if (!m || typeof m !== 'object' || m.kind !== 'background_task') return null;
    if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
    if (!clean(m.label, 256) || m.label.startsWith('-')) return null;
    if (!clean(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
    if (!clean(m.plist) || !m.plist.startsWith('/')) return null;
    if (typeof m.will_change !== 'string' || m.will_change.trim() === '') return null;
    if (!Array.isArray(m.how_to_undo) || m.how_to_undo.length === 0) return null;
    if (!m.how_to_undo.every((s) => typeof s === 'string' && s.trim() !== '')) return null;
    return m;
  }

  // The mark id on a finding the person already marked, or null.
  function markedIdOf(finding) {
    const d = finding && finding.data;
    if (!d || d.marked_by_user !== true) return null;
    return typeof d.known_item_id === 'string' && MARK_ID.test(d.known_item_id) ? d.known_item_id : null;
  }

  // Every mark id the engine grouped with this one (same task, other checks), own id first.
  function groupOf(ownId, list) {
    const ids = Array.isArray(list) ? list.filter((x) => typeof x === 'string' && MARK_ID.test(x)) : [];
    return [ownId, ...ids].filter((x, i, a) => a.indexOf(x) === i);
  }

  function coversHtml(count) {
    if (count < 2) return '';
    return `<p class="fix-panel__line">That is ${count} warnings about this task on this checkup; one answer covers them all.</p>`;
  }

  function undoListHtml(steps) {
    return `<ol class="fix-undo">${(steps || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`;
  }

  function markControlsHtml(finding) {
    const m = markableOf(finding);
    if (m) {
      const group = groupOf(m.id, m.ids);
      return `
      <div class="mark-mine" data-mark-card data-mark-id="${esc(m.id)}" data-mark-group="${esc(group.join(' '))}">
        <button type="button" class="btn btn--secondary btn--small" data-mark-open>This is mine — stop flagging it</button>
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Confirm this is yours">
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(m.will_change)}</p>
          ${coversHtml(group.length)}
          <p class="fix-panel__line"><strong>To undo later:</strong></p>
          ${undoListHtml(m.how_to_undo)}
          <p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>
          <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
          <div class="fix-panel__actions">
            <button type="button" class="btn btn--primary btn--small" data-mark-confirm>Yes, it’s mine</button>
            <button type="button" class="btn btn--secondary btn--small" data-mark-cancel>Cancel</button>
          </div>
        </div>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
    }
    const id = markedIdOf(finding);
    if (id) {
      const group = groupOf(id, finding.marked_ids);
      return `
      <div class="mark-mine" data-mark-card data-unmark-id="${esc(id)}" data-unmark-group="${esc(group.join(' '))}">
        <button type="button" class="btn btn--secondary btn--small" data-unmark>Stop treating this as mine</button>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
    }
    return '';
  }

  // Words for the engine's answer. Never says "saved" unless the engine did.
  function describeMarkResult(result) {
    const r = result && typeof result === 'object' ? result : {};
    const undo = Array.isArray(r.how_to_undo) ? r.how_to_undo.filter((s) => typeof s === 'string') : [];
    if (r.status === 'marked' || r.status === 'already_marked') {
      return {
        tone: 'success', done: true,
        headline: 'Marked as yours.',
        detail: 'From your next checkup it will be listed as “marked as yours” instead of being flagged.',
        undo,
      };
    }
    if (r.status === 'removed') {
      return { tone: 'info', done: true, headline: 'No longer marked as yours.', detail: 'Its warning comes back on your next checkup.', undo: [] };
    }
    if (r.error === 'not_allowed' || r.status === 'refused') {
      return {
        tone: 'error', headline: 'We couldn’t mark this one.',
        detail: `${typeof r.message === 'string' ? r.message + ' ' : ''}Nothing was changed.`.trim(), undo: [],
      };
    }
    return {
      tone: 'error', headline: 'That didn’t go through.',
      detail: `${typeof r.message === 'string' ? r.message + ' ' : ''}Nothing was confirmed. Run the checkup again to see where things stand.`.trim(),
      undo: [],
    };
  }

  function resultHtml(result) {
    const d = describeMarkResult(result);
    return `
      <div class="fix-status--${d.tone} fix-status__box">
        <p class="fix-status__headline"><strong>${esc(d.headline)}</strong></p>
        ${d.detail ? `<p class="fix-status__detail">${esc(d.detail)}</p>` : ''}
        ${d.undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(d.undo)}` : ''}
      </div>`;
  }

  // Shown on the other cards about the same task once one card's answer covered them.
  function siblingHtml(kind) {
    const d = kind === 'marked'
      ? {
        tone: 'success', headline: 'Marked as yours.',
        detail: 'Marked together with the other warning about this task. From your next checkup it will be listed as “marked as yours” instead of being flagged.',
      }
      : {
        tone: 'info', headline: 'No longer marked as yours.',
        detail: 'Removed together with the other warning about this task. Its warning comes back on your next checkup.',
      };
    return `
      <div class="fix-status--${d.tone} fix-status__box">
        <p class="fix-status__headline"><strong>${esc(d.headline)}</strong></p>
        <p class="fix-status__detail">${esc(d.detail)}</p>
      </div>`;
  }

  function idsAttr(card, name) {
    return String(card.getAttribute(name) || '').split(/\s+/).filter((x) => MARK_ID.test(x));
  }

  const CLICK_TARGETS = '[data-mark-open],[data-mark-confirm],[data-mark-cancel],[data-unmark]';

  // Delegated handlers on a container that survives re-renders. `api` is the
  // preload bridge: api.markMine(id), api.unmarkMine(id).
  function attach(root, api, hooks) {
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    const state = new WeakMap(); // card -> 'confirming' | 'running'

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-mark-card]') : null;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-mark-panel]');
      if (panel) panel.hidden = true;
      state.delete(card);
    }

    // The same task is often reported by more than one check, so it has more
    // than one card. Once the engine has saved (or removed) the marks for all
    // of them, the other cards say so instead of offering the button again.
    function updateSiblings(card, kind, result) {
      if (typeof root.querySelectorAll !== 'function') return;
      const ownAttr = kind === 'marked' ? 'data-mark-id' : 'data-unmark-id';
      const groupAttr = kind === 'marked' ? 'data-mark-group' : 'data-unmark-group';
      const own = card.getAttribute(ownAttr);
      let ids = idsAttr(card, groupAttr).filter((x) => x !== own);
      // When the engine lists what it saved or removed, only those.
      if (result && Array.isArray(result.ids)) ids = ids.filter((x) => result.ids.includes(x));
      if (!ids.length) return;
      for (const other of Array.from(root.querySelectorAll(`[${ownAttr}]`))) {
        if (other === card || !ids.includes(other.getAttribute(ownAttr))) continue;
        if (state.get(other) === 'running') continue;
        closePanel(other);
        other.querySelectorAll('[data-mark-open],[data-unmark]').forEach((b) => { b.hidden = true; });
        const status = other.querySelector('[data-mark-status]');
        if (status) { status.hidden = false; status.innerHTML = siblingHtml(kind); }
        other.setAttribute('data-mark-handled-by-other', '');
      }
    }

    async function send(card, call, kind) {
      state.set(card, 'running');
      const panel = card.querySelector('[data-mark-panel]');
      const status = card.querySelector('[data-mark-status]');
      const buttons = card.querySelectorAll('[data-mark-open],[data-unmark]');
      if (panel) panel.hidden = true;
      buttons.forEach((b) => { b.hidden = true; });
      status.hidden = false;
      status.innerHTML = '<p class="fix-status__headline fix-status--running">Saving…</p>';
      let d;
      try {
        const result = await call();
        status.innerHTML = resultHtml(result);
        d = describeMarkResult(result);
        if (onResult) { try { onResult({ kind, result, described: d }); } catch (_) { /* never break a mark */ } }
        const r = result || {};
        if (kind === 'marked' && (r.status === 'marked' || r.status === 'already_marked')) updateSiblings(card, kind, r);
        if (kind === 'removed' && r.status === 'removed') updateSiblings(card, kind, r);
      } catch (_) {
        status.innerHTML = resultHtml(null);
        d = { done: false };
      }
      state.delete(card);
      if (!d.done) buttons.forEach((b) => { b.hidden = false; });
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest ? event.target.closest(CLICK_TARGETS) : null;
      const card = cardOf(target);
      if (!target || !card || state.get(card) === 'running') return undefined;
      if (target.hasAttribute('data-mark-open')) {
        const panel = card.querySelector('[data-mark-panel]');
        const status = card.querySelector('[data-mark-status]');
        if (status) { status.hidden = true; status.innerHTML = ''; }
        if (panel) panel.hidden = false;
        state.set(card, 'confirming');
        return undefined;
      }
      if (target.hasAttribute('data-mark-cancel')) {
        closePanel(card);
        return undefined;
      }
      if (target.hasAttribute('data-unmark')) {
        const id = card.getAttribute('data-unmark-id');
        if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
        return send(card, () => api.unmarkMine(id), 'removed');
      }
      if (state.get(card) !== 'confirming') return undefined;
      // Only the engine's id is sent; the main process looks up what it showed.
      const id = card.getAttribute('data-mark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.markMine(id), 'marked');
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      if (card && state.get(card) === 'confirming') closePanel(card);
    });
  }

  return { ONLY_IF_YOURS, groupOf, markableOf, markedIdOf, markControlsHtml, describeMarkResult, resultHtml, attach, esc };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MarkFlow;
}
