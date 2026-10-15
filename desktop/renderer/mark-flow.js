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

  function undoListHtml(steps) {
    return `<ol class="fix-undo">${(steps || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`;
  }

  function markControlsHtml(finding) {
    const m = markableOf(finding);
    if (m) {
      return `
      <div class="mark-mine" data-mark-card data-mark-id="${esc(m.id)}">
        <button type="button" class="btn btn--secondary btn--small" data-mark-open>This is mine — stop flagging it</button>
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Confirm this is yours">
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(m.will_change)}</p>
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
      return `
      <div class="mark-mine" data-mark-card data-unmark-id="${esc(id)}">
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

  const CLICK_TARGETS = '[data-mark-open],[data-mark-confirm],[data-mark-cancel],[data-unmark]';

  // Delegated handlers on a container that survives re-renders. `api` is the
  // preload bridge: api.markMine(id), api.unmarkMine(id).
  function attach(root, api) {
    const state = new WeakMap(); // card -> 'confirming' | 'running'

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-mark-card]') : null;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-mark-panel]');
      if (panel) panel.hidden = true;
      state.delete(card);
    }

    async function send(card, call) {
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
        return send(card, () => api.unmarkMine(id));
      }
      if (state.get(card) !== 'confirming') return undefined;
      // Only the engine's id is sent; the main process looks up what it showed.
      const id = card.getAttribute('data-mark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.markMine(id));
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      if (card && state.get(card) === 'confirming') closePanel(card);
    });
  }

  return { ONLY_IF_YOURS, markableOf, markedIdOf, markControlsHtml, describeMarkResult, resultHtml, attach, esc };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MarkFlow;
}
