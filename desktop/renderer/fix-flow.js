'use strict';

/*
 * "Fix it for me": the button, the in-page confirmation, and the result.
 *
 * Nothing here changes anything by itself. The button only opens a confirmation
 * that says what will change and how to undo it; the engine is asked to act only
 * after the person presses "Yes, fix it". Everything that comes from the engine
 * is HTML-escaped before it is shown.
 *
 * Loaded as a plain script in the renderer (global `FixFlow`) and required from
 * Node by the tests.
 */
const FixFlow = (function () {
  const MODULE_NAME = /^[a-z0-9_]+$/;
  const ACTION_NAME = /^[a-z0-9_]+$/;
  const QUARANTINE_ID = /^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;
  const WATCHED_WARNING = 'Turning this off may be noticed by whoever set it up. If you\u2019re not sure that\u2019s safe for you, talk to an advocate first.';

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // The `fixable` block the engine attaches to a finding, or null if it is
  // missing or malformed (in which case no button is shown).
  function fixableOf(finding) {
    const f = finding && finding.fixable;
    if (!f || typeof f !== 'object') return null;
    if (typeof f.will_change !== 'string' || f.will_change.trim() === '') return null;
    if (!Array.isArray(f.how_to_undo) || f.how_to_undo.length === 0) return null;
    if (!f.how_to_undo.every((s) => typeof s === 'string' && s.trim() !== '')) return null;
    return f;
  }

  function undoListHtml(steps) {
    return `<ol class="fix-undo">${(steps || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`;
  }

  // Markup placed inside a finding card. The confirmation panel is rendered
  // hidden; opening it is a separate, deliberate click.
  // A fixable that names an engine action must also name a plausible target.
  function actionOf(fixable) {
    if (!fixable || fixable.action === undefined) return null;
    if (typeof fixable.action !== 'string' || !ACTION_NAME.test(fixable.action)) return false;
    if (typeof fixable.target !== 'string' || !fixable.target.startsWith('/') || fixable.target.includes('\0')) return false;
    return { action: fixable.action, target: fixable.target };
  }

  // opts.watched (city mode): every fix confirmation, with or without an
  // engine action, says it may be noticed. Any change to the computer can be.
  function fixControlsHtml(finding, opts) {
    const fixable = fixableOf(finding);
    if (!fixable || typeof finding.module !== 'string' || !MODULE_NAME.test(finding.module)) return '';
    const act = actionOf(fixable);
    if (act === false) return '';
    const attrs = act
      ? ` data-fix-action="${esc(act.action)}" data-fix-target="${esc(act.target)}"`
      : '';
    const watched = opts && opts.watched
      ? `<p class="fix-panel__line fix-panel__warning"><strong>${esc(WATCHED_WARNING)}</strong></p>`
      : '';
    return `
      <div class="fix-it" data-fix-module="${esc(finding.module)}"${attrs}>
        <button type="button" class="btn btn--secondary btn--small" data-fix-open>Fix it for me</button>
        <div class="fix-panel" data-fix-panel hidden role="group" aria-label="Confirm fix">
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(fixable.will_change)}</p>
          <p class="fix-panel__line"><strong>To undo later:</strong></p>
          ${undoListHtml(fixable.how_to_undo)}
          ${watched}
          <p class="muted fix-panel__note">Nothing else on your computer will be changed.</p>
          <div class="fix-panel__actions">
            <button type="button" class="btn btn--primary btn--small" data-fix-confirm>Yes, fix it</button>
            <button type="button" class="btn btn--secondary btn--small" data-fix-cancel>Cancel</button>
          </div>
        </div>
        <div class="fix-status" data-fix-status role="status" aria-live="polite" hidden></div>
      </div>`;
  }

  // Turn the engine's answer into words. Never reports success unless the engine
  // both applied the change and confirmed it by checking again.
  function describeFixResult(result) {
    const r = result && typeof result === 'object' ? result : {};
    const undo = Array.isArray(r.how_to_undo) ? r.how_to_undo.filter((s) => typeof s === 'string') : [];
    const said = typeof r.message === 'string' ? r.message : '';
    const qid = typeof r.quarantine_id === 'string' && QUARANTINE_ID.test(r.quarantine_id) ? r.quarantine_id : null;

    if (r.action === 'disable_launch_agent' && r.applied === true && r.verified === true && r.status === 'fixed') {
      return { tone: 'success', headline: 'Done. Nothing was deleted.', detail: '', undo, undoId: qid };
    }
    if (r.action === 'undo_disable_launch_agent' && r.applied === true && r.status === 'restored') {
      return { tone: 'info', restored: true, headline: 'Put back the way it was.', detail: said, undo: [] };
    }

    if (r.action === 'disable_launch_agent' && r.status === 'nothing_to_fix' && !r.error) {
      return { tone: 'info', headline: 'This is already turned off.', detail: said, undo: [] };
    }
    if (r.status === 'nothing_to_fix' && !r.error) {
      return { tone: 'info', headline: 'There is nothing to fix. This already looks fine.', detail: '', undo: [] };
    }
    if (r.applied === true && r.verified === true && r.status === 'fixed') {
      return { tone: 'success', headline: 'Done, and checked again: fixed ✓', detail: '', undo };
    }
    if (r.applied === true) {
      return {
        tone: 'warning',
        headline: 'We made the change, but the problem still shows.',
        detail: 'When we checked again, this was still showing. Nothing else was touched. You can undo the change with the steps below, or follow "How to fix this" instead.',
        undo,
      };
    }
    // Refused because a checkup is running (main's scan gate): nothing was tried.
    if (r.error === 'scan_running') {
      return { tone: 'info', headline: 'The checkup is still running.',
        detail: 'You can fix this once it’s done. Nothing was changed.', undo: [] };
    }
    if (r.error === 'not_allowed' || r.error === 'not_confirmed') {
      return {
        tone: 'error',
        headline: 'We can’t do this one for you.',
        detail: 'Nothing was changed. Please use the "How to fix this" steps instead.',
        undo: [],
      };
    }
    return {
      tone: 'error',
      headline: 'The fix didn’t go through.',
      detail: `${said ? said + ' ' : ''}Run the checkup again to see where things stand. The "How to fix this" steps still work.`.trim(),
      undo: [],
    };
  }

  function resultHtml(result) {
    const d = describeFixResult(result);
    return `
      <div class="fix-status--${d.tone} fix-status__box">
        <p class="fix-status__headline"><strong>${esc(d.headline)}</strong></p>
        ${d.detail ? `<p class="fix-status__detail">${esc(d.detail)}</p>` : ''}
        ${d.undoId ? `<p><button type="button" class="btn btn--secondary btn--small" data-fix-undo data-quarantine-id="${esc(d.undoId)}">Undo</button></p>` : ''}
        ${d.undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(d.undo)}` : ''}
      </div>`;
  }

  // Shown on other cards about the same background job once one card turned it off.
  function handledElsewhereHtml() {
    return `
      <div class="fix-status--info fix-status__box">
        <p class="fix-status__headline"><strong>Already turned off.</strong></p>
        <p class="fix-status__detail">This is the same background job you just turned off on another card. Nothing more to do here.</p>
      </div>`;
  }

  function runningHtml() {
    return '<p class="fix-status__headline fix-status--running">Fixing… this can take a moment.</p>';
  }

  function errorHtml() {
    return `
      <div class="fix-status--error fix-status__box">
        <p class="fix-status__headline"><strong>We couldn’t reach the checkup engine.</strong></p>
        <p class="fix-status__detail">Nothing was confirmed. Run the checkup again to see where things stand.</p>
      </div>`;
  }

  const CLICK_TARGETS = '[data-fix-open],[data-fix-confirm],[data-fix-cancel],[data-fix-undo]';

  // Delegated handlers on a container that survives re-renders. `api.runFix(name)`
  // is the preload bridge to the 'run-fix' IPC channel. `hooks` (optional):
  // onFixed(cards) after a fix the engine confirmed by checking again, and
  // onRestored(cards) after Undo put it back, with every card it covered.
  // onResult({kind, module, result, described}) after the engine answers
  // (game mode).
  function attach(root, api, hooks) {
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    function notify(kind, card, result, described) {
      if (!onResult) return;
      try { onResult({ kind, module: card.getAttribute('data-fix-module'), result, described }); } catch (_) { /* a listener must never break a fix */ }
    }
    const state = new WeakMap(); // card element -> 'confirming' | 'running'
    const on = hooks || {};

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-fix-module]') : null;
    }

    // The same background job is often reported by more than one check, so it
    // shows up on more than one card with the same action and target. Once one
    // card has turned it off, the others must not keep offering a button that
    // can only come back with "nothing to do".
    function sameTargetCards(card) {
      const action = card.getAttribute('data-fix-action');
      const target = card.getAttribute('data-fix-target');
      if (!action || !target || typeof root.querySelectorAll !== 'function') return [];
      return Array.from(root.querySelectorAll('[data-fix-action][data-fix-target]')).filter((other) =>
        other !== card
        && other.getAttribute('data-fix-action') === action
        && other.getAttribute('data-fix-target') === target);
    }

    function markHandledElsewhere(card) {
      const touched = [];
      for (const other of sameTargetCards(card)) {
        if (state.get(other) === 'running') continue;
        closePanel(other);
        const open = other.querySelector('[data-fix-open]');
        const status = other.querySelector('[data-fix-status]');
        if (open) open.hidden = true;
        if (status) { status.hidden = false; status.innerHTML = handledElsewhereHtml(); }
        other.setAttribute('data-fix-handled-by-other', '');
        touched.push(other);
      }
      return touched;
    }

    function unmarkHandledElsewhere(card) {
      const touched = [];
      for (const other of sameTargetCards(card)) {
        if (!other.hasAttribute('data-fix-handled-by-other')) continue;
        touched.push(other);
        other.removeAttribute('data-fix-handled-by-other');
        const open = other.querySelector('[data-fix-open]');
        const status = other.querySelector('[data-fix-status]');
        if (open) open.hidden = false;
        if (status) { status.hidden = true; status.innerHTML = ''; }
      }
      return touched;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-fix-panel]');
      if (panel) panel.hidden = true;
      state.delete(card);
    }

    async function confirm(card) {
      if (state.get(card) !== 'confirming') return;
      const name = card.getAttribute('data-fix-module');
      const action = card.getAttribute('data-fix-action');
      const actionTarget = card.getAttribute('data-fix-target');
      state.set(card, 'running');
      const panel = card.querySelector('[data-fix-panel]');
      const status = card.querySelector('[data-fix-status]');
      const open = card.querySelector('[data-fix-open]');
      if (panel) panel.hidden = true;
      if (open) open.hidden = true;
      status.hidden = false;
      status.innerHTML = runningHtml();
      try {
        const result = action ? await api.runAction(action, actionTarget) : await api.runFix(name);
        status.innerHTML = resultHtml(result);
        const d = describeFixResult(result);
        notify('fix', card, result, d);
        state.delete(card);
        const others = action && (d.tone === 'success' || d.tone === 'info') ? markHandledElsewhere(card) : [];
        if (d.tone === 'success' && typeof on.onFixed === 'function') on.onFixed([card, ...others]);
        // After a real success there is nothing left to offer; otherwise allow a retry.
        if (open && d.tone !== 'success' && d.tone !== 'info') open.hidden = false;
      } catch (_) {
        status.innerHTML = errorHtml();
        state.delete(card);
        if (open) open.hidden = false;
      }
    }

    async function undo(card, button) {
      const id = button.getAttribute('data-quarantine-id');
      if (typeof id !== 'string' || !QUARANTINE_ID.test(id)) return;
      state.set(card, 'running');
      const status = card.querySelector('[data-fix-status]');
      const open = card.querySelector('[data-fix-open]');
      status.innerHTML = runningHtml();
      try {
        const result = await api.undoFix(id);
        status.innerHTML = resultHtml(result);
        const d = describeFixResult(result);
        notify('undo', card, result, d);
        if (d.restored === true) {
          if (open) open.hidden = false;
          const others = unmarkHandledElsewhere(card);
          if (typeof on.onRestored === 'function') on.onRestored([card, ...others]);
        }
      } catch (_) {
        status.innerHTML = errorHtml();
      }
      state.delete(card);
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest
        ? event.target.closest(CLICK_TARGETS)
        : null;
      const card = cardOf(target);
      if (!target || !card) return undefined;
      if (state.get(card) === 'running') return undefined;
      if (target.hasAttribute('data-fix-open')) {
        const panel = card.querySelector('[data-fix-panel]');
        const status = card.querySelector('[data-fix-status]');
        if (status) { status.hidden = true; status.innerHTML = ''; }
        if (panel) panel.hidden = false;
        state.set(card, 'confirming');
        return undefined;
      }
      if (target.hasAttribute('data-fix-cancel')) {
        closePanel(card);
        return undefined;
      }
      if (target.hasAttribute('data-fix-undo')) return undo(card, target);
      return confirm(card);
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      if (card && state.get(card) === 'confirming') closePanel(card);
    });
  }

  return { WATCHED_WARNING, fixableOf, fixControlsHtml, describeFixResult, resultHtml, attach, esc };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FixFlow;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.FixFlow = FixFlow;
}
