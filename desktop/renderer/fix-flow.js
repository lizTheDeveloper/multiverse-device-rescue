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
  function fixControlsHtml(finding) {
    const fixable = fixableOf(finding);
    if (!fixable || typeof finding.module !== 'string' || !MODULE_NAME.test(finding.module)) return '';
    return `
      <div class="fix-it" data-fix-module="${esc(finding.module)}">
        <button type="button" class="btn btn--secondary btn--small" data-fix-open>Fix it for me</button>
        <div class="fix-panel" data-fix-panel hidden role="group" aria-label="Confirm fix">
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(fixable.will_change)}</p>
          <p class="fix-panel__line"><strong>To undo later:</strong></p>
          ${undoListHtml(fixable.how_to_undo)}
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
        ${d.undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(d.undo)}` : ''}
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

  // Delegated handlers on a container that survives re-renders. `api.runFix(name)`
  // is the preload bridge to the 'run-fix' IPC channel.
  function attach(root, api) {
    const state = new WeakMap(); // card element -> 'confirming' | 'running'

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-fix-module]') : null;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-fix-panel]');
      if (panel) panel.hidden = true;
      state.delete(card);
    }

    async function confirm(card) {
      if (state.get(card) !== 'confirming') return;
      const name = card.getAttribute('data-fix-module');
      state.set(card, 'running');
      const panel = card.querySelector('[data-fix-panel]');
      const status = card.querySelector('[data-fix-status]');
      const open = card.querySelector('[data-fix-open]');
      if (panel) panel.hidden = true;
      if (open) open.hidden = true;
      status.hidden = false;
      status.innerHTML = runningHtml();
      try {
        const result = await api.runFix(name);
        status.innerHTML = resultHtml(result);
        const d = describeFixResult(result);
        state.delete(card);
        // After a real success there is nothing left to offer; otherwise allow a retry.
        if (open && d.tone !== 'success' && d.tone !== 'info') open.hidden = false;
      } catch (_) {
        status.innerHTML = errorHtml();
        state.delete(card);
        if (open) open.hidden = false;
      }
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest
        ? event.target.closest('[data-fix-open],[data-fix-confirm],[data-fix-cancel]')
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
      return confirm(card);
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      if (card && state.get(card) === 'confirming') closePanel(card);
    });
  }

  return { fixableOf, fixControlsHtml, describeFixResult, resultHtml, attach, esc };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FixFlow;
}
