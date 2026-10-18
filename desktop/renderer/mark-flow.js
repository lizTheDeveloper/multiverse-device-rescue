'use strict';

/*
 * "It's mine": the button, the in-page confirmation, and the result. Also
 * "Stop treating this as mine" on a marked item. One mechanism for every kind
 * the engine offers: background tasks, sharing settings, proxies, extensions,
 * app permission lists, remote-login keys, AI tool settings.
 *
 * Nothing is saved until the person presses "Yes, it's mine". Only the
 * engine's mark id is sent back, so what is saved is what the scan showed. A
 * marked item is never hidden: the engine keeps listing it as "marked as
 * yours". Everything that comes from the engine is HTML-escaped before it is
 * shown. Findings from the monitoring-software checks never offer it.
 *
 * Loaded as a plain script in the renderer (global `MarkFlow`) and required
 * from Node by the tests.
 */
const MarkFlow = (function () {
  const MARK_ID = /^[0-9a-f]{12}$/;
  const ONLY_IF_YOURS = 'Only do this if you set this up yourself. If you’re not sure, leave it as it is.';
  const COULD_WATCH = 'Something like this can be used to watch or get into a computer. That is why we ask.';
  // Why we ask about a list of apps: an ordinary list, not an accusation.
  const LIST_REASON = 'We ask so the list stays accurate: if a new app appears, you’ll hear about it.';
  const NOT_SURE_LIST = 'Not sure about one? Leave the whole list as it is.';
  // Kinds that really are about watching a computer or getting into it remotely.
  const WATCH_KINDS = new Set(['sharing_service', 'network_proxy', 'system_extension', 'browser_extension', 'ssh_authorized_keys']);
  // Kinds whose list gets the neutral reason instead.
  const LIST_KINDS = new Set(['app_permissions']);
  const ITEM_KINDS = new Set([
    'sharing_service', 'network_proxy', 'system_extension', 'browser_extension',
    'app_permissions', 'ssh_authorized_keys', 'ai_tooling',
  ]);
  // Checks for monitoring software: "It's mine" is never offered on them.
  const NEVER_MARKABLE_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  // One plain answer per kind of thing.
  const BUTTON = {
    background_task: 'I set this up — it’s mine',
    sharing_service: 'I turned this on — it’s mine',
    network_proxy: 'I set this up — it’s mine',
    system_extension: 'I installed this — it’s mine',
    browser_extension: 'I installed this — it’s mine',
    app_permissions: 'I know these apps — they’re mine',
    ssh_authorized_keys: 'I added these keys — they’re mine',
    ai_tooling: 'I set this up — it’s mine',
  };

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

  function textList(list) {
    return Array.isArray(list) && list.length > 0 && list.every((s) => typeof s === 'string' && s.trim() !== '');
  }

  // The engine's `markable` block, or null if missing, malformed, or on a
  // finding that must never be marked.
  function markableOf(finding) {
    const m = finding && finding.markable;
    if (!m || typeof m !== 'object') return null;
    if (finding && NEVER_MARKABLE_MODULES.has(finding.module)) return null;
    if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
    if (typeof m.will_change !== 'string' || m.will_change.trim() === '') return null;
    if (!textList(m.how_to_undo)) return null;
    if (ITEM_KINDS.has(m.kind)) {
      if (typeof m.group !== 'string' || !MARK_ID.test(m.group)) return null;
      if (typeof m.code === 'string' && NEVER_MARKABLE_MODULES.has(m.code.split('.')[1])) return null;
      return m;
    }
    if (m.kind !== 'background_task') return null;
    if (!clean(m.label, 256) || m.label.startsWith('-')) return null;
    if (!clean(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
    if (!clean(m.plist) || !m.plist.startsWith('/')) return null;
    return m;
  }

  // The mark id on a finding the person already marked, or null.
  function markedIdOf(finding) {
    const d = finding && finding.data;
    if (!d || d.marked_by_user !== true) return null;
    return typeof d.known_item_id === 'string' && MARK_ID.test(d.known_item_id) ? d.known_item_id : null;
  }

  // Asks for the stronger confirmation: anything that could be used to watch
  // someone, any background task, and everything when the person said
  // "someone is watching me". A missing flag counts as yes.
  function needsStrongConfirm(m, opts) {
    if (opts && opts.watched) return true;
    if (m.kind === 'background_task') return true;
    return m.monitoring !== false;
  }

  function buttonLabel(m) {
    return BUTTON[m.kind] || BUTTON.background_task;
  }

  // Every mark id the engine grouped with this one (same item, other checks), own id first.
  function groupOf(ownId, list) {
    const ids = Array.isArray(list) ? list.filter((x) => typeof x === 'string' && MARK_ID.test(x)) : [];
    return [ownId, ...ids].filter((x, i, a) => a.indexOf(x) === i);
  }

  function coversHtml(count, kind) {
    if (count < 2) return '';
    const what = kind === 'background_task' ? 'this task' : 'this';
    return `<p class="fix-panel__line">That is ${count} warnings about ${what} on this checkup; one answer covers them all.</p>`;
  }

  function undoListHtml(steps) {
    return `<ol class="fix-undo">${(steps || []).map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`;
  }

  // The engine's per-app rows ({id, name}) on a list of apps, or [].
  function appRowsOf(m) {
    if (!m || !LIST_KINDS.has(m.kind) || !Array.isArray(m.apps)) return [];
    return m.apps.filter((r) => r && clean(r.id) && clean(r.name, 256));
  }

  // "Made by …" for one app, from the finding's `made_by` entry for that id.
  function makerOf(madeBy, id) {
    const e = Array.isArray(madeBy) ? madeBy.find((x) => x && x.subject === id) : null;
    if (!e || typeof e.name !== 'string' || !e.name.trim() || e.name === 'Unknown maker') return '';
    return e.verified ? `Made by ${e.name}` : `Says it is made by ${e.name} (couldn’t verify)`;
  }

  function appsHtml(rows, madeBy, count) {
    const items = rows.map((r) => {
      const maker = makerOf(madeBy, r.id);
      return `<li class="mark-apps__row"><span class="mark-apps__name">${esc(r.name)}</span>${maker ? `<span class="mark-apps__maker">${esc(maker)}</span>` : ''}</li>`;
    }).join('');
    const ids = rows.map((r) => `<li><code>${esc(r.id)}</code>${r.name !== r.id ? ` (${esc(r.name)})` : ''}</li>`).join('');
    return `<p class="fix-panel__line"><strong>What you are saying is yours${count ? ` (${esc(count)} apps)` : ''}:</strong></p>
          <ul class="mark-apps">${items}</ul>
          <p class="fix-panel__line muted">${esc(NOT_SURE_LIST)}</p>
          <details class="mark-tech"><summary>Technical details</summary>
            <p class="fix-panel__line">The names the permission list uses for these apps (bundle IDs):</p>
            <ul class="mark-tech__ids">${ids}</ul>
          </details>`;
  }

  function showsHtml(m, finding) {
    const rows = Array.isArray(m.shows)
      ? m.shows.filter((r) => Array.isArray(r) && r.length === 2 && typeof r[0] === 'string' && typeof r[1] === 'string')
      : [];
    const apps = appRowsOf(m);
    if (apps.length) {
      const count = (rows.find(([k]) => k === 'How many') || [])[1] || String(apps.length);
      return appsHtml(apps, finding && finding.made_by, count);
    }
    if (m.kind === 'background_task') {
      rows.unshift(['Task', m.label], ['Program', m.program]);
    }
    if (!rows.length) return '';
    return `<p class="fix-panel__line"><strong>What you are saying is yours:</strong></p>
          <dl class="mark-shows">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
  }

  // Why we ask: the watching line only where it is about watching or remote access.
  function reasonHtml(m, strong) {
    if (!strong || m.kind === 'background_task') return '';
    if (LIST_KINDS.has(m.kind)) return `<p class="fix-panel__line">${esc(LIST_REASON)}</p>`;
    if (WATCH_KINDS.has(m.kind)) return `<p class="fix-panel__line">${esc(COULD_WATCH)}</p>`;
    return '';
  }

  // opts.watched: the person said "I think someone is watching me".
  function markControlsHtml(finding, opts) {
    const m = markableOf(finding);
    if (m) {
      const group = groupOf(m.id, m.ids);
      const strong = needsStrongConfirm(m, opts);
      return `
      <div class="mark-mine" data-mark-card data-mark-kind="${esc(m.kind)}" data-mark-id="${esc(m.id)}" data-mark-group="${esc(group.join(' '))}">
        <button type="button" class="btn btn--secondary btn--small" data-mark-open>${esc(buttonLabel(m))}</button>
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Confirm this is yours">
          ${showsHtml(m, finding)}
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(m.will_change)}</p>
          ${coversHtml(group.length, m.kind)}
          <p class="fix-panel__line"><strong>To undo later:</strong></p>
          ${undoListHtml(m.how_to_undo)}
          ${strong ? `<p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>` : ''}
          ${reasonHtml(m, strong)}
          <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
          <div class="fix-panel__actions">
            <button type="button" class="btn btn--primary btn--small" data-mark-confirm>${LIST_KINDS.has(m.kind) ? 'Yes, these are mine' : 'Yes, it’s mine'}</button>
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
        detail: 'This is remembered: from your next checkup it will be listed as “marked as yours” instead of being flagged.',
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

  // Shown on the other cards about the same item once one card's answer covered them.
  function siblingHtml(kind) {
    const d = kind === 'marked'
      ? {
        tone: 'success', headline: 'Marked as yours.',
        detail: 'Marked together with the other warning about this. From your next checkup it will be listed as “marked as yours” instead of being flagged.',
      }
      : {
        tone: 'info', headline: 'No longer marked as yours.',
        detail: 'Removed together with the other warning about this. Its warning comes back on your next checkup.',
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
  // preload bridge: api.markMine(id), api.unmarkMine(id). `hooks` (optional):
  // onMarked(cards) and onUnmarked(cards) after the engine saved or removed
  // marks, with every card the answer covered. Returns {unmark(card)} so the
  // "Cleared" list can offer Undo.
  // onResult({kind, result, described}) after the engine answers (game mode).
  function attach(root, api, hooks) {
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    const state = new WeakMap(); // card -> 'confirming' | 'running'
    const on = hooks || {};

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-mark-card]') : null;
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-mark-panel]');
      if (panel) panel.hidden = true;
      state.delete(card);
    }

    function setButtons(card, hidden) {
      card.querySelectorAll('[data-mark-open],[data-unmark]').forEach((b) => { b.hidden = hidden; });
    }

    // A card that was just marked can be unmarked again ("Undo"): it learns
    // the ids the engine saved for it.
    function becomeMarked(card, ids) {
      const own = card.getAttribute('data-mark-id');
      if (!own || !ids.includes(own)) return;
      card.setAttribute('data-unmark-id', own);
      card.setAttribute('data-unmark-group', [own, ...ids.filter((x) => x !== own)].join(' '));
      card.setAttribute('data-marked-now', '');
    }

    // After an unmark, a card that was marked in this session offers the button again.
    function becomeUnmarked(card) {
      if (!card.hasAttribute || !card.hasAttribute('data-marked-now')) return;
      card.removeAttribute('data-marked-now');
      card.removeAttribute('data-unmark-id');
      card.removeAttribute('data-unmark-group');
      setButtons(card, false);
    }

    // The same item is often reported by more than one check, so it has more
    // than one card. Once the engine has saved (or removed) the marks for all
    // of them, the other cards say so instead of offering the button again.
    function updateSiblings(card, kind, result) {
      if (typeof root.querySelectorAll !== 'function') return [];
      const ownAttr = kind === 'marked' ? 'data-mark-id' : 'data-unmark-id';
      const groupAttr = kind === 'marked' ? 'data-mark-group' : 'data-unmark-group';
      const own = card.getAttribute(ownAttr);
      let ids = idsAttr(card, groupAttr).filter((x) => x !== own);
      // When the engine lists what it saved or removed, only those.
      if (result && Array.isArray(result.ids)) ids = ids.filter((x) => result.ids.includes(x));
      if (!ids.length) return [];
      const touched = [];
      for (const other of Array.from(root.querySelectorAll(`[${ownAttr}]`))) {
        if (other === card || !ids.includes(other.getAttribute(ownAttr))) continue;
        if (state.get(other) === 'running') continue;
        closePanel(other);
        setButtons(other, true);
        const status = other.querySelector('[data-mark-status]');
        if (status) { status.hidden = false; status.innerHTML = siblingHtml(kind); }
        other.setAttribute('data-mark-handled-by-other', '');
        if (kind === 'marked') becomeMarked(other, [own, ...ids]);
        else becomeUnmarked(other);
        touched.push(other);
      }
      return touched;
    }

    async function send(card, call, kind) {
      state.set(card, 'running');
      const panel = card.querySelector('[data-mark-panel]');
      const status = card.querySelector('[data-mark-status]');
      if (panel) panel.hidden = true;
      setButtons(card, true);
      status.hidden = false;
      status.innerHTML = '<p class="fix-status__headline fix-status--running">Saving…</p>';
      let d;
      try {
        const result = await call();
        status.innerHTML = resultHtml(result);
        d = describeMarkResult(result);
        if (onResult) { try { onResult({ kind, result, described: d }); } catch (_) { /* never break a mark */ } }
        const r = result || {};
        if (kind === 'marked' && (r.status === 'marked' || r.status === 'already_marked')) {
          const own = card.getAttribute('data-mark-id');
          const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x)) : [own];
          const others = updateSiblings(card, kind, r);
          becomeMarked(card, saved.length ? saved : [own]);
          if (typeof on.onMarked === 'function') on.onMarked([card, ...others]);
        }
        if (kind === 'removed' && r.status === 'removed') {
          const others = updateSiblings(card, kind, r);
          state.delete(card);
          becomeUnmarked(card);
          if (typeof on.onUnmarked === 'function') on.onUnmarked([card, ...others]);
        }
      } catch (_) {
        status.innerHTML = resultHtml(null);
        d = { done: false };
      }
      state.delete(card);
      if (!d.done) setButtons(card, false);
    }

    function unmark(card) {
      if (!card || state.get(card) === 'running') return undefined;
      const id = card.getAttribute('data-unmark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.unmarkMine(id), 'removed');
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
      if (target.hasAttribute('data-unmark')) return unmark(card);
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

    return { unmark };
  }

  return {
    ONLY_IF_YOURS, COULD_WATCH, LIST_REASON, NOT_SURE_LIST, BUTTON, NEVER_MARKABLE_MODULES, groupOf, markableOf, markedIdOf,
    needsStrongConfirm, markControlsHtml, describeMarkResult, resultHtml, attach, esc,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MarkFlow;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.MarkFlow = MarkFlow;
}
