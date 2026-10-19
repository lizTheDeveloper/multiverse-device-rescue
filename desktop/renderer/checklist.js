'use strict';

/*
 * One checklist for every list the app lets the person choose from: apps on a
 * permission list, saved keys, worries. Real checkboxes with real labels in a
 * fieldset, "Select all" and "Select none" as plain buttons, a live count,
 * and a primary button that says what it will do and to how many ("Mark 3
 * apps as mine"). Everything starts unticked. Ticking changes nothing: the
 * button only hands the ticked keys to the caller, which asks before it acts.
 * Selection lives in the page only and starts again on every redraw.
 *
 * Loaded as a plain script (global `Checklist`, also on window for the game's
 * ES modules) and required from Node by the tests.
 */
const Checklist = (function () {
  // Long lists show this many rows, then "Show all N".
  const SHOWN = 50;

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Control and format characters (bidi overrides, zero-width spaces) shown as
  // [U+XXXX], so text can't reorder or hide itself on screen.
  function visible(s) {
    return String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  }

  // A list id usable inside an element id.
  function safeId(s) {
    return String(s == null ? '' : s).replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  // Ids handed out since the last redraw. A second list that asks for a taken
  // id (or one that collapses to it) gets a suffix, so `label for` stays right.
  // preserveFocus() starts a fresh redraw; resetIds() does the same by hand.
  let usedIds = new Set();
  function resetIds() {
    usedIds = new Set();
  }
  function uniqueId(raw) {
    const base = safeId(raw);
    let id = base;
    for (let n = 2; usedIds.has(id); n += 1) id = `${base}-${n}`;
    usedIds.add(id);
    return id;
  }

  function nounFor(action, n) {
    const noun = Array.isArray(action.noun) && action.noun.length === 2 ? action.noun : ['item', 'items'];
    return n === 1 ? noun[0] : noun[1];
  }

  function minOf(action) {
    const m = Number(action && action.min);
    return Number.isInteger(m) && m > 0 ? m : 1;
  }

  // "Mark 3 apps as mine"; "Select at least one" below the minimum. Never "Apply".
  function actionLabel(action, n) {
    if (!n || n < minOf(action)) return 'Select at least one';
    return [action.verb, String(n), nounFor(action, n), action.suffix].filter((p) => p).join(' ');
  }

  function countText(n, total) {
    return `${n} of ${total} selected`;
  }

  function rowHtml(listId, it, i) {
    const boxId = `${listId}-item-${i}`;
    const more = i >= SHOWN ? ' data-cl-more hidden' : '';
    return `<li class="checklist__row"${more}>`
      + `<input type="checkbox" id="${boxId}" class="checklist__box" data-cl-item data-cl-key="${esc(it.key)}"${it.disabled ? ' disabled' : ''}>`
      + `<label for="${boxId}" class="checklist__label">`
      + `<span class="checklist__name">${esc(visible(it.label))}</span>`
      + (it.detail ? ` <code class="checklist__detail">${esc(visible(it.detail))}</code>` : '')
      + (it.evidenceHtml || '')
      + (it.note ? `<span class="checklist__note">${esc(visible(it.note))}</span>` : '')
      + '</label></li>';
  }

  function actionHtml(a) {
    const noun = Array.isArray(a.noun) && a.noun.length === 2 ? a.noun : ['item', 'items'];
    return `<button type="button" class="btn btn--primary btn--small" data-cl-action="${esc(a.id)}"`
      + ` data-cl-verb="${esc(a.verb)}" data-cl-one="${esc(noun[0])}" data-cl-many="${esc(noun[1])}"`
      + ` data-cl-suffix="${esc(a.suffix || '')}" data-cl-min="${minOf(a)}" disabled>${esc(actionLabel(a, 0))}</button>`;
  }

  function html(opts) {
    const o = opts || {};
    const listId = uniqueId(o.id);
    const items = Array.isArray(o.items) ? o.items.filter((it) => it && typeof it.key === 'string') : [];
    const actions = Array.isArray(o.actions) ? o.actions.filter((a) => a && typeof a.id === 'string') : [];
    const theme = o.theme === 'game' ? 'game' : 'plain';
    const choosable = items.filter((it) => !it.disabled).length;
    const bulk = o.selectAll && choosable > 1
      ? '<div class="checklist__bulk"><button type="button" class="link-button" data-cl-all>Select all</button> '
        + '<button type="button" class="link-button" data-cl-none>Select none</button></div>'
      : '';
    const more = items.length > SHOWN
      ? `<button type="button" class="link-button checklist__more" data-cl-more-show>Show all ${items.length}</button>`
      : '';
    return `<fieldset class="checklist checklist--${theme}" data-cl-list="${listId}">`
      + `<legend class="checklist__legend">${esc(visible(o.legend))}</legend>`
      + bulk
      + `<ul class="checklist__items">${items.map((it, i) => rowHtml(listId, it, i)).join('')}</ul>`
      + more
      + `<p class="checklist__count" data-cl-count aria-live="polite">${esc(countText(0, choosable))}</p>`
      + `<div class="checklist__actions">${actions.map(actionHtml).join('')}</div>`
      + '</fieldset>';
  }

  function isDisabled(el) {
    return el.disabled === true || (typeof el.hasAttribute === 'function' && el.hasAttribute('disabled') && el.disabled !== false);
  }

  function actionOf(btn) {
    const one = btn.getAttribute('data-cl-one') || 'item';
    const many = btn.getAttribute('data-cl-many') || 'items';
    return {
      id: btn.getAttribute('data-cl-action'),
      verb: btn.getAttribute('data-cl-verb') || '',
      noun: [one, many],
      suffix: btn.getAttribute('data-cl-suffix') || '',
      min: Number(btn.getAttribute('data-cl-min')) || 1,
    };
  }

  // Up/Left and Down/Right move one row; Home and End jump. null: not a move.
  function moveIndex(i, n, key) {
    if (n === 0 || i < 0) return null;
    if (key === 'ArrowDown' || key === 'ArrowRight') return Math.min(n - 1, i + 1);
    if (key === 'ArrowUp' || key === 'ArrowLeft') return Math.max(0, i - 1);
    if (key === 'Home') return 0;
    if (key === 'End') return n - 1;
    return null;
  }

  function attach(root, hooks) {
    const on = hooks || {};
    const listOf = (el) => (el && typeof el.closest === 'function' ? el.closest('[data-cl-list]') : null);
    const boxes = (list) => Array.from(list.querySelectorAll('[data-cl-item]')).filter((b) => !isDisabled(b));
    const chosen = (list) => boxes(list).filter((b) => b.checked === true).map((b) => b.getAttribute('data-cl-key'));

    function update(list) {
      const n = chosen(list).length;
      const count = list.querySelector('[data-cl-count]');
      if (count) count.textContent = countText(n, boxes(list).length);
      Array.from(list.querySelectorAll('[data-cl-action]')).forEach((btn) => {
        const action = actionOf(btn);
        btn.disabled = n < action.min;
        btn.textContent = actionLabel(action, n);
      });
    }

    root.addEventListener('change', (event) => {
      const t = event && event.target;
      if (!t || typeof t.hasAttribute !== 'function' || !t.hasAttribute('data-cl-item')) return;
      const list = listOf(t);
      if (list) update(list);
    });

    root.addEventListener('click', (event) => {
      const t = event && event.target && typeof event.target.closest === 'function'
        ? event.target.closest('[data-cl-all],[data-cl-none],[data-cl-action],[data-cl-more-show]')
        : null;
      const list = listOf(t);
      if (!t || !list) return undefined;
      if (t.hasAttribute('data-cl-all') || t.hasAttribute('data-cl-none')) {
        const tick = t.hasAttribute('data-cl-all');
        // Show every row before ticking, so nobody approves rows they haven't seen.
        if (tick) {
          Array.from(list.querySelectorAll('[data-cl-more]')).forEach((row) => { row.hidden = false; });
          const showMore = list.querySelector('[data-cl-more-show]');
          if (showMore) showMore.hidden = true;
        }
        boxes(list).forEach((b) => { b.checked = tick; });
        update(list);
        return undefined;
      }
      if (t.hasAttribute('data-cl-more-show')) {
        Array.from(list.querySelectorAll('[data-cl-more]')).forEach((row) => { row.hidden = false; });
        t.hidden = true;
        return undefined;
      }
      const keys = chosen(list);
      if (keys.length < actionOf(t).min) return undefined;
      if (typeof on.onAction === 'function') return on.onAction(list.getAttribute('data-cl-list'), t.getAttribute('data-cl-action'), keys);
      return undefined;
    });

    root.addEventListener('keydown', (event) => {
      const t = event && event.target;
      if (!t || typeof t.hasAttribute !== 'function' || !t.hasAttribute('data-cl-item')) return;
      const list = listOf(t);
      if (!list) return;
      const rows = boxes(list).filter((b) => {
        const more = typeof b.closest === 'function' ? b.closest('[data-cl-more]') : null;
        return !(more && more.hidden);
      });
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const next = moveIndex(rows.indexOf(t), rows.length, event.key);
      if (next === null) return;
      if (typeof event.preventDefault === 'function') event.preventDefault();
      if (typeof rows[next].focus === 'function') rows[next].focus();
    });

    return { update, chosen };
  }

  // What has focus inside a checklist: its list, and the row or control.
  function focusKey(el) {
    if (!el || typeof el.getAttribute !== 'function' || typeof el.closest !== 'function') return null;
    const list = el.closest('[data-cl-list]');
    if (!list) return null;
    const listId = list.getAttribute('data-cl-list');
    for (const attr of ['data-cl-key', 'data-cl-action']) {
      const value = el.getAttribute(attr);
      if (value !== null) return { listId, attr, value };
    }
    for (const attr of ['data-cl-all', 'data-cl-none', 'data-cl-more-show']) {
      if (el.hasAttribute(attr)) return { listId, attr, value: null };
    }
    return null;
  }

  function activeIn(root) {
    const node = root && typeof root.getRootNode === 'function' ? root.getRootNode() : null;
    if (node && node.activeElement) return node.activeElement;
    const doc = root && root.ownerDocument;
    return doc ? doc.activeElement || null : null;
  }

  // Redraw `root` with render(), then put focus back on the same row or
  // control of the same list, if it is still there. Works in a shadow root.
  function preserveFocus(root, render) {
    const key = focusKey(activeIn(root));
    resetIds();
    render();
    if (!key || !root || typeof root.querySelectorAll !== 'function') return;
    const list = Array.from(root.querySelectorAll('[data-cl-list]')).find((l) => l.getAttribute('data-cl-list') === key.listId);
    if (!list) return;
    const target = Array.from(list.querySelectorAll(`[${key.attr}]`))
      .find((el) => key.value === null || el.getAttribute(key.attr) === key.value);
    const usable = (el) => el && !isDisabled(el);
    let dest = usable(target) ? target : null;
    if (!dest) {
      dest = Array.from(list.querySelectorAll('[data-cl-item]')).find(usable) || null;
    }
    if (!dest) {
      if (typeof list.setAttribute === 'function') list.setAttribute('tabindex', '-1');
      dest = list;
    }
    if (typeof dest.focus === 'function') dest.focus();
  }

  return { SHOWN, html, attach, actionLabel, countText, moveIndex, preserveFocus, resetIds, focusKey, esc, visible };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Checklist;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.Checklist = Checklist;
}
