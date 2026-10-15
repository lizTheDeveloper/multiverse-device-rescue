'use strict';

/*
 * Clearing the list: each card on "Needs attention now" and "Worth a look"
 * can be answered, and an answered card moves into a collapsed "Cleared"
 * section at the bottom, still readable, with Undo. A line at the top says
 * how far along the person is.
 *
 * Two kinds of clearing, and the page always says which:
 *   - "I did this" (did): the person says they followed the steps. This
 *     checkup only. Nothing is saved; the next checkup checks again for real.
 *   - "It's mine" (marked / marked_before): saved by the engine and kept
 *     across checkups (MarkFlow does the saving; this only moves the card).
 *   - "Fix it for me" (fixed): the engine changed it and checked again.
 *
 * The pure parts (createState, progress, words) are tested from Node; attach()
 * does the moving in the page. Loaded as a plain script (global `ClearList`).
 */
const ClearList = (function () {
  const HOWS = new Set(['did', 'marked', 'marked_before', 'fixed']);

  // Pure state: which cards count toward the list, and how each was cleared.
  function createState() {
    const cards = new Map(); // key -> { counts, how }
    return {
      add(key, counts) { cards.set(String(key), { counts: !!counts, how: null }); },
      has(key) { return cards.has(String(key)); },
      how(key) { const c = cards.get(String(key)); return c ? c.how : null; },
      clear(key, how) {
        const c = cards.get(String(key));
        if (!c || !HOWS.has(how)) return false;
        c.how = how;
        return true;
      },
      // No longer on the list (an earlier mark the person just removed:
      // it is information now, and its warning comes back next checkup).
      uncount(key) { const c = cards.get(String(key)); if (c) c.counts = false; },
      restore(key) {
        const c = cards.get(String(key));
        if (!c || c.how === null) return false;
        c.how = null;
        return true;
      },
      progress() {
        let total = 0;
        let cleared = 0;
        let did = 0;
        let clearedAll = 0;
        for (const c of cards.values()) {
          if (c.how) clearedAll += 1;
          if (!c.counts) continue;
          total += 1;
          if (c.how) cleared += 1;
          if (c.how === 'did') did += 1;
        }
        return { total, cleared, did, clearedAll };
      },
    };
  }

  // The words at the top of the results. Honest about what wasn't checked
  // and about what was only the person's say-so.
  function progressText(p, opts) {
    const couldNotCheck = (opts && opts.couldNotCheck) || 0;
    const notChecked = couldNotCheck
      ? `${couldNotCheck} check${couldNotCheck === 1 ? '' : 's'} couldn’t run on this computer, so ${couldNotCheck === 1 ? 'that wasn’t' : 'those weren’t'} checked (listed at the bottom).`
      : '';
    const sayso = p.did
      ? `${p.did === 1 ? 'One thing' : `${p.did} things`} you said you did will be checked again on your next checkup.`
      : '';
    if (!p.total) return null;
    if (p.cleared >= p.total) {
      return {
        allClear: true,
        headline: 'All clear — nothing left on your list.',
        detail: [sayso, notChecked, 'A clear list lowers the odds of a problem; it can’t rule one out.'].filter(Boolean).join(' '),
      };
    }
    return {
      allClear: false,
      headline: `${p.cleared} of ${p.total} cleared`,
      detail: p.cleared
        ? [sayso, notChecked].filter(Boolean).join(' ')
        : 'Answer each card below as you go: “I did this” when you’ve followed its steps, or “It’s mine” when you set it up yourself.',
    };
  }

  // The note on a cleared card.
  function noteText(how) {
    if (how === 'did') return 'You said you did this. This checkup only: nothing is saved, and your next checkup checks it again.';
    if (how === 'marked') return 'Marked as yours. This is remembered across checkups, and it stays listed as “marked as yours”.';
    if (how === 'marked_before') return 'You marked this as yours on an earlier checkup. It stays listed so anyone helping you can see it.';
    if (how === 'fixed') return 'Device Rescue changed this and checked again.';
    return '';
  }

  function undoLabel(how) {
    if (how === 'did') return 'Undo';
    if (how === 'marked' || how === 'marked_before') return 'Undo — stop treating this as mine';
    return '';
  }

  // What a session answer means, for "Copy for any AI" and the technical details.
  function personSaid(how) {
    if (how === 'did') return 'the person said they did this (this checkup only; not checked again yet)';
    if (how === 'marked') return 'marked as theirs by the person just now (kept across checkups)';
    if (how === 'marked_before') return 'marked as theirs by the person on an earlier checkup';
    if (how === 'fixed') return 'fixed by Device Rescue and checked again';
    return null;
  }

  // "I did this" for cards with steps to follow; "I've looked at this" for
  // warnings without. Critical findings with no steps get nothing: they
  // can't be cleared by a look.
  function didLabel(finding, severity) {
    if (severity !== 'critical' && severity !== 'warning') return null;
    const steps = finding && finding.remediation && Array.isArray(finding.remediation.steps)
      && finding.remediation.steps.length > 0;
    const todo = /(^|\n)\s*what to do:/i.test(String((finding && finding.description) || ''));
    if (steps || todo) return 'I did this';
    return severity === 'warning' ? 'I’ve looked at this' : null;
  }

  function didControlsHtml(finding, severity, esc) {
    const label = didLabel(finding, severity);
    if (!label) return '';
    return `<div class="did-this" data-did-wrap>
        <button type="button" class="btn btn--secondary btn--small" data-clear-did>${esc(label)}</button>
        <span class="muted did-this__hint">For this checkup only. Nothing is changed or saved.</span>
      </div>`;
  }

  function sectionHtml() {
    return `
      <section class="results-cleared" data-cleared-section hidden>
        <details data-cleared-details>
          <summary><span class="results-cleared__title">Cleared</span> (<span data-cleared-count>0</span>)</summary>
          <p class="muted">“I did this” lasts for this checkup only: the next checkup looks again for real. “It’s mine” is remembered, and those items stay listed as “marked as yours”.</p>
          <ul class="findings-list" data-cleared-list></ul>
        </details>
      </section>`;
  }

  // Wire it up in the page. `opts`:
  //   progressEl: where the progress line goes
  //   esc: HTML escaper
  //   couldNotCheck: how many checks couldn't run
  //   onChange(card, how|null): after a card is cleared or put back
  //   undoMark(markCard): ask MarkFlow to unmark (Undo on a marked card)
  function attach(root, opts) {
    const o = opts || {};
    const esc = o.esc || ((s) => String(s));
    let state = createState();
    const slots = new Map(); // key -> placeholder where the card lived

    const section = () => root.querySelector('[data-cleared-section]');
    const list = () => root.querySelector('[data-cleared-list]');
    const keyOf = (card) => card && card.getAttribute && card.getAttribute('data-card-key');
    const cardOf = (el) => (el && el.closest ? el.closest('[data-card-key]') : null);

    function register(card) {
      const key = keyOf(card);
      if (key == null || state.has(key)) return;
      state.add(key, card.getAttribute('data-card-counts') === '1');
    }

    function renderProgress() {
      const el = o.progressEl;
      const p = state.progress();
      const sec = section();
      if (sec) {
        sec.hidden = p.clearedAll === 0;
        const count = sec.querySelector('[data-cleared-count]');
        if (count) count.textContent = String(p.clearedAll);
      }
      // Each severity group's count is what is still on it.
      root.querySelectorAll('[data-results-group]').forEach((group) => {
        const n = group.querySelectorAll('[data-group-list] > [data-card-key]').length;
        const count = group.querySelector('.results-group__count');
        if (count) count.textContent = String(n);
        const empty = group.querySelector('[data-group-empty]');
        if (empty) empty.hidden = n !== 0;
      });
      if (!el) return;
      const t = progressText(p, { couldNotCheck: o.couldNotCheck || 0 });
      if (!t) { el.hidden = true; el.innerHTML = ''; return; }
      el.hidden = false;
      const pct = p.total ? Math.round((p.cleared / p.total) * 100) : 0;
      el.innerHTML = `
        <p class="results-progress__headline${t.allClear ? ' results-progress__headline--clear' : ''}"><strong>${esc(t.headline)}</strong></p>
        <div class="results-progress__bar" role="progressbar" aria-valuemin="0" aria-valuemax="${p.total}" aria-valuenow="${p.cleared}" aria-label="Cleared so far"><div class="results-progress__fill" style="width:${pct}%"></div></div>
        ${t.detail ? `<p class="muted results-progress__detail">${esc(t.detail)}</p>` : ''}`;
    }

    function setNote(card, how) {
      const note = card.querySelector('[data-cleared-note]');
      if (!note) return;
      if (!how) { note.hidden = true; note.innerHTML = ''; return; }
      const undo = undoLabel(how);
      note.hidden = false;
      note.innerHTML = `<p class="cleared-note__text"><span class="cleared-note__tick" aria-hidden="true">✓</span> ${esc(noteText(how))}</p>
        ${undo ? `<button type="button" class="btn btn--secondary btn--small" data-clear-undo>${esc(undo)}</button>` : ''}`;
    }

    function clear(card, how) {
      register(card);
      const key = keyOf(card);
      if (key == null || !state.clear(key, how)) return;
      if (!slots.has(key) && card.parentNode && card.ownerDocument) {
        const slot = card.ownerDocument.createElement('li');
        slot.hidden = true;
        slot.setAttribute('data-card-slot', key);
        card.parentNode.insertBefore(slot, card);
        slots.set(key, slot);
      }
      const target = list();
      if (target && card.parentNode !== target) target.appendChild(card);
      card.setAttribute('data-cleared', how);
      const did = card.querySelector('[data-did-wrap]');
      if (did) did.hidden = true;
      setNote(card, how);
      renderProgress();
      if (typeof o.onChange === 'function') o.onChange(card, how);
    }

    function restore(card) {
      const key = keyOf(card);
      if (key == null || !state.restore(key)) return;
      const slot = slots.get(key);
      if (slot && slot.parentNode) {
        slot.parentNode.insertBefore(card, slot);
        slot.parentNode.removeChild(slot);
      }
      slots.delete(key);
      card.removeAttribute('data-cleared');
      if (card.hasAttribute('data-marked-before')) state.uncount(key);
      const did = card.querySelector('[data-did-wrap]');
      if (did) did.hidden = false;
      setNote(card, null);
      renderProgress();
      if (typeof o.onChange === 'function') o.onChange(card, null);
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest ? event.target.closest('[data-clear-did],[data-clear-undo]') : null;
      const card = cardOf(target);
      if (!target || !card) return;
      if (target.hasAttribute('data-clear-did')) { clear(card, 'did'); return; }
      const how = state.how(keyOf(card));
      if (how === 'did' || how === 'fixed') { restore(card); return; }
      if ((how === 'marked' || how === 'marked_before') && typeof o.undoMark === 'function') {
        o.undoMark(card.querySelector('[data-mark-card]'));
      }
    });

    // A new checkup: forget every answer from the last one (none of "I did
    // this" carries over) and pick up the newly rendered cards.
    function reset(next) {
      Object.assign(o, next || {});
      state = createState();
      slots.clear();
      root.querySelectorAll('[data-card-key]').forEach(register);
      renderProgress();
    }

    return {
      reset,
      register,
      clear,
      restore,
      refresh: renderProgress,
      cardOf,
      progress: () => state.progress(),
    };
  }

  return {
    createState, progressText, noteText, undoLabel, personSaid, didLabel, didControlsHtml, sectionHtml, attach,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ClearList;
}
