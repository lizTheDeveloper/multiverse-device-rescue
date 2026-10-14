// "Ask about this" UI. Kept out of app.js so that file stays easy to merge.
// app.js calls askButtonHtml(finding) inside each finding card; everything
// else (consent panel, request, answer) is wired here by event delegation.
// The network request is made by the main process, never from here.

const ASK_FOOTER = 'AI-generated. It can be wrong — the step-by-step guide is the reliable source.';
const ASK_CONSENT_TEXT =
  "This sends only this finding's title and description to The Multiverse School's AI helper. " +
  'No files, no account names. Nothing is stored.';
const ASK_WARMING_TEXT = 'The helper is waking up, this takes about 30 seconds…';
const ASK_ERRORS = {
  unavailable: "The helper isn't available right now. The step-by-step guide still works.",
  rate_limited: 'Lots of people are asking right now. Please try again in a minute.',
  network: "We couldn't reach the helper. Check your internet connection and try again.",
  warming_up: "The helper is still waking up. Please try again in a minute.",
  invalid: "We couldn't ask about this one.",
};

const ASK_HEADINGS = /^(?:#{1,6}\s*|\*\*)?(what this is|is it normal\??|what to do)\s*[:?]?(?:\*\*)?:?\s*$/i;

function askEscape(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Turn the model's answer into safe HTML: headings, lists, paragraphs, bold.
 * Everything is escaped first; no raw HTML from the answer ever reaches the DOM.
 */
function renderAnswerHtml(text) {
  const inline = (v) => askEscape(v).replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  const out = [];
  let list = null;
  let para = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of String(text || '').split('\n')) {
    const heading = raw.trim().match(ASK_HEADINGS);
    const ol = raw.match(/^\s*\d+[.)]\s+(.*)$/);
    const ul = raw.match(/^\s*[-*•]\s+(.*)$/);
    if (heading) {
      flushPara(); closeList();
      const label = heading[1].charAt(0).toUpperCase() + heading[1].slice(1).toLowerCase();
      out.push(`<h4>${askEscape(label)}</h4>`);
    } else if (ol || ul) {
      flushPara();
      const kind = ol ? 'ol' : 'ul';
      if (list !== kind) { closeList(); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${inline((ol || ul)[1])}</li>`);
    } else if (raw.trim() === '') {
      flushPara(); closeList();
    } else {
      closeList(); para.push(raw.trim());
    }
  }
  flushPara(); closeList();
  return out.join('');
}

const askRegistry = [];

/** HTML for the button plus an empty slot; remembers the finding by index. */
function askButtonHtml(finding) {
  const id = askRegistry.push({
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    category: finding.category,
    code: finding.code,
  }) - 1;
  return `<div class="ask">
    <button type="button" class="btn btn--secondary btn--small" data-ask-id="${id}">Ask about this</button>
    <div class="ask__slot" data-ask-slot="${id}" aria-live="polite"></div>
  </div>`;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { renderAnswerHtml, ASK_FOOTER, ASK_CONSENT_TEXT, ASK_WARMING_TEXT };
}

if (typeof document !== 'undefined') {
  let askConsented = false; // this session only; deliberately not persisted
  const pending = new Set();

  const slotFor = (id) => document.querySelector(`[data-ask-slot="${id}"]`);
  const buttonFor = (id) => document.querySelector(`[data-ask-id="${id}"]`);

  function showConsent(id) {
    slotFor(id).innerHTML = `
      <div class="ask__panel" role="group" aria-label="Before we ask">
        <p>${askEscape(ASK_CONSENT_TEXT)}</p>
        <div class="ask__actions">
          <button type="button" class="btn btn--primary btn--small" data-ask-go="${id}">OK, ask</button>
          <button type="button" class="btn btn--secondary btn--small" data-ask-cancel="${id}">Cancel</button>
        </div>
      </div>`;
  }

  async function runAsk(id) {
    const slot = slotFor(id);
    const btn = buttonFor(id);
    if (!slot || pending.has(id)) return;
    pending.add(id);
    if (btn) btn.disabled = true;
    slot.innerHTML = '<p class="ask__status muted" data-ask-status>Asking…</p>';
    let result;
    try {
      result = await window.rescue.askAbout({ finding: askRegistry[id] });
    } catch (_e) {
      result = { ok: false, reason: 'network' };
    }
    pending.delete(id);
    if (btn) btn.disabled = false;
    if (result && result.ok) {
      slot.innerHTML = `<div class="ask__answer">${renderAnswerHtml(result.answer)}
        <p class="ask__footer muted">${askEscape(ASK_FOOTER)}</p></div>`;
    } else {
      const msg = ASK_ERRORS[result && result.reason] || ASK_ERRORS.unavailable;
      slot.innerHTML = `<p class="ask__error">${askEscape(msg)}</p>`;
    }
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest && ev.target.closest('[data-ask-id],[data-ask-go],[data-ask-cancel]');
    if (!t) return;
    if (t.hasAttribute('data-ask-id')) {
      const id = Number(t.getAttribute('data-ask-id'));
      if (askConsented) runAsk(id); else showConsent(id);
    } else if (t.hasAttribute('data-ask-go')) {
      askConsented = true;
      runAsk(Number(t.getAttribute('data-ask-go')));
    } else {
      slotFor(Number(t.getAttribute('data-ask-cancel'))).innerHTML = '';
    }
  });

  if (window.rescue && window.rescue.onAskWarming) {
    window.rescue.onAskWarming(() => {
      document.querySelectorAll('[data-ask-status]').forEach((el) => { el.textContent = ASK_WARMING_TEXT; });
    });
  }
}
