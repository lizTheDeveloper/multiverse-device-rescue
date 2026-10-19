// "Copy for any AI" UI. Each card on the city's LIST gets a button (none for
// held or monitoring evidence in city mode); the LIST gets one for the whole
// report. A click asks the main process to build the redacted text, shows it
// in full, and copies only when the person presses Copy.

const COPY_AI_INTRO =
  'Here is exactly what will be copied. Paste it into any AI assistant you use (ChatGPT, Claude, Gemini, Copilot…). ' +
  'Your name, computer name, network addresses and anything that looks like a password have been blanked out. ' +
  'Read it first. Delete anything you would rather not share.';

const copyAiRegistry = [];
let copyAiReport = null;

function copyAiEscape(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Only the parts of a finding the prompt builder reads. */
function copyAiPick(f) {
  return {
    title: f.title, description: f.description, severity: f.severity, category: f.category,
    code: f.code, module: f.module, confidence: f.confidence, made_by: f.made_by,
    remediation: f.remediation, data: f.data,
  };
}

// `pick` (optional) is the card's own copy object, shared with the
// whole-report copy, so an answer given on the card shows in both.
function copyAiButtonHtml(finding, pick) {
  const id = copyAiRegistry.push(pick || copyAiPick(finding)) - 1;
  return `<div class="copy-ai">
    <button type="button" class="btn btn--secondary btn--small" data-copy-ai="${id}">Copy for any AI</button>
    <span class="muted get-help__where">Copies the text to paste into ChatGPT, Claude or another assistant.</span>
    <div class="copy-ai__slot" data-copy-ai-slot="${id}" aria-live="polite"></div>
  </div>`;
}

/** Called by app.js after a scan: everything needed for the whole-report copy. */
function setCopyAiReport(report) {
  copyAiRegistry.length = 0;
  copyAiReport = report;
}

function copyAiPanelHtml(text, key) {
  return `<div class="ask__panel copy-ai__panel" role="group" aria-label="Text to copy">
    <h4>What will be copied</h4>
    <p>${copyAiEscape(COPY_AI_INTRO)}</p>
    <textarea class="copy-ai__text" rows="14" spellcheck="false" data-copy-ai-text="${key}">${copyAiEscape(text)}</textarea>
    <div class="ask__actions">
      <button type="button" class="btn btn--primary btn--small" data-copy-ai-go="${key}">Copy</button>
      <button type="button" class="btn btn--secondary btn--small" data-copy-ai-close="${key}">Close</button>
      <span class="muted" role="status" data-copy-ai-status="${key}"></span>
    </div>
  </div>`;
}

// "Copy technical report": the raw scan, except saved-key comments (often
// user@host or a person's name), as `rescue export` leaves them out. They are
// in data.keys[].comment and in a key list's markable.items[].detail; the card
// on screen still shows them.
const KEY_COMMENT_LEFT_OUT = '[left out: key comment]';

function withoutKeyCommentsDeep(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 12) return value;
  if (Array.isArray(value)) return value.map((v) => withoutKeyCommentsDeep(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (k === 'keys' && Array.isArray(v)) {
      out[k] = v.map((key) => (key && typeof key === 'object' && !Array.isArray(key) && key.comment
        ? Object.assign({}, key, { comment: KEY_COMMENT_LEFT_OUT }) : withoutKeyCommentsDeep(key, depth + 1)));
    } else if (k === 'markable' && v && typeof v === 'object' && v.kind === 'ssh_authorized_keys' && Array.isArray(v.items)) {
      out[k] = Object.assign({}, v, { items: v.items.map((it) => (it && typeof it === 'object' && it.detail
        ? Object.assign({}, it, { detail: KEY_COMMENT_LEFT_OUT }) : it)) });
    } else {
      out[k] = withoutKeyCommentsDeep(v, depth + 1);
    }
  }
  return out;
}

// City mode: the monitoring checks are left out of the copy entirely (names,
// ids and findings), since monitoring software can read the clipboard.
const COVER_LEFT_OUT = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
function withoutMonitoring(doc) {
  if (!doc || !Array.isArray(doc.modules)) return doc;
  return Object.assign({}, doc, { modules: doc.modules.filter((m) => !(m && COVER_LEFT_OUT.has(m.name))) });
}

function technicalReportText(doc, opts) {
  const shown = opts && opts.cover ? withoutMonitoring(doc) : doc;
  return JSON.stringify(withoutKeyCommentsDeep(shown), null, 2);
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { copyAiPanelHtml, copyAiPick, COPY_AI_INTRO, technicalReportText, KEY_COMMENT_LEFT_OUT, withoutMonitoring };
}

if (typeof document !== 'undefined') {
  const slot = (key) => document.querySelector(`[data-copy-ai-slot="${key}"]`);

  async function open(key) {
    // 'all' (the whole LIST) or one card's id.
    const findings = key === 'all'
      ? (copyAiReport && copyAiReport.findings) || []
      : /^\d+$/.test(String(key)) ? [copyAiRegistry[Number(key)]].filter(Boolean) : [];
    if (!findings.length && key !== 'all') return;
    const payload = Object.assign({}, copyAiReport || {}, { findings });
    let text = null;
    try {
      text = await window.rescue.aiPrompt(payload);
    } catch (_e) {
      text = null;
    }
    slot(key).innerHTML = text
      ? copyAiPanelHtml(text, key)
      : '<p class="ask__error">There was nothing to copy.</p>';
  }

  async function copy(key) {
    const box = document.querySelector(`[data-copy-ai-text="${key}"]`);
    const status = document.querySelector(`[data-copy-ai-status="${key}"]`);
    try {
      // The textarea, so anything the person deleted stays deleted.
      await navigator.clipboard.writeText(box.value);
      status.textContent = ' Copied. Paste it into your AI assistant.';
    } catch (err) {
      status.textContent = ` Couldn’t copy (${err && err.message ? err.message : err}). Select the text and copy it by hand.`;
    }
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest && ev.target.closest('[data-copy-ai],[data-copy-ai-go],[data-copy-ai-close]');
    if (!t) return;
    if (t.hasAttribute('data-copy-ai')) open(t.getAttribute('data-copy-ai'));
    else if (t.hasAttribute('data-copy-ai-go')) copy(t.getAttribute('data-copy-ai-go'));
    else slot(t.getAttribute('data-copy-ai-close')).innerHTML = '';
  });
}
