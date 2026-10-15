// "Copy for any AI" UI. Each finding card gets a button; the results page gets
// one for the whole report. A click asks the main process to build the
// redacted text, shows it in full, and copies only when the person presses Copy.

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

function copyAiButtonHtml(finding) {
  const id = copyAiRegistry.push(copyAiPick(finding)) - 1;
  return `<div class="copy-ai">
    <button type="button" class="btn btn--secondary btn--small" data-copy-ai="${id}">Copy for any AI</button>
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

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { copyAiPanelHtml, copyAiPick, COPY_AI_INTRO };
}

if (typeof document !== 'undefined') {
  const slot = (key) => document.querySelector(`[data-copy-ai-slot="${key}"]`);

  async function open(key) {
    const findings = key === 'all'
      ? (copyAiReport && copyAiReport.findings) || []
      : [copyAiRegistry[Number(key)]].filter(Boolean);
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
