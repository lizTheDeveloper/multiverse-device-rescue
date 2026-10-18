'use strict';

/*
 * How much the list and the game say to someone who may be watched by a
 * person close to them. Standard mode: none of it, except on a finding that
 * is itself monitoring software, which carries one line with the full note
 * behind it. Everything here works on copies; the scan is never changed.
 *
 * Loaded as a plain script (global `QuietNotes`, also on window for the game).
 */
const QuietNotes = (function () {
  // The same three checks app.js's ALWAYS_SAFETY_MODULES names; a test keeps them equal.
  const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  // A paragraph or list item that speaks to someone close to the person.
  const MARKERS = /799-7233|88788|\badvocates?\b|domestic\s+violence|someone\s+close\s+to\s+you|\b(ex-)?partner\b|\babuser\b/i;
  const LINE = 'Removing this can alert whoever installed it. Read this first.';
  const DEFAULT_FULL = 'If someone close to you may have installed it, talk to an advocate before you remove anything. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.';

  function isMonitoring(finding) {
    return !!finding && MONITORING_MODULES.has(finding.module);
  }

  const isItem = (line) => /^\s*([-*]|\d+\.)\s+/.test(line);

  function quietParagraph(p) {
    const lines = p.split('\n');
    if (!lines.some(isItem)) return MARKERS.test(p) ? '' : p;
    // A list: only the items (with their wrapped lines) that carry it come out.
    const items = [];
    for (const line of lines) {
      if (isItem(line) || !items.length) items.push([line]);
      else items[items.length - 1].push(line);
    }
    return items.filter((it) => !MARKERS.test(it.join(' '))).map((it) => it.join('\n')).join('\n');
  }

  function paragraphs(text) {
    return String(text == null ? '' : text).split(/\n\s*\n/);
  }

  function quiet(text) {
    return paragraphs(text).map(quietParagraph).filter((p) => p.trim() !== '').join('\n\n');
  }

  function loud(text) {
    return paragraphs(text).map((p) => p.trim()).filter((p) => p && MARKERS.test(p));
  }

  function quietFinding(f) {
    if (!f || typeof f !== 'object') return f;
    const out = { ...f };
    if (f.description != null) out.description = quiet(f.description);
    const rem = f.remediation && typeof f.remediation === 'object' ? f.remediation : null;
    if (rem) {
      out.remediation = { ...rem };
      delete out.remediation.safety_note;
      if (Array.isArray(rem.steps)) out.remediation.steps = rem.steps.map((s) => (s && typeof s === 'object' ? { ...s, body: quiet(s.body) } : s));
    }
    return out;
  }

  function quietDoc(doc) {
    if (!doc || !Array.isArray(doc.modules)) return doc;
    return { ...doc, modules: doc.modules.map((m) => {
      if (!m || !Array.isArray(m.findings) || MONITORING_MODULES.has(m.name)) return m;
      return { ...m, findings: m.findings.map(quietFinding) };
    }) };
  }

  // 'line': the one line, with the full note behind it. 'none': nothing.
  function noteFor(mode, finding) {
    return isMonitoring(finding) ? 'line' : 'none';
  }

  function fullNote(f) {
    const out = [];
    const sn = f.remediation && f.remediation.safety_note;
    if (sn) out.push(String(sn));
    for (const p of loud(f.description)) if (!out.includes(p)) out.push(p);
    return out.length ? out : [DEFAULT_FULL];
  }

  // What one card may say. Monitoring software keeps its own steps: they are
  // the careful way to deal with it, read after the line.
  function cardText(mode, finding) {
    const f = finding || {};
    const note = noteFor(mode, f);
    const steps = f.remediation && Array.isArray(f.remediation.steps) ? f.remediation.steps : [];
    if (note === 'line') return { note, description: quiet(f.description), steps, full: fullNote(f) };
    const q = quietFinding(f);
    return { note, description: q.description == null ? '' : q.description,
      steps: q.remediation && Array.isArray(q.remediation.steps) ? q.remediation.steps : [], full: [] };
  }

  function lineHtml(card, esc) {
    if (!card || card.note !== 'line') return '';
    return `<details class="finding-card__note"><summary>${esc(LINE)}</summary>${card.full.map((p) => `<p>${esc(p)}</p>`).join('')}</details>`;
  }

  return { MONITORING_MODULES, MARKERS, LINE, isMonitoring, quiet, quietFinding, quietDoc, noteFor, cardText, lineHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuietNotes;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.QuietNotes = QuietNotes;
}
