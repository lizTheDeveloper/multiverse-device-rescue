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
  // A sentence that is hotline or domestic-violence wording: a number, the
  // hotline, an advocate, or "a partner, ex or housemate". Only those
  // sentences come out; every other sentence (keep the evidence, don't delete
  // it, change passwords from another device, back up and reinstall) stays.
  // Generic words like "partner" alone don't count.
  const MARKERS = /799-7233|88788|\btext\s+START\b|\badvocates?\b|domestic\s+violence|\bDV\b|\bpartner,\s+(?:an\s+)?ex\b|\bex-partner\b|\bhousemates?\b|\babuser\b/i;
  const LINE = 'Removing this can alert whoever installed it. Read this first.';
  const DEFAULT_FULL = 'If someone close to you may have installed it, talk to an advocate before you remove anything. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.';

  function isMonitoring(finding) {
    return !!finding && MONITORING_MODULES.has(finding.module);
  }

  const ITEM = /^\s*(?:[-*]|\d{1,3}\.)\s+/; // "88788." wrapped onto its own line is not item 88788
  const HEADING = /^\s*#{1,6}\s/;
  const ABBREV = /\b(?:e\.g|i\.e|etc|vs|Mr|Mrs|Ms|Dr|St)\.$/i;

  // Text cut into sentences, each with the whitespace after it, so joining
  // them gives the text back exactly.
  function sentences(text) {
    const out = [];
    const re = /[.!?]+["'”’)\]*_`]*(?=\s)/g;
    let start = 0;
    let m;
    while ((m = re.exec(text))) {
      const end = m.index + m[0].length;
      const ws = /^\s+/.exec(text.slice(end))[0];
      const next = text.charAt(end + ws.length);
      if (/[a-z]/.test(next) || ABBREV.test(text.slice(start, end))) continue; // "e.g. the", not a new sentence
      out.push(text.slice(start, end + ws.length));
      start = end + ws.length;
    }
    if (start < text.length) out.push(text.slice(start));
    return out;
  }

  // [kept text, removed sentences] for one run of prose.
  function split(text) {
    const parts = sentences(text);
    const gone = parts.filter((x) => MARKERS.test(x));
    if (!gone.length) return [text, []];
    return [parts.filter((x) => !MARKERS.test(x)).join('').replace(/\s+$/, ''), gone.map((x) => x.trim())];
  }

  // Units of a paragraph: heading lines and list items (with their wrapped
  // lines) on their own, so a sentence never runs across them.
  function units(p) {
    const out = [];
    for (const line of p.split('\n')) {
      const prev = out[out.length - 1];
      if (HEADING.test(line) || ITEM.test(line) || !prev || prev.heading) out.push({ lines: [line], heading: HEADING.test(line) });
      else prev.lines.push(line);
    }
    return out.map((u) => u.lines.join('\n'));
  }

  // [quiet paragraph, removed sentences].
  function quietParagraph(p) {
    const kept = [];
    const gone = [];
    for (const u of units(p)) {
      const lead = (ITEM.exec(u) || HEADING.exec(u) || [''])[0];
      const [body, out] = split(u.slice(lead.length));
      gone.push(...out);
      if (body.trim() !== '') kept.push(lead + body);
    }
    return [kept.join('\n'), gone];
  }

  function paragraphs(text) {
    return String(text == null ? '' : text).split(/\n\s*\n/);
  }

  function quiet(text) {
    return paragraphs(text).map((p) => quietParagraph(p)[0]).filter((p) => p.trim() !== '').join('\n\n');
  }

  // What quiet() takes out, one entry per paragraph.
  function loud(text) {
    return paragraphs(text).map((p) => quietParagraph(p)[1].join(' ')).filter((p) => p !== '');
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
    // The hotline once: when the walkthrough's note already gives it, the
    // description's own hotline sentences aren't repeated under it.
    const gives = (t) => /799-7233/.test(t);
    for (const p of loud(f.description)) {
      if (out.includes(p) || (sn && gives(String(sn)) && gives(p))) continue;
      out.push(p);
    }
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
