'use strict';

/*
 * How much the list and the game say to someone who may be watched by a
 * person close to them. Standard mode: no hotline or advocate wording, except
 * that a finding that is monitoring software, or that warns removing it can
 * alert someone (a walkthrough's safety note, or a sentence saying so), keeps
 * one line with the full note behind it. Quieting never takes the warning
 * away. City mode is never quieted: every finding keeps its own text and its
 * safety note in full, and monitoring software gets the hold line and its
 * help instead, and nothing to act on. Everything here works on copies; the
 * scan is never changed.
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
  // Generic words like "partner" alone don't count, and neither does a bare
  // "DV": under /i it matched the flag in `codesign -dv`.
  const MARKERS = /799-7233|88788|\btext\s+START\b|\badvocates?\b|domestic\s+violence|\bDV\s+Hotline\b|\bpartner,\s+(?:an\s+)?ex\b|\bex-partner\b|\bhousemates?\b|\babuser\b/i;
  const LINE = 'Removing this can alert whoever installed it. Read this first.';
  // The same warning, on its face, before a card's fix and mark buttons and in the fix confirm.
  const LINE_SHORT = 'Removing this can alert whoever installed it.';
  // A sentence that warns removing or switching something off can alert
  // someone: "removing it can alert them", "Switching off remote access
  // someone else set up can alert them", "removal can alert them".
  const ALERTS = /\b(?:remov(?:e|es|ed|ing|al)|uninstall\w*|delet\w*|disabl\w*|(?:switch|turn)\w*\s+(?:\S+\s+){0,3}?off)\b[^.!?]*?\b(?:can|may|could|might|will|would)\s+(?:alert|tip\s+off|notify|warn)\b/i;
  const DEFAULT_FULL = 'If someone close to you may have installed it, talk to an advocate before you remove anything. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.';
  const HELD_LINE = 'Don’t remove it yet. Talk to an advocate first.';
  const HELD_MORE = 'Open the city to see how to keep a quiet record of it.';
  // The help behind the hold line, until the city's own district has it:
  // "Keep a record" and the last sentence of "Decide whether it's safe to
  // remove", word for word from guides/remediation/respond_to_monitoring_software.md,
  // and the advocate note above. Nothing here says to remove anything.
  // What an AI is told about a held finding ("Copy for any AI", "Ask about this").
  const HELD_AI_NOTE = 'Don’t suggest removing or disabling it; the person may be at risk if it’s removed. Suggest documenting it and talking to an advocate.';
  // A sentence that tells the person to act on the software: remove, uninstall,
  // delete, disable, move, or turn or switch it off, and the engine's own
  // "What to do". None of it is shown on a held card.
  const ACTS = /\b(?:re)?mov(?:e|es|ed|ing|al)\b|\buninstall\w*|\bdelet\w*|\bdisabl\w*|\b(?:turn|switch)\w*\b(?:\s+\S+){0,3}?\s+off\b|\bwhat to do\b/i;
  const HELD_ABOUT = 'The checkup found this on your computer.';
  const HELD_HELP_TITLE = 'How to keep a quiet record, and who can help';
  const HELD_HELP = [
    'On paper or on another device, write down the name the scan found, where it was found, and today\'s date. Take a photo of the scan result with your phone. That record can matter later, for a protective order or a police report, and removing the software erases most of it.',
    DEFAULT_FULL,
    'Use a phone or computer the other person can\'t reach.',
  ];

  function isMonitoring(finding) {
    return !!finding && MONITORING_MODULES.has(finding.module);
  }

  // What these checks say when they found nothing, or couldn't look: MVT's
  // status lines (no backups, not installed, scan not run, too large, clean)
  // and keylogger_indicators' plain list of apps with keyboard access. None of
  // them is monitoring software, so they read like any other finding. Anything
  // else from these checks with a code is a detection, at any severity (an
  // info-level product like remote-support software is still on the computer).
  // With no code, only an info line isn't one. held.js has the same rule; a
  // test keeps them equal.
  const NOT_DETECTIONS = new Set([
    'security.mvt_spyware_scan.mvt_requires_wsl',
    'security.mvt_spyware_scan.no_backups_found',
    'security.mvt_spyware_scan.mvt_not_installed',
    'security.mvt_spyware_scan.mvt_scan_available',
    'security.mvt_spyware_scan.mvt_backup_too_large',
    'security.mvt_spyware_scan.mvt_clean_scan',
    'security.keylogger_indicators.input_monitoring_access',
  ]);
  function isDetection(finding) {
    if (!isMonitoring(finding)) return false;
    if (finding.code) return !NOT_DETECTIONS.has(finding.code);
    return finding.severity !== 'info';
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

  // A held card says only what the software is: the description's first
  // paragraph, without hotline sentences or any sentence that says to act on it.
  function heldDescription(text) {
    const first = paragraphs(text).find((p) => p.trim() !== '') || '';
    const kept = sentences(quiet(first)).filter((x) => !ACTS.test(x)).join('').trim();
    return kept || HELD_ABOUT;
  }

  // Whether a finding warns that removing it can alert someone: a safety
  // note, a sentence that says so in its description or steps, or (already
  // quieted) the note quietFinding kept for it.
  function carriesAlert(f) {
    if (!f || typeof f !== 'object') return false;
    if (Array.isArray(f.quiet_full) && f.quiet_full.length) return true;
    const rem = f.remediation && typeof f.remediation === 'object' ? f.remediation : null;
    if (rem && rem.safety_note) return true;
    if (ALERTS.test(String(f.description == null ? '' : f.description))) return true;
    return !!(rem && Array.isArray(rem.steps) && rem.steps.some((s) => s && ALERTS.test(String(s.body == null ? '' : s.body))));
  }

  // Standard mode's copy of a finding: no hotline or advocate wording in its
  // description or steps, and no safety note. A finding that warned about
  // removal keeps that warning as `quiet_full` (memory only), which the one
  // line shows behind it.
  function quietFinding(f) {
    if (!f || typeof f !== 'object') return f;
    const out = { ...f };
    if (carriesAlert(f)) out.quiet_full = fullNote(f);
    if (f.description != null) out.description = quiet(f.description);
    const rem = f.remediation && typeof f.remediation === 'object' ? f.remediation : null;
    if (rem) {
      out.remediation = { ...rem };
      delete out.remediation.safety_note;
      if (Array.isArray(rem.steps)) out.remediation.steps = rem.steps.map((s) => (s && typeof s === 'object' ? { ...s, body: quiet(s.body) } : s));
    }
    return out;
  }

  // City mode is never quieted.
  function quietDoc(doc, mode) {
    if (mode === 'city' || !doc || !Array.isArray(doc.modules)) return doc;
    return { ...doc, modules: doc.modules.map((m) => {
      if (!m || !Array.isArray(m.findings) || MONITORING_MODULES.has(m.name)) return m;
      return { ...m, findings: m.findings.map(quietFinding) };
    }) };
  }

  // 'line': the one line, full note behind it (standard). 'held': the hold
  // line and nothing to act on (city, monitoring software). 'full': the
  // finding's own text, unquieted, with its safety note in full (city).
  // 'none': nothing more to say.
  function noteFor(mode, finding) {
    if (isDetection(finding)) return mode === 'city' ? 'held' : 'line';
    if (!carriesAlert(finding)) return 'none';
    // A safety control: city mode always shows the full note, and an
    // explicit engine safety note (or one already kept as quiet_full) always
    // shows. Only a warning inferred from description or step text may be
    // left off, and only when the finding plainly can't be monitoring
    // software: not a monitoring-capable check AND no way to remove it on
    // the card. A verified signature never suppresses it. In doubt: shown.
    if (mode === 'city') return 'full';
    if (hasExplicitNote(finding)) return 'line';
    return inferredOnlyNoise(finding) ? 'none' : 'line';
  }
  function hasExplicitNote(f) {
    if (!f || typeof f !== 'object') return false;
    if (Array.isArray(f.quiet_full) && f.quiet_full.length) return true;
    return !!(f.remediation && typeof f.remediation === 'object' && f.remediation.safety_note);
  }
  function inferredOnlyNoise(f) {
    const x = f || {};
    return !MONITOR_CAPABLE.has(x.module) && !offersRemoval(x);
  }

  // Checks whose findings can be monitoring software: things that start on
  // their own, give remote access or can watch. Used only to leave off a
  // warning that was inferred from text (see noteFor).
  const MONITOR_CAPABLE = new Set([
    'launch_agent_audit', 'launchd_persistence_audit', 'scheduled_tasks_audit', 'cron_jobs_audit', 'login_items',
    'startup_auditor', 'ai_worm_persistence', 'crypto_miner_persistence', 'linux_persistence_audit',
    'remote_login_check', 'sharing_services', 'sharing_preferences_audit', 'ssh_key_audit', 'session_revocation_scan',
    'network_proxy', 'network_proxy_check', 'network_proxy_detect', 'browser_extension_audit', 'chrome_extensions',
    'safari_extensions', 'system_extensions', 'kernel_extensions_audit', 'mdm_enrollment', 'mdm_enrollment_check',
    'certificate_trust_audit', 'win_autorun', 'win_autoruns_audit', 'win_scheduled_tasks', 'win_scheduled_tasks_security',
    'win_services_audit', 'win_services_security_audit', 'win_rdp_check', 'win_remote_access_audit', 'win_proxy_detect',
  ]);
  const REMOVAL = /\b(?:remov\w*|uninstall\w*|delet\w*|disabl\w*|unload\w*|bootout|quarantin\w*|revok\w*|(?:turn|switch)\w*\s+(?:\S+\s+){0,3}?off)\b/i;
  function offersRemoval(f) {
    if (f.fixable && typeof f.fixable === 'object') return true;
    const rem = f.remediation && typeof f.remediation === 'object' ? f.remediation : null;
    if (rem && Array.isArray(rem.steps) && rem.steps.some((st) => st && REMOVAL.test(`${st.title || ''} ${st.body || ''}`))) return true;
    return /(^|\n)\s*what to do:[^\n]*/i.test(String(f.description || ''))
      && REMOVAL.test((/(?:^|\n)\s*what to do:([^\n]*)/i.exec(String(f.description || '')) || [])[1] || '');
  }
  function canMonitor(finding) {
    const f = finding || {};
    return !inferredOnlyNoise(f);
  }

  function fullNote(f) {
    if (Array.isArray(f.quiet_full) && f.quiet_full.length) return f.quiet_full.slice();
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
  // the careful way to deal with it, read after the line. In city mode
  // nothing is quieted.
  // A sentence that points at steps the card doesn't show ("the steps below
  // cover removal…"): out, when there are none.
  const STEPS_BELOW = /\bsteps?\s+below\b|\bbelow\b[^.!?]*\bsteps?\b/i;
  function withoutMissingSteps(text, steps) {
    if (steps && steps.length) return text;
    return paragraphs(text).map((p) => sentences(p).filter((x) => !STEPS_BELOW.test(x)).join('').replace(/\s+$/, ''))
      .filter((p) => p.trim() !== '').join('\n\n');
  }

  function cardText(mode, finding) {
    const out = cardTextRaw(mode, finding);
    return { ...out, description: withoutMissingSteps(out.description, out.steps) };
  }

  function cardTextRaw(mode, finding) {
    const f = finding || {};
    const note = noteFor(mode, f);
    if (note === 'held') return { note, description: heldDescription(f.description), steps: [], full: [] };
    const steps = f.remediation && Array.isArray(f.remediation.steps) ? f.remediation.steps : [];
    if (mode === 'city') {
      const sn = f.remediation && f.remediation.safety_note;
      return { note, description: f.description == null ? '' : String(f.description), steps, full: sn ? [String(sn)] : [] };
    }
    if (note === 'line' && isDetection(f)) return { note, description: quiet(f.description), steps, full: fullNote(f) };
    const q = quietFinding(f);
    if (note === 'line') {
      return { note, description: q.description == null ? '' : q.description,
        steps: q.remediation && Array.isArray(q.remediation.steps) ? q.remediation.steps : [], full: fullNote(f) };
    }
    return { note, description: q.description == null ? '' : q.description,
      steps: q.remediation && Array.isArray(q.remediation.steps) ? q.remediation.steps : [], full: [] };
  }

  // City mode: the safety note as it is, on its face.
  function fullHtml(card, esc) {
    if (!card || card.note !== 'full' || !card.full.length) return '';
    return `<div class="finding-card__note" role="note">${card.full.map((p) => `<p>${esc(p)}</p>`).join('')}</div>`;
  }

  // `opts.first`: the card has fix or mark buttons, so the warning is on its
  // face above them, with the full note behind "Read this first".
  function lineHtml(card, esc, opts = {}) {
    if (!card || card.note !== 'line') return '';
    if (opts.first) {
      return `<div class="finding-card__note finding-card__note--first" role="note"><p><strong>${esc(LINE_SHORT)}</strong></p>`
        + `<details><summary>Read this first</summary>${card.full.map((p) => `<p>${esc(p)}</p>`).join('')}</details></div>`;
    }
    return `<details class="finding-card__note"><summary>${esc(LINE)}</summary>${card.full.map((p) => `<p>${esc(p)}</p>`).join('')}</details>`;
  }

  // The hold line, then the help behind it. `more: false` leaves out the
  // pointer to the city (when this is already in the city); `open: true`
  // shows the help without a click.
  function heldHtml(card, esc, opts = {}) {
    if (!card || card.note !== 'held') return '';
    const more = opts.more === false ? '' : ` ${esc(HELD_MORE)}`;
    return `<p class="finding-card__note" role="note"><strong>${esc(HELD_LINE)}</strong>${more}</p>`
      + `<details class="finding-card__held-help"${opts.open ? ' open' : ''}><summary>${esc(HELD_HELP_TITLE)}</summary>`
      + `${HELD_HELP.map((p) => `<p>${esc(p)}</p>`).join('')}</details>`;
  }

  // What "Copy for any AI" and "Ask about this" get for a held card: the
  // card's own text, never the engine's description, steps or evidence (which
  // carry removal steps and the path). `held: true` has the copy carry
  // HELD_AI_NOTE; the ask, which takes only these fields, has it in the text.
  function heldPick(card, finding) {
    const f = finding || {};
    return { title: f.title, description: card.description, severity: f.severity, category: f.category,
      code: f.code, module: f.module, held: true };
  }
  function heldAsk(card, finding) {
    const f = finding || {};
    return { title: f.title, description: `${card.description}\n\n${HELD_AI_NOTE}`, severity: f.severity,
      category: f.category, code: f.code };
  }

  return { MONITORING_MODULES, NOT_DETECTIONS, MONITOR_CAPABLE, canMonitor, isDetection, MARKERS, ALERTS, carriesAlert, fullHtml, LINE, LINE_SHORT, HELD_LINE, HELD_MORE, HELD_HELP, HELD_HELP_TITLE, HELD_AI_NOTE, ACTS, heldDescription, heldPick, heldAsk, isMonitoring, quiet, quietFinding, quietDoc, noteFor, cardText, lineHtml, heldHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuietNotes;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.QuietNotes = QuietNotes;
}
