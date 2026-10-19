'use strict';

/*
 * Reclaim City renderer app.
 *
 * Pure helpers (detectOS, groupFindingsBySeverity) live at the top and are
 * exported for Node so they can be sanity-checked outside the browser. The
 * DOM-wiring code below only runs when a `document` is present (i.e. inside
 * Electron's renderer process).
 */

const SEVERITY_ORDER = ['critical', 'warning', 'info'];
const SEVERITY_LABELS = {
  critical: 'Needs attention now',
  warning: 'Worth a look',
  info: 'Good to know',
};
const SEVERITY_DESCRIPTIONS = {
  critical: 'These are the most important findings from your checkup.',
  warning: 'These are worth reviewing when you have a moment.',
  info: 'Things we noticed. Nothing to do.',
};

/**
 * The "what's worrying you?" choices. Each runs one profile from profiles/
 * (null = every check) and links to that situation's step-by-step guide.
 * Worded the way a frightened person would say it, not the way we name things.
 */
const SITUATIONS = [
  { id: 'hacked', icon: '\u{1F513}', title: 'I think I\u2019ve been hacked',
    sub: 'Strange logins, passwords changed, accounts acting on their own',
    profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/' },
  { id: 'watched', icon: '\u{1F440}', title: 'I think someone is watching me',
    sub: 'A partner, ex, or housemate may have put something on this computer',
    profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/', safety: true },
  { id: 'wifi', icon: '\u{1F4F6}', title: 'Someone is on my Wi-Fi, or my computer is hot and slow',
    sub: 'Unknown devices, a hijacked router, or hidden crypto-mining',
    profile: 'home_network_intrusion', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/home-network-intrusion/' },
  { id: 'identity', icon: '\u{1FAAA}', title: 'Someone stole my identity',
    sub: 'Accounts opened in my name, money missing, credit alerts',
    profile: 'identity_theft_recovery', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/identity-theft-recovery/' },
  { id: 'sketchy', icon: '\u{1F41B}', title: 'I installed something sketchy',
    sub: 'A bad npm or pip package, an AI tool, a coding extension',
    profile: 'ai_worm_response', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/ai-worm-response/' },
  { id: 'phone', icon: '\u{1F4F1}', title: 'I\u2019m worried about spyware on my iPhone',
    sub: 'Needs a backup of the iPhone saved on this computer',
    profile: 'iphone_spyware_check', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/iphone-spyware-check/' },
  { id: 'helping', icon: '\u{1F381}', title: 'I\u2019m helping a family member',
    sub: 'A friendly tune-up and safety check on someone else\u2019s computer',
    profile: 'home_for_the_holidays', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/home-for-the-holidays/' },
  { id: 'unsure', icon: '\u{1F937}', title: 'I\u2019m not sure \u2014 check everything',
    sub: 'The full checkup: every check there is.',
    profile: null, guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/' },
];

// worries.js loads before app.js in the page; the Node tests require it.
const WorryPick = typeof Worries !== 'undefined' ? Worries : require('./worries.js');

const CATEGORY_PHRASES = {
  security: 'Looking for security problems',
  integrity: 'Checking that your system is healthy',
  performance: 'Checking speed and storage',
  network: 'Checking your network',
  bloatware: 'Looking for unwanted software',
};

/** Render a traced command for the technical log, shell-style. */
function formatExec(ev) {
  const argv = (ev.argv || []).map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${String(a).replace(/'/g, "'\\''")}'`));
  const outcome = ev.returncode == null ? `did not start${ev.error ? `: ${ev.error}` : ''}` : `exit ${ev.returncode}`;
  return `    $ ${argv.join(' ')}   (${outcome}, ${ev.seconds}s)`;
}

/**
 * Turn an engine progress event into words for the status line, e.g.
 * {phase:'start', index:23, total:120, module:'launch_agent_audit', category:'security'}
 *  -> { headline: 'Looking for security problems', detail: 'Launch agent audit · check 23 of 120', percent: 18 }
 */
function describeProgress(ev) {
  // No check id on screen ("Smcreset guide"): the count is what helps.
  const done = ev.phase === 'done' ? ev.index : ev.index - 1;
  return {
    headline: CATEGORY_PHRASES[ev.category] || 'Checking your computer',
    detail: `Check ${ev.index} of ${ev.total}`,
    percent: ev.total ? Math.round((done / ev.total) * 100) : 0,
  };
}

/**
 * "Who made it?" One plain line per program a finding names, from the engine's
 * `made_by` entries ({subject, name, verified, how, location_note, what?}).
 * tone 'ok' = calm green, 'warn' = amber. `what` ("Loom: records your screen…")
 * is only ever set by the engine for a verified signature; it is shown only then.
 */
const MADE_BY_VERIFIED_LABEL = {
  'Developer ID signature': 'verified signature',
  'Authenticode signature': 'verified signature',
  'Mac App Store signature': 'App Store signature',
  'Apple system file': 'part of macOS',
  'Homebrew package': 'Homebrew package',
  'system package': 'installed by your system package manager',
};
const MADE_BY_REASON = {
  unsigned: 'not signed',
  'ad-hoc signed': 'only self-signed by whoever built it',
  'development certificate': "signed with a developer's test certificate, not a published one",
  'unrecognised signature': 'its signature could not be recognised',
  'not part of any installed package': 'not part of any installed package',
  'started with extra instructions': 'the program is signed, but this background job gives it extra instructions the signature doesn\u2019t cover',
  'inline command': 'it runs a command written into its settings',
  'program not named by full path': 'its settings don\u2019t say exactly which program runs',
  'settings change how the program loads code': 'its settings change how or where the program runs',
  'unreadable settings': 'its settings could not be read clearly',
};
// For these, the engine's note (rescue/attribution.py) is a whole sentence that
// already says why, so it replaces the short reason instead of repeating it.
const MADE_BY_NOTE_SAYS_WHY = new Set([
  'script',
  'inline command',
  'program not named by full path',
  'settings change how the program loads code',
  'unreadable settings',
]);

function sameStart(note, reason) {
  const norm = (s) => String(s).toLowerCase().replace(/[’']/g, "'").replace(/\s+/g, ' ').trim();
  return norm(note).startsWith(norm(reason));
}

function describeMadeBy(entry) {
  const e = entry || {};
  const name = e.name || 'Unknown maker';
  const note = e.location_note ? String(e.location_note).trim() : '';
  const subject = String(e.subject || '').split(/[\\/]/).filter(Boolean).pop() || '';
  if (e.verified) {
    const label = MADE_BY_VERIFIED_LABEL[e.how] || e.how || 'verified';
    // A verified maker running from a risky folder deserves a second look.
    const mark = note ? '⚠' : '✓';
    const what = typeof e.what === 'string' ? e.what.trim() : '';
    return { tone: note ? 'warn' : 'ok', text: `${mark} Made by ${name} (${label})${note ? '. ' + note : ''}`, subject, what };
  }
  if (e.how === 'script') {
    return { tone: 'warn', text: `⚠ Unknown maker: ${note || 'a script, not signed; check who created it.'}`, subject };
  }
  const reason = MADE_BY_REASON[e.how] || e.how || 'not verified';
  const head = name === 'Unknown maker' ? 'Unknown maker' : `Made by ${name}, but it cannot be verified`;
  if (note && (MADE_BY_NOTE_SAYS_WHY.has(e.how) || sameStart(note, reason))) {
    return { tone: 'warn', text: `⚠ ${head}: ${note}`, subject };
  }
  return { tone: 'warn', text: `⚠ ${head}: ${reason}.${note ? ' ' + note : ''}`, subject };
}

// `opts.explain: false` leaves out "What does this mean?": it is taught once,
// on the first card that has a made-by line.
function madeByHtml(entries, esc, opts) {
  if (!Array.isArray(entries) || entries.length === 0) return '';
  const lines = entries.map((entry) => {
    const d = describeMadeBy(entry);
    const who = entries.length > 1 && d.subject ? `<span class="made-by__subject">${esc(d.subject)}</span> ` : '';
    const what = d.what ? `<span class="made-by__what"> \u2014 ${esc(d.what)}</span>` : '';
    return `<li class="made-by__line made-by__line--${d.tone}">${who}${esc(d.text)}${what}</li>`;
  }).join('');
  if (opts && opts.explain === false) return `<div class="made-by"><ul class="made-by__list">${lines}</ul></div>`;
  return `<div class="made-by"><ul class="made-by__list">${lines}</ul>
    <details class="made-by__explainer"><summary>What does this mean?</summary>
      <p>Programs can be digitally signed by the company that made them, like a seal on a package. A <strong>verified signature</strong> means the seal is real and names the maker. An <strong>unknown maker</strong> is not proof of anything bad, but nobody has vouched for it, so be more careful, especially if it runs from a temporary folder or one you did not install into. For some well-known programs we also say what they are for, but only when the signature proves which program it is.</p>
    </details></div>`;
}

/**
 * A deliberately tiny Markdown renderer for the fix walkthroughs: paragraphs,
 * numbered and bulleted lists, `code`, **bold**, and ```fenced``` blocks.
 * Everything is HTML-escaped first, so walkthrough text can never inject markup.
 */
/**
 * A finding description as paragraphs (blank lines separate them), with a
 * leading "What to do:" picked out so the action is easy to find.
 */
function descriptionHtml(text, esc) {
  return String(text || '')
    .split(/\n\s*\n/)
    .map((para) => para.trim())
    .filter(Boolean)
    .map((para) => {
      const m = para.match(/^(what to do:)\s*/i);
      const body = esc(m ? para.slice(m[0].length) : para).replace(/\n/g, '<br>');
      return m
        ? `<p class="finding-card__todo"><strong>${esc(m[1])}</strong> ${body}</p>`
        : `<p>${body}</p>`;
    })
    .join('');
}

// Findings that are themselves monitoring software: these carry the advocate
// note whatever worry the person picked.
const ALWAYS_SAFETY_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

const RECLAIM_CITY_URL = 'https://play.multiversegames.ai/reclaim-city/';

/**
 * Reclaim City, the same team's free privacy game, as a "learn this properly"
 * link at the end of the results. The checkup doesn't teach passwords or
 * two-step sign-in itself; the game does, so the worries where that matters
 * point there. Each points at the district that teaches it: the game routes
 * #/district/<id>, and its Quick Quests are links to those same districts.
 * Worries with no real match get nothing.
 */
const GAME_INTRO = 'Reclaim City also comes as a free game you play in your web browser.';
const LEARN_MORE = {
  hacked: { path: '#/district/master-keys',
    text: 'Its “My email got hacked” Quick Quest opens The Master Keys, which walks you through checking who has signed in, setting new passwords and turning on two-step sign-in for your email, one account at a time.' },
  identity: { path: '#/district/reclamation',
    text: 'Its chapter The Reclamation walks you through freezing your credit and asking data brokers to remove your details, one small mission at a time.' },
  helping: { path: '',
    text: 'It walks you through passwords, two-step sign-in, data brokers and spotting scams, one small mission at a time.' },
  unsure: { path: '',
    text: 'It walks you through passwords, two-step sign-in, data brokers and spotting scams, one small mission at a time.' },
};

/**
 * Whether the person may be watched by someone close to them: they said so
 * ("watching me"), they're worried about iPhone spyware, or the scan found
 * monitoring software. Then the web game's link isn't offered. (Game mode no
 * longer depends on this: see gameOfferedFor.)
 */
function mayBeWatched(situation, doc) {
  if (situation && (situation.safety || WorryPick.has(situation, 'phone'))) return true;
  const modules = (doc && doc.modules) || [];
  return modules.some((mod) => mod && ALWAYS_SAFETY_MODULES.has(mod.name)
    && (mod.findings || []).some((f) => f && (f.severity === 'critical' || f.severity === 'warning')));
}

/**
 * Whether the city plays this worry: every worry does, the iPhone check too
 * (its long backup sweep waits in the city until the person starts it).
 * Plain view is retired. In 'city' the game is the cover and its help lives
 * in one district; in 'standard' the city uses plain words.
 */
function gameOfferedFor(situation) {
  return !!situation;
}

/** 'city' opens straight into the game, before any worry is picked. */
function opensInGame(mode) {
  return mode === 'city';
}

/**
 * The game's home when the app opens in 'city' with no worry picked: the same
 * checkup as "I think someone is watching me", under a plain title.
 */
const CITY_SITUATION = Object.freeze({
  id: 'city', icon: '', title: 'Take back the city', sub: '',
  profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/',
});

/** After a worry is picked: its scan starts at once on the game's sweep screen when the game can draw. */
function gameScanFirst({ offered, ready }) {
  return !!(offered && ready);
}

/**
 * Whether monitoring software has turned up in any scan or re-check this
 * session. Sticky: not every profile runs the safety modules, so a later,
 * narrower clean scan says nothing about it. Kept in memory only, never in
 * storage, where it could tip off whoever is watching.
 */
function noteMonitoring(seen, doc) {
  return !!seen || mayBeWatched(null, doc);
}

/**
 * A failed scan's message, without Electron's IPC wrapper
 * ("Error invoking remote method 'rescue:scan': Error: ..."), which means
 * nothing to the person. '' when nothing is left; callers have a fallback.
 */
function scanErrorText(message) {
  return String(message == null ? '' : message)
    .replace(/^Error invoking remote method '[^']*':\s*/, '')
    .replace(/^[A-Za-z]*Error:\s*/, '')
    .trim();
}

/**
 * Each guide's name, for the list shown when several worries have different
 * guides. Named by what the guide helps with, never by the worry, so nothing
 * on screen says "watching me" under the city cover.
 */
const GUIDE_BASE = 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/';
const GUIDE_NAMES = Object.freeze({
  [`${GUIDE_BASE}digital-security-reset/`]: 'Securing your accounts',
  [`${GUIDE_BASE}home-network-intrusion/`]: 'Your home network and a hot, slow computer',
  [`${GUIDE_BASE}identity-theft-recovery/`]: 'Recovering from identity theft',
  [`${GUIDE_BASE}ai-worm-response/`]: 'After installing something sketchy',
  [`${GUIDE_BASE}iphone-spyware-check/`]: 'Checking an iPhone for spyware',
  [`${GUIDE_BASE}home-for-the-holidays/`]: 'A tune-up for a family member’s computer',
  [GUIDE_BASE]: 'All the step-by-step guides',
});

/** Every guide for these worries, in the list's order, each once: [{url, name}]. */
function guideLinksFor(situation) {
  if (!situation) return [];
  const urls = Array.isArray(situation.guides) && situation.guides.length ? situation.guides : [situation.guide];
  return [...new Set(urls.filter((u) => typeof u === 'string' && u))]
    .map((url) => ({ url, name: GUIDE_NAMES[url] || 'Step-by-step guide' }));
}

/**
 * The worry line "Copy for any AI" puts on the clipboard. In city mode, when
 * "someone is watching me" is among the worries, none: a clipboard-history
 * app can save the text to disk, where whoever is watching could read it.
 */
function copyAiSituation(situation, mode) {
  if (!situation || typeof situation.title !== 'string') return undefined;
  if (opensInGame(mode) && (situation.safety || WorryPick.has(situation, 'watched'))) return undefined;
  return situation.title;
}

/** The worry click: its scan starts at once in the game, or on the scan screen when the game can't draw. */
function worryStartsGameScan({ situation, ready }) {
  return gameScanFirst({ offered: gameOfferedFor(situation), ready });
}

/**
 * Where a finished scan lands: the city. The LIST (the results screen) only
 * when the city can't be drawn or the person left it (the city failed to
 * draw mid-scan). Monitoring software doesn't change it: the follow-up
 * question, when due, comes before this.
 */
function postScanView({ inGame, left, offered, ready }) {
  if (!offered || !ready || left) return 'results';
  return inGame ? 'boss-city' : 'city';
}

/** The Reclaim City suggestion for these results, or null (see mayBeWatched). */
function learnMoreFor(situation, doc) {
  if (!situation || mayBeWatched(situation, doc)) return null;
  // Several worries: the first one (in the list's order) that has a suggestion.
  const entry = WorryPick.firstWith(situation, LEARN_MORE);
  if (!entry) return null;
  return { text: `${GAME_INTRO} ${entry.text}`, url: RECLAIM_CITY_URL + entry.path };
}

/** "Step 2: Turn it off" -> "Turn it off" for the short What-to-do list. */
function stepTitle(title) {
  return String(title || '').replace(/^\s*step\s*\d+\s*[:.)-]\s*/i, '');
}

function renderMiniMarkdown(text) {
  const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const inline = (v) => esc(v)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  const out = [];
  let list = null; // 'ol' | 'ul'
  let para = [];
  let fence = null;
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of String(text || '').split('\n')) {
    if (fence !== null) {
      if (/^\s*```/.test(raw)) { out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`); fence = null; }
      else fence.push(raw);
      continue;
    }
    if (/^\s*```/.test(raw)) { flushPara(); closeList(); fence = []; continue; }
    const ol = raw.match(/^\s*\d+\.\s+(.*)$/);
    const ul = raw.match(/^\s*[-*]\s+(.*)$/);
    if (ol || ul) {
      flushPara();
      const kind = ol ? 'ol' : 'ul';
      if (list !== kind) { closeList(); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${inline((ol || ul)[1])}</li>`);
    } else if (raw.trim() === '') {
      flushPara(); closeList();
    } else if (list && /^\s+\S/.test(raw)) {
      // continuation of the previous list item
      out[out.length - 1] = out[out.length - 1].replace(/<\/li>$/, ` ${inline(raw.trim())}</li>`);
    } else {
      closeList(); para.push(raw.trim());
    }
  }
  if (fence !== null) out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`);
  flushPara(); closeList();
  return out.join('');
}

/**
 * Map a scan-result `platform` value (Node's process.platform strings, e.g.
 * "darwin"/"win32"/"linux") or a browser's navigator.userAgent to one of the
 * keys used in permissions-content.json: "macos" | "windows" | "linux".
 */
function detectOS(platformHint) {
  if (platformHint === 'darwin') return 'macos';
  if (platformHint === 'win32') return 'windows';
  if (platformHint === 'linux') return 'linux';

  const ua =
    (typeof navigator !== 'undefined' && navigator.userAgent) || '';
  if (/Mac/i.test(ua)) return 'macos';
  if (/Win/i.test(ua)) return 'windows';
  if (/Linux/i.test(ua)) return 'linux';

  // Sensible default when we truly can't tell.
  return 'macos';
}

/**
 * The permission tips worth showing beside a running checkup: everything for
 * this OS except the install-time ones (Gatekeeper, SmartScreen), which the
 * person has already got past by the time the app is open.
 */
function duringScanTips(content, osKey, { fdaNeeded = false } = {}) {
  const steps = (content && content[osKey]) || [];
  // Full Disk Access only once a check actually needed it (a permission error).
  return steps.filter((step) => step && step.stage !== 'install' && (fdaNeeded || !isFdaTip(step)));
}
function isFdaTip(step) {
  return !!step && /Privacy_AllFiles/.test(String(step.setting_url || ''));
}
// Whether a scan event says a check was stopped by a missing permission.
function needsFda(ev) {
  if (!ev) return false;
  if (ev.type === 'module' && ev.result) {
    const r = ev.result;
    return r.error_kind === 'permission' || (r.status === 'error' && errorKind(r.error) === 'permission');
  }
  return ev.type === 'progress' && ev.phase === 'done' && !!ev.error && errorKind(ev.error) === 'permission';
}

// Only security and network findings can be "Needs attention now": a
// crashing app, a missing backup or a busy program is worth a look, not an alarm.
// What wasn't fully checked, and every number the list shows: one rule for
// the list and the city (not-checked.js).
const NotCheckedRule = typeof NotChecked !== 'undefined' ? NotChecked : require('./not-checked.js');
// The severity rule is the shared one, so the list and the city put a finding at the same level.
const shownSeverity = NotCheckedRule.shownSeverity;
const isPartlyChecked = NotCheckedRule.isPartlyChecked;

/**
 * Group every finding across every module by severity, and collect the
 * modules that failed to run at all. Unknown/missing severities fall back
 * to "info" so nothing silently disappears.
 *
 * @param {{modules?: Array<{name:string,status:string,error:?string,findings?:Array}>}} doc
 * `unfinishedModules`: checks that ran but stopped before the end (the
 * engine's "complete": false). Their findings are listed, but what's missing
 * from them may not have been looked at, so they are never a clean result.
 *
 * @returns {{groups: {critical: Array, warning: Array, info: Array}, erroredModules: Array<{name:string,error:?string}>, unfinishedModules: Array<{name:string}>, partlyChecked: Array<{name:string,title:string}>}}
 */
function groupFindingsBySeverity(doc) {
  const groups = { critical: [], warning: [], info: [] };
  // Could not run here (or a monitoring check couldn't look): not a clean
  // result, so it must not read as one. Findings that say part of a check
  // couldn't look are listed with them (partlyChecked), not as notes. The
  // same rule as the city's (not-checked.js).
  const parts = NotCheckedRule.notCheckedParts(doc);
  const erroredModules = parts.couldntRun;
  const unfinishedModules = parts.unfinished;
  const partlyChecked = parts.partly;
  const modules = (doc && doc.modules) || [];

  for (const mod of modules) {
    const findings = (mod && mod.findings) || [];
    for (const finding of findings) {
      if (isPartlyChecked(finding)) continue;
      groups[shownSeverity(finding)].push(Object.assign({}, finding, { module: mod.name }));
    }
  }

  return { groups, erroredModules, unfinishedModules, partlyChecked };
}

// The Evidence block (evidence.js): what each finding actually saw.
const EvidenceRule = typeof Evidence !== 'undefined' ? Evidence : require('./evidence.js');

/**
 * One card's Evidence rows. A card that merged several checks says
 * "Seen by" with each check's name, and lists the commands of all of them.
 * A held card (city) gets only what to write down, with no clipboard.
 */
function cardEvidenceRows(finding, { mode, held, doc, commands } = {}) {
  const f = finding || {};
  const seenIn = Array.isArray(f.seen_in) && f.seen_in.length ? f.seen_in : [f.module];
  const cmds = [];
  for (const m of seenIn) for (const c of (commands && commands.get ? commands.get(m) : null) || []) cmds.push(c);
  const rows = EvidenceRule.evidenceRows(f, {
    mode: mode === 'city' ? 'city' : 'standard',
    held: !!held,
    checkName: checkName(f.module, mode, doc),
    commands: cmds,
  });
  if (seenIn.length > 1 && !rows.held) {
    const at = rows.findIndex((r) => r.label === 'Check');
    const names = seenIn.map((m) => checkName(m, mode, doc)).join(', ');
    const seen = { label: 'Seen by', value: names, mono: false, copy: names };
    if (at >= 0) rows.splice(at, 1, seen); else rows.push(seen);
  }
  return rows;
}

// One count of what wasn't fully checked, the same one the city shows.
const notCheckedSummary = NotCheckedRule.notCheckedSummary;
// The top line when something wasn't fully checked. Never an all-clear.
const notCheckedLine = NotCheckedRule.notCheckedLine;

// The engine's walkthroughs say `<path-to-plist>` or `<label>` where the scan
// already knows the value. Filled by the one rule the game uses too
// (step-fill.js): only values that can't run as code or change the markup,
// only for macOS and Linux. The step is HTML-escaped afterwards (renderMiniMarkdown).
const StepFillRule = typeof StepFill !== 'undefined' ? StepFill : require('./step-fill.js');
const fillPlaceholders = StepFillRule.fillPlaceholders;
const fillStep = StepFillRule.fillStep;
const safePlaceholderValue = StepFillRule.safeValue;

/**
 * A check's name for people: "launch_agent_audit" -> "Launch agent audit",
 * the same words the progress line uses. Never the raw id. In city mode a
 * monitoring check is never named: just "A check".
 */
function checkName(module, mode, doc) {
  if (mode === 'city' && ALWAYS_SAFETY_MODULES.has(module)) return 'A check';
  // The engine's own name for the check, when it gives one.
  const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
  const hit = mods.find((m) => m && m.name === module);
  if (hit && typeof hit.check_name === 'string' && hit.check_name.trim()) return hit.check_name.trim();
  const words = String(module || '').replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check';
}

/**
 * A check as the copy-for-AI report names it: its words, then its id in
 * parentheses (an AI can look the id up). In city mode a monitoring check is
 * "A check", with no id.
 */
function aiCheckLabel(module, mode, doc) {
  const words = checkName(module, mode, doc);
  if (mode === 'city' && ALWAYS_SAFETY_MODULES.has(module)) return words;
  return `${words} (${String(module || '')})`;
}

const UNFINISHED_LINE = 'It didn’t finish, so it may have missed something.';

// The engine's error, in words: needs a permission, took too long, or
// couldn't run. The raw text goes under "For tech helpers". The engine's
// own `error_kind` decides when it gives one; the text is the fallback.
const ENGINE_KINDS = { permission: 'permission', timeout: 'slow', stopped: 'stopped' };
function errorKind(error, engineKind) {
  if (engineKind && ENGINE_KINDS[engineKind]) return ENGINE_KINDS[engineKind];
  const e = String(error || '');
  if (/PermissionError|Operation not permitted|Errno 1\b|not permitted|Full Disk Access/i.test(e)) return 'permission';
  if (/timed out|timeout/i.test(e)) return 'slow';
  return 'failed';
}
const ERROR_WORDS = {
  permission: 'Needs permission (Full Disk Access).',
  slow: 'Took too long.',
  failed: 'Couldn’t run.',
  stopped: 'Didn’t get to run: the checkup stopped.',
};

/**
 * The "couldn't check these" list: checks that couldn't run, then checks
 * that didn't finish. In city mode a monitoring check's reason isn't shown
 * either (it can name what it looked for).
 */
function couldntCheckItems(erroredModules, unfinishedModules, mode, partlyChecked, doc) {
  const hide = (name) => mode === 'city' && ALWAYS_SAFETY_MODULES.has(name);
  const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
  const engineKind = (name) => { const m = mods.find((x) => x && x.name === name); return m ? m.error_kind : null; };
  return [
    ...erroredModules.map((m) => {
      // City mode: a monitoring check's cause can say what it looked for.
      const kind = hide(m.name) ? 'failed' : errorKind(m.error, engineKind(m.name));
      return { name: checkName(m.name, mode, doc), kind,
        reason: hide(m.name) ? '' : m.error || kind !== 'failed' ? ERROR_WORDS[kind] : '', raw: hide(m.name) ? '' : m.error || '' };
    }),
    ...unfinishedModules.map((m) => ({ name: checkName(m.name, mode, doc), kind: 'unfinished', reason: UNFINISHED_LINE, raw: '' })),
    ...(partlyChecked || []).map((m) => ({ name: checkName(m.name, mode, doc), kind: 'partly',
      reason: hide(m.name) ? '' : m.title, raw: '' })),
  ];
}

/**
 * The couldn't-check box, by cause: one line per cause with the check names
 * inline and at most one button ("Open the setting" for Full Disk Access,
 * "Run them again" for the slow ones). Partly-checked notes keep their own
 * words, one per line. `raw`: every engine message, for the one
 * "For tech helpers" under the whole box.
 */
const CAUSE_ORDER = ['permission', 'slow', 'failed', 'stopped', 'unfinished', 'partly'];
// Past this many names, a cause's line gives the count and the names go under a fold.
const NAMES_INLINE = 5;
function couldntCheckGroups(items) {
  const by = new Map();
  for (const it of items || []) {
    if (!by.has(it.kind)) by.set(it.kind, []);
    by.get(it.kind).push(it);
  }
  const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
  const uniq = (list) => [...new Set(list.map((i) => i.name))];
  const groups = [];
  for (const kind of CAUSE_ORDER) {
    const list = by.get(kind);
    if (!list || !list.length) continue;
    const c = list.length;
    // A few names stay in the line; more go under a fold (`folded`), and the line ends at the count.
    // NotChecked.namesLine, the one rule for names in a line.
    const names = NotCheckedRule.namesLine(uniq(list), { max: NAMES_INLINE });
    const folded = kind !== 'partly' && names.folded;
    const named = (head) => (folded || !names.inline ? `${head}.` : `${head}: ${names.inline}.`);
    let line;
    if (kind === 'permission') line = named(`${n(c, 'check needs', 'checks need')} Full Disk Access`);
    else if (kind === 'slow') line = named(`${n(c, 'check', 'checks')} took too long`);
    else if (kind === 'failed') line = named(`${n(c, 'check', 'checks')} couldn’t run`);
    else if (kind === 'stopped') line = named(`${n(c, 'check', 'checks')} didn’t get to run because the checkup stopped`);
    else if (kind === 'unfinished') line = named(`${n(c, 'check', 'checks')} didn’t finish, so ${c === 1 ? 'it' : 'they'} may have missed something`);
    else line = `${n(c, 'thing was', 'things were')} only partly checked`;
    groups.push({ kind, line, names: list.map((i) => i.name), folded: folded ? names.all : [],
      notes: kind === 'partly' ? list.map((i) => (i.reason ? `${i.name}: ${i.reason}` : i.name)) : [] });
  }
  const raw = (items || []).filter((i) => i.raw).map((i) => `${i.name}: ${i.raw}`).join('\n');
  return { groups, raw };
}

/**
 * Plain's cards: one per item of NotChecked.displayItems, the list both views
 * render, so the cards are scanCounts' `todo` (critical + warning) and
 * `notes` (info). The merge rule lives there (same_key, then the thing the
 * finding names, then its title; a to-do never merges with a note;
 * monitoring never merges). Each card is NotChecked.asCard: the lead finding
 * with `seen_in` (every check that saw it) and `also` (the other findings).
 * Marked items are listed at their old severity (and start out cleared);
 * held items (city mode) stay on the list at theirs, out of the numbers.
 * A card carries the engine's removal warning when any of its findings does.
 */
function plainCards(doc, mode) {
  const list = NotCheckedRule.displayItems(doc, { mode: mode === 'city' ? 'city' : 'standard' });
  const out = { critical: [], warning: [], info: [] };
  for (const item of [...list.critical, ...list.warning, ...list.info, ...list.marked, ...list.held]) {
    const card = NotCheckedRule.asCard(item);
    if (item.findings.some((f) => f && f.removal_alert === true)) card.removal_alert = true;
    (out[item.severity] || out.info).push(card);
  }
  return out;
}

/**
 * Within one level, what to look at first: something we can fix for you,
 * then the signs someone got in (a redirected website, a saved key that lets
 * another computer in, the router open, unknown DNS, new listening ports or
 * startup items, connections waiting from outside), then security lists to
 * review, then the rest of security, then network, then everything else.
 * Ties keep the checkup's own order (higher confidence first).
 */
const SIGNAL_MODULES = [
  'hosts_file_check', 'session_revocation_scan', 'router_security_audit', 'dns_config', 'security_baseline_diff',
  'suspicious_connections', 'dns_poisoning_check', 'browser_hijack_check', 'network_proxy', 'network_proxy_check',
  'network_proxy_detect', 'arp_spoof_check', 'remote_login_check', 'sharing_services', 'ssh_key_audit',
  'certificate_trust_audit', 'rootkit_check', 'malware_scan_indicators', 'crypto_miner_persistence',
];
function importanceRank(f) {
  if (!f) return [9, 0];
  if (f.fixable && typeof f.fixable === 'object') return [0, 0];
  const signal = SIGNAL_MODULES.indexOf(f.module);
  if (signal >= 0) return [1, signal];
  if (f.category === 'security' && f.markable && typeof f.markable === 'object') return [2, 0];
  if (f.category === 'security') return [3, 0];
  if (f.category === 'network') return [4, 0];
  return [5, 0];
}
function sortByImportance(findings) {
  return (findings || []).map((f, i) => ({ f, i, r: importanceRank(f), c: f && typeof f.confidence === 'number' ? f.confidence : 0 }))
    .sort((a, b) => a.r[0] - b.r[0] || a.r[1] - b.r[1] || b.c - a.c || a.i - b.i)
    .map((x) => x.f);
}

/**
 * Good to know, by area: one closed box per area (the city's districts, in
 * plain words) with its count; inside, a check with several notes is its own
 * closed box, and a check's single note is one line. Areas in a fixed order,
 * checks in the order the checkup ran them. The area is the check's category
 * (as NotChecked.scanCounts' byDistrict counts it).
 */
const NOTE_AREAS = [
  { id: 'security', name: 'Security' },
  { id: 'network', name: 'Network' },
  { id: 'integrity', name: 'Updates and system files' },
  { id: 'performance', name: 'Speed and storage' },
  { id: 'bloatware', name: 'Clutter' },
  { id: 'other', name: 'Everything else' },
];
function noteAreaOf(category) {
  return NOTE_AREAS.some((a) => a.id === category && a.id !== 'other') ? category : 'other';
}
function groupByCheck(findings, mode, doc) {
  const by = new Map();
  for (const f of findings || []) {
    const key = f && f.module ? f.module : '';
    if (!by.has(key)) by.set(key, []);
    by.get(key).push(f);
  }
  return [...by.entries()].map(([module, list]) => ({ module, name: checkName(module, mode, doc), findings: list }));
}
function groupByArea(findings, mode, doc) {
  const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
  const cat = new Map(mods.filter(Boolean).map((m) => [m.name, m.category]));
  const checks = groupByCheck(findings, mode, doc);
  return NOTE_AREAS.map((a) => ({ id: a.id, name: a.name,
    checks: checks.filter((c) => noteAreaOf(cat.get(c.module) || null) === a.id) }))
    .filter((a) => a.checks.length);
}

// The line for a check that waits to be started. City mode names nothing.
const PHONE_WAITING_LINE = 'Not started \u2014 your iPhone backup can be checked for spyware. This is a long scan.';
const WAITING_LINE_CITY = 'A check is waiting for you to start it. It only runs when you ask.';
// Where it is started: the city's own waiting signal (the LIST starts nothing).
const NOT_STARTED_WHERE = 'You can start it from the city.';
function notStartedLine(names, mode) {
  if (!names || !names.length) return '';
  if (mode === 'city') return WAITING_LINE_CITY;
  return names.includes('mvt_spyware_scan') ? PHONE_WAITING_LINE : WAITING_LINE_CITY;
}

/**
 * What wasn't fully checked (the names, for the boxes) and every number the
 * list shows, all from NotChecked: `counts` is scanCounts (city mode leaves
 * held findings out, as the city does), `summary` the parts notCheckedLine reads.
 */
function plainNotChecked(doc, mode) {
  const parts = NotCheckedRule.notCheckedParts(doc);
  const counts = NotCheckedRule.scanCounts(doc, { mode: mode === 'city' ? 'city' : 'standard' });
  const summary = { checks: counts.checks, couldntRun: counts.couldntRun, notReached: counts.notReached,
    unfinished: counts.unfinished, notStarted: counts.notStarted, partly: counts.partly };
  // Checks a stopped checkup never got to are listed with the ones that
  // couldn't run, under their own cause (error_kind "stopped").
  const mods = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean) : [];
  const notReached = parts.notReached.map((m) => {
    const hit = mods.find((x) => x.name === m.name);
    return { name: m.name, error: hit && hit.error ? hit.error : null };
  });
  return { couldntRun: [...parts.couldntRun, ...notReached], unfinished: parts.unfinished, partly: parts.partly,
    notStarted: parts.notStarted.map((m) => m.name), summary, counts };
}

/**
 * What a card says in prose, beside its Evidence block. `why`: at most two
 * sentences of the description, leaving out what the evidence already shows
 * (a sentence quoting a path or id from `data`), the removal warning when the
 * card shows it in its own box (`alertShown`), generic explanations (those
 * live in the lessons), and the "What to do:" paragraph. `todo`: that
 * paragraph, only when the card has no steps (otherwise the steps say it).
 */
const GENERIC = [
  /\bnot automatically (?:dangerous|bad|a sign)\b/i,
  /\bhidden folders are often used\b/i,
];
const ALERT_SENTENCE = /\b(?:remov(?:e|es|ed|ing|al)|uninstall\w*|delet\w*|disabl\w*|(?:switch|turn)\w*\s+(?:\S+\s+){0,3}?off)\b[^.!?]*?\b(?:can|may|could|might|will|would)\s+(?:alert|tip\s+off|notify|warn)\b/i;
function evidenceStrings(data) {
  const out = [];
  const add = (v) => {
    if (typeof v !== 'string' || v.length < 4) return;
    // A path is shown in the evidence even with spaces in it ("/Applications/Baba Is You.app").
    if (/^[/~]/.test(v) && !/\n/.test(v)) out.push(v);
    else if (!/\s/.test(v) && /[/._-]/.test(v)) out.push(v);
  };
  for (const v of Object.values(data && typeof data === 'object' ? data : {})) {
    if (Array.isArray(v)) v.forEach(add); else add(v);
  }
  return out;
}
function splitSentences(text) {
  return String(text || '').replace(/\s+/g, ' ').trim()
    .split(/(?<=[.!?])\s+(?=[A-Z'‘“(])/).map((s) => s.trim()).filter(Boolean);
}
function cardProse(description, finding, { steps = 0, alertShown = false } = {}) {
  const f = finding || {};
  const paras = String(description || '').split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  let todo = '';
  const about = [];
  for (const p of paras) {
    const m = p.match(/^what to do:\s*/i);
    if (m) { if (!todo) todo = p.slice(m[0].length); continue; }
    about.push(p);
  }
  const shown = evidenceStrings(f.data);
  const why = about.flatMap(splitSentences).filter((s) => !GENERIC.some((re) => re.test(s))
    && !(alertShown && ALERT_SENTENCE.test(s))
    && !shown.some((v) => s.includes(v)));
  return { why: why.slice(0, 2).join(' '), todo: steps ? '' : todo };
}

/**
 * "What does this mean?": taught once, in the "How to read these cards" box
 * under the list. A card links to the part that explains it.
 */
const BACKGROUND_MODULES = new Set(['launch_agent_audit', 'launchd_persistence_audit', 'scheduled_tasks_audit',
  'ai_worm_persistence', 'startup_optimizer', 'crypto_miner_persistence', 'linux_persistence_audit', 'login_items']);
function lessonFor(finding) {
  const f = finding || {};
  if (BACKGROUND_MODULES.has(f.module)) return 'background';
  if (Array.isArray(f.made_by) && f.made_by.length) return 'makers';
  return '';
}

// The scan events the game's sweep screen follows.
const GAME_SCAN_EVENTS = new Set(['progress', 'plan', 'module']);

/**
 * Results while a scan runs. The engine streams each finished check's entry
 * ({type:'module', result}) after its 'done' progress line, and names every
 * check first ({type:'plan', total}). This keeps what has arrived, so the
 * results screen can show it, always as partial: "N of M checks done", never
 * an all-clear, and nothing to act on until the whole scan is in.
 */
function partialScanState() {
  return { total: 0, done: 0, modules: [] };
}

// Returns true when the findings on show changed (a check's entry arrived).
function applyPartialEvent(state, ev) {
  if (!state || !ev) return false;
  const n = (x) => (typeof x === 'number' && Number.isFinite(x) && x >= 0 ? x : null);
  if (ev.type === 'plan') {
    if (n(ev.total) !== null) state.total = ev.total;
    return false;
  }
  if (ev.type === 'progress') {
    if (n(ev.total) !== null && ev.total > 0) state.total = ev.total;
    if (ev.phase === 'done' && n(ev.index) !== null) state.done = Math.max(state.done, ev.index);
    return false;
  }
  if (ev.type === 'module' && ev.result && typeof ev.result === 'object' && typeof ev.result.name === 'string') {
    const at = state.modules.findIndex((m) => m.name === ev.result.name);
    if (at >= 0) state.modules[at] = ev.result; else state.modules.push(ev.result);
    return true;
  }
  return false;
}

// The scan so far, in the final document's shape, marked partial.
function partialDocOf(state, platform) {
  return { schema_version: 1, platform: platform || null, modules: state.modules.slice(),
    partial: { done: state.done, total: state.total } };
}

// A checkup that stopped before the end: what arrived, marked stopped, in
// engine-runner's stoppedDocOf shape (doc.stopped.stage), so the city reads it too.
function stoppedDocOf(state, platform) {
  const doc = partialDocOf(state, platform);
  const { done, total } = doc.partial;
  const stage = total > 0 && done >= total ? 'assembly' : 'early';
  doc.partial.stopped = stage;
  doc.stopped = { stage, reason: 'exit', done, total };
  return doc;
}
const STOPPED_LINE = 'The checkup stopped before it finished. Nothing on your computer was changed.';
// The plain lines a stop arrives with (this file's, and engine-runner's
// SCAN_STOPPED_MESSAGE): already said on screen, so never under "For tech helpers".
const PLAIN_STOP_LINES = new Set([STOPPED_LINE]);

// The scan screen's line when the checkup stopped, by how it stopped
// (doc.stopped: { stage, done, total }), the same words as the results' line.
function stoppedScreenLine(stopped, esc) {
  const e = esc || ((x) => String(x));
  const after = ' Nothing on your computer was changed.';
  const total = stopped && stopped.total > 0 ? stopped.total : 0;
  const done = stopped && stopped.done > 0 ? stopped.done : 0;
  if (stopped && stopped.stage === 'assembly' && total) {
    return `<strong>${e(`All ${total} checks ran, but the report couldn\u2019t be put together.`)}</strong>${e(after)}`;
  }
  if (stopped && total) {
    return `<strong>${e('The checkup stopped before it finished')}</strong>${e(` (${done} of ${total} checks done).${after}`)}`;
  }
  return `<strong>${e('The checkup stopped before it finished.')}</strong>${e(after)}`;
}

// The end of the technical log, for tech helpers: the last lines, where the traceback is.
const LOG_TAIL_LINES = 40;
function logTail(text) {
  const lines = String(text || '').split('\n').filter((l) => l.trim());
  return lines.slice(-LOG_TAIL_LINES).join('\n');
}

function isPartialDoc(doc) {
  return !!(doc && doc.partial && typeof doc.partial === 'object');
}

// "34 of 120 checks done": what the partial results screen says it is.
// After the last check, before the results: the engine's "Who made it?" lookups.
const LOOKUP_TEXT = 'All checks are done. Looking up who made each program\u2026';
// A scan asked for while a fix or mark is still being made starts after it.
const WAIT_FOR_CHANGE_TEXT = 'Waiting for the change you asked for to finish, then the checkup starts\u2026';

function partialCountText(partial) {
  const done = partial && partial.done > 0 ? partial.done : 0;
  const total = partial && partial.total > 0 ? partial.total : 0;
  if (partial && partial.stopped) {
    // doc.stopped.stage, mirrored in partial.stopped; an older `true` is read from the counts.
    const stage = partial.stopped === 'assembly' || partial.stopped === 'early' ? partial.stopped
      : (total && done >= total ? 'assembly' : 'early');
    if (stage === 'assembly') return `All ${total} checks ran, but the report couldn\u2019t be put together. This is what they found.`;
    return total ? `The checkup stopped before it finished: ${done} of ${total} checks done. This is only what they found.`
      : 'The checkup stopped before it finished. This is only what it found before then.';
  }
  if (!total) return 'The checkup is still running.';
  if (done >= total) return LOOKUP_TEXT;
  return `The checkup is still running: ${done} of ${total} checks done.`;
}

// The sentence at the top of partial results. Never an all-clear: the
// checks still running haven't looked yet. `worth` = warnings and criticals.
function partialSummaryText({ worth = 0, other = 0, stopped = false } = {}) {
  if (stopped) {
    return worth > 0 ? `${worth} thing${worth === 1 ? '' : 's'} worth a look in the part that ran. The rest wasn’t checked.`
      : 'Nothing worth a look in the part that ran. The rest wasn’t checked, so this isn’t a clean bill of health.';
  }
  if (worth > 0) return `So far, ${worth} thing${worth === 1 ? '' : 's'} worth a look. More may turn up.`;
  if (other > 0) return 'Nothing worth a look so far. The checkup isn’t finished, so more may turn up.';
  return 'Nothing to show yet. The checkup isn’t finished.';
}

// The LIST before any checkup has run this session. Never an all-clear.
const NO_SCAN_LINE = 'No checkup has run yet, so there is nothing to list. Nothing has been checked.';
// The LIST changes nothing; what is still to come is all it has to say.
const STOPPED_ACTIONS_TEXT = 'The rest wasn’t checked. Run the checkup again to check it.';
const PARTIAL_ACTIONS_TEXT = 'More may turn up as the other checks finish.';

/**
 * The LIST's top sentence: how many things to look at and how many notes,
 * the numbers scanCounts gives (todo, notes). null when there are none.
 */
function listSummaryText(listCount, infoCount) {
  const list = Math.max(0, listCount | 0);
  const info = Math.max(0, infoCount | 0);
  const notes = info === 1 ? '1 good-to-know note' : `${info} good-to-know notes`;
  if (!list && !info) return null;
  if (!list) return `Nothing to look at. There ${info === 1 ? 'is' : 'are'} ${notes} further down.`;
  const things = list === 1 ? '1 thing to look at' : `${list} things to look at`;
  if (!info) return `${things}, grouped by how important ${list === 1 ? 'it is' : 'they are'}.`;
  return `${things}, and ${notes} further down.`;
}

// An item marked as the person's on an earlier checkup: mentioned on its
// card, never treated as cleared (ai-prompt.js says so to an AI from data.marked_by_user).
const MARKED_BEFORE_LINE = 'Marked as yours on an earlier checkup. It stays listed so anyone helping you can see it.';

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectOS,
    GAME_SCAN_EVENTS,
    partialScanState,
    applyPartialEvent,
    partialDocOf,
    isPartialDoc,
    stoppedDocOf,
    stoppedScreenLine,
    logTail,
    STOPPED_LINE,
    partialCountText,
    partialSummaryText,
    PARTIAL_ACTIONS_TEXT,
    STOPPED_ACTIONS_TEXT,
    NO_SCAN_LINE,
    listSummaryText,
    MARKED_BEFORE_LINE,
    LOOKUP_TEXT,
    WAIT_FOR_CHANGE_TEXT,
    duringScanTips,
    needsFda,
    groupFindingsBySeverity,
    checkName,
    aiCheckLabel,
    couldntCheckItems,
    couldntCheckGroups,
    cardEvidenceRows,
    plainCards,
    sortByImportance,
    importanceRank,
    groupByCheck,
    groupByArea,
    noteAreaOf,
    plainNotChecked,
    notStartedLine,
    PHONE_WAITING_LINE,
    cardProse,
    lessonFor,
    errorKind,
    notCheckedSummary,
    notCheckedLine,
    isPartlyChecked,
    shownSeverity,
    fillPlaceholders,
    fillStep,
    safePlaceholderValue,
    UNFINISHED_LINE,
    SITUATIONS,
    describeProgress,
    formatExec,
    renderMiniMarkdown,
    stepTitle,
    learnMoreFor,
    mayBeWatched,
    ALWAYS_SAFETY_MODULES,
    gameOfferedFor,
    gameScanFirst,
    worryStartsGameScan,
    copyAiSituation,
    guideLinksFor,
    GUIDE_NAMES,
    noteMonitoring,
    opensInGame,
    CITY_SITUATION,
    ALWAYS_SAFETY_MODULES,
    scanErrorText,
    postScanView,
    RECLAIM_CITY_URL,
    descriptionHtml,
    describeMadeBy,
    MADE_BY_REASON,
    MADE_BY_VERIFIED_LABEL,
    madeByHtml,
    SEVERITY_ORDER,
    SEVERITY_LABELS,
  };
}

// ---------------------------------------------------------------------------
// Browser-only wiring below. Guarded so this file stays importable in Node
// for the pure helpers above (used by a small sanity-check script).
// ---------------------------------------------------------------------------

if (typeof document !== 'undefined') {
  (function () {
    const screens = {
      welcome: document.getElementById('screen-welcome'),
      worry: document.getElementById('screen-worry'),
      question: document.getElementById('screen-question'),
      scan: document.getElementById('screen-scan'),
      results: document.getElementById('screen-results'),
      city: document.getElementById('screen-city'),
    };
    const stepDots = document.querySelectorAll('[data-step-dot]');
    const stepsBar = typeof document.querySelector === 'function' ? document.querySelector('.steps') : null;

    let permissionsContent = null;
    // A check in this scan was stopped by missing Full Disk Access (needsFda).
    let fdaNeeded = false;
    let lastKnownPlatform = null; // e.g. "darwin" | "win32" | "linux", once we have a scan result
    // The scan's own platform once there is one; before that, what preload says.
    const currentPlatform = () => lastKnownPlatform || (window.rescue && window.rescue.platform) || null;
    // The default browser's name, for the router button ("in Safari"); null until known or if unknown.
    let browserName = null;
    if (window.rescue && window.rescue.defaultBrowser) {
      Promise.resolve().then(() => window.rescue.defaultBrowser()).then((n) => { browserName = n || null; }).catch(() => {});
    }
    let routerCtx = null; // RouterLink context for the results on screen
    let situation = null; // the SITUATIONS entry the person picked
    let leftGame = false; // the city couldn't draw (or the person left it): the LIST and scan screens carry on
    let scanRunning = false;
    // The running scan is the game's sweep (its boss screen follows it).
    let gameScan = false;
    // The results screen is showing a running scan's results so far.
    let resultsPartial = false;
    // Monitoring software seen in any scan or re-check this session (noteMonitoring).
    // Memory only: never written to storage.
    let monitoringSeen = false;
    // The display preference (DisplayMode): 'city', 'standard', or null before the question.
    const store = (() => { try { return window.localStorage; } catch (_) { return null; } })();
    let mode = DisplayMode.readMode(store);
    // Whether the follow-up was asked this session. Memory only, like monitoringSeen.
    let recheckAsked = false;
    // A change of mode redraws the LIST, so a held card shows as held at once.
    function setMode(next) {
      const changed = next !== mode;
      mode = next;
      DisplayMode.writeMode(store, next);
      // The game saves its profile once in the new mode (city mode retires the old store).
      if (changed && window.RescueGame && typeof window.RescueGame.profileModeChanged === 'function') window.RescueGame.profileModeChanged();
      const shownDoc = currentResultsDoc();
      if (changed && shownDoc) renderResults(shownDoc);
    }
    // Made once per install for the game's own use, and written for everyone alike.
    const citySeed = DisplayMode.ensureSeed(store);

    // One question on its own screen (FirstQuestion): the answer picks the
    // display preference, then `then` carries on where the person was going.
    function ask(kind, then) {
      const card = document.getElementById('question-card');
      card.innerHTML = FirstQuestion.questionHtml(kind, escapeHtml);
      card.querySelectorAll('[data-answer]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const next = FirstQuestion.modeFor(kind, btn.dataset.answer);
          if (next) setMode(next);
          then();
        });
      });
      showScreen('question');
      // Move focus to the question so a screen reader announces it.
      const title = document.getElementById('question-title');
      if (title && typeof title.focus === 'function') title.focus();
    }

    function cityAvailable() {
      return gameOfferedFor(situation) && !!(window.RescueGame && window.RescueGame.isReady);
    }
    // The city from a finished scan. If it can't be drawn, the LIST, which has the same results.
    function showCity(doc) {
      if (!cityAvailable()) { showList(); return; }
      // false: the city couldn't be drawn and the controller already left the game.
      if (window.RescueGame.show(doc, situation) === false) { showList(); return; }
      leftGame = false;
      showScreen('city');
    }
    // Whether the LIST can go back to the city: a finished scan to show, or
    // the game's own sweep still running (its boss screen is where it was).
    function canGoBackToCity() {
      if (!cityAvailable()) return false;
      if (scanRunning) return gameScan;
      return !!lastScanDoc || !!stoppedDoc;
    }
    // "Back to the city" and Esc on the LIST. Mid-sweep the city is shown as
    // it is (RescueGame.show would end the game's sweep); otherwise it is
    // drawn from the scan the LIST shows.
    function backToCity() {
      if (!canGoBackToCity()) return;
      if (scanRunning) { leftGame = false; showScreen('city'); return; }
      showCity(resultsPartial && stoppedDoc ? stoppedDoc : lastScanDoc);
    }
    function renderCitySwitch() {
      const btn = document.getElementById('results-city-switch');
      if (btn) btn.hidden = !canGoBackToCity();
    }
    // The LIST: whatever the results screen should show now (a running
    // scan's results so far, a stopped one's, or the last finished one).
    function showList() {
      const doc = currentResultsDoc();
      if (doc) renderResults(doc); else renderNoScan();
      showScreen('results');
    }
    // The LIST before any checkup this session: it says so, and never reads as clean.
    function renderNoScan() {
      renderResultsFrame(null);
      document.getElementById('results-summary').innerHTML = `<p>${escapeHtml(NO_SCAN_LINE)}</p>`;
      document.getElementById('results-groups').innerHTML = '';
      document.getElementById('results-errors').hidden = true;
      document.getElementById('results-waiting').hidden = true;
      document.getElementById('results-next').hidden = true;
      document.getElementById('results-more').hidden = true;
    }

    window.RescueHost = {
      // The city's LIST tab: the read-only list of everything, always there.
      showList() { showList(); },
      // A re-check changed the scan. Keep the LIST in step. Monitoring software
      // no longer closes the city; in standard mode it brings the follow-up once.
      docChanged(doc) {
        lastScanDoc = doc;
        moduleCommandCache = new Map();
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        renderResults(doc);
        renderLearnMore(doc);
        renderCitySwitch();
        if (FirstQuestion.recheckDue({ mode, monitoringSeen, asked: recheckAsked })) {
          recheckAsked = true;
          ask('recheck', () => showCity(doc));
          return false;
        }
        return true;
      },
      // The game's briefing shows a mission's safety note wherever the list shows it.
      wantsSafety(finding) { const n = QuietNotes.noteFor(mode, finding); return n === 'line' || n === 'full'; },
      // The display preference and the install's seed, for the game.
      mode() { return mode; },
      citySeed() { return citySeed; },
      // What wasn't fully checked, counted the same way the list counts it, so both views agree.
      notChecked(doc) { return notCheckedSummary(doc || lastScanDoc); },
      startCheckup() { runCheckup({ game: true }); },
      // The OS pop-ups the person may see during the scan, for the boss screen.
      async scanTips() {
        try {
          const content = await loadPermissionsContent();
          return duringScanTips(content, detectOS(lastKnownPlatform), { fdaNeeded }).map((t) => ({ title: t.title, body: t.body }));
        } catch (_) {
          return [];
        }
      },
      // The city couldn't draw (or its old PLAIN VIEW button): the person
      // carries on outside it. A running scan carries on on the scan screen,
      // with its live progress (setScanBusy(true) already ran); a finished
      // one is on the LIST.
      leaveGame() {
        leftGame = true;
        if (scanRunning) { goToScan(); return; }
        if (lastScanDoc || stoppedDoc) { showList(); return; }
        goToScan();
      },
    };
    window.addEventListener('rescue-game-ready', () => renderCitySwitch());

    let activeDot = null;
    function showScreen(name) {
      Object.keys(screens).forEach((key) => {
        if (!screens[key]) return;
        screens[key].hidden = key !== name;
      });
      // The question screen keeps the step the person was on (worry, or the checkup's follow-up).
      const dotName = name === 'question' ? activeDot : name === 'city' ? 'results' : name;
      activeDot = dotName;
      // The city has its own screens: the setup steps would label its sweep "Results".
      if (stepsBar) stepsBar.hidden = name === 'city';
      stepDots.forEach((dot) => {
        dot.classList.toggle('step-dot--active', dot.dataset.stepDot === dotName);
      });
      // The LIST's way back to the city follows what the city can show now.
      if (name === 'results') renderCitySwitch();
      window.scrollTo(0, 0);
    }

    function escapeHtml(value) {
      const div = document.createElement('div');
      div.textContent = String(value == null ? '' : value);
      return div.innerHTML;
    }

    async function loadPermissionsContent() {
      if (permissionsContent) return permissionsContent;
      const response = await fetch('permissions-content.json');
      if (!response.ok) {
        throw new Error('Could not load the permissions walkthrough.');
      }
      permissionsContent = await response.json();
      return permissionsContent;
    }

    function renderScanTips(content, osKey) {
      const aside = document.getElementById('scan-tips');
      const container = document.getElementById('scan-tips-list');
      const steps = duringScanTips(content, osKey, { fdaNeeded });
      aside.hidden = steps.length === 0;
      if (steps.length === 0) return;
      // One line on its face; what each pop-up means is behind "What each pop-up means".
      const who = osKey === 'windows' ? 'Windows' : osKey === 'linux' ? 'Your computer' : 'Your Mac';
      document.getElementById('scan-tips-line').textContent = `${who} may ask for permission. Click Allow. We never ask for your password.`;

      const card = (step) => {
        const button =
          step.setting_url && step.action_label
            ? `<button type="button" class="btn btn--secondary btn--small" data-setting-url="${escapeHtml(step.setting_url)}">${escapeHtml(step.action_label)}</button>`
            : '';
        return `
            <li class="tip-card">
              <h3>${escapeHtml(step.title)}</h3>
              <p>${escapeHtml(step.body)}</p>
              ${button}
            </li>
          `;
      };
      // Full Disk Access, once a check needed it, is on the face: it is the one to act on.
      const fda = steps.find(isFdaTip);
      const needed = document.getElementById('scan-tips-needed');
      needed.hidden = !fda;
      needed.innerHTML = fda ? `<p><strong>A check needs Full Disk Access.</strong></p>`
        + `<button type="button" class="btn btn--secondary btn--small" data-setting-url="${escapeHtml(fda.setting_url)}">${escapeHtml(fda.action_label || 'Open the setting')}</button>` : '';
      container.innerHTML = `<ul class="tip-list">${steps.map(card).join('')}</ul>`;

      [container, needed].forEach((root) => root.querySelectorAll('[data-setting-url]').forEach((btn) => {
        btn.addEventListener('click', () => {
          window.rescue.openSetting(btn.getAttribute('data-setting-url'));
        });
      }));
    }

    // The worries: a checklist of the ones that combine, unticked, and a
    // button each for the two that run on their own ("check everything" and
    // the iPhone check). Ticking changes nothing until "Start the checkup".
    function renderSituations() {
      const list = document.getElementById('situations');
      const alone = document.getElementById('situations-alone');
      list.innerHTML = Checklist.html({
        id: 'worries',
        // The screen's heading, "What's worrying you?", names the list.
        labelledBy: 'worry-title',
        items: SITUATIONS.filter((s) => WorryPick.CHECKLIST_IDS.includes(s.id))
          .map((s) => ({ key: s.id, label: s.title, note: s.sub })),
        actions: [{ id: 'start', verb: 'Start the checkup for', noun: ['worry', 'worries'], min: 1 }],
        selectAll: false,
      });
      alone.innerHTML = SITUATIONS.filter((s) => WorryPick.ON_THEIR_OWN.includes(s.id)).map(
        (s) => `
          <li>
            <button type="button" class="situation" data-situation="${escapeHtml(s.id)}">
              <span class="situation__icon" aria-hidden="true">${escapeHtml(s.icon)}</span>
              <span class="situation__text">
                <span class="situation__title">${escapeHtml(s.title)}</span>
                <span class="situation__sub">${escapeHtml(s.sub)}</span>
              </span>
            </button>
          </li>`
      ).join('');
      const start = list.querySelectorAll('[data-cl-action]')[0];
      if (start) {
        start.addEventListener('click', () => {
          const ids = Array.from(list.querySelectorAll('[data-cl-key]'))
            .filter((box) => box.checked === true)
            .map((box) => box.getAttribute('data-cl-key'));
          const picked = WorryPick.combine(ids, SITUATIONS);
          if (picked) chooseWorry(picked);
        });
      }
      alone.querySelectorAll('[data-situation]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const picked = WorryPick.combine([btn.dataset.situation], SITUATIONS);
          if (picked) chooseWorry(picked);
        });
      });
    }

    // One worry or several: the display preference first, then the scan.
    function chooseWorry(picked) {
      situation = picked;
      const next = FirstQuestion.afterWorry(situation, mode);
      if (next === 'ask') { ask('first', startWorry); return; }
      if (next !== mode) setMode(next);
      startWorry();
    }

    // What a picked worry does once the display preference is known: its
    // scan starts at once on the city's sweep screen. Only when the game
    // can't draw does the scan screen show (Run checkup), landing on the LIST.
    function startWorry() {
      if (!scanRunning && worryStartsGameScan({ situation, ready: !!(window.RescueGame && window.RescueGame.isReady) })) {
        leftGame = false;
        window.RescueGame.newWorry(situation);
        // The city screen first: if the sweep can't be drawn, leaveGame() then
        // shows the scan screen, where the same scan carries on.
        showScreen('city');
        runCheckup({ game: true });
        return;
      }
      goToScan();
    }

    function renderScanIntro() {
      // City mode names no worry on screen.
      document.getElementById('scan-situation').textContent = !situation ? ''
        : opensInGame(mode) ? 'Checking your computer' : `Checking for: ${situation.title}`;
    }

    // Several worries can have several guides: one button each. Each URL
    // still goes through main's open-guide allowlist.
    let guideLinks = [];
    function renderNextStep() {
      const box = document.getElementById('results-next');
      const list = document.getElementById('results-guides');
      const single = document.getElementById('btn-open-guide');
      const text = document.getElementById('results-next-text');
      guideLinks = guideLinksFor(situation);
      if (!guideLinks.length) {
        box.hidden = true;
        list.hidden = true;
        list.innerHTML = '';
        return;
      }
      const several = guideLinks.length > 1;
      single.hidden = several;
      list.hidden = !several;
      list.innerHTML = several
        ? guideLinks.map((g, i) => `<li><button type="button" class="btn btn--secondary" data-guide-index="${i}">${escapeHtml(g.name)}</button></li>`).join('')
        : '';
      text.textContent = several
        ? 'There’s a step-by-step guide for each part of your situation. Each opens in your web browser.'
        : 'There’s a step-by-step guide for your situation. It opens in your web browser.';
      box.hidden = false;
    }

    let learnMoreUrl = null;
    function renderLearnMore(doc) {
      const box = document.getElementById('results-learn');
      // The Reclaim City link is playful too: not once monitoring software was seen.
      const learn = monitoringSeen ? null : learnMoreFor(situation, doc);
      learnMoreUrl = learn ? learn.url : null;
      box.hidden = !learn;
      if (!learn) return;
      document.getElementById('results-learn-text').textContent = learn.text;
    }

    // Per card: what "Copy for any AI" and the technical details say about
    // it. Reset on every render.
    let cardPicks = new Map(); // card key -> copy-ai pick
    // While the list renders (standard mode): each card's QuietNotes text, for the one warning banner.
    let safetyCards = null;
    let nextCardKey = 0;

    const FDA_URL = 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles';

    // Each check's traced commands from the last finished scan, for the
    // Evidence block: fetched once per check, cleared when a new scan lands.
    let moduleCommandCache = new Map();
    // Per card: the finding (and whether it is held), to redraw its Evidence
    // block once the commands are in. Reset on every render.
    let cardFindings = new Map();

    // One LIST card. The LIST is read-only: it shows what the checkup saw
    // and changes nothing, so no card has a fix, a mark, "I did this" or a
    // checkbox (the city's missions do that, through the same flows).
    // City mode: a held card (monitoring software) is drawn as the help
    // district draws it: what to write down, no clipboard, the hold line and
    // its help, and no steps.
    function cardHtml(finding, severity, shownDoc) {
      const key = String(nextCardKey++);
      const note = severity === 'info';
      // What this card may say (QuietNotes). Standard: no hotline text, and the one
      // line wherever removing something can alert someone. City: everything, unquieted.
      const card = QuietNotes.cardText(mode, finding);
      if (safetyCards) safetyCards.push(card);
      const held = card.note === 'held';
      // City mode: nothing from a monitoring check goes to the clipboard or
      // to a website (monitoring apps can read the clipboard), and the
      // whole-report copy leaves it out.
      const noClipboard = held || EvidenceRule.noClipboard(mode, finding.seen_in || finding.module);
      const pick = noClipboard ? null : copyAiPick(finding);
      if (pick) cardPicks.set(key, pick);
      const tech = {
        check: finding.seen_in && finding.seen_in.length > 1 ? finding.seen_in : finding.module,
        code: finding.code || null,
        category: finding.category,
        confidence: finding.confidence == null ? null : finding.confidence,
        evidence: finding.data || {},
      };
      const marked = !!(finding.data && finding.data.marked_by_user === true);
      const steps = held ? [] : card.steps.map((step) => ({ title: step.title, body: fillStep(step.body, finding.data, { platform: currentPlatform() }) }));
      // Evidence first; then at most two sentences of why, never what the
      // evidence, the warning box, the steps or a lesson already say.
      const rows = cardEvidenceRows(finding, { mode, held, doc: shownDoc, commands: moduleCommandCache });
      cardFindings.set(key, { finding, held });
      const alerts = card.note === 'line' || card.note === 'full';
      const warned = alerts || (card.note === 'full' && card.full.length > 0);
      const prose = held ? { why: card.description, todo: '' }
        : EvidenceRule.replacesDescription(finding) ? { why: '', todo: '' }
          : cardProse(card.description, finding, { steps: steps.length, alertShown: warned });
      const lesson = held ? '' : lessonFor(finding);
      // "Ask about this" sends what the card shows: the evidence first, then the why.
      const askFinding = Object.assign({}, finding, {
        description: [rows.length ? `Evidence:\n${EvidenceRule.evidenceText(rows)}` : '', prose.why || card.description || ''].filter(Boolean).join('\n\n'),
      });
      const title = `<h3 tabindex="-1">${escapeHtml(finding.title || 'Untitled finding')}</h3>`;
      const evidence = held ? EvidenceRule.renderEvidence(rows, { held: true, title: 'Write this down' })
        : EvidenceRule.renderEvidence(rows, { copy: !noClipboard });
      const body = `
              ${marked ? `<p class="finding-card__marked" role="note">${escapeHtml(MARKED_BEFORE_LINE)}</p>` : ''}
              <div class="evidence-slot" data-evidence-slot>${evidence}</div>
              ${prose.why || lesson ? `<p class="finding-card__why">${escapeHtml(prose.why)}${lesson ? `${prose.why ? ' ' : ''}<button type="button" class="link-button finding-card__lesson" data-lesson-link="${lesson}">What does this mean?</button>` : ''}</p>` : ''}
              ${prose.todo ? `<p class="finding-card__todo"><strong>What to do:</strong> ${escapeHtml(prose.todo)}</p>` : ''}
              ${QuietNotes.lineHtml(card, escapeHtml, { banner: !!safetyCards })}${QuietNotes.fullHtml(card, escapeHtml)}${QuietNotes.heldHtml(card, escapeHtml)}
              ${held ? '' : SettingPanes.findingButtonHtml(finding, currentPlatform())}
              ${held ? '' : RouterLink.findingLinkHtml(finding, routerCtx)}
              ${steps.length ? `
              <details class="fix-steps">
                <summary>Show me how, step by step (${steps.length})</summary>
                <ol class="fix-steps__list">
                  ${steps.map((step) => `
                    <li>
                      <h4>${escapeHtml(step.title)}</h4>
                      <div class="fix-steps__body">${renderMiniMarkdown(step.body)}</div>
                    </li>`).join('')}
                </ol>
              </details>` : ''}
              ${noClipboard ? '' : `
              <details class="get-help">
                <summary>Get help with this</summary>
                ${askButtonHtml(askFinding)}
                ${copyAiButtonHtml(finding, pick)}
              </details>`}
              ${held ? '' : `
              <details class="tech-details">
                <summary>Technical details</summary>
                ${card.description ? `<div class="tech-details__about">${descriptionHtml(card.description, escapeHtml)}</div>` : ''}
                <pre class="tech-log">${escapeHtml(JSON.stringify(tech, null, 2))}</pre>
              </details>`}`;
      const attrs = `class="finding-card finding-card--${severity}${note ? ' finding-card--note' : ''}${held ? ' finding-card--held' : ''}" data-card-key="${key}" data-finding-key="${escapeHtml(`${finding.module}|${finding.code || ''}|${finding.title || ''}`).replace(/"/g, '&quot;')}"${marked ? ' data-marked-before' : ''}${held ? ' data-held' : ''}`;
      const chip = `<span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>`;
      if (note) {
        return `
            <li ${attrs}>
              <details class="finding-note"><summary class="finding-note__summary">${chip}${title}</summary>${body}</details>
            </li>`;
      }
      return `
            <li ${attrs}>
              <div class="finding-card__header">
                <div class="finding-card__titles">${chip}${title}</div>
              </div>${body}
            </li>`;
    }

    // One level of the LIST, every card on show: the LIST is literal, so a
    // person can always see everything.
    function renderSeverityGroup(severity, findings, shownDoc = null, counts = null) {
      if (findings.length === 0) return '';
      // Good to know: one closed box, then one closed box per area with its
      // count; inside, a closed box per check with several notes, and a
      // check's one note as its line. Nothing in it needs doing.
      if (severity === 'info') {
        const areas = groupByArea(findings, mode, shownDoc);
        // The numbers are scanCounts' (byDistrict, by area).
        const byArea = NotCheckedRule.scanCounts(shownDoc, { mode: mode === 'city' ? 'city' : 'standard', districtOf: noteAreaOf }).byDistrict;
        const areaCount = (a) => (byArea[a.id] ? byArea[a.id].notes : 0);
        const checkHtml = (c) => (c.findings.length === 1 ? cardHtml(c.findings[0], 'info', shownDoc) : `
                <li class="info-check">
                  <details class="info-check__fold">
                    <summary><span class="info-check__name">${escapeHtml(c.name)}</span> <span class="results-group__count">${c.findings.length}</span></summary>
                    <ul class="findings-list findings-list--notes" data-group-list>${c.findings.map((f) => cardHtml(f, 'info', shownDoc)).join('')}</ul>
                  </details>
                </li>`);
        // Checks with several notes first, then the single notes.
        const boxes = areas.map((a) => `
            <li class="info-area">
              <details class="info-area__fold">
                <summary><span class="info-area__name">${escapeHtml(a.name)}</span> <span class="results-group__count">${areaCount(a)}</span></summary>
                <ul class="info-checks">${[...a.checks.filter((c) => c.findings.length > 1), ...a.checks.filter((c) => c.findings.length === 1)].map(checkHtml).join('')}</ul>
              </details>
            </li>`).join('');
        return `
        <section class="results-group results-group--info" data-results-group="info">
          <details class="results-group__fold">
            <summary><span class="chip chip--info">${escapeHtml(SEVERITY_LABELS.info)}</span>
              <span class="results-group__count">${counts ? counts.notes : findings.length}</span>
              <span class="muted">${escapeHtml(SEVERITY_DESCRIPTIONS.info)}</span></summary>
            <ul class="info-areas">${boxes}</ul>
          </details>
        </section>`;
      }
      return `
        <section class="results-group results-group--${severity}" data-results-group="${severity}">
          <h2>
            <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
            <span class="results-group__count">${findings.length}</span>
          </h2>
          <ul class="findings-list" data-group-list>${findings.map((f) => cardHtml(f, severity, shownDoc)).join('')}</ul>
        </section>
      `;
    }

    // While a scan runs, a redraw keeps open what the person opened.
    function openDetailsIn(root) {
      const open = new Set();
      if (!root || typeof root.querySelectorAll !== 'function') return open;
      root.querySelectorAll('[data-finding-key] details[open]').forEach((d) => {
        const card = d.closest && d.closest('[data-finding-key]');
        if (card) open.add(`${card.getAttribute('data-finding-key')}|${d.className}`);
      });
      return open;
    }
    function reopenDetailsIn(root, open) {
      if (!open.size || !root || typeof root.querySelectorAll !== 'function') return;
      root.querySelectorAll('[data-finding-key] details').forEach((d) => {
        const card = d.closest && d.closest('[data-finding-key]');
        if (card && open.has(`${card.getAttribute('data-finding-key')}|${d.className}`)) d.open = true;
      });
    }

    // New cards can land above what the person is reading. Remember the
    // topmost card on screen and where it sat, then put it back there.
    const cardSelector = (key) => `[data-finding-key="${String(key).replace(/["\\]/g, '\\$&')}"]`;
    function readingAnchor(root) {
      if (!root || typeof root.querySelectorAll !== 'function' || typeof window.scrollBy !== 'function') return null;
      for (const card of root.querySelectorAll('[data-finding-key]')) {
        if (typeof card.getBoundingClientRect !== 'function') return null;
        const r = card.getBoundingClientRect();
        if (r.bottom > 0) return r.top >= (window.innerHeight || 0) ? null : { key: card.getAttribute('data-finding-key'), top: r.top };
      }
      return null;
    }
    function keepReadingAnchor(root, anchor) {
      if (!anchor || typeof root.querySelector !== 'function') return;
      const card = root.querySelector(cardSelector(anchor.key));
      if (!card || typeof card.getBoundingClientRect !== 'function') return;
      const moved = card.getBoundingClientRect().top - anchor.top;
      if (moved) window.scrollBy(0, moved);
    }

    // The results screen's frame: "still running" (partial) or the finished checkup.
    function renderResultsFrame(partial) {
      const running = document.getElementById('results-running');
      running.hidden = !partial;
      resultsPartial = !!partial;
      if (partial) {
        document.getElementById('results-running-text').textContent = partialCountText(partial);
        document.getElementById('results-running-actions').textContent = partial.stopped ? STOPPED_ACTIONS_TEXT : PARTIAL_ACTIONS_TEXT;
      }
      const stopped = !!(partial && partial.stopped);
      const back = document.getElementById('btn-back-to-scan');
      if (back) back.textContent = stopped ? 'Back to run it again' : 'Show the checkup\u2019s progress';
      document.getElementById('results-title').textContent = stopped ? 'What the checkup found before it stopped'
        : partial ? 'What we\u2019ve found so far' : 'Here\'s what we found';
      // The whole-report copies would read as the full checkup: only once it's done.
      document.getElementById('results-copy-all').hidden = !!partial;
      document.getElementById('results-tech').hidden = !!partial;
      document.getElementById('results-more').hidden = false;
      if (partial) document.getElementById('results-learn').hidden = true;
      renderCitySwitch();
    }

    function renderResults(doc) {
      const partial = isPartialDoc(doc) ? doc.partial : null;
      renderResultsFrame(partial);
      const { unfinishedModules, partlyChecked } = groupFindingsBySeverity(doc);
      // One card per item (NotChecked.displayItems), the same items the city
      // counts; the most important first. Good to know is grouped by area.
      const groups = plainCards(doc, mode);
      groups.critical = sortByImportance(groups.critical);
      groups.warning = sortByImportance(groups.warning);
      // One count, the same one the city shows (notCheckedSummary), with a
      // check that waits for the person to start it kept apart from "couldn't run".
      const plain = plainNotChecked(doc, mode);
      const erroredModules = plain.couldntRun;
      const notChecked = plain.summary;
      const counts = plain.counts;
      // Never an all-clear while any check wasn't fully checked (scanCounts.notFully).
      const notFullyChecked = counts.notFully;
      // Nothing at all to show (a held card in city mode is left out of the counts, not of the list).
      const nothing = counts.todo === 0 && counts.notes === 0 && counts.markedItems === 0 && counts.heldItems === 0;

      // Before the cards render: it resets the per-finding copy registry. The
      // whole-report copy uses the same per-card objects.
      const reportFindings = [];
      setCopyAiReport({
        findings: reportFindings,
        situation: copyAiSituation(situation, mode),
        platform: doc && doc.platform,
        couldNotCheck: [...erroredModules, ...unfinishedModules, ...partlyChecked].map((m) => aiCheckLabel(m.name, mode, doc)),
        // Checks waiting for the person's go-ahead (the iPhone backup scan) weren't run either.
        notStarted: plain.notStarted.map((name) => aiCheckLabel(name, mode, doc)),
      });
      cardPicks = new Map();
      cardFindings = new Map();
      nextCardKey = 0;
      routerCtx = RouterLink.contextFrom(doc, browserName);
      const groupsEl = document.getElementById('results-groups');
      const wasOpen = partial ? openDetailsIn(groupsEl) : new Set();
      const anchor = partial ? readingAnchor(groupsEl) : null;
      // Standard mode: the removal warning once above the list, when any card
      // carries it; those cards keep the one bold line. City mode: every
      // card keeps its note in full, as before.
      safetyCards = mode === 'city' ? null : [];
      const cardsHtml = SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev], doc, counts)).join('');
      const banner = safetyCards ? QuietNotes.bannerHtml(QuietNotes.bannerNotes(safetyCards), escapeHtml) : '';
      safetyCards = null;
      groupsEl.innerHTML = banner + cardsHtml;
      reopenDetailsIn(groupsEl, wasOpen);
      keepReadingAnchor(groupsEl, anchor);
      reportFindings.push(...cardPicks.values());

      const summaryEl = document.getElementById('results-summary');
      // The numbers are scanCounts', the same ones the city shows.
      const said = listSummaryText(counts.todo, counts.notes);
      if (partial) {
        // Never an all-clear while checks are still running.
        summaryEl.innerHTML = `<p>${escapeHtml(partialSummaryText({
          worth: counts.todo, other: counts.notes, stopped: !!partial.stopped }))}</p>`;
      } else if ((nothing || !said) && notFullyChecked > 0) {
        // Never an all-clear while a check couldn't run or didn't finish.
        summaryEl.innerHTML = '<p>The checks that finished found nothing worth a look.</p>';
      } else if (nothing || !said) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out during this checkup. Nice and tidy.</p>';
      } else {
        summaryEl.innerHTML = `<p>${escapeHtml(said)}</p>`;
      }

      document.getElementById('results-lessons').hidden = nothing;
      renderCouldntCheck(doc, { notChecked, counts, erroredModules, unfinishedModules, partlyChecked, partial: !!partial });
      renderNotStarted(plain.notStarted);
      if (!partial) fillCommands(doc);
    }

    // The couldn't-check box: one line per cause, with the check names inline
    // and one button per cause; one "For tech helpers" for the whole box.
    function renderCouldntCheck(doc, { notChecked, counts, erroredModules, unfinishedModules, partlyChecked, partial }) {
      const errorsSection = document.getElementById('results-errors');
      const errorsList = document.getElementById('results-errors-list');
      const tech = document.getElementById('results-errors-tech');
      // The box is for what ran and wasn't fully checked; a check waiting to be started has its own line.
      if (counts.didntFinish === 0 && counts.partly === 0) {
        errorsSection.hidden = true;
        errorsList.innerHTML = '';
        tech.hidden = true;
        return;
      }
      document.getElementById('results-errors-line').textContent = notCheckedLine(notChecked);
      const mac = currentPlatform() === 'darwin';
      const { groups, raw } = couldntCheckGroups(couldntCheckItems(erroredModules, unfinishedModules, mode, partlyChecked, doc));
      // "Run them again": only the checks that took too long, and not while a scan runs.
      slowModules = erroredModules.filter((m) => couldntCheckItems([m], [], mode, [], doc)[0].kind === 'slow').map((m) => m.name);
      errorsList.innerHTML = groups.map((g) => `<li data-cause="${g.kind}">${g.notes.length ? '' : `<span>${escapeHtml(g.line)}</span>`}`
        + (g.kind === 'permission' && mac ? ` <button type="button" class="btn btn--secondary btn--small" data-setting-url="${FDA_URL}">Open the setting</button>` : '')
        + (g.kind === 'slow' && !partial && window.rescue && typeof window.rescue.recheckModule === 'function'
          ? ` <button type="button" class="btn btn--secondary btn--small" data-rerun-slow>Run ${g.names.length === 1 ? 'it' : 'them'} again</button>` : '')
        + (g.folded && g.folded.length ? `<details class="errors-list__names"><summary>${escapeHtml(`See which (${g.folded.length})`)}</summary><ul>${g.folded.map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ul></details>` : '')
        + (g.notes.length ? `<details class="errors-list__partly"><summary>${escapeHtml(`See what was only partly checked (${g.notes.length})`)}</summary><ul>${g.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join('')}</ul></details>` : '')
        + '</li>').join('');
      tech.hidden = !raw;
      document.getElementById('results-errors-raw').textContent = raw;
      errorsSection.hidden = false;
    }

    // A check waiting for the person to start it (the iPhone backup scan):
    // one line and a Start button that asks first. Never in "couldn't run".
    // The LIST starts nothing: the city's waiting signal is where it starts.
    function renderNotStarted(names) {
      const box = document.getElementById('results-waiting');
      if (!box) return;
      const line = notStartedLine(names, mode);
      box.hidden = !line;
      document.getElementById('results-waiting-line').textContent = line ? `${line} ${NOT_STARTED_WHERE}` : '';
    }

    // Run the checks that took too long again, one at a time (main runs one
    // change at a time). Each one that comes back replaces its entry; the
    // list then redraws from the merged scan, as after any re-check.
    let slowModules = [];
    let rerunning = false;
    async function rerunSlow() {
      if (rerunning || scanRunning || !slowModules.length) return;
      rerunning = true;
      const status = document.getElementById('results-errors-rerun');
      const names = slowModules.slice();
      status.textContent = `Running ${names.length === 1 ? 'it' : `${names.length} checks`} again\u2026`;
      let doc = null;
      let stillSlow = 0;
      for (const name of names) {
        try {
          const res = await window.rescue.recheckModule(name);
          if (res && res.ok && res.doc) doc = res.doc; else stillSlow += 1;
        } catch (_) {
          stillSlow += 1;
        }
      }
      rerunning = false;
      if (doc) {
        moduleCommandCache = new Map();
        window.RescueHost.docChanged(doc);
      }
      document.getElementById('results-errors-rerun').textContent = stillSlow
        ? `${stillSlow === names.length ? 'Still' : `${stillSlow} of ${names.length}`} couldn\u2019t finish. A tech helper can look at why below.`
        : 'Done. Those checks finished this time.';
    }

    // The Evidence block's "Checked with" row: each check's traced commands,
    // fetched once per check after the cards are drawn, then put into the
    // cards that show that check. Nothing changes when there are none.
    async function fillCommands(doc) {
      if (!window.rescue || typeof window.rescue.moduleCommands !== 'function') return;
      const root = document.getElementById('results-groups');
      const want = new Set();
      for (const { finding } of cardFindings.values()) {
        for (const m of finding.seen_in || [finding.module]) if (!moduleCommandCache.has(m)) want.add(m);
      }
      if (!want.size) return;
      const got = await Promise.all([...want].map((m) => Promise.resolve()
        .then(() => window.rescue.moduleCommands(m)).then((c) => [m, Array.isArray(c) ? c : []], () => [m, []])));
      // A newer scan or render may have landed meanwhile: only fill this one's cards.
      if (doc !== currentResultsDoc()) return;
      got.forEach(([m, c]) => moduleCommandCache.set(m, c));
      if (!got.some(([, c]) => c.length) || typeof root.querySelector !== 'function') return;
      for (const [key, { finding, held }] of cardFindings) {
        if (!(finding.seen_in || [finding.module]).some((m) => got.some(([g, c]) => g === m && c.length))) continue;
        const slot = root.querySelector(`[data-card-key="${key}"] [data-evidence-slot]`);
        if (slot) {
          slot.innerHTML = EvidenceRule.renderEvidence(cardEvidenceRows(finding, { mode, held, doc, commands: moduleCommandCache }),
            { copy: !EvidenceRule.noClipboard(mode, finding.seen_in || finding.module) });
        }
      }
    }

    function setScanBusy(isBusy) {
      const runButton = document.getElementById('btn-run-scan');
      const progress = document.getElementById('scan-progress');
      const errorNote = document.getElementById('scan-error');
      runButton.disabled = isBusy;
      runButton.hidden = isBusy;
      progress.hidden = !isBusy;
      document.getElementById('scan-intro').hidden = isBusy;
      document.getElementById('scan-keep-open').hidden = false;
      document.getElementById('scan-title').textContent = isBusy
        ? 'Your checkup is running'
        : 'Ready for your checkup';
      if (isBusy) errorNote.hidden = true;
    }

    // One plain line, saying which way it stopped; under "For tech helpers"
    // only what the line doesn't say: the engine's own words and the end of
    // the technical log. Never the plain line again.
    function showScanError(message) {
      const errorNote = document.getElementById('scan-error');
      document.getElementById('scan-error-line').innerHTML = stoppedScreenLine(stoppedDoc && stoppedDoc.stopped, escapeHtml);
      const raw = PLAIN_STOP_LINES.has(String(message || '').trim()) ? '' : String(message || '');
      const tech = [raw, logTail(document.getElementById('scan-log').textContent)].filter(Boolean).join('\n\n');
      document.getElementById('scan-error-text').textContent = tech;
      document.getElementById('scan-error-tech').hidden = !tech;
      document.getElementById('btn-scan-sofar').hidden = !stoppedDoc;
      // One way to run it again: the box's own button.
      document.getElementById('btn-run-scan').hidden = true;
      document.getElementById('scan-intro').hidden = true;
      document.getElementById('scan-title').textContent = 'The checkup stopped';
      document.getElementById('scan-keep-open').hidden = true;
      errorNote.hidden = false;
    }
    // The results the stopped checkup sent before it stopped, or null.
    let stoppedDoc = null;
    function showStopped() {
      if (!stoppedDoc) return;
      renderResults(stoppedDoc);
      showScreen('results');
    }

    let lastScanDoc = null;
    let foundSoFar = 0;
    // What the running scan has found so far (partialScanState), or null.
    let partialScan = null;
    let partialTimer = null;
    const partialShowing = () => !!partialScan && scanRunning;
    // What the results screen shows: the running scan's results so far, or the last scan.
    function currentResultsDoc() {
      if (partialShowing()) return partialDocOf(partialScan, currentPlatform());
      return resultsPartial && stoppedDoc ? stoppedDoc : lastScanDoc;
    }
    function viewingPartial() {
      return partialShowing() && !screens.results.hidden;
    }
    function updatePartialStatus() {
      document.getElementById('scan-partial').hidden = !(partialShowing() && partialScan.modules.length > 0);
      if (viewingPartial()) {
        document.getElementById('results-running-text').textContent = partialCountText(partialScan);
      }
    }
    // New findings while the person is looking: redraw, at most a few times a second.
    function schedulePartialRender() {
      if (partialTimer) return;
      partialTimer = setTimeout(() => {
        partialTimer = null;
        if (viewingPartial()) renderResults(currentResultsDoc());
      }, 400);
    }
    function showPartialResults() {
      if (!partialShowing()) return;
      renderResults(currentResultsDoc());
      showScreen('results');
    }
    // A scan ended: the results screen goes back to the last finished scan.
    function endPartial() {
      partialScan = null;
      document.getElementById('scan-partial').hidden = true;
    }

    function resetProgress() {
      foundSoFar = 0;
      document.getElementById('scan-status').textContent = 'Getting ready\u2026';
      document.getElementById('scan-substatus').textContent = 'Starting the checkup engine.';
      document.getElementById('scan-bar-fill').style.width = '0%';
      document.getElementById('scan-bar').setAttribute('aria-valuenow', '0');
      document.getElementById('scan-log').textContent = '';
    }

    function appendLog(text) {
      const log = document.getElementById('scan-log');
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
      log.textContent += text + '\n';
      if (atBottom) log.scrollTop = log.scrollHeight;
    }

    function onScanEvent(ev) {
      if (!fdaNeeded && needsFda(ev)) {
        fdaNeeded = true;
        if (permissionsContent) renderScanTips(permissionsContent, detectOS(lastKnownPlatform));
      }
      if (partialScan) {
        const changed = applyPartialEvent(partialScan, ev);
        updatePartialStatus();
        if (changed) schedulePartialRender();
      }
      if (ev.type === 'module' || ev.type === 'plan') return;
      if (ev.type === 'wait') {
        document.getElementById('scan-status').textContent = WAIT_FOR_CHANGE_TEXT;
        document.getElementById('scan-substatus').textContent = '';
        return;
      }
      if (ev.type === 'log') {
        appendLog(ev.line);
        return;
      }
      if (ev.type === 'exec') {
        appendLog(formatExec(ev));
        return;
      }
      if (ev.type !== 'progress') return;
      const p = describeProgress(ev);
      document.getElementById('scan-bar-fill').style.width = `${p.percent}%`;
      document.getElementById('scan-bar').setAttribute('aria-valuenow', String(p.percent));
      if (ev.phase === 'start') {
        document.getElementById('scan-status').textContent = `${p.headline}\u2026`;
        const found = foundSoFar
          ? ` \u00b7 ${foundSoFar} thing${foundSoFar === 1 ? '' : 's'} noted so far`
          : '';
        document.getElementById('scan-substatus').textContent = p.detail + found;
        appendLog(`[${ev.index}/${ev.total}] ${ev.module} ...`);
      } else {
        foundSoFar += ev.findings || 0;
        // The last check is done; the engine now looks up who made each program.
        if (ev.total && ev.index >= ev.total) {
          document.getElementById('scan-status').textContent = LOOKUP_TEXT;
          document.getElementById('scan-substatus').textContent = '';
        }
        appendLog(`[${ev.index}/${ev.total}] ${ev.module}: ${
          ev.error ? `could not run (${ev.error})` : `${ev.findings} finding(s)`}`);
      }
    }

    async function runCheckup(opts) {
      if (scanRunning) return; // one scan at a time, however many buttons are pressed
      scanRunning = true;
      // A click handler passes an Event here; only {game: true} from the game counts.
      const inGame = !!(opts && opts.game === true && window.RescueGame && window.RescueGame.isReady);
      if (inGame) leftGame = false;
      gameScan = inGame;
      setScanBusy(true);
      resetProgress();
      fdaNeeded = false;
      stoppedDoc = null;
      let resolvedStopped = null;
      if (permissionsContent) renderScanTips(permissionsContent, detectOS(lastKnownPlatform));
      partialScan = partialScanState();
      updatePartialStatus();
      if (inGame) window.RescueGame.showBoss();
      const unsubscribe = window.rescue.onScanEvent((ev) => {
        onScanEvent(ev);
        if (inGame && !leftGame && GAME_SCAN_EVENTS.has(ev.type)) window.RescueGame.scanEvent(ev);
      });
      try {
        // One profile, the union of several (one --profile each), or null for every check.
        const doc = await window.rescue.runScan(WorryPick.scanProfile(situation));
        if (doc && doc.stopped && typeof doc.stopped === 'object') {
          // A checkup that stopped: kept as "what it found so far", never as a result.
          resolvedStopped = doc;
          throw new Error(STOPPED_LINE);
        }
        if (doc && typeof doc.platform === 'string') {
          lastKnownPlatform = doc.platform;
        }
        lastScanDoc = doc;
        moduleCommandCache = new Map();
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        endPartial();
        // scanRunning stays true until `finally`: the LIST's way back to the city follows the finished scan now.
        scanRunning = false;
        renderResults(doc);
        renderNextStep();
        renderLearnMore(doc);
        setScanBusy(false);
        const land = () => {
          const view = postScanView({
            inGame, left: leftGame,
            offered: gameOfferedFor(situation), ready: !!(window.RescueGame && window.RescueGame.isReady),
          });
          if (view === 'boss-city') {
            if (window.RescueGame.scanDone(doc, situation) === false) {
              showScreen('results'); // the city couldn't be drawn: the LIST, which has the same results
            } else {
              showScreen('city');
            }
          } else if (view === 'city') {
            showCity(doc);
          } else {
            showScreen('results');
          }
        };
        if (FirstQuestion.recheckDue({ mode, monitoringSeen, asked: recheckAsked })) {
          recheckAsked = true;
          ask('recheck', land);
        } else {
          land();
        }
      } catch (err) {
        // Results so far go: the list shows the last finished checkup again,
        // and the error shows where the checkup's progress was.
        const wasViewing = viewingPartial();
        // What arrived before it stopped is kept, behind "See what it found
        // so far": marked as stopped, so it never reads as the whole checkup.
        stoppedDoc = resolvedStopped || (partialScan && partialScan.modules.length ? stoppedDocOf(partialScan, currentPlatform()) : null);
        endPartial();
        scanRunning = false;
        if (lastScanDoc) {
          renderResults(lastScanDoc);
          renderLearnMore(lastScanDoc);
        } else {
          renderResultsFrame(null);
        }
        if (wasViewing) showScreen('scan');
        setScanBusy(false);
        const message = scanErrorText(err && err.message ? err.message : String(err));
        if (inGame && !leftGame && stoppedDoc) {
          // What the stopped checkup found goes to the city, which shows it as
          // stopped (its stopped deck, nothing to act on). The list behind the
          // city's "see it in the list" shows the same stopped results.
          renderResults(stoppedDoc);
          // The city's own entry for it (B5): scanFailed with the stopped doc.
          if (window.RescueGame.scanFailed(message, stoppedDoc) === false) {
            showScreen('scan');
            showScanError(message);
          } else {
            showScreen('city');
          }
        } else if (inGame && !leftGame) {
          if (window.RescueGame.scanFailed(message) === false) showScanError(message);
          else showScreen('city');
        } else {
          showScanError(message);
        }
      } finally {
        unsubscribe();
        scanRunning = false;
        gameScan = false;
        if (partialTimer) { clearTimeout(partialTimer); partialTimer = null; }
      }
    }

    function resetToWelcome() {
      const runButton = document.getElementById('btn-run-scan');
      runButton.disabled = false;
      runButton.hidden = false;
      document.getElementById('scan-progress').hidden = true;
      document.getElementById('scan-error').hidden = true;
      document.getElementById('scan-intro').hidden = false;
      document.getElementById('scan-title').textContent = 'Ready for your checkup';
      document.getElementById('scan-keep-open').hidden = false;
      situation = null;
      leftGame = false;
      showScreen('welcome');
    }

    // The LIST's delegated controls: none of them changes the computer.
    const resultsRoot = document.getElementById('results-groups');
    document.getElementById('results-errors-list').addEventListener('click', (event) => {
      const btn = event.target.closest && event.target.closest('[data-setting-url]');
      if (btn) window.rescue.openSetting(btn.getAttribute('data-setting-url'));
      if (event.target.closest && event.target.closest('[data-rerun-slow]')) rerunSlow();
    });
    // "Read this first" on a card: the removal warning, said once above the list.
    resultsRoot.addEventListener('click', (event) => {
      const jump = event.target.closest && event.target.closest('[data-safety-jump]');
      if (!jump) return;
      const banner = document.getElementById('results-safety');
      if (banner && typeof banner.scrollIntoView === 'function') banner.scrollIntoView({ block: 'start' });
      const more = banner && typeof banner.querySelector === 'function' ? banner.querySelector('[data-safety-details]') : null;
      if (more) more.open = true;
      if (banner && typeof banner.focus === 'function') banner.focus();
    });
    // "What does this mean?": opens the one place it is taught, at that part.
    resultsRoot.addEventListener('click', (event) => {
      const link = event.target.closest && event.target.closest('[data-lesson-link]');
      if (!link) return;
      const box = document.getElementById('results-lessons');
      const part = document.getElementById(`lesson-${link.getAttribute('data-lesson-link')}`);
      const more = document.getElementById('results-more');
      if (more) more.open = true;
      box.open = true;
      if (part && typeof part.scrollIntoView === 'function') part.scrollIntoView({ block: 'start' });
      if (part && typeof part.focus === 'function') part.focus();
    });

    // "Open in System Settings": opens the page and nothing else; main allowlists the URL.
    resultsRoot.addEventListener('click', (event) => {
      const btn = event.target.closest && event.target.closest('[data-setting-url]');
      if (btn && resultsRoot.contains(btn)) window.rescue.openSetting(btn.getAttribute('data-setting-url'));
      // "Open your router's settings": only the address goes to main, which builds the URL.
      const router = event.target.closest && event.target.closest('[data-router-ip]');
      if (router && resultsRoot.contains(router)) window.rescue.openRouter(router.getAttribute('data-router-ip'));
    });
    // The Evidence block's Copy buttons (none on a held card: renderEvidence leaves them out).
    EvidenceRule.wireCopy(document, (t) => navigator.clipboard.writeText(t));
    // Each visit to the worry screen starts with nothing ticked.
    document.getElementById('btn-get-started').addEventListener('click', () => {
      leftGame = false;
      renderSituations();
      showScreen('worry');
    });
    // "Something changed?": the question again, then back to the worry screen.
    document.getElementById('btn-something-changed').addEventListener('click', () => {
      // Before any answer this is the first ask; after one, the re-ask, where
      // Back and "rather not say" leave the setting as it is.
      // Back on the worry screen, the ticks are as they were and focus returns
      // to this link, so the person carries on where they were.
      ask(mode ? 'change' : 'first', () => {
        showScreen('worry');
        const back = document.getElementById('btn-something-changed');
        if (back && typeof back.focus === 'function') back.focus();
      });
    });
    document.getElementById('btn-back-city').addEventListener('click', backToCity);

    async function goToScan() {
      renderScanIntro();
      showScreen('scan');
      try {
        const content = await loadPermissionsContent();
        renderScanTips(content, detectOS(lastKnownPlatform));
      } catch (err) {
        // The tips are a convenience; the checkup runs fine without them.
        document.getElementById('scan-tips').hidden = true;
      }
    }

    document.getElementById('btn-copy-json').addEventListener('click', async () => {
      const status = document.getElementById('copy-json-status');
      try {
        await navigator.clipboard.writeText(technicalReportText(lastScanDoc, { cover: mode === 'city' }));
        status.textContent = ' Copied.';
      } catch (err) {
        status.textContent = ` Couldn\u2019t copy (${err && err.message ? err.message : err}).`;
      }
    });

    document.getElementById('btn-open-guide').addEventListener('click', () => {
      if (guideLinks.length) window.rescue.openGuide(guideLinks[0].url);
    });
    document.getElementById('results-guides').addEventListener('click', (event) => {
      const btn = event.target && typeof event.target.closest === 'function' ? event.target.closest('[data-guide-index]') : null;
      const link = btn ? guideLinks[Number(btn.getAttribute('data-guide-index'))] : null;
      if (link) window.rescue.openGuide(link.url);
    });

    document.getElementById('btn-open-game').addEventListener('click', () => {
      if (learnMoreUrl) window.rescue.openGuide(learnMoreUrl);
    });

    document.getElementById('btn-see-partial').addEventListener('click', showPartialResults);
    // The running box's way back: the city's sweep screen when the sweep is
    // the game's, else the scan screen (its progress, or "Run it again").
    document.getElementById('btn-back-to-scan').addEventListener('click', () => {
      if (scanRunning && gameScan && !leftGame && cityAvailable()) showScreen('city');
      else showScreen('scan');
    });
    document.getElementById('btn-run-scan').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-retry').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-sofar').addEventListener('click', showStopped);
    // Start over throws these results away: asked first, as the city asks.
    document.getElementById('btn-start-over').addEventListener('click', () => {
      document.getElementById('btn-start-over').hidden = true;
      document.getElementById('start-over-confirm').hidden = false;
      const yes = document.getElementById('btn-start-over-yes');
      if (yes && typeof yes.focus === 'function') yes.focus();
    });
    function closeStartOver() {
      document.getElementById('btn-start-over').hidden = false;
      document.getElementById('start-over-confirm').hidden = true;
    }
    document.getElementById('btn-start-over-yes').addEventListener('click', () => { closeStartOver(); resetToWelcome(); });
    document.getElementById('btn-start-over-no').addEventListener('click', () => {
      closeStartOver();
      const back = document.getElementById('btn-start-over');
      if (back && typeof back.focus === 'function') back.focus();
    });

    // Esc on the LIST goes back to the city, in both modes, as it does from
    // the help district. Not when Esc just closed a confirm panel.
    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      if (!screens.results || screens.results.hidden) return;
      backToCity();
    });

    // 'city' opens straight into the game: the command deck, with the sweep
    // as its main action until one has run this session. LIST, TRAINING and
    // every worry still work from there.
    function openCityHome() {
      if (!(window.RescueGame && window.RescueGame.isReady)) return false;
      situation = CITY_SITUATION;
      leftGame = false;
      if (window.RescueGame.showHome(situation) !== false) showScreen('city');
      return true;
    }

    // The worry list's count, button words and arrow keys: delegated on its
    // container once, so redrawing the list on each visit adds no listeners.
    Checklist.attach(document.getElementById('situations'), {});
    renderSituations();
    // 'city' opens the city first, so the welcome screen never draws on the
    // way. Only while the game's module is still loading (or it declines) does
    // the welcome screen show, until the game is ready.
    const cityOpened = opensInGame(mode) && openCityHome();
    if (!cityOpened || screens.city.hidden) showScreen('welcome');
    if (opensInGame(mode) && !cityOpened) {
      window.addEventListener('rescue-game-ready', () => {
        if (opensInGame(mode) && !screens.welcome.hidden) openCityHome();
      });
    }
  })();
}
