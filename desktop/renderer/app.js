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
 * Whether to offer game mode: every worry but the iPhone check, which reads a
 * phone backup on its own plain screen. Monitoring software no longer closes
 * it. In 'city' the game is the cover and its help lives in one district; in
 * 'standard' the person is asked first (FirstQuestion's follow-up).
 */
function gameOfferedFor(situation) {
  return !!situation && !WorryPick.has(situation, 'phone');
}

/** 'city' always plays: the app opens into the game, and every worry's scan runs there. */
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

/** After a worry is picked: its scan starts at once on the game's sweep screen, or the plain scan screen. */
function gameScanFirst({ wantsCity, offered, ready }) {
  return !!(wantsCity && offered && ready);
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

/** The worry click: its scan starts at once in the game, or the plain scan screen. */
function worryStartsGameScan({ situation, wantsCity, mode, ready }) {
  return gameScanFirst({ wantsCity: !!wantsCity || opensInGame(mode), offered: gameOfferedFor(situation), ready });
}

/**
 * Where a finished scan lands. Monitoring software doesn't change it: the
 * follow-up question, when due, comes before this. "Plain view" stays plain.
 */
function postScanView({ inGame, left, wantsCity, rememberedCity, offered, ready, mode }) {
  if (!offered || !ready || left) return 'results';
  if (inGame) return 'boss-city';
  return wantsCity || rememberedCity || opensInGame(mode) ? 'city' : 'results';
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
function duringScanTips(content, osKey) {
  const steps = (content && content[osKey]) || [];
  return steps.filter((step) => step && step.stage !== 'install');
}

// Only these kinds of finding can be "Needs attention now". A crashing app,
// a missing backup or a busy program is worth a look, not an alarm.
const ALARM_CATEGORIES = new Set(['security', 'network']);
function shownSeverity(finding) {
  const sev = finding && Object.prototype.hasOwnProperty.call(SEVERITY_LABELS, finding.severity) ? finding.severity : 'info';
  return sev === 'critical' && !ALARM_CATEGORIES.has(finding.category) ? 'warning' : sev;
}

// A note that says part of a check couldn't look ("We couldn't list your USB
// devices", "Checked 16 of 110 app signatures"). It belongs with the checks
// that couldn't run, not among the good-to-know notes.
const COULDNT_TITLE = /^(?:we\s+)?(?:couldn[’']t|could\s+not)\s+(?:check|list|read|see|tell|find\s+out)\b/i;
function isPartlyChecked(finding) {
  if (!finding || finding.severity !== 'info') return false;
  const title = String(finding.title || '');
  if (COULDNT_TITLE.test(title)) return true;
  return !!(finding.data && finding.data.incomplete) && /^checked\s+\d+\s+of\s+\d+/i.test(title);
}

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
  const erroredModules = [];
  const unfinishedModules = [];
  // Findings that say part of a check couldn't look: listed with the checks
  // that couldn't run (partlyChecked), not as notes.
  const partlyChecked = [];
  const modules = (doc && doc.modules) || [];

  for (const mod of modules) {
    if (mod && mod.status === 'error') {
      erroredModules.push({ name: mod.name, error: mod.error || null });
    } else if (mod && mod.supported === false) {
      // Could not run here: not a clean result, so it must not read as one.
      erroredModules.push({ name: mod.name, error: mod.unsupported_reason || null });
    } else if (mod && mod.complete === false) {
      unfinishedModules.push({ name: mod.name });
    }
    const findings = (mod && mod.findings) || [];
    for (const finding of findings) {
      if (isPartlyChecked(finding)) {
        partlyChecked.push({ name: mod.name, title: String(finding.title || '') });
        continue;
      }
      groups[shownSeverity(finding)].push(Object.assign({}, finding, { module: mod.name }));
    }
  }

  return { groups, erroredModules, unfinishedModules, partlyChecked };
}

/**
 * One count of what wasn't fully checked, for the list and the city alike:
 * checks that couldn't run or didn't finish, plus notes that say part of a
 * check couldn't look. `checks` is every check in the scan.
 */
function notCheckedSummary(doc) {
  const { erroredModules, unfinishedModules, partlyChecked } = groupFindingsBySeverity(doc);
  const checks = ((doc && doc.modules) || []).length;
  return {
    checks,
    couldntRun: erroredModules.length,
    unfinished: unfinishedModules.length,
    partly: partlyChecked.length,
    count: erroredModules.length + unfinishedModules.length + partlyChecked.length,
  };
}

// The top line when something wasn't fully checked. Never an all-clear.
function notCheckedLine(sum) {
  const s = sum || {};
  const ran = (s.couldntRun || 0) + (s.unfinished || 0);
  const how = s.couldntRun && s.unfinished ? 'couldn’t run or didn’t finish' : s.couldntRun ? 'couldn’t run' : 'didn’t finish';
  const parts = [];
  if (ran) parts.push(`${ran} ${ran === 1 ? 'check' : 'checks'} ${how}`);
  if (s.partly) parts.push(`${s.partly} ${s.partly === 1 ? 'thing was' : 'things were'} only partly checked`);
  if (!parts.length) return '';
  return `${parts.join(', and ')}, so this isn’t a clean bill of health.`;
}

/**
 * The engine's walkthroughs say `<path-to-plist>` or `<label>` where the scan
 * already knows the value. Fill in what the finding's data has; leave the
 * rest as written.
 */
const PLACEHOLDERS = { 'path-to-plist': ['plist', 'plist_path'], plist: ['plist', 'plist_path'], label: ['label'],
  path: ['path', 'location'], pid: ['pid'], program: ['program'], 'bundle-id': ['bundle_id'] };
function fillPlaceholders(text, data) {
  const d = data && typeof data === 'object' ? data : {};
  return String(text == null ? '' : text).replace(/<([a-z-]+)>/g, (all, name) => {
    const keys = PLACEHOLDERS[name];
    const key = keys && keys.find((k) => (typeof d[k] === 'string' && d[k]) || typeof d[k] === 'number');
    return key ? String(d[key]) : all;
  });
}

/**
 * A check's name for people: "launch_agent_audit" -> "Launch agent audit",
 * the same words the progress line uses. Never the raw id. In city mode a
 * monitoring check is never named: just "A check".
 */
function checkName(module, mode) {
  if (mode === 'city' && ALWAYS_SAFETY_MODULES.has(module)) return 'A check';
  const words = String(module || '').replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check';
}

/**
 * A check as the copy-for-AI report names it: its words, then its id in
 * parentheses (an AI can look the id up). In city mode a monitoring check is
 * "A check", with no id.
 */
function aiCheckLabel(module, mode) {
  const words = checkName(module, mode);
  if (mode === 'city' && ALWAYS_SAFETY_MODULES.has(module)) return words;
  return `${words} (${String(module || '')})`;
}

const UNFINISHED_LINE = 'It didn’t finish, so it may have missed something.';

// The engine's error, in words: needs a permission, took too long, or
// couldn't run. The raw text goes under "For tech helpers".
function errorKind(error) {
  const e = String(error || '');
  if (/PermissionError|Operation not permitted|Errno 1\b|not permitted|Full Disk Access/i.test(e)) return 'permission';
  if (/timed out|timeout/i.test(e)) return 'slow';
  return 'failed';
}
const ERROR_WORDS = {
  permission: 'Needs permission (Full Disk Access).',
  slow: 'Took too long.',
  failed: 'Couldn’t run.',
};

/**
 * The "couldn't check these" list: checks that couldn't run, then checks
 * that didn't finish. In city mode a monitoring check's reason isn't shown
 * either (it can name what it looked for).
 */
function couldntCheckItems(erroredModules, unfinishedModules, mode, partlyChecked) {
  const hide = (name) => mode === 'city' && ALWAYS_SAFETY_MODULES.has(name);
  return [
    ...erroredModules.map((m) => {
      const kind = errorKind(m.error);
      return { name: checkName(m.name, mode), kind,
        reason: hide(m.name) ? '' : m.error ? ERROR_WORDS[kind] : '', raw: hide(m.name) ? '' : m.error || '' };
    }),
    ...unfinishedModules.map((m) => ({ name: checkName(m.name, mode), kind: 'unfinished', reason: UNFINISHED_LINE, raw: '' })),
    ...(partlyChecked || []).map((m) => ({ name: checkName(m.name, mode), kind: 'partly',
      reason: hide(m.name) ? '' : m.title, raw: '' })),
  ];
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
  if (!total) return 'The checkup is still running.';
  if (done >= total) return LOOKUP_TEXT;
  return `The checkup is still running: ${done} of ${total} checks done.`;
}

// The sentence at the top of partial results. Never an all-clear: the
// checks still running haven't looked yet. `worth` = warnings and criticals.
function partialSummaryText({ worth = 0, other = 0 } = {}) {
  if (worth > 0) return `So far, ${worth} thing${worth === 1 ? '' : 's'} worth a look. More may turn up.`;
  if (other > 0) return 'Nothing worth a look so far. The checkup isn’t finished, so more may turn up.';
  return 'Nothing to show yet. The checkup isn’t finished.';
}

const PARTIAL_ACTIONS_TEXT = 'Fixes and “It’s mine” open when the checkup is done.';

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectOS,
    GAME_SCAN_EVENTS,
    partialScanState,
    applyPartialEvent,
    partialDocOf,
    isPartialDoc,
    partialCountText,
    partialSummaryText,
    PARTIAL_ACTIONS_TEXT,
    LOOKUP_TEXT,
    WAIT_FOR_CHANGE_TEXT,
    duringScanTips,
    groupFindingsBySeverity,
    checkName,
    aiCheckLabel,
    couldntCheckItems,
    errorKind,
    notCheckedSummary,
    notCheckedLine,
    isPartlyChecked,
    shownSeverity,
    fillPlaceholders,
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

    let permissionsContent = null;
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
    let wantsCity = false; // came in through "Play it as a game"
    let leftGame = false; // chose "Plain view" during game mode
    let scanRunning = false;
    // The results screen is showing a running scan's results so far.
    let resultsPartial = false;
    let lastScanSituation = null; // the worry lastScanDoc was run for
    // Monitoring software seen in any scan or re-check this session (noteMonitoring).
    // Memory only: never written to storage.
    let monitoringSeen = false;
    // The display preference (DisplayMode): 'city', 'standard', or null before the question.
    const store = (() => { try { return window.localStorage; } catch (_) { return null; } })();
    let mode = DisplayMode.readMode(store);
    // Whether the follow-up was asked this session. Memory only, like monitoringSeen.
    let recheckAsked = false;
    // A change of mode redraws the list, so a card loses or gains its controls at once.
    function setMode(next) {
      const changed = next !== mode;
      mode = next;
      DisplayMode.writeMode(store, next);
      // The game saves its profile once in the new mode (city mode retires the old store).
      if (changed && window.RescueGame && typeof window.RescueGame.profileModeChanged === 'function') window.RescueGame.profileModeChanged();
      const shownDoc = currentResultsDoc();
      if (changed && shownDoc) renderResults(shownDoc);
      // "Your progress" (game/profile/plain-panel.js) shows only in standard mode.
      if (changed && typeof window.dispatchEvent === 'function' && typeof Event === 'function') window.dispatchEvent(new Event('rescue-mode-changed'));
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
    const VIEW_KEY = 'device-rescue.view';
    function rememberView(v) { try { localStorage.setItem(VIEW_KEY, v); } catch (_) { /* per-viewer nicety only */ } }
    function rememberedView() { try { return localStorage.getItem(VIEW_KEY); } catch (_) { return null; } }

    function cityAvailable() {
      return gameOfferedFor(situation) && !!(window.RescueGame && window.RescueGame.isReady);
    }
    function showCity(doc) {
      if (!cityAvailable()) { showScreen('results'); return; }
      // false: the city couldn't be drawn and the controller already left the game.
      if (window.RescueGame.show(doc, situation) === false) { showScreen('results'); return; }
      rememberView('city');
      showScreen('city');
    }
    function renderCitySwitch(doc) {
      // Not while the list is partial: the city opens from the finished checkup.
      document.getElementById('results-city-switch').hidden = !cityAvailable() || resultsPartial;
    }

    window.RescueHost = {
      showList() { rememberView('list'); showScreen('results'); },
      // A re-check changed the scan. Keep the list in step. Monitoring software
      // no longer closes the city; in standard mode it brings the follow-up once.
      docChanged(doc) {
        lastScanDoc = doc;
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        renderResults(doc);
        renderLearnMore(doc);
        renderCitySwitch(doc);
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
          return duringScanTips(content, detectOS(lastKnownPlatform)).map((t) => ({ title: t.title, body: t.body }));
        } catch (_) {
          return [];
        }
      },
      // "Plain view": back to the app's own plain screens. A running scan carries
      // on there, with its live progress (setScanBusy(true) already ran).
      leaveGame() {
        leftGame = true;
        wantsCity = false;
        rememberView('list');
        if (lastScanDoc && !scanRunning && WorryPick.key(lastScanSituation) === WorryPick.key(situation)) showScreen('results');
        else goToScan();
      },
    };
    window.addEventListener('rescue-game-ready', () => { if (lastScanDoc) renderCitySwitch(lastScanDoc); });

    let activeDot = null;
    function showScreen(name) {
      Object.keys(screens).forEach((key) => {
        if (!screens[key]) return;
        screens[key].hidden = key !== name;
      });
      // The question screen keeps the step the person was on (worry, or the checkup's follow-up).
      const dotName = name === 'question' ? activeDot : name === 'city' ? 'results' : name;
      activeDot = dotName;
      stepDots.forEach((dot) => {
        dot.classList.toggle('step-dot--active', dot.dataset.stepDot === dotName);
      });
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
      const steps = duringScanTips(content, osKey);
      aside.hidden = steps.length === 0;
      if (steps.length === 0) return;
      // One line on its face; what each pop-up means is behind "What each pop-up means".
      const who = osKey === 'windows' ? 'Windows' : osKey === 'linux' ? 'Your computer' : 'Your Mac';
      document.getElementById('scan-tips-line').textContent = `${who} may ask for permission. Click Allow. We never ask for your password.`;

      const stepsHtml = steps
        .map((step) => {
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
        })
        .join('');

      container.innerHTML = `<ul class="tip-list">${stepsHtml}</ul>`;

      container.querySelectorAll('[data-setting-url]').forEach((btn) => {
        btn.addEventListener('click', () => {
          window.rescue.openSetting(btn.getAttribute('data-setting-url'));
        });
      });
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

    // What a picked worry does once the display preference is known.
    function startWorry() {
      if (!scanRunning && worryStartsGameScan({ situation, wantsCity, mode,
        ready: !!(window.RescueGame && window.RescueGame.isReady) })) {
        leftGame = false;
        window.RescueGame.newWorry(situation);
        // The city screen first: if the sweep can't be drawn, leaveGame() then
        // shows the plain scan screen, where the same scan carries on.
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
        ? guideLinks.map((g, i) => `<li><button type="button" class="btn btn--primary" data-guide-index="${i}">${escapeHtml(g.name)}</button></li>`).join('')
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

    // Per card, for the session answers: what "Copy for any AI" and the
    // technical details say about it. Reset on every render.
    let cardPicks = new Map(); // card key -> copy-ai pick
    let cardTech = new Map(); // card key -> technical-details object
    let nextCardKey = 0;

    function techText(key, how) {
      const base = cardTech.get(key) || {};
      const said = ClearList.personSaid(how);
      return JSON.stringify(said ? Object.assign({}, base, { person_said: said }) : base, null, 2);
    }

    // A card was cleared (how) or put back (null): keep the AI text and the
    // technical details honest about it.
    function onCardChange(card, how) {
      const key = card.getAttribute('data-card-key');
      const pick = cardPicks.get(key);
      if (pick) {
        const said = ClearList.personSaid(how);
        if (said) pick.person_said = said; else delete pick.person_said;
      }
      const pre = card.querySelector('[data-tech-log]');
      if (pre) pre.textContent = techText(key, how);
      const box = card.querySelector('[data-card-pick]');
      if (box && how) box.checked = false;
      // A card past "Show more" can be cleared too (marked on an earlier checkup): in Cleared it shows.
      if (how && card.hasAttribute('data-card-more')) { card.hidden = false; card.removeAttribute('data-card-more'); }
      const root = document.getElementById('results-groups');
      topUp(root);
      updateBulk();
    }

    const FDA_URL = 'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles';
    // The actions on ticked cards. Ticking changes nothing; these buttons do, and only to the ticked cards.
    const BULK_HTML = `
      <div class="results-bulk" data-bulk role="group" aria-label="Ticked cards" hidden>
        <span class="results-bulk__count" data-bulk-count aria-live="polite"></span>
        <button type="button" class="btn btn--secondary btn--small" data-bulk-did></button>
        <button type="button" class="btn btn--secondary btn--small" data-bulk-copy data-copy-ai="sel:">Copy these for any AI</button>
        <button type="button" class="link-button" data-bulk-none>Untick all</button>
        <div class="copy-ai__slot" data-bulk-slot data-copy-ai-slot="sel:" aria-live="polite"></div>
      </div>`;

    // The bulk bar follows the ticks: how many, and what each button would do.
    function updateBulk() {
      const root = document.getElementById('results-groups');
      const bar = root && root.querySelector('[data-bulk]');
      if (!bar) return;
      const ticked = Array.from(root.querySelectorAll('[data-card-pick]')).filter((b) => b.checked && !b.closest('[data-cleared]'));
      bar.hidden = ticked.length === 0;
      bar.querySelector('[data-bulk-count]').textContent = `${ticked.length} ticked`;
      const canDid = ticked.filter((b) => b.closest('[data-card-key]').querySelector('[data-clear-did]:not([hidden])'));
      const did = bar.querySelector('[data-bulk-did]');
      did.hidden = canDid.length === 0;
      did.textContent = canDid.length === 1 ? 'I did this one' : `I did these ${canDid.length}`;
      const ids = ticked.map((b) => b.closest('[data-card-key]').querySelector('[data-copy-ai]'))
        .filter(Boolean).map((btn) => btn.getAttribute('data-copy-ai')).join(',');
      const copy = bar.querySelector('[data-bulk-copy]');
      const slot = bar.querySelector('[data-bulk-slot]');
      if (copy.getAttribute('data-copy-ai') !== `sel:${ids}`) slot.innerHTML = '';
      copy.setAttribute('data-copy-ai', `sel:${ids}`);
      slot.setAttribute('data-copy-ai-slot', `sel:${ids}`);
    }

    // How many cards each group shows before "Show more".
    const PAGE = 10;
    // "What does this mean?" under the made-by line: on the first card only.
    let madeByExplained = false;

    // `partial`: the scan is still running. The cards are the same, with
    // nothing on them that changes the computer or the list (main refuses
    // those mid-scan too: scan-gate.js).
    function renderSeverityGroup(severity, findings, partial = false) {
      if (findings.length === 0) return '';
      // City mode: the fix panel's extra warning about whoever set something up.
      const watched = mode === 'city';
      const items = findings
        .map((finding, index) => {
          const key = String(nextCardKey++);
          // What this card may say (QuietNotes). Standard: no hotline text, and the one
          // line wherever removing something can alert someone. City: everything, unquieted.
          const card = QuietNotes.cardText(mode, finding);
          // City mode, monitoring software: the hold line and its help. No fix,
          // no "It's mine", no steps, and it doesn't count toward the list's progress.
          const held = card.note === 'held';
          // City mode never offers a fix or a mark on these checks, even on a
          // status line that found nothing ("No device backups found").
          const noControls = partial || held || (mode === 'city' && QuietNotes.isMonitoring(finding));
          // Nor does an AI get its removal steps or evidence: only the card's own text.
          const pick = held ? QuietNotes.heldPick(card, finding) : copyAiPick(finding);
          cardPicks.set(key, pick);
          cardTech.set(key, {
            check: finding.module,
            code: finding.code || null,
            category: finding.category,
            confidence: finding.confidence == null ? null : finding.confidence,
            evidence: finding.data || {},
          });
          const marked = !!(finding.data && finding.data.marked_by_user === true);
          // On the list: everything worth acting on, plus what was marked as yours.
          const counts = !held && (severity === 'critical' || severity === 'warning' || marked);
          // Monitoring software never gets "I did this": it reads as "I removed it".
          const did = marked || held || partial || QuietNotes.isDetection(finding)
            ? '' : ClearList.didControlsHtml(finding, severity, escapeHtml);
          // Whether removing this can alert someone: said before any fix or mark, and in the fix confirm.
          const alerts = card.note === 'line' || card.note === 'full';
          const fix = noControls ? '' : FixFlow.fixControlsHtml(finding, { watched, safety: alerts && !watched ? QuietNotes.LINE_SHORT : '' });
          const mark = noControls ? '' : MarkFlow.markControlsHtml(finding, { watched });
          const explain = !madeByExplained;
          const madeBy = madeByHtml(finding.made_by, escapeHtml, { explain });
          if (madeBy) madeByExplained = true;
          const steps = card.steps.map((step) => ({ title: step.title, body: fillPlaceholders(step.body, finding.data) }));
          // Ticking selects the card for the actions above the list; it changes nothing by itself.
          const pickBox = counts && !partial ? `<input type="checkbox" class="finding-card__pick" data-card-pick aria-label="${escapeHtml(`Select: ${finding.title || 'this finding'}`)}">` : '';
          return `
            <li class="finding-card finding-card--${severity}" data-card-key="${key}" data-finding-key="${escapeHtml(`${finding.module}|${finding.code || ''}|${finding.title || ''}`).replace(/"/g, '&quot;')}" data-card-counts="${counts ? '1' : '0'}"${marked ? ' data-marked-before' : ''}${index >= PAGE ? ' data-card-more hidden' : ''}>
              <div class="finding-card__header">
                ${pickBox}
                <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
                <h3>${escapeHtml(finding.title || 'Untitled finding')}</h3>
              </div>
              <div class="cleared-note" data-cleared-note role="status" aria-live="polite" hidden></div>
              ${descriptionHtml(card.description, escapeHtml)}
              ${madeBy}
              ${QuietNotes.lineHtml(card, escapeHtml, { first: !!(fix || mark) })}${QuietNotes.fullHtml(card, escapeHtml)}${QuietNotes.heldHtml(card, escapeHtml)}
              ${fix || mark || did ? `<div class="card-answers">${fix}${mark}${did}</div>` : ''}
              ${steps.length ? `
              <div class="next-steps">
                <h4>What to do</h4>
                <ol>${steps.map((step) => `<li>${escapeHtml(stepTitle(step.title))}</li>`).join('')}</ol>
              </div>` : ''}
              ${held ? '' : SettingPanes.findingButtonHtml(finding, currentPlatform())}
              ${held ? '' : RouterLink.findingLinkHtml(finding, routerCtx)}
              ${finding.remediation && !held && steps.length ? `
              <details class="fix-steps">
                <summary>${finding.fixable ? 'Or fix it yourself, step by step' : 'Show me how, step by step'}</summary>
                <ol class="fix-steps__list">
                  ${steps.map((step) => `
                    <li>
                      <h4>${escapeHtml(step.title)}</h4>
                      <div class="fix-steps__body">${renderMiniMarkdown(step.body)}</div>
                    </li>`).join('')}
                </ol>
              </details>` : ''}
              <details class="get-help">
                <summary>Get help with this</summary>
                ${askButtonHtml(held ? QuietNotes.heldAsk(card, finding) : finding)}
                ${copyAiButtonHtml(finding, pick)}
              </details>
              <details class="tech-details">
                <summary>Technical details</summary>
                <pre class="tech-log" data-tech-log>${escapeHtml(techText(key, null))}</pre>
              </details>
            </li>
          `;
        })
        .join('');

      const more = findings.length > PAGE
        ? `<button type="button" class="btn btn--secondary btn--small results-group__more" data-show-more>${escapeHtml(moreLabel(findings.length - PAGE))}</button>` : '';
      const list = `
          <p class="muted results-group__empty" data-group-empty hidden>Nothing left here. Everything in this group is in “Cleared” below.</p>
          <ul class="findings-list" data-group-list>${items}</ul>
          ${more}`;
      // Good to know: one closed box with its count. Nothing in it needs doing.
      if (severity === 'info') {
        return `
        <section class="results-group results-group--info" data-results-group="info">
          <details class="results-group__fold">
            <summary><span class="chip chip--info">${escapeHtml(SEVERITY_LABELS.info)}</span>
              <span class="results-group__count">${findings.length}</span>
              <span class="muted">${escapeHtml(SEVERITY_DESCRIPTIONS.info)}</span></summary>
            ${list}
          </details>
        </section>`;
      }
      return `
        <section class="results-group results-group--${severity}" data-results-group="${severity}">
          <h2>
            <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
            <span class="results-group__count">${findings.length}</span>
          </h2>
          ${list}
        </section>
      `;
    }

    function moreLabel(left) {
      return left > PAGE ? `Show ${PAGE} more (${left} not shown)` : `Show the last ${left}`;
    }

    // Each group keeps PAGE cards on show: a cleared card's place goes to the next one.
    function topUp(root) {
      root.querySelectorAll('[data-results-group]').forEach((group) => {
        const list = group.querySelector('[data-group-list]');
        if (!list) return;
        const cards = Array.from(list.querySelectorAll(':scope > [data-card-key]'));
        let shown = cards.filter((c) => !c.hidden).length;
        for (const c of cards) {
          if (shown >= PAGE) break;
          if (c.hidden && c.hasAttribute('data-card-more')) { c.hidden = false; c.removeAttribute('data-card-more'); shown += 1; }
        }
        updateMore(group);
      });
    }
    function updateMore(group) {
      const btn = group.querySelector('[data-show-more]');
      if (!btn) return;
      const left = group.querySelectorAll('[data-group-list] > [data-card-more]').length;
      btn.hidden = left === 0;
      btn.textContent = moreLabel(left);
    }

    // A re-check redraws the list; focus stays on the same checklist row.
    const keepFocus = (root, render) => (typeof Checklist !== 'undefined' ? Checklist.preserveFocus(root, render) : render());

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
        document.getElementById('results-running-actions').textContent = PARTIAL_ACTIONS_TEXT;
      }
      document.getElementById('results-title').textContent = partial ? 'What we\u2019ve found so far' : 'Here\'s what we found';
      // The whole-report copies would read as the full checkup: only once it's done.
      document.getElementById('results-copy-all').hidden = !!partial;
      document.getElementById('results-tech').hidden = !!partial;
      // "Your progress" waits for the finished checkup too (plain-panel.js shows it in standard mode).
      const progressBtn = document.getElementById('btn-your-progress');
      document.getElementById('progress-link').hidden = !!partial || !progressBtn || progressBtn.hidden;
      if (partial) {
        document.getElementById('results-learn').hidden = true;
        document.getElementById('results-city-switch').hidden = true;
      }
    }

    function renderResults(doc) {
      const partial = isPartialDoc(doc) ? doc.partial : null;
      renderResultsFrame(partial);
      const { groups, erroredModules, unfinishedModules, partlyChecked } = groupFindingsBySeverity(doc);
      // One count, the same one the city shows (notCheckedSummary).
      const notChecked = notCheckedSummary(doc);
      const notFullyChecked = notChecked.count;
      const total = SEVERITY_ORDER.reduce((sum, sev) => sum + groups[sev].length, 0);

      // Before the cards render: it resets the per-finding copy registry. The
      // whole-report copy uses the same per-card objects, so an answer given
      // on a card ("I did this", "It's mine") shows in both.
      const reportFindings = [];
      setCopyAiReport({
        findings: reportFindings,
        situation: copyAiSituation(situation, mode),
        platform: doc && doc.platform,
        couldNotCheck: [...erroredModules, ...unfinishedModules, ...partlyChecked].map((m) => aiCheckLabel(m.name, mode)),
      });
      cardPicks = new Map();
      cardTech = new Map();
      nextCardKey = 0;
      madeByExplained = false;
      routerCtx = RouterLink.contextFrom(doc, browserName);
      const groupsEl = document.getElementById('results-groups');
      const wasOpen = partial ? openDetailsIn(groupsEl) : new Set();
      const anchor = partial ? readingAnchor(groupsEl) : null;
      keepFocus(groupsEl, () => {
        groupsEl.innerHTML = (partial ? '' : BULK_HTML)
          + SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev], !!partial)).join('')
          + ClearList.sectionHtml();
      });
      reopenDetailsIn(groupsEl, wasOpen);
      keepReadingAnchor(groupsEl, anchor);
      reportFindings.push(...cardPicks.values());

      // Items marked as yours on an earlier checkup start out cleared.
      clearList.reset({ couldNotCheck: notFullyChecked });
      groupsEl.querySelectorAll('[data-marked-before]').forEach((card) => clearList.clear(card, 'marked_before'));
      topUp(groupsEl);
      updateBulk();

      // The sentence at the top counts what the progress bar counts.
      const summaryEl = document.getElementById('results-summary');
      const listCount = clearList.progress().total;
      const said = ClearList.summaryText(listCount, total - listCount);
      if (partial) {
        // Never an all-clear while checks are still running.
        document.getElementById('results-progress').hidden = true;
        summaryEl.innerHTML = `<p>${escapeHtml(partialSummaryText({
          worth: groups.critical.length + groups.warning.length, other: groups.info.length }))}</p>`;
      } else if ((total === 0 || !said) && notFullyChecked > 0) {
        // Never an all-clear while a check couldn't run or didn't finish.
        summaryEl.innerHTML = '<p>The checks that finished found nothing worth a look.</p>';
      } else if (total === 0 || !said) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out during this checkup. Nice and tidy.</p>';
      } else {
        summaryEl.innerHTML = `<p>${escapeHtml(said)}</p>`;
      }

      const errorsSection = document.getElementById('results-errors');
      const errorsList = document.getElementById('results-errors-list');
      if (notFullyChecked > 0) {
        document.getElementById('results-errors-line').textContent = notCheckedLine(notChecked);
        const mac = currentPlatform() === 'darwin';
        errorsList.innerHTML = couldntCheckItems(erroredModules, unfinishedModules, mode, partlyChecked)
          .map((item) => `<li><strong>${escapeHtml(item.name)}</strong>${item.reason ? ` &mdash; ${escapeHtml(item.reason)}` : ''}`
            + (item.kind === 'permission' && mac ? ` <button type="button" class="btn btn--secondary btn--small" data-setting-url="${FDA_URL}">Open the setting</button>` : '')
            + (item.raw ? `<details class="tech-details"><summary>For tech helpers</summary><pre class="tech-log">${escapeHtml(item.raw)}</pre></details>` : '')
            + '</li>')
          .join('');
        errorsSection.hidden = false;
      } else {
        errorsSection.hidden = true;
        errorsList.innerHTML = '';
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
      document.getElementById('scan-title').textContent = isBusy
        ? 'Your checkup is running'
        : 'Ready for your checkup';
      if (isBusy) errorNote.hidden = true;
    }

    function showScanError(message) {
      const errorNote = document.getElementById('scan-error');
      const errorText = document.getElementById('scan-error-text');
      errorText.textContent =
        message || "We couldn't finish the checkup. Please try again.";
      errorNote.hidden = false;
    }

    let lastScanDoc = null;
    let foundSoFar = 0;
    // What the running scan has found so far (partialScanState), or null.
    let partialScan = null;
    let partialTimer = null;
    const partialShowing = () => !!partialScan && scanRunning;
    // What the results screen shows: the running scan's results so far, or the last scan.
    function currentResultsDoc() {
      return partialShowing() ? partialDocOf(partialScan, currentPlatform()) : lastScanDoc;
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
      const scanSituation = situation;
      setScanBusy(true);
      resetProgress();
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
        if (doc && typeof doc.platform === 'string') {
          lastKnownPlatform = doc.platform;
        }
        lastScanDoc = doc;
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        lastScanSituation = scanSituation;
        endPartial();
        renderResults(doc);
        renderNextStep();
        renderLearnMore(doc);
        setScanBusy(false);
        renderCitySwitch(doc);
        const land = () => {
          const view = postScanView({
            inGame, left: leftGame, wantsCity, rememberedCity: rememberedView() === 'city',
            offered: gameOfferedFor(situation), ready: !!(window.RescueGame && window.RescueGame.isReady), mode,
          });
          if (view === 'boss-city') {
            if (window.RescueGame.scanDone(doc, situation) === false) {
              showScreen('results'); // the city couldn't be drawn: the list, which has the same results
            } else {
              rememberView('city');
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
        endPartial();
        if (lastScanDoc) {
          renderResults(lastScanDoc);
          renderLearnMore(lastScanDoc);
          renderCitySwitch(lastScanDoc);
        } else {
          renderResultsFrame(null);
        }
        if (wasViewing) showScreen('scan');
        setScanBusy(false);
        const message = scanErrorText(err && err.message ? err.message : String(err));
        if (inGame && !leftGame) {
          if (window.RescueGame.scanFailed(message) === false) showScanError(message);
          else showScreen('city');
        } else {
          showScanError(message);
        }
      } finally {
        unsubscribe();
        scanRunning = false;
        if (partialTimer) { clearTimeout(partialTimer); partialTimer = null; }
      }
    }

    function resetToWelcome() {
      const runButton = document.getElementById('btn-run-scan');
      runButton.disabled = false;
      runButton.hidden = false;
      document.getElementById('scan-progress').hidden = true;
      document.getElementById('scan-error').hidden = true;
      situation = null;
      wantsCity = false;
      leftGame = false;
      showScreen('welcome');
    }

    // Clearing the list: answered cards move to "Cleared" at the bottom.
    const resultsRoot = document.getElementById('results-groups');
    let markControl = null;
    const clearList = ClearList.attach(resultsRoot, {
      progressEl: document.getElementById('results-progress'),
      esc: escapeHtml,
      onChange: onCardChange,
      undoMark: (markCard) => markControl && markControl.unmark(markCard),
    });
    const cardsOf = (els) => els.map((el) => clearList.cardOf(el)).filter(Boolean);

    // Ticking a card: only the bulk bar changes.
    resultsRoot.addEventListener('change', (event) => {
      if (event.target && event.target.hasAttribute && event.target.hasAttribute('data-card-pick')) updateBulk();
    });
    resultsRoot.addEventListener('click', (event) => {
      const t = event.target && event.target.closest ? event.target.closest('[data-show-more],[data-bulk-did],[data-bulk-none]') : null;
      if (!t) return;
      if (t.hasAttribute('data-show-more')) {
        const group = t.closest('[data-results-group]');
        Array.from(group.querySelectorAll('[data-group-list] > [data-card-more]')).slice(0, PAGE).forEach((c) => {
          c.hidden = false; c.removeAttribute('data-card-more');
        });
        updateMore(group);
        return;
      }
      const ticked = Array.from(resultsRoot.querySelectorAll('[data-card-pick]')).filter((b) => b.checked);
      if (t.hasAttribute('data-bulk-did')) {
        ticked.forEach((b) => {
          const card = b.closest('[data-card-key]');
          if (card && card.querySelector('[data-clear-did]:not([hidden])')) { b.checked = false; clearList.clear(card, 'did'); }
        });
      } else {
        ticked.forEach((b) => { b.checked = false; });
      }
      updateBulk();
    });
    document.getElementById('results-errors-list').addEventListener('click', (event) => {
      const btn = event.target.closest && event.target.closest('[data-setting-url]');
      if (btn) window.rescue.openSetting(btn.getAttribute('data-setting-url'));
    });

    // "Open in System Settings": opens the page and nothing else; main allowlists the URL.
    resultsRoot.addEventListener('click', (event) => {
      const btn = event.target.closest && event.target.closest('[data-setting-url]');
      if (btn && resultsRoot.contains(btn)) window.rescue.openSetting(btn.getAttribute('data-setting-url'));
      // "Open your router's settings": only the address goes to main, which builds the URL.
      const router = event.target.closest && event.target.closest('[data-router-ip]');
      if (router && resultsRoot.contains(router)) window.rescue.openRouter(router.getAttribute('data-router-ip'));
    });
    // "Fix it for me": delegated, so it keeps working when results are re-rendered.
    FixFlow.attach(resultsRoot, window.rescue, {
      onFixed: (els) => cardsOf(els).forEach((card) => clearList.clear(card, 'fixed')),
      onRestored: (els) => cardsOf(els).forEach((card) => clearList.restore(card)),
    });
    // "It's mine": same delegation; the engine keeps marked items listed.
    markControl = MarkFlow.attach(resultsRoot, window.rescue, {
      onMarked: (els) => cardsOf(els).forEach((card) => clearList.clear(card, 'marked')),
      onUnmarked: (els) => cardsOf(els).forEach((card) => clearList.restore(card)),
    });

    // Each visit to the worry screen starts with nothing ticked.
    document.getElementById('btn-get-started').addEventListener('click', () => {
      wantsCity = false;
      renderSituations();
      showScreen('worry');
    });
    document.getElementById('btn-play-game').addEventListener('click', () => {
      wantsCity = true;
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
    document.getElementById('btn-see-city').addEventListener('click', () => {
      if (lastScanDoc) showCity(lastScanDoc);
    });

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
        await navigator.clipboard.writeText(technicalReportText(lastScanDoc));
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
    document.getElementById('btn-back-to-scan').addEventListener('click', () => showScreen('scan'));
    document.getElementById('btn-run-scan').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-retry').addEventListener('click', runCheckup);
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

    // City mode: Esc on the list goes back to the city, as it does from the
    // help district. Not when Esc just closed a confirm panel or a dialog.
    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      if (mode !== 'city' || !screens.results || screens.results.hidden) return;
      const dialog = document.getElementById('progress-dialog');
      if (dialog && dialog.open) return;
      if (!lastScanDoc || scanRunning || !cityAvailable()) return;
      showCity(lastScanDoc);
    });

    // 'city' opens straight into the game: the command deck, with the sweep
    // as its main action until one has run this session. Plain view, Start
    // over, TRAINING and every worry still work from there.
    function openCityHome() {
      if (!(window.RescueGame && window.RescueGame.isReady)) return false;
      situation = CITY_SITUATION;
      wantsCity = true;
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
