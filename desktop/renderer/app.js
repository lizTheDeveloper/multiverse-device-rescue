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
  info: 'Background details and reassurance-level notes.',
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
    sub: 'The full checkup. It takes longer: often 10 minutes or more',
    profile: null, guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/' },
];

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
  const words = String(ev.module || '').replace(/_/g, ' ');
  const name = words.charAt(0).toUpperCase() + words.slice(1);
  const done = ev.phase === 'done' ? ev.index : ev.index - 1;
  return {
    headline: CATEGORY_PHRASES[ev.category] || 'Checking your computer',
    detail: `${name} \u00b7 check ${ev.index} of ${ev.total}`,
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

function madeByHtml(entries, esc) {
  if (!Array.isArray(entries) || entries.length === 0) return '';
  const lines = entries.map((entry) => {
    const d = describeMadeBy(entry);
    const who = entries.length > 1 && d.subject ? `<span class="made-by__subject">${esc(d.subject)}</span> ` : '';
    const what = d.what ? `<span class="made-by__what"> \u2014 ${esc(d.what)}</span>` : '';
    return `<li class="made-by__line made-by__line--${d.tone}">${who}${esc(d.text)}${what}</li>`;
  }).join('');
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
const GAME_INTRO = 'It also comes as a free game you play in your web browser.';
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
  if (situation && (situation.safety || situation.id === 'phone')) return true;
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
  return !!situation && situation.id !== 'phone';
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
  const entry = LEARN_MORE[situation.id];
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

/**
 * Group every finding across every module by severity, and collect the
 * modules that failed to run at all. Unknown/missing severities fall back
 * to "info" so nothing silently disappears.
 *
 * @param {{modules?: Array<{name:string,status:string,error:?string,findings?:Array}>}} doc
 * @returns {{groups: {critical: Array, warning: Array, info: Array}, erroredModules: Array<{name:string,error:?string}>}}
 */
function groupFindingsBySeverity(doc) {
  const groups = { critical: [], warning: [], info: [] };
  const erroredModules = [];
  const modules = (doc && doc.modules) || [];

  for (const mod of modules) {
    if (mod && mod.status === 'error') {
      erroredModules.push({ name: mod.name, error: mod.error || null });
    } else if (mod && mod.supported === false) {
      // Could not run here: not a clean result, so it must not read as one.
      erroredModules.push({ name: mod.name, error: mod.unsupported_reason || null });
    }
    const findings = (mod && mod.findings) || [];
    for (const finding of findings) {
      const sev = Object.prototype.hasOwnProperty.call(groups, finding.severity)
        ? finding.severity
        : 'info';
      groups[sev].push(Object.assign({}, finding, { module: mod.name }));
    }
  }

  return { groups, erroredModules };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectOS,
    duringScanTips,
    groupFindingsBySeverity,
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
    const appRoot = document.getElementById('app');

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
    let scanToGame = false; // the running scan reports to the game's sweep screen
    let visitedCity = false; // the city has been on screen this session
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
      if (changed && lastScanDoc) renderResults(lastScanDoc);
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
      document.getElementById('results-city-switch').hidden = !cityAvailable();
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
        if (lastScanDoc && !scanRunning && lastScanSituation === situation) showScreen('results');
        else goToScan();
      },
    };
    window.addEventListener('rescue-game-ready', () => { if (lastScanDoc) renderCitySwitch(lastScanDoc); });

    function showScreen(name) {
      Object.keys(screens).forEach((key) => {
        if (!screens[key]) return;
        screens[key].hidden = key !== name;
      });
      // The city fills the window; styles.css drops the plain header for it.
      appRoot.dataset.screen = name;
      if (name === 'city') visitedCity = true;
      renderBackToCity();
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

    function renderSituations() {
      const list = document.getElementById('situations');
      list.innerHTML = SITUATIONS.map(
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
      list.querySelectorAll('[data-situation]').forEach((btn) => {
        btn.addEventListener('click', () => {
          situation = SITUATIONS.find((s) => s.id === btn.dataset.situation) || null;
          const next = FirstQuestion.afterWorry(situation, mode);
          if (next === 'ask') { ask('first', startWorry); return; }
          if (next !== mode) setMode(next);
          startWorry();
        });
      });
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

    function renderNextStep() {
      const box = document.getElementById('results-next');
      if (!situation || !situation.guide) {
        box.hidden = true;
        return;
      }
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
    }

    function renderSeverityGroup(severity, findings) {
      if (findings.length === 0) return '';
      // City mode: the fix panel's extra warning about whoever set something up.
      const watched = mode === 'city';
      const items = findings
        .map((finding) => {
          const key = String(nextCardKey++);
          // What this card may say (QuietNotes). Standard: no hotline text, and the one
          // line wherever removing something can alert someone. City: everything, unquieted.
          const card = QuietNotes.cardText(mode, finding);
          // City mode, monitoring software: the hold line and its help. No fix,
          // no "It's mine", no steps, and it doesn't count toward the list's progress.
          const held = card.note === 'held';
          // City mode never offers a fix or a mark on these checks, even on a
          // status line that found nothing ("No device backups found").
          const noControls = held || (mode === 'city' && QuietNotes.isMonitoring(finding));
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
          return `
            <li class="finding-card finding-card--${severity}" data-card-key="${key}" data-card-counts="${counts ? '1' : '0'}"${marked ? ' data-marked-before' : ''}>
              <div class="finding-card__header">
                <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
                <h3>${escapeHtml(finding.title || 'Untitled finding')}</h3>
              </div>
              <div class="cleared-note" data-cleared-note role="status" aria-live="polite" hidden></div>
              ${descriptionHtml(card.description, escapeHtml)}
              ${madeByHtml(finding.made_by, escapeHtml)}
              <div class="card-answers">
              ${noControls ? '' : FixFlow.fixControlsHtml(finding, { watched })}
              ${noControls ? '' : MarkFlow.markControlsHtml(finding, { watched })}
              ${marked || held ? '' : ClearList.didControlsHtml(finding, severity, escapeHtml)}
              </div>
              ${QuietNotes.lineHtml(card, escapeHtml)}${QuietNotes.fullHtml(card, escapeHtml)}${QuietNotes.heldHtml(card, escapeHtml)}
              ${card.steps.length ? `
              <div class="next-steps">
                <h4>What to do</h4>
                <ol>${card.steps.map((step) => `<li>${escapeHtml(stepTitle(step.title))}</li>`).join('')}</ol>
              </div>` : ''}
              ${held ? '' : SettingPanes.findingButtonHtml(finding, currentPlatform())}
              ${held ? '' : RouterLink.findingLinkHtml(finding, routerCtx)}
              ${finding.remediation && !held ? `
              <details class="fix-steps">
                <summary>${finding.fixable ? 'Or fix it yourself, step by step' : 'Show me how, step by step'}</summary>
                <ol class="fix-steps__list">
                  ${card.steps.map((step) => `
                    <li>
                      <h4>${escapeHtml(step.title)}</h4>
                      <div class="fix-steps__body">${renderMiniMarkdown(step.body)}</div>
                    </li>`).join('')}
                </ol>
              </details>` : ''}
              ${askButtonHtml(held ? QuietNotes.heldAsk(card, finding) : finding)}
              ${copyAiButtonHtml(finding, pick)}
              <details class="tech-details">
                <summary>Technical details</summary>
                <pre class="tech-log" data-tech-log>${escapeHtml(techText(key, null))}</pre>
              </details>
            </li>
          `;
        })
        .join('');

      return `
        <section class="results-group results-group--${severity}" data-results-group="${severity}">
          <h2>
            <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
            <span class="results-group__count">${findings.length}</span>
          </h2>
          <p class="muted">${escapeHtml(SEVERITY_DESCRIPTIONS[severity])}</p>
          <p class="muted results-group__empty" data-group-empty hidden>Nothing left here. Everything in this group is in “Cleared” below.</p>
          <ul class="findings-list" data-group-list>${items}</ul>
        </section>
      `;
    }

    function renderResults(doc) {
      const { groups, erroredModules } = groupFindingsBySeverity(doc);
      const total = SEVERITY_ORDER.reduce((sum, sev) => sum + groups[sev].length, 0);


      // Before the cards render: it resets the per-finding copy registry. The
      // whole-report copy uses the same per-card objects, so an answer given
      // on a card ("I did this", "It's mine") shows in both.
      const reportFindings = [];
      setCopyAiReport({
        findings: reportFindings,
        situation: situation ? situation.title : undefined,
        platform: doc && doc.platform,
        couldNotCheck: erroredModules.map((m) => m.name),
      });
      cardPicks = new Map();
      cardTech = new Map();
      nextCardKey = 0;
      routerCtx = RouterLink.contextFrom(doc, browserName);
      const groupsEl = document.getElementById('results-groups');
      groupsEl.innerHTML = SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev])).join('')
        + ClearList.sectionHtml();
      reportFindings.push(...cardPicks.values());

      // Items marked as yours on an earlier checkup start out cleared.
      clearList.reset({ couldNotCheck: erroredModules.length });
      groupsEl.querySelectorAll('[data-marked-before]').forEach((card) => clearList.clear(card, 'marked_before'));

      // The sentence at the top counts what the progress bar counts.
      const summaryEl = document.getElementById('results-summary');
      const listCount = clearList.progress().total;
      const said = ClearList.summaryText(listCount, total - listCount);
      if (total === 0 && erroredModules.length > 0) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out in the checks that ran. Some checks couldn\'t run on this computer &mdash; they\'re listed at the bottom.</p>';
      } else if (total === 0 || !said) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out during this checkup. Nice and tidy.</p>';
      } else {
        summaryEl.innerHTML = `<p>${escapeHtml(said)}</p>`;
      }

      const errorsSection = document.getElementById('results-errors');
      const errorsList = document.getElementById('results-errors-list');
      if (erroredModules.length > 0) {
        errorsList.innerHTML = erroredModules
          .map(
            (mod) =>
              `<li><strong>${escapeHtml(mod.name)}</strong>${mod.error ? ` &mdash; ${escapeHtml(mod.error)}` : ''}</li>`
          )
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
      scanToGame = inGame;
      const scanSituation = situation;
      setScanBusy(true);
      resetProgress();
      if (inGame) window.RescueGame.showBoss();
      const unsubscribe = window.rescue.onScanEvent((ev) => {
        onScanEvent(ev);
        if (scanToGame && !leftGame && ev.type === 'progress') window.RescueGame.scanEvent(ev);
      });
      try {
        const doc = await window.rescue.runScan(situation ? situation.profile : null);
        if (doc && typeof doc.platform === 'string') {
          lastKnownPlatform = doc.platform;
        }
        lastScanDoc = doc;
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        lastScanSituation = scanSituation;
        renderResults(doc);
        renderNextStep();
        renderLearnMore(doc);
        setScanBusy(false);
        renderCitySwitch(doc);
        const land = () => {
          const view = postScanView({
            inGame: scanToGame, left: leftGame, wantsCity, rememberedCity: rememberedView() === 'city',
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
        setScanBusy(false);
        const message = scanErrorText(err && err.message ? err.message : String(err));
        if (scanToGame && !leftGame) {
          if (window.RescueGame.scanFailed(message) === false) showScanError(message);
          else showScreen('city');
        } else {
          showScanError(message);
        }
      } finally {
        unsubscribe();
        scanRunning = false;
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

    document.getElementById('btn-get-started').addEventListener('click', () => {
      wantsCity = false;
      showScreen('worry');
    });
    document.getElementById('btn-play-game').addEventListener('click', () => {
      wantsCity = true;
      leftGame = false;
      showScreen('worry');
    });
    // "Something changed?": the question again, then back to the worry screen.
    document.getElementById('btn-something-changed').addEventListener('click', () => {
      // Before any answer this is the first ask; after one, the re-ask, where
      // Back and "rather not say" leave the setting as it is.
      ask(mode ? 'change' : 'first', () => showScreen('worry'));
    });
    document.getElementById('btn-see-city').addEventListener('click', () => {
      if (lastScanDoc) showCity(lastScanDoc);
    });

    // "Back to the city", in the plain header once the city has been on screen:
    // the sweep if a scan is running, this worry's city if it has one, or the
    // Training Grounds.
    // Once it shows, the city's HUD already names the app, so the plain
    // header drops its brand rather than say "Reclaim City" twice.
    function renderBackToCity() {
      const show = !!(visitedCity
        && window.RescueGame && window.RescueGame.isReady
        && (!situation || gameOfferedFor(situation)));
      document.getElementById('btn-back-to-city').hidden = !show;
      document.getElementById('app-brand').hidden = show;
    }
    document.getElementById('btn-back-to-city').addEventListener('click', () => {
      if (!(window.RescueGame && window.RescueGame.isReady)) return;
      leftGame = false;
      wantsCity = true;
      if (!situation) situation = CITY_SITUATION;
      if (scanRunning) {
        scanToGame = true;
        window.RescueGame.showBoss();
        showScreen('city');
      } else if (lastScanDoc && lastScanSituation === situation) {
        showCity(lastScanDoc);
      } else if (window.RescueGame.showTraining(situation) !== false) {
        showScreen('city');
      }
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
        await navigator.clipboard.writeText(JSON.stringify(lastScanDoc, null, 2));
        status.textContent = ' Copied.';
      } catch (err) {
        status.textContent = ` Couldn\u2019t copy (${err && err.message ? err.message : err}).`;
      }
    });

    document.getElementById('btn-open-guide').addEventListener('click', () => {
      if (situation && situation.guide) window.rescue.openGuide(situation.guide);
    });

    document.getElementById('btn-open-game').addEventListener('click', () => {
      if (learnMoreUrl) window.rescue.openGuide(learnMoreUrl);
    });

    document.getElementById('btn-run-scan').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-retry').addEventListener('click', runCheckup);
    document.getElementById('btn-start-over').addEventListener('click', resetToWelcome);

    // 'city' opens straight into the game: the Training Grounds until a sweep
    // has run. Plain view, Start over and every worry still work from there.
    function openCityHome() {
      if (!(window.RescueGame && window.RescueGame.isReady)) return false;
      situation = CITY_SITUATION;
      wantsCity = true;
      leftGame = false;
      if (window.RescueGame.showTraining(situation) !== false) showScreen('city');
      return true;
    }

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
