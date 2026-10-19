// The mini-game contract (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
//
// Every game is one ES module, renderer/missions/games/<type>.js, whose default export is:
//
//   {
//     type: 'door',                                     // a TYPE_IDS entry
//     title: { standard: '…', city: '…' },               // standard = plain words; city = stealth game words
//     concepts: ['where-it-lives'],                      // existing profile concept ids it trains
//     decisions(item, ctx) -> Decision[],                // 2–3; the first is the safe default
//     research(item, ctx)  -> { rows, what, links },     // rows from ctx.evidenceRows; links are LINK INTENTS
//     practice: { items: Item[], script: Step[] },       // synthetic items only + guided steps
//     render(view, ctx)    -> string,                    // HTML for ONE item; escape every scan value with ctx.esc
//     summary(results, ctx) -> string,                   // end-of-mission recap
//   }
//
//   Decision = { id, label: { standard, city }, effect: Effect }
//   Effect   = { kind: EFFECT_KINDS[i], ...args }   // games never act; the runner carries effects out
//   Link     = { kind: LINK_KINDS[i], ...args }     // intents; runner/research.js turns them into allowlisted URLs
//   Step     = { item: index into practice.items, say: { standard, city }, expect?: decision id }
//   ctx      = { mode: 'standard'|'city', practice: bool, platform: 'darwin'|'win32'|'linux', districtName,
//                esc(s), visible(s), evidenceRows(finding, {mode}) }
//   view     = { item, research, decisions, index, total, practice, step? }
//
// Games are pure: no DOM, no storage, no window/globals, no network, no clipboard. Only what ctx hands them.
//
// Rulings (binding; the runner is missions/runner.js):
//   R1 The RUNNER draws the decision buttons, the removal-warning line, the evidence rows (research.rows through
//      Evidence.renderEvidence) and the links (intents through research.js). render(view, ctx) returns ONLY the
//      game's own item card; it needs no buttons, rows or links.
//   R2 Items carry `unfinished: true` when one of their checks has complete:false (groupMissions sets it); the
//      runner then shows "This check didn't finish" with the research.
//   R3 research may return `copy: false`: the evidence is drawn with no clipboard. In city mode a monitoring
//      check's evidence never has one (Evidence.noClipboard), whatever the game says.
//   R5 A settings intent may carry `permission` (camera, microphone, location, contacts, screen, full-disk,
//      keyboard, accessibility, automation, screen-time) so research.js opens the exact Windows privacy page.
//   R6 A decision whose effect carries `warning: true` shows the removal warning before it acts (a settings pane
//      opens only after the person has read it), as every `fix` confirm does.
//   R8 An info finding from a Lock Run module that says it couldn't check (code ending _unknown, _failed,
//      _unavailable, _permission_denied) is a Lock Run item, never a mere note.
//   R9 covers may narrow by `checks` (data.check values) for a module that emits no codes:
//      { module, checks: ['unsigned_drivers'] }. Effects may carry `steps` (instructions when a page can't be
//      linked); the runner shows them, escaped. A recheck effect is { kind: 'recheck', module?, modules? }.
//      summary(results, ctx) receives [{ item, decision, effect, points? }] (decision: the Decision's id).
//   R10 Any effect may carry `steps`; a link effect may carry its look-up intent in `effect.link`.
//   covers: [{ module, codes?, checks? }]; the notes game's wildcard { module: '*', severities: ['info'] } means every
//      note no other game claims; it is matched last and never counts as a double claim.

export const TYPE_IDS = ['door', 'keyring', 'loadout', 'seal', 'switchboard', 'locker', 'locks', 'junkyard', 'notes', 'simple'];

export const EFFECT_KINDS = ['mark', 'fix', 'settings', 'link', 'closer', 'later', 'note', 'odd', 'recheck', 'keep'];

// Link intents. A game never builds a URL from scan data; research.js maps each intent to a fixed template.
//   settings: { kind: 'settings', pane }            pane from SETTINGS_PANES
//   lookup:   { kind: 'lookup', query, source }     source from LOOKUP_SOURCES; in city mode shown as text only
//   lesson:   { kind: 'lesson', concept }
export const LINK_KINDS = ['settings', 'lookup', 'lesson'];
export const SETTINGS_PANES = [
  'login-items', 'privacy-accessibility', 'privacy-input-monitoring', 'privacy-screen-recording', 'privacy-camera',
  'privacy-microphone', 'privacy-full-disk', 'privacy-location', 'privacy-automation', 'network', 'firewall', 'sharing',
  'software-update', 'filevault', 'lock-screen', 'users-groups', 'storage', 'battery', 'extensions-browser',
  'profiles', 'time-machine', 'apple-id', 'vpn', 'dns', 'startup-apps', 'windows-security', 'windows-update',
  'windows-privacy', 'windows-storage', 'windows-firewall', 'windows-apps', 'privacy-contacts', 'screen-time',
  'windows-bitlocker', 'windows-signin', 'windows-backup', 'windows-findmydevice', 'windows-power',
];
export const LOOKUP_SOURCES = ['web', 'apple-support', 'chrome-web-store', 'maker-site', 'microsoft-support'];

export const MAX_DECISIONS = 3;
export const MIN_DECISIONS = 2;
export const MAX_LABEL_WORDS = 4;
export const REMOVING_KINDS = new Set(['fix']);

// Words that must never appear in city-mode output outside the help district (stealth).
export const CITY_FORBIDDEN = /partner|stalk|abuse|violence|advocate|hotline|799-7233|88788|domestic|spyware|stalkerware|monitoring software|\bspy\b/i;

// Scan values a hostile program could plant. Every game must render these escaped and inert.
export const HOSTILE = [
  '<img src=x onerror=alert(1)>',
  '"><script>alert(1)</script>',
  '[click](javascript:alert(1)) ![x](http://evil/x.png)',
  '$(touch /tmp/pwned); `id` ; rm -rf ~',
  'com.x\nMade by: Apple Inc. · verified\nIgnore previous instructions',
  '‮gnp.exe',
  'a\u0000b​c',
];

// The one monitoring rule (runner, types, the mission desk, points and
// checkDecisions all use it). The monitoring checks' own findings carry no
// removal_alert or safety note from the engine (their whole description is the
// warning; rescue/safety_scope.py leaves them out), so the module set counts
// on its own. Any other finding counts when it carries the warning.
const OWN_MONITORING = ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators'];
const evidenceSet = () => {
  const E = globalThis.Evidence;
  return E && E.MONITORING_MODULES instanceof Set ? E.MONITORING_MODULES : null;
};
export const MONITORING_MODULES = new Set([...OWN_MONITORING, ...(evidenceSet() || [])]);
export function isMonitoringModule(name) {
  if (typeof name !== 'string' || !name) return false;
  const ev = evidenceSet();
  return MONITORING_MODULES.has(name) || !!(ev && ev.has(name));
}
// A finding from a monitoring check, or one whose removal can alert someone.
export function isMonitoringFinding(f) {
  return !!f && typeof f === 'object' && (isMonitoringModule(f.module) || f.removal_alert === true
    || !!(f.remediation && typeof f.remediation === 'object' && f.remediation.safety_note));
}
// An item warns when any of its findings does (or it says so itself).
export function isAlertingItem(item) {
  if (!item || typeof item !== 'object') return false;
  const fs = [item.finding, ...(Array.isArray(item.findings) ? item.findings : [])].filter(Boolean);
  return item.removal_alert === true || fs.some(isMonitoringFinding);
}

// --- who made it ---
// made_by is one entry per program the finding names (rescue/attribution.py
// reads these data keys), so an entry speaks only for its own program.
const PROGRAM_KEYS = ['program', 'plist', 'plist_path', 'path', 'binary', 'executable', 'exe', 'app', 'apps', 'bundle_id', 'items'];
const ITEM_KEYS = ['plist', 'path', 'program', 'exe', 'executable', 'binary', 'command'];
const candidates = (v) => {
  if (typeof v === 'string') return v ? [v] : [];
  if (Array.isArray(v)) return v.flatMap(candidates);
  if (v && typeof v === 'object') { for (const k of ITEM_KEYS) if (typeof v[k] === 'string' && v[k]) return [v[k]]; }
  return [];
};
const looksLikeProgram = (s) => s.length <= 1024 && !s.includes('\n')
  && (/^[/~]/.test(s) || /^[A-Za-z]:[\\/]/.test(s) || /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(s) || /\.app$/i.test(s));
// The programs a finding names, in order, without repeats.
export function programsOf(f) {
  const d = f && f.data && typeof f.data === 'object' ? f.data : {};
  const out = [];
  for (const k of PROGRAM_KEYS) for (const c of candidates(d[k])) if (looksLikeProgram(c) && !out.includes(c)) out.push(c);
  return out;
}
/*
 * makerFor(finding, subject?) -> { name, verified, what, how, subject } | null
 * The maker of the program an item is about, never another program's:
 * - `subject` given: that program's own entry, else null.
 * - no subject: the finding's one program (its entry, or the only entry);
 *   several programs: one shared maker only when the engine verified every
 *   one (makers_verified), else null.
 * `verified` only when the entry is the subject's own and verifies (or the
 * engine says every program named verified).
 */
export function makerFor(f, subject = null) {
  const list = Array.isArray(f && f.made_by) ? f.made_by.filter((e) => e && typeof e === 'object' && typeof e.name === 'string' && e.name) : [];
  if (!list.length) return null;
  const out = (e, verified) => ({ name: e.name, verified: verified && e.verified === true, what: verified && e.verified === true && typeof e.what === 'string' ? e.what : '',
    how: typeof e.how === 'string' ? e.how : '', subject: typeof e.subject === 'string' ? e.subject : '' });
  if (typeof subject === 'string' && subject) {
    const own = list.find((e) => e.subject === subject);
    return own ? out(own, true) : null;
  }
  const programs = programsOf(f);
  if (programs.length <= 1) {
    const own = list.find((e) => programs.length && e.subject === programs[0]);
    if (own) return out(own, true);
    return list.length === 1 ? out(list[0], f.makers_verified === true) : null;
  }
  const names = [...new Set(list.map((e) => e.name))];
  if (f.makers_verified === true && names.length === 1 && list.every((e) => e.verified === true)) return { name: names[0], verified: true, what: '', how: '', subject: '' };
  return null;
}

const wordCount = (s) => String(s || '').trim().split(/\s+/).filter(Boolean).length;

// Validate a game module's shape. Returns a list of problems (empty = valid).
export function validateGame(game) {
  const p = [];
  if (!game || typeof game !== 'object') return ['default export is not an object'];
  if (!TYPE_IDS.includes(game.type)) p.push(`type "${game.type}" is not one of ${TYPE_IDS.join(', ')}`);
  if (!game.title || typeof game.title.standard !== 'string' || typeof game.title.city !== 'string') p.push('title needs {standard, city}');
  if (!Array.isArray(game.concepts)) p.push('concepts must be an array');
  for (const fn of ['decisions', 'research', 'render', 'summary']) if (typeof game[fn] !== 'function') p.push(`${fn} must be a function`);
  const pr = game.practice;
  if (!pr || !Array.isArray(pr.items) || pr.items.length < 2 || pr.items.length > 3) p.push('practice.items must hold 2–3 synthetic items');
  if (!pr || !Array.isArray(pr.script) || pr.script.length < 1) p.push('practice.script must have at least one step');
  if ('covers' in game) p.push(...checkCovers(game));
  return p;
}

// `covers`: [{ module, codes? }] — the engine modules (macOS and Windows) a
// game claims, `codes` narrowing a shared module to finding-code prefixes.
export function checkCovers(game) {
  const c = game && game.covers;
  if (!Array.isArray(c)) return ['covers must be an array of { module, codes? }'];
  const p = [];
  c.forEach((x, i) => {
    if (x && x.module === '*') {
      if (!Array.isArray(x.severities) || !x.severities.length || !x.severities.every((v) => ['critical', 'warning', 'info'].includes(v))) {
        p.push(`covers ${i}: the wildcard needs severities (critical, warning, info)`);
      }
      return;
    }
    if (!x || typeof x.module !== 'string' || !/^[a-z0-9_]+$/.test(x.module)) { p.push(`covers ${i}: module must be an engine module name`); return; }
    for (const field of ['codes', 'checks']) {
      if (field in x && (!Array.isArray(x[field]) || !x[field].length || !x[field].every((k) => typeof k === 'string' && k.length > 0))) {
        p.push(`covers ${i} (${x.module}): ${field} must be a non-empty list of strings`);
      }
    }
  });
  return p;
}

// Two claims on one module conflict when both are whole, or both have codes
// and one code is a prefix of the other (the same finding claimed twice). A
// whole claim and a code claim don't: the code claim is more specific.
// `byType`: { [type]: [{ module, codes? }] }.
export function claimConflicts(byType) {
  const out = [];
  const claims = [];
  for (const [type, list] of Object.entries(byType || {})) for (const c of Array.isArray(list) ? list : []) if (c && c.module && c.module !== '*') claims.push({ type, ...c });
  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const a = claims[i]; const b = claims[j];
      if (a.module !== b.module) continue;
      const narrowA = a.codes || a.checks; const narrowB = b.codes || b.checks;
      if (!narrowA && !narrowB) { out.push(`${a.module} is claimed whole by ${a.type} and ${b.type}`); continue; }
      if (a.checks && b.checks) for (const x of a.checks) if (b.checks.includes(x)) out.push(`${a.module} check ${x} is claimed by ${a.type} and ${b.type}`);
      if (!a.codes || !b.codes) continue;
      for (const x of a.codes) for (const y of b.codes) {
        if (x.startsWith(y) || y.startsWith(x)) out.push(`${a.module} code ${x.length > y.length ? x : y} is claimed by ${a.type} and ${b.type}`);
      }
    }
  }
  return out;
}

// No two registered games claim the same (module, code).
export function noDoubleClaims(games) {
  const byType = {};
  for (const g of games || []) if (g && Array.isArray(g.covers)) byType[g.type] = [...(byType[g.type] || []), ...g.covers];
  return claimConflicts(byType);
}

// Validate the decisions a game returns for one item.
export function checkDecisions(decisions, item) {
  const p = [];
  if (!Array.isArray(decisions)) return ['decisions() must return an array'];
  if (decisions.length < MIN_DECISIONS || decisions.length > MAX_DECISIONS) p.push(`expected ${MIN_DECISIONS}–${MAX_DECISIONS} decisions, got ${decisions.length}`);
  const ids = new Set();
  decisions.forEach((d, i) => {
    if (!d || typeof d.id !== 'string') { p.push(`decision ${i} has no id`); return; }
    if (ids.has(d.id)) p.push(`duplicate decision id ${d.id}`);
    ids.add(d.id);
    if (!d.label || typeof d.label.standard !== 'string' || typeof d.label.city !== 'string') p.push(`${d.id}: label needs {standard, city}`);
    else for (const m of ['standard', 'city']) if (wordCount(d.label[m]) > MAX_LABEL_WORDS) p.push(`${d.id}: ${m} label over ${MAX_LABEL_WORDS} words`);
    if (!d.effect || !EFFECT_KINDS.includes(d.effect.kind)) p.push(`${d.id}: effect kind must be one of ${EFFECT_KINDS.join(', ')}`);
  });
  if (isAlertingItem(item) &&decisions[0] && decisions[0].effect && REMOVING_KINDS.has(decisions[0].effect.kind)) {
    p.push('an item with a removal warning must not have a removing decision first (default)');
  }
  return p;
}

// Validate research output: link intents only, from the allowlists.
export function checkResearch(research) {
  const p = [];
  if (!research || typeof research !== 'object') return ['research() must return an object'];
  if (!Array.isArray(research.rows)) p.push('research.rows must be an array');
  for (const [i, l] of (research.links || []).entries()) {
    if (!l || !LINK_KINDS.includes(l.kind)) { p.push(`link ${i}: kind must be one of ${LINK_KINDS.join(', ')}`); continue; }
    if ('href' in l || 'url' in l) p.push(`link ${i}: games return intents, never URLs`);
    if (l.kind === 'settings' && !SETTINGS_PANES.includes(l.pane)) p.push(`link ${i}: unknown settings pane ${l.pane}`);
    if (l.kind === 'lookup' && !LOOKUP_SOURCES.includes(l.source)) p.push(`link ${i}: unknown lookup source ${l.source}`);
  }
  return p;
}

// Rendered HTML must not contain a live tag or attribute from a hostile value.
export function checkInert(html) {
  const p = [];
  const s = String(html);
  if (/<script\b/i.test(s)) p.push('rendered a <script> tag');
  if (/<img\b[^>]*onerror/i.test(s)) p.push('rendered an <img onerror>');
  if (/<[a-z][^>]*\son\w+\s*=/i.test(s)) p.push('rendered an inline event handler');
  if (/href\s*=\s*["']?\s*javascript:/i.test(s)) p.push('rendered a javascript: link');
  if (/[‪-‮⁦-⁩\u0000​]/.test(s)) p.push('rendered a raw control/bidi character (use ctx.visible)');
  return p;
}

// City-mode output must use game words only.
export function checkCityWords(text) {
  const m = String(text).match(CITY_FORBIDDEN);
  return m ? [`city output contains "${m[0]}"`] : [];
}

// A minimal context for tests: real escaping, a pass-through evidenceRows unless one is supplied.
export function testContext(overrides = {}) {
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const visible = (s) => String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  return {
    mode: 'standard', practice: false, platform: 'darwin', districtName: 'The Gatehouse',
    esc: (s) => esc(visible(s)), visible,
    evidenceRows: () => [],
    ...overrides,
  };
}

// Build an Item (the shape groupMissions hands a game) around one finding.
export function makeItem(finding, extra = {}) {
  const f = { severity: 'warning', category: 'security', data: {}, ...finding };
  return { key: `${f.module || 'm'}:${f.code || f.title}`, severity: f.severity, finding: f, findings: [f], seen_in: [f.module || 'm'], marked: false, held: false, removal_alert: isMonitoringFinding(f), ...extra };
}

// Run every contract check for a game against some items; returns problems with context.
export function runContractChecks(game, items) {
  const out = validateGame(game).map((x) => `shape: ${x}`);
  const all = [...(items || []), ...((game.practice && game.practice.items) || [])];
  for (const mode of ['standard', 'city']) {
    for (const item of all) {
      const ctx = testContext({ mode });
      let d, r, html;
      try { d = game.decisions(item, ctx); } catch (e) { out.push(`${mode} decisions threw: ${e.message}`); continue; }
      out.push(...checkDecisions(d, item).map((x) => `${mode} ${item.key}: ${x}`));
      try { r = game.research(item, ctx); } catch (e) { out.push(`${mode} research threw: ${e.message}`); continue; }
      out.push(...checkResearch(r).map((x) => `${mode} ${item.key}: ${x}`));
      try { html = game.render({ item, research: r, decisions: d, index: 0, total: 1, practice: false }, ctx); } catch (e) { out.push(`${mode} render threw: ${e.message}`); continue; }
      out.push(...checkInert(html).map((x) => `${mode} ${item.key}: ${x}`));
      if (mode === 'city' && !item.held) out.push(...checkCityWords(html).map((x) => `${item.key}: ${x}`));
    }
    // Hostile values in every common data field.
    for (const h of HOSTILE) {
      const f = { module: 'x', title: h, description: h, code: 'x.y', data: { path: h, label: h, program: h, name: h, bundle_id: h, app: h, apps: [h], target: h, extension_id: h } };
      const item = makeItem(f);
      const ctx = testContext({ mode });
      try {
        const d = game.decisions(item, ctx); const r = game.research(item, ctx);
        out.push(...checkResearch(r).map((x) => `${mode} hostile: ${x}`));
        out.push(...checkInert(game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx)).map((x) => `${mode} hostile ${JSON.stringify(h).slice(0, 30)}: ${x}`));
      } catch (e) { out.push(`${mode} hostile input threw: ${e.message}`); }
    }
    try {
      const s = game.summary([], testContext({ mode }));
      if (typeof s !== 'string') out.push(`${mode} summary must return a string`);
      if (mode === 'city') out.push(...checkCityWords(s));
    } catch (e) { out.push(`${mode} summary threw: ${e.message}`); }
  }
  return out;
}
