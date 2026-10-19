// Signal or Noise, in batches: the good-to-know notes game (spec: little missions, "notes").
//
// Every `info` finding no other game claims comes here, five at a time from one area. Each note is
// called Normal (noise) or Odd (a signal); the runner turns an odd one into an item of its own type
// in a new mission. Batches are optional and resumable. Points and the area bonus are the runner's;
// the summary only reports them.
//
// Pure, like every game: no DOM, storage, globals or network. Only what ctx hands in. It reuses the
// Signal or Noise clues (game/clues.js) so a note reads the same way it does on the deck.
//
//   batchNotes(items, { areaOf, size }) -> [{ area, part, parts, items }]   batches of BATCH_SIZE per area
//   summary(results, ctx): results = [{ item, decision, effect, points? }]; progress comes from
//     ctx.notes (or results.progress): { sorted, total, areaSorted, areaTotal, batchPoints, cleared, bonus }
import { CITY_FORBIDDEN, MONITORING_MODULES } from '../contract.js';
import { cluesFor, placeFor, pathOf } from '../../game/clues.js';

export const BATCH_SIZE = 5;

// Every info finding not claimed by another game. The foundation's types.js reads this.
export const covers = [{ module: '*', severities: ['info'] }];

// The same three checks as evidence.js and game/held.js. In city mode their notes stay in game words,
// carry no evidence rows and no look-up, and never offer the clipboard.
export { MONITORING_MODULES };

const WORDS = {
  standard: {
    kicker: 'GOOD TO KNOW', note: 'Note', practice: 'Practice. This isn’t on your computer.',
    lean: 'The checkup only noted this. Most notes are normal; the clues are how you tell.',
    none: 'The scan recorded no clues for this one. Its title is all there is to go on.',
    unfinished: 'This check didn’t finish, so part of what it covers wasn’t looked at.',
    oneClue: 'One clue: ',
  },
  city: {
    kicker: 'SIGNAL OR NOISE', note: 'CALL', practice: 'A made-up one. Not on this computer.',
    lean: 'Most of these are noise. The clues are how you tell.',
    none: 'No clues on this one. Its title is all there is to go on.',
    unfinished: 'This check didn’t finish, so part of its ground wasn’t covered.',
    oneClue: 'One clue: ',
  },
};
const QUIET_TITLE = 'A quiet check left a note';
const QUIET_LINE = 'The LIST tab has its own words.';

const modeOf = (ctx) => (ctx && ctx.mode === 'city' ? 'city' : 'standard');
const dataOf = (f) => (f && f.data && typeof f.data === 'object' ? f.data : {});
const str = (v) => (typeof v === 'string' ? v : '');
const quiet = (f, mode) => mode === 'city' && MONITORING_MODULES.has(f && f.module);
// City output never carries a non-game word, whatever the scan wrote.
const cityText = (s, mode) => (mode === 'city' && CITY_FORBIDDEN.test(String(s)) ? QUIET_LINE : String(s == null ? '' : s));
// A clue line is one line: the scan's line breaks read as spaces, not as [U+000A].
const oneLine = (s) => String(s == null ? '' : s).replace(/[ \t]*[\r\n]+[ \t]*/g, ' ');
const fmt = (n) => (Number.isFinite(n) ? Number(n).toLocaleString('en-US') : '0');
const isUnfinished = (item) => !!(item && (item.unfinished || (item.finding && item.finding.unfinished)));

// Scheduled tasks name their program in `command` and their file in `location`; the Signal or Noise
// clues read `program`/`path`. Lend them the program first (where it runs says the most), then the file.
function asClueFinding(f) {
  const d = dataOf(f);
  if (pathOf(f)) return f;
  const cmd = str(d.command);
  const lent = /^[~/]|^[A-Za-z]:\\/.test(cmd) ? cmd : str(d.location);
  return lent ? { ...f, data: { ...d, path: lent } } : f;
}

const madeBy = (f) => (Array.isArray(f && f.made_by) ? f.made_by.filter((e) => e && typeof e === 'object') : []);

// What stands out, said for the person so they don't have to work it out.
export function tellOf(finding) {
  const f = asClueFinding(finding || {});
  const place = placeFor(pathOf(f));
  if (place && place.risky) return `it lives in ${place.short}.`;
  const mb = madeBy(f);
  if (mb.some((e) => e.verified !== true)) return 'nobody has vouched for who made it.';
  if (mb.length) return 'its maker’s signature checked out. That says who made it, not that it’s safe.';
  return '';
}

export function decisions(item) {
  const f = (item && item.finding) || {};
  return [
    { id: 'normal', label: { standard: 'Looks normal', city: 'Noise, normal' }, effect: { kind: 'note', key: item && item.key } },
    { id: 'odd', label: { standard: 'Looks odd', city: 'Signal, odd' },
      effect: { kind: 'odd', key: item && item.key, module: f.module || null, code: f.code || null } },
  ];
}

// Settings panes by what a note is about. Intents only; research.js holds the URLs.
const TCC_PANES = {
  kTCCServiceCamera: 'privacy-camera', kTCCServiceMicrophone: 'privacy-microphone',
  kTCCServiceScreenCapture: 'privacy-screen-recording', kTCCServiceAccessibility: 'privacy-accessibility',
  kTCCServiceSystemPolicyAllFiles: 'privacy-full-disk', kTCCServiceListenEvent: 'privacy-input-monitoring',
  kTCCServiceAppleEvents: 'privacy-automation',
};
const PANE_RULES = [
  { test: /autorun|startup|launch|login_item|scheduled|cron|persistence/, darwin: 'login-items', win32: 'startup-apps' },
  { test: /storage|cache|large_files|trash|cleanup|temp|disk_space/, darwin: 'storage', win32: 'windows-storage' },
  { test: /update/, darwin: 'software-update', win32: 'windows-update' },
  { test: /firewall/, darwin: 'firewall', win32: 'windows-firewall' },
  { test: /defender|antivirus/, darwin: null, win32: 'windows-security' },
  { test: /sharing|airdrop/, darwin: 'sharing', win32: null },
  { test: /dns/, darwin: 'dns', win32: null },
  { test: /energy|battery/, darwin: 'battery', win32: null },
  { test: /permission|privacy|tcc/, darwin: 'privacy-full-disk', win32: 'windows-privacy' },
];

export function paneFor(finding, platform) {
  if (platform !== 'darwin' && platform !== 'win32') return null;
  const f = finding || {};
  const service = str(dataOf(f).service);
  if (service && TCC_PANES[service]) return platform === 'darwin' ? TCC_PANES[service] : 'windows-privacy';
  const m = str(f.module).toLowerCase();
  const rule = PANE_RULES.find((r) => r.test.test(m));
  return rule ? rule[platform] : null;
}

function lookupName(f) {
  const d = dataOf(f);
  for (const k of ['label', 'bundle_id', 'name', 'app']) {
    const v = str(d[k]).trim();
    if (v && v.length <= 200) return v;
  }
  const t = str(f.title).trim();
  return t && t.length <= 200 ? t : '';
}

function whatOf(f) {
  const mb = madeBy(f);
  const known = mb.find((e) => e.verified === true && str(e.what).trim());
  if (known) return known.what.trim();
  return mb.length && !mb.some((e) => e.verified === true) ? 'Unknown maker' : '';
}

export function research(item, ctx = {}) {
  const f = (item && item.finding) || {};
  const mode = modeOf(ctx);
  const hush = quiet(f, mode);
  let rows = [];
  if (!hush && typeof ctx.evidenceRows === 'function') rows = ctx.evidenceRows(f, { mode }) || [];
  const links = [];
  const pane = hush ? null : paneFor(f, ctx.platform);
  if (pane) links.push({ kind: 'settings', pane });
  const name = hush ? '' : lookupName(f);
  if (name) {
    const apple = madeBy(f).some((e) => e.verified === true && e.how === 'Apple system file');
    links.push({ kind: 'lookup', source: apple ? 'apple-support' : 'web', query: name });
  }
  links.push({ kind: 'lesson', concept: 'where-it-lives' });
  return { rows: Array.isArray(rows) ? rows : [], what: hush ? '' : whatOf(f), links, copy: !hush, unfinished: isUnfinished(item) };
}

function clueHtml(c, mode, esc) {
  return `<li class="clue open nt-clue" data-clue="${esc(c.kind)}"><div class="label">${esc(c.label)}</div>${
    c.lines.map((l) => `<p class="clue-line">${esc(cityText(oneLine(l), mode))}</p>`).join('')}</li>`;
}

export function render(view, ctx = {}) {
  const mode = modeOf(ctx);
  const w = WORDS[mode];
  const esc = ctx.esc;
  const item = (view && view.item) || {};
  const f = item.finding || {};
  const hush = quiet(f, mode);
  const total = Number.isFinite(view && view.total) ? view.total : 1;
  const index = Number.isFinite(view && view.index) ? view.index : 0;
  const title = hush ? QUIET_TITLE : cityText(str(f.title) || 'A note', mode);
  const clues = hush ? [] : cluesFor(asClueFinding(f));
  const tell = hush ? '' : tellOf(f);
  const r = (view && view.research) || {};
  const step = view && view.step && view.step.say ? view.step.say[mode] : '';
  const practice = !!(view && (view.practice || ctx.practice));
  return `
  <article class="nt-card${practice ? ' nt-practice' : ''}" aria-labelledby="nt-title">
    ${practice ? `<p class="nt-banner"><span class="badge drill-stamp">${mode === 'city' ? 'DRILL' : 'PRACTICE'}</span> ${esc(w.practice)}</p>` : ''}
    <p class="nt-head"><span class="badge cyan">${esc(w.kicker)}</span>
      <small>${esc(ctx.districtName || '')}</small>
      <span class="nt-count">${esc(w.note)} ${esc(index + 1)} of ${esc(total)}</span></p>
    <h3 class="m-title nt-title" id="nt-title" tabindex="-1">${esc(title)}</h3>
    ${r.unfinished || isUnfinished(item) ? `<p class="intel nt-unfinished"><span class="badge warn">DIDN’T FINISH</span> ${esc(w.unfinished)}</p>` : ''}
    ${hush ? `<p class="intel">${esc(QUIET_LINE)}</p>`
      : clues.length ? `<ul class="clues nt-clues">${clues.map((c) => clueHtml(c, mode, esc)).join('')}</ul>`
        : `<p class="intel">${esc(w.none)}</p>`}
    ${tell ? `<p class="intel nt-tell">${esc(w.oneClue + tell)}</p>` : ''}
    <p class="intel faint nt-lean">${esc(w.lean)}</p>
    ${step ? `<div class="scout-row nt-step"><p class="say">${esc(step)}</p></div>` : ''}
  </article>`;
}

// Practice: three made-up notes. Nothing here is real scan data.
const practiceItem = (n, finding) => ({
  key: `practice:notes:${n}`, severity: 'info', finding: { severity: 'info', category: 'security', ...finding },
  findings: [], seen_in: [finding.module], marked: false, held: false, removal_alert: false, practice: true,
});
const PRACTICE_ITEMS = [
  practiceItem(1, {
    module: 'scheduled_tasks_audit', code: 'security.scheduled_tasks_audit.launch_agent_info',
    title: 'Background item: com.apple.example.daily-cleanup',
    description: 'A daily housekeeping job that comes with the system.',
    data: { check: 'launch_agent_info', label: 'com.apple.example.daily-cleanup', type: 'daemon',
      location: '/System/Library/LaunchDaemons/com.apple.example.daily-cleanup.plist', command: '/usr/libexec/example-cleanup daily' },
    made_by: [{ subject: '/usr/libexec/example-cleanup', name: 'Apple', verified: true, how: 'Apple system file' }],
  }),
  practiceItem(2, {
    module: 'scheduled_tasks_audit', code: 'security.scheduled_tasks_audit.launch_agent_info',
    title: 'Background item: com.example.updater-helper',
    description: 'A background task set to start when you log in.',
    data: { check: 'launch_agent_info', label: 'com.example.updater-helper', type: 'agent',
      location: '~/Library/LaunchAgents/com.example.updater-helper.plist', command: '~/.hidden/updater.sh' },
    made_by: [{ subject: '~/.hidden/updater.sh', name: 'Unknown maker', verified: false, how: '' }],
  }),
  practiceItem(3, {
    module: 'privacy_permissions_audit', code: 'security.privacy_permissions_audit.camera_access',
    title: 'Camera access: 1 app(s)',
    description: '1 app(s) have been granted Camera access: Example Video Call.',
    data: { check: 'camera_access', service: 'kTCCServiceCamera', display_name: 'Camera', apps: ['Example Video Call'] },
  }),
];

export const practice = {
  items: PRACTICE_ITEMS,
  // Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict and its clue. Several ids in
  // `expect`: all of them fit (the first is the best).
  script: [
    { item: 0, expect: 'normal', say: {
      standard: 'Read where it runs and who made it. Normal or odd?',
      city: 'Read where it runs and whose seal it carries. Noise or signal?' }, why: {
      standard: 'It runs from a system folder, and its maker is Apple, verified. Housekeeping like this is normal.',
      city: 'System folder, Apple’s seal, verified. That’s noise.' } },
    { item: 1, expect: 'odd', say: {
      standard: 'Read where this one runs. Normal or odd?',
      city: 'Read where this one runs. Noise or signal?' }, why: {
      standard: '~/.hidden is a hidden folder, and nobody has vouched for the maker. That’s odd. Calling it odd makes it a mission of its own.',
      city: 'A hidden folder, and no seal. That’s a signal. Calling it makes it a mission of its own.' } },
    { item: 2, expect: ['normal', 'odd'], say: {
      standard: 'One app can use the camera: a video-call app. Normal or odd?',
      city: 'One video-call app has the lens key. Noise or signal?' }, why: {
      standard: 'If you make video calls, that’s normal. If you don’t, call it odd and look at it.',
      city: 'If you make calls, that’s noise. If you don’t, call it a signal and look at it.' } },
  ],
};

export function summary(results, ctx = {}) {
  const mode = modeOf(ctx);
  const city = mode === 'city';
  const esc = typeof ctx.esc === 'function' ? ctx.esc : (s) => String(s);
  const rs = Array.isArray(results) ? results.filter(Boolean) : [];
  const p = (ctx.notes && typeof ctx.notes === 'object' ? ctx.notes : results && results.progress) || {};
  const isOdd = (r) => r.decision === 'odd' || (r.effect && r.effect.kind === 'odd');
  const sorted = rs.filter((r) => r.decision || r.effect);
  const odd = sorted.filter(isOdd).length;
  const normal = sorted.length - odd;
  const points = sorted.reduce((n, r) => n + (Number.isFinite(r.points) ? r.points : 0), 0) + (Number.isFinite(p.batchPoints) ? p.batchPoints : 0);
  const area = cityText(ctx.districtName || (city ? 'this district' : 'this area'), mode);
  const lines = [];
  if (!sorted.length) lines.push(city ? 'No signals sorted in this batch.' : 'No notes sorted in this batch.');
  else {
    lines.push(city ? `${fmt(sorted.length)} sorted: ${fmt(normal)} noise, ${fmt(odd)} signal.`
      : `${fmt(sorted.length)} ${sorted.length === 1 ? 'note' : 'notes'} sorted: ${fmt(normal)} normal, ${fmt(odd)} odd.`);
    if (odd) lines.push(city ? 'Each signal became a mission of its own.' : (odd === 1 ? 'The odd one became a mission of its own, with its own steps.' : 'The odd ones became missions of their own, with their own steps.'));
  }
  const out = [`<section class="nt-summary"><div class="label">${city ? 'BATCH SORTED' : 'Batch sorted'}</div>`,
    ...lines.map((l) => `<p class="intel">${esc(l)}</p>`)];
  if (points > 0) out.push(`<p class="points nt-points">+${esc(fmt(points))} ${city ? 'POINTS' : 'points'} for this batch</p>`);
  if (Number.isFinite(p.total) && p.total > 0) {
    out.push(`<p class="nt-progress"><strong>${esc(fmt(p.sorted || 0))} of ${esc(fmt(p.total))} sorted</strong></p>`);
  }
  if (Number.isFinite(p.areaTotal) && p.areaTotal > 0) {
    out.push(`<p class="intel faint nt-area">${esc(`${fmt(p.areaSorted || 0)} of ${fmt(p.areaTotal)} in ${area}`)}</p>`);
  }
  if (p.cleared) {
    const bonus = Number.isFinite(p.bonus) && p.bonus > 0 ? ` +${fmt(p.bonus)} ${city ? 'BONUS' : 'bonus points'}.` : '';
    out.push(`<p class="points nt-bonus">${esc(city ? `Every signal in ${area} sorted!${bonus}` : `You sorted every note in ${area}.${bonus}`)}</p>`);
  } else if (sorted.length) {
    out.push(`<p class="intel faint">${city ? 'More batches are here if you want them.' : 'Notes are optional. More batches are here if you want them.'}</p>`);
  }
  out.push(`<p class="intel faint">${city ? 'Sorting is the game’s. It changes nothing on this computer.' : 'Sorting is the game’s. It changes nothing on your computer.'}</p></section>`);
  return out.join('\n');
}

// Notes in batches of BATCH_SIZE, one area at a time, in doc order. Held items never batch.
const defaultArea = (it) => it.district || (Array.isArray(it.seen_in) && it.seen_in[0]) || '';
export function batchNotes(items, { areaOf = defaultArea, size = BATCH_SIZE } = {}) {
  const byArea = new Map();
  for (const it of Array.isArray(items) ? items : []) {
    if (!it || it.held || it.severity !== 'info') continue;
    const a = String(areaOf(it) ?? '');
    if (!byArea.has(a)) byArea.set(a, []);
    byArea.get(a).push(it);
  }
  const out = [];
  for (const [area, list] of byArea) {
    const parts = Math.ceil(list.length / size);
    for (let i = 0; i < parts; i += 1) out.push({ area, part: i + 1, parts, items: list.slice(i * size, (i + 1) * size) });
  }
  return out;
}

export default {
  type: 'notes',
  title: { standard: 'Good to know', city: 'Signal or Noise' },
  concepts: ['who-made-it', 'where-it-lives'],
  covers,
  decisions,
  research,
  practice,
  render,
  summary,
};
