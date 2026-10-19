// The Door: things that start on their own (spec: docs/superpowers/specs/
// 2026-10-19-little-missions-and-minigames-design.md, type `door`).
//
// Each launch agent, login item, scheduled job, startup entry, auto-start
// service or kernel/system extension "knocks": a card with its name, the
// program it runs (a hidden or temporary folder highlighted), who signed it
// and whether that was verified, when it appeared, and what the program is.
// The person answers Mine / Look closer / Not mine.
//
// Pure, per the contract (missions/contract.js): no DOM, storage or globals;
// decisions are effects and links are intents the runner carries out. Every
// scan value goes through ctx.esc. Decision buttons and the removal warning are
// the runner's chrome; render() draws the card only.
import { placeFor } from '../../game/clues.js';

const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const dataOf = (f) => (f && isObj(f.data) ? f.data : {});
const str = (v) => (typeof v === 'string' && v.trim() ? v : '');
const pick = (mode, t) => (mode === 'city' ? t.city : t.standard);

// Engine modules this game claims (macOS first, then the Windows equivalents).
// Field names below are the ones each module's Finding(data=...) writes.
export const covers = [
  { module: 'launch_agent_audit' },
  { module: 'launchd_persistence_audit' },
  { module: 'login_items_cleanup' },
  { module: 'login_items' },
  { module: 'scheduled_tasks_audit' },
  { module: 'cron_jobs_audit' },
  { module: 'startup_optimizer' },
  { module: 'startup_auditor' },
  { module: 'security_baseline_diff', codes: ['security.security_baseline_diff.new_persistence'] },
  { module: 'ai_worm_persistence' },
  { module: 'crypto_miner_persistence' },
  { module: 'kext_audit' },
  { module: 'kernel_extensions_audit' },
  { module: 'system_extensions_check' },
  { module: 'win_autoruns_audit' },
  { module: 'win_startup' },
  { module: 'win_startup_programs_audit' },
  { module: 'win_scheduled_tasks' },
  { module: 'win_scheduled_tasks_security' },
  { module: 'win_services_audit' },
  { module: 'win_services_security_audit' },
];

// What kind of door each module watches. It picks the switch-off route and the
// "what to check" list.
const KIND_BY_MODULE = {
  launch_agent_audit: 'launch', launchd_persistence_audit: 'launch', scheduled_tasks_audit: 'launch',
  startup_optimizer: 'launch', startup_auditor: 'launch', security_baseline_diff: 'launch',
  ai_worm_persistence: 'launch', crypto_miner_persistence: 'launch',
  login_items_cleanup: 'login', login_items: 'login',
  cron_jobs_audit: 'cron',
  kext_audit: 'kext', kernel_extensions_audit: 'kext', system_extensions_check: 'kext',
  win_autoruns_audit: 'win-startup', win_startup: 'win-startup', win_startup_programs_audit: 'win-startup',
  win_scheduled_tasks: 'win-task', win_scheduled_tasks_security: 'win-task',
  win_services_audit: 'win-service', win_services_security_audit: 'win-service',
};

const moduleOf = (item) => {
  const f = item && item.finding;
  return str(f && f.module) || (item && Array.isArray(item.seen_in) && str(item.seen_in[0])) || '';
};

export function kindOf(finding) {
  const mod = str(finding && finding.module);
  const d = dataOf(finding);
  if (mod === 'crypto_miner_persistence' && /cron/i.test(str(d.mechanism))) return 'cron';
  // ai_worm_persistence also reports a line in a shell profile or a hook file.
  if (mod === 'ai_worm_persistence' && (str(d.file) || (str(d.path) && !str(d.plist)))) return 'file';
  if (mod === 'ai_worm_persistence' && str(d.task_name)) return 'cron';
  return KIND_BY_MODULE[mod] || (/^win_/.test(mod) ? 'win-startup' : 'launch');
}

const NAME_KEYS = ['label', 'entry_name', 'task_name', 'display_name', 'service_name', 'item_name', 'unit_name', 'name', 'bundle_id', 'indicator'];
const RUNS_KEYS = ['program', 'path', 'command', 'file', 'plist', 'location'];
// Lists some findings carry instead of one entry (counts, inventories, diffs).
const LIST_KEYS = ['added', 'entries', 'items', 'kexts', 'names', 'services', 'tasks', 'waiting_extensions', 'terminated_extensions', 'third_party_labels'];
const DATE_KEYS = ['created_date', 'first_seen', 'created', 'installed', 'modified', 'date'];
const MAX_LIST = 4;

const firstString = (d, keys) => { for (const k of keys) if (str(d[k])) return d[k]; return ''; };

export const nameOf = (f) => firstString(dataOf(f), NAME_KEYS) || String((f && f.title) || '');

export function runsOf(f) {
  const d = dataOf(f);
  for (const k of RUNS_KEYS) {
    if (k === 'location' && str(d.label) && !str(d.program)) continue; // a folder, not the program
    if (str(d[k])) return d[k];
  }
  return '';
}

// Where it was set up, when that isn't the program itself (a plist, a Run key).
export function setUpIn(f) {
  const d = dataOf(f);
  const runs = runsOf(f);
  const v = str(d.plist) || str(d.location) || str(d.task_path);
  return v && v !== runs ? v : '';
}

const entryText = (e) => (typeof e === 'string' ? e
  : isObj(e) ? str(e.path) || str(e.program) || str(e.display_name) || str(e.name) || str(e.label) || str(e.bundle_id) || str(e.Name) : '');

export function listOf(f) {
  const d = dataOf(f);
  for (const k of LIST_KEYS) {
    if (Array.isArray(d[k]) && d[k].length) return d[k].map(entryText).filter(Boolean);
  }
  return [];
}

// A home folder reads "~" (Mac and Windows), so a card never shows an account name.
// The same rule as evidence.js (anywhere in a command line), plus macOS's /private/tmp.
export function homeRelative(p) {
  return String(p == null ? '' : p)
    .replace(/(^|[\s'"=:(])\/(?:Users|home)\/(?!Shared(?:\/|$))[^/\s'"]+(?=\/|$|[\s'"])/g, '$1~')
    .replace(/(^|[\s'"=:(])[A-Za-z]:\\Users\\(?!Public(?:\\|$))[^\\\s'"]+(?=\\|$|[\s'"])/gi, '$1~')
    .replace(/^\/private(?=\/(?:tmp|var\/tmp)(?:\/|$))/, '');
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// "2026-10-10T18:44:55+00:00" -> "10 Oct 2026", as written (no time-zone shift).
export function plainDay(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(v == null ? '' : v).trim());
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 12) return '';
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

// { day, since }: the date the scan recorded for it, or the baseline it is new since.
export function appearedOf(f) {
  const d = dataOf(f);
  for (const k of DATE_KEYS) { const day = plainDay(d[k]); if (day) return { day, since: false }; }
  const base = plainDay(d.baseline_captured_at);
  return base ? { day: base, since: true } : null;
}

// The made_by entry for the program it runs (else the first one), or null.
export function makerOf(f) {
  const entries = Array.isArray(f && f.made_by) ? f.made_by.filter(isObj) : [];
  if (!entries.length) return null;
  const runs = runsOf(f);
  return entries.find((e) => runs && e.subject === runs) || entries[0];
}

const isVerified = (m) => !!(m && m.verified === true);
const isApple = (m) => isVerified(m) && (m.how === 'Apple system file' || /^Apple\b/.test(str(m.name)));

// What the program is: only when its signed identity was verified (the engine
// gives `what` only then; a claimed name proves nothing).
export function whatOf(f) {
  const m = makerOf(f);
  if (isVerified(m) && str(m.what)) return m.what.trim();
  if (isVerified(m) && m.how === 'Apple system file') return 'Part of macOS.';
  return '';
}

function alerting(item) {
  const f = (item && item.finding) || {};
  return !!(item && (item.removal_alert || f.removal_alert || (isObj(f.remediation) && f.remediation.safety_note)));
}

const unfinished = (item) => {
  const f = (item && item.finding) || {};
  return !!(item && (item.unfinished || item.complete === false || f.complete === false || dataOf(f).incomplete));
};

// Folder names that are hidden (start with a dot) or temporary / download spots.
const RISKY_PART = /^(?:\.[^./\\]|tmp$|temp$|downloads$)/i;

// The "Runs" path as HTML: each folder name escaped on its own, hidden or
// temporary folders wrapped in <mark>. The last part (the file) is never marked.
export function pathHtml(p, ctx) {
  const shown = homeRelative(p);
  const parts = shown.split(/([\\/])/);
  let lastName = -1;
  parts.forEach((x, i) => { if (x !== '/' && x !== '\\' && x !== '') lastName = i; });
  return parts.map((x, i) => {
    if (x === '/' || x === '\\') return ctx.esc(x);
    if (i !== lastName && RISKY_PART.test(x)) return `<mark class="door-hidden">${ctx.esc(x)}</mark>`;
    return ctx.esc(x);
  }).join('');
}

export function hiddenOrTemp(p) {
  const parts = homeRelative(p).split(/[\\/]/).filter(Boolean);
  return parts.slice(0, -1).some((x) => RISKY_PART.test(x));
}

const PANE = { launch: 'login-items', login: 'login-items', kext: 'login-items', 'win-startup': 'startup-apps' };

// Switch-off steps for doors that have no settings switch, in the modules' own words.
const OFF_STEPS = {
  'win-task': [
    { standard: 'Open Task Scheduler (search for it in the Start menu) and find the task by name.', city: 'Open Task Scheduler (search for it in the Start menu) and find it by name.' },
    { standard: 'Right-click it and choose Disable. Don’t delete its file yet.', city: 'Right-click it and choose Disable. Keep its file for now.' },
  ],
  'win-service': [
    { standard: 'Open Services (type services.msc in the Start menu) and double-click it.', city: 'Open Services (type services.msc in the Start menu) and double-click it.' },
    { standard: 'Set Startup type to Disabled. Don’t delete its file; someone may want to look at it.', city: 'Set Startup type to Disabled. Keep its file for now.' },
  ],
  cron: [
    { standard: 'Write down the scheduled line exactly as shown here.', city: 'Write down the line exactly as shown here.' },
    { standard: 'Don’t delete anything yet. Take the line out with someone you trust, keeping a copy of it and of any file it runs.', city: 'Keep a copy of the line and any file it runs. Take it out with someone you trust.' },
  ],
  file: [
    { standard: 'Write down the file and the line shown here.', city: 'Write down the file and the line shown here.' },
    { standard: 'Don’t delete the file. Take the line out with someone you trust, keeping a copy.', city: 'Keep a copy. Take the line out with someone you trust.' },
  ],
};

function notMineEffect(f, kind, mode) {
  if (isObj(f.fixable)) return { kind: 'fix' };
  if (PANE[kind]) return { kind: 'settings', pane: PANE[kind] };
  return { kind: 'closer', off: true, checklist: (OFF_STEPS[kind] || OFF_STEPS.file).map((s) => pick(mode, s)) };
}

// "What to check" for Look closer. Plain text; the runner escapes it.
export function checklistFor(item, ctx) {
  const f = findingOf(item);
  const mode = ctx && ctx.mode;
  const kind = kindOf(f);
  const name = nameOf(f);
  const out = [];
  const where = {
    launch: { standard: 'Is it listed under Login Items in System Settings?', city: 'Is it listed under Login Items in System Settings?' },
    login: { standard: 'Is it listed under Login Items in System Settings?', city: 'Is it listed under Login Items in System Settings?' },
    kext: { standard: 'Does it belong to hardware or security software you use?', city: 'Does it belong to a device or a guard program you use?' },
    cron: { standard: 'Did you, or an app you use, set up this scheduled job?', city: 'Did you, or an app you use, set up this schedule?' },
    file: { standard: 'Did you, or a tool you use, add this line?', city: 'Did you, or a tool you use, add this line?' },
    'win-startup': { standard: 'Is it listed in Task Manager under Startup apps?', city: 'Is it listed in Task Manager under Startup apps?' },
    'win-task': { standard: 'Find it by name in Task Scheduler. Do you recognise the program it runs?', city: 'Find it by name in Task Scheduler. Do you know what it runs?' },
    'win-service': { standard: 'Find it by name in Services (type services.msc in the Start menu). Do you recognise it?', city: 'Find it by name in Services (type services.msc in the Start menu). Do you know it?' },
  }[kind];
  if (where) out.push(pick(mode, where));
  out.push(pick(mode, { standard: 'Do you recognise the maker?', city: 'Do you know the maker on the seal?' }));
  if (hiddenOrTemp(runsOf(f))) out.push(pick(mode, { standard: 'It runs from a hidden or temporary folder. Did you put a program there?', city: 'It comes from a hidden or temporary folder. Did you put it there?' }));
  const when = appearedOf(f);
  if (when) out.push(pick(mode, { standard: `Did you install something around ${when.day}?`, city: `Did you set something up around ${when.day}?` }));
  if (name) out.push(pick(mode, { standard: `Search the name: ${name}`, city: `Search the name on another device: ${name}` }));
  return out;
}

// The item's lead finding, with its module filled in from seen_in when missing.
const findingOf = (item) => {
  const f = (item && item.finding) || {};
  return str(f.module) ? f : { ...f, module: moduleOf(item) };
};

export function decisions(item, ctx) {
  const f = findingOf(item);
  const kind = kindOf(f);
  const mine = { id: 'mine', label: { standard: 'Mine', city: 'Let it in' }, effect: isObj(f.markable) ? { kind: 'mark' } : { kind: 'keep' } };
  const closer = { id: 'closer', label: { standard: 'Look closer', city: 'Look closer' }, effect: { kind: 'closer', checklist: checklistFor(item, ctx) } };
  const notMine = { id: 'not-mine', label: { standard: 'Not mine', city: 'Bar the door' }, effect: notMineEffect(f, kind, ctx && ctx.mode) };
  const wary = alerting(item) || (f.severity === 'critical' && !isVerified(makerOf(f)));
  return wary ? [closer, mine, notMine] : [mine, closer, notMine];
}

export function research(item, ctx) {
  const f = findingOf(item);
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const rows = typeof (ctx && ctx.evidenceRows) === 'function' ? ctx.evidenceRows(f, { mode }) || [] : [];
  const kind = kindOf(f);
  const m = makerOf(f);
  const what = whatOf(f);
  const links = [];
  const pane = PANE[kind];
  if (pane) links.push({ kind: 'settings', pane });
  const name = nameOf(f);
  if (isVerified(m) && what && str(m.name)) links.push({ kind: 'lookup', source: 'maker-site', query: m.name });
  else if (name) {
    links.push({ kind: 'lookup', source: isApple(m) ? 'apple-support' : 'web', query: name });
  }
  links.push({ kind: 'lesson', concept: 'where-it-lives', lesson: 'starts-on-its-own' });
  return { rows: Array.isArray(rows) ? rows : [], what, links, unfinished: unfinished(item) };
}

const WORDS = {
  eyebrow: { standard: 'Starts on its own', city: 'Knock, knock' },
  runs: { standard: 'Runs', city: 'Runs' },
  setUp: { standard: 'Set up in', city: 'Set up in' },
  signer: { standard: 'Signed by', city: 'Seal' },
  appeared: { standard: 'Appeared on', city: 'First knocked' },
  what: { standard: 'What it is', city: 'Who it is' },
  verified: { standard: 'verified', city: 'seal checks out' },
  notVerified: { standard: 'not verified', city: 'seal not checked out' },
  noMaker: { standard: 'Not checked: the checkup didn’t read a maker for this.', city: 'Not checked: no seal was read for this.' },
  noDate: { standard: 'Not recorded', city: 'Not recorded' },
  since: { standard: 'New since', city: 'New since' },
  unknownWhat: { standard: 'Not known: nobody has vouched for who made it.', city: 'Unknown: no seal vouches for it.' },
  unfinished: { standard: 'This check didn’t finish, so this may not be everything.', city: 'This check didn’t finish, so this may not be everything.' },
  hiddenNote: { standard: 'A hidden or temporary folder. Installed apps don’t normally run from here.', city: 'A hidden or temporary folder. Settled residents don’t live here.' },
  none: { standard: 'Not recorded', city: 'Not recorded' },
};
const w = (ctx, k) => pick(ctx && ctx.mode, WORDS[k]);

function fact(cls, label, body, point) {
  return `<div class="door-fact door-${cls}${point ? ' door-point' : ''}"><dt>${label}</dt><dd>${body}</dd></div>`;
}

export function render(view, ctx) {
  const item = (view && view.item) || {};
  const f = findingOf(item);
  const r = (view && view.research) || research(item, ctx);
  const step = view && view.step;
  const point = (k) => !!(step && step.point === k);
  const sev = ['critical', 'warning', 'info'].includes(f.severity) ? f.severity : 'warning';
  const kind = kindOf(f);
  const runs = runsOf(f);
  const list = runs ? [] : listOf(f);
  const m = makerOf(f);
  const when = appearedOf(f);
  const total = Number(view && view.total) || 1;
  const index = Number(view && view.index) || 0;

  let runsBody;
  if (runs) {
    runsBody = `<code class="door-path">${pathHtml(runs, ctx)}</code>`;
    if (hiddenOrTemp(runs)) {
      const place = placeFor(homeRelative(runs));
      const note = ctx.mode !== 'city' && place && place.risky ? place.note : w(ctx, 'hiddenNote');
      runsBody += `<p class="door-place">${ctx.esc(note)}</p>`;
    }
  } else if (list.length) {
    const more = list.length - MAX_LIST;
    runsBody = `<ul class="door-list">${list.slice(0, MAX_LIST).map((x) => `<li><code class="door-path">${pathHtml(x, ctx)}</code></li>`).join('')}</ul>`
      + (more > 0 ? `<p class="door-more">and ${more} more</p>` : '');
  } else runsBody = `<span class="door-none">${w(ctx, 'none')}</span>`;

  let signer;
  if (m) {
    const ok = isVerified(m);
    const how = str(m.how) && m.how.length <= 40 ? ` <span class="door-how">${ctx.esc(m.how)}</span>` : '';
    signer = `<span class="door-maker">${ctx.esc(str(m.name) || 'Unknown maker')}</span> <span class="door-chip ${ok ? 'door-verified' : 'door-unverified'}">${w(ctx, ok ? 'verified' : 'notVerified')}</span>${how}`;
  } else signer = `<span class="door-none">${w(ctx, 'noMaker')}</span>`;

  const appeared = when ? `${when.since ? `${w(ctx, 'since')} ` : ''}${ctx.esc(when.day)}` : `<span class="door-none">${w(ctx, 'noDate')}</span>`;
  const what = r.what ? ctx.esc(r.what) : `<span class="door-none">${w(ctx, 'unknownWhat')}</span>`;
  const setup = setUpIn(f);
  const practiceSetup = view && view.practice && str(f.setup) ? `<p class="door-setup">${ctx.esc(f.setup)}</p>` : '';
  const say = step && step.say ? `<p class="door-say" role="note">${ctx.esc(pick(ctx.mode, step.say))}</p>` : '';

  return `<article class="door-card door-sev-${sev}" data-door-kind="${ctx.esc(kind)}">`
    + `<header class="door-knock"><span class="door-eyebrow">${w(ctx, 'eyebrow')}</span>`
    + `<span class="door-count">${index + 1} of ${total}</span>`
    + `<h3 class="door-name">${ctx.esc(nameOf(f))}</h3></header>`
    + practiceSetup
    + (r.unfinished ? `<p class="door-unfinished">${w(ctx, 'unfinished')}</p>` : '')
    + '<dl class="door-facts">'
    + fact('runs', w(ctx, 'runs'), runsBody, point('runs'))
    + (setup ? fact('setup', w(ctx, 'setUp'), `<code class="door-path">${pathHtml(setup, ctx)}</code>`, point('setup')) : '')
    + fact('signer', w(ctx, 'signer'), signer, point('signer'))
    + fact('appeared', w(ctx, 'appeared'), appeared, point('appeared'))
    + fact('what', w(ctx, 'what'), what, point('what'))
    + '</dl>'
    + say
    + '</article>';
}

// results: [{ decision: 'mine'|'closer'|'not-mine', ... }] (also accepts `id` or `choice`).
export function summary(results, ctx) {
  const list = Array.isArray(results) ? results : [];
  const count = (id) => list.filter((x) => x && (x.decision === id || x.id === id || x.choice === id)).length;
  const mine = count('mine');
  const off = count('not-mine');
  const open = list.length - mine - off;
  const city = ctx && ctx.mode === 'city';
  if (!list.length) {
    return `<p class="door-summary">${city ? 'No knocks answered yet.' : 'Nothing answered yet.'}</p>`;
  }
  const parts = city
    ? [`${mine} let in`, `${off} barred`, `${open} still being looked at`]
    : [`${mine} yours`, `${off} not yours`, `${open} still to look at`];
  const head = city ? `${list.length} ${list.length === 1 ? 'knock' : 'knocks'} at the door:` : `You answered ${list.length} ${list.length === 1 ? 'thing that starts' : 'things that start'} on their own:`;
  const tail = city
    ? 'The Door only knows what knocked during this check. Look again after you add something new.'
    : 'This covers what the checkup saw this time. A new app can add more, so it’s worth looking again after you install something.';
  return `<div class="door-summary"><p>${head} ${parts.join(', ')}.</p><p class="door-summary-note">${tail}</p></div>`;
}

// Practice: made-up items only. A verified Apple agent, an unsigned agent in a
// hidden folder, and a developer tool the person installed.
const practiceItem = (finding, extra = {}) => ({
  key: `practice:${finding.data.label}`, severity: finding.severity, finding, findings: [finding],
  seen_in: [finding.module], marked: false, held: false, removal_alert: !!finding.removal_alert, ...extra,
});

export const practice = {
  items: [
    practiceItem({
      module: 'launchd_persistence_audit', severity: 'info', category: 'security', code: 'security.launchd_persistence_audit.non_apple_info',
      title: 'A background item starts at login', description: 'Practice item.',
      data: { check: 'non_apple_info', label: 'com.apple.photolibraryd', program: '/System/Library/Frameworks/Photos.framework/Support/photolibraryd' },
      made_by: [{ subject: '/System/Library/Frameworks/Photos.framework/Support/photolibraryd', name: 'Apple Inc.', verified: true, how: 'Apple system file', what: 'Part of macOS: looks after your Photos library.' }],
    }),
    practiceItem({
      module: 'launch_agent_audit', severity: 'critical', category: 'security', code: 'security.launch_agent_audit.suspicious_path',
      title: 'A background item runs from a hidden folder', description: 'Practice item.', removal_alert: true,
      data: { check: 'suspicious_path', label: 'com.upd8r.agent', program: '~/.hidden/upd8r/upd8r', first_seen: '2026-09-30' },
      made_by: [{ subject: '~/.hidden/upd8r/upd8r', name: 'Unknown maker', verified: false, how: 'unsigned' }],
    }),
    practiceItem({
      module: 'launch_agent_audit', severity: 'warning', category: 'security', code: 'security.launch_agent_audit.suspicious_path',
      title: 'A background item starts at login', description: 'Practice item.',
      setup: 'Practice setup: you installed a database with Homebrew for a coding project.',
      data: { check: 'suspicious_path', label: 'homebrew.mxcl.postgresql@16', program: '/opt/homebrew/opt/postgresql@16/bin/postgres' },
      made_by: [{ subject: '/opt/homebrew/opt/postgresql@16/bin/postgres', name: 'Unknown maker', verified: false, how: 'not signed by a developer' }],
    }),
  ],
  script: [
    { item: 0, say: { standard: 'Each thing that starts on its own knocks like this. Read two things: what it runs, and who signed it.', city: 'Each visitor knocks like this. Read two things: what it runs, and whose seal it carries.' } },
    { item: 0, point: 'signer', say: { standard: 'Signed by Apple, verified, and it runs from /System, where macOS keeps its own files. This one belongs here.', city: 'Apple’s seal checks out, and it runs from /System, where macOS keeps its own files. This one belongs here.' }, expect: 'mine' },
    { item: 1, point: 'runs', say: { standard: 'See the Runs path? “.hidden” starts with a dot, so it’s a hidden folder, and nobody has vouched for the maker. Installed apps don’t run from places like this.', city: 'See the Runs path? “.hidden” starts with a dot, so it’s a hidden folder, and no seal vouches for it. Settled residents don’t live in places like this.' }, expect: 'not-mine' },
    { item: 2, point: 'runs', say: { standard: 'Not verified, but it runs from Homebrew’s folder, for the database you installed. When you know why it’s there, it’s yours.', city: 'No checked seal, but it runs from Homebrew’s folder, for the database you set up. When you know why it’s there, let it in.' }, expect: 'mine' },
  ],
};

export default {
  type: 'door',
  title: { standard: 'Things that start on their own', city: 'The Door' },
  concepts: ['where-it-lives', 'who-made-it'],
  covers,
  decisions,
  research,
  practice,
  render,
  summary,
};
