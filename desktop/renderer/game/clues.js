// Clues for Signal or Noise, built from a finding's own evidence, and Scout's
// read after the person tags it. Pure. Only clues the evidence supports are
// made. Every place note and every "how to read this" line names a file in
// this repo and a phrase from it; desktop/test/game-clues.test.js checks both.
import { WATCH_GROUP_CODE, WATCH_SUMMARY_CODE } from './signals.js';

const LAUNCH = { source: 'guides/remediation/review_launch_persistence.md', quote: 'starts on every login' };
const TEMP = { source: 'rescue/attribution.py', quote: 'a temporary folder any program can write to' };
const HIDDEN = { source: 'guides/remediation/clean_ai_worm_filesystem.md', quote: 'dropped scripts under' };
const CRON = { source: 'guides/remediation/review_cron_jobs.md', quote: 'system crontabs' };

// Most specific first. `prefix` matches whole folder names from the start of
// the path (after ~ for a home folder); `contains` matches whole folder names
// anywhere, for Windows paths.
export const PLACES = [
  { id: 'user-launch-agents', kind: 'prefix', pattern: '~/Library/LaunchAgents', risky: false, short: 'your launch agents folder',
    note: 'Things set to start on their own when you log in.', ...LAUNCH },
  { id: 'launch-agents', kind: 'prefix', pattern: '/Library/LaunchAgents', risky: false, short: 'the launch agents folder',
    note: 'Things set to start on their own when someone logs in.', ...LAUNCH },
  { id: 'launch-daemons', kind: 'prefix', pattern: '/Library/LaunchDaemons', risky: false, short: 'the launch daemons folder',
    note: 'Background jobs for the whole computer. They run with full control of it.',
    source: 'guides/remediation/respond_to_malware_indicators.md', quote: 'system-wide, runs as root' },
  { id: 'tmp', kind: 'prefix', pattern: '/tmp', risky: true, short: 'a temporary folder',
    note: 'A temporary folder any program can write to. Installed apps don’t normally run from here.', ...TEMP },
  { id: 'var-tmp', kind: 'prefix', pattern: '/var/tmp', risky: true, short: 'a temporary folder',
    note: 'A temporary folder any program can write to. Installed apps don’t normally run from here.', ...TEMP },
  { id: 'hidden-cache', kind: 'prefix', pattern: '~/.cache', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'hidden-config', kind: 'prefix', pattern: '~/.config', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'hidden-local-bin', kind: 'prefix', pattern: '~/.local/bin', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'app-support', kind: 'prefix', pattern: '~/Library/Application Support', risky: false, short: 'your apps’ own files',
    note: 'Where apps keep their own files. An unfamiliar name here is worth a look.',
    source: 'guides/remediation/remove_cryptominer.md', quote: 'under an unfamiliar name' },
  { id: 'applications', kind: 'prefix', pattern: '/Applications', risky: false, short: 'the Applications folder',
    note: 'Where Mac apps are normally installed.',
    source: 'guides/remediation/investigate_keylogger_indicators.md', quote: 'check its install location' },
  { id: 'cron-d', kind: 'prefix', pattern: '/etc/cron.d', risky: false, short: 'the system’s scheduled jobs',
    note: 'Scheduled jobs for the whole computer.', ...CRON },
  { id: 'crontab', kind: 'prefix', pattern: '/etc/crontab', risky: false, short: 'the system’s scheduled jobs',
    note: 'Scheduled jobs for the whole computer.', ...CRON },
  { id: 'hosts', kind: 'prefix', pattern: '/etc/hosts', risky: false, short: 'the hosts file',
    note: 'A small file that can send website names to different addresses, ahead of the internet’s normal lookup.',
    source: 'guides/remediation/clean_hosts_file.md', quote: 'overrides DNS entirely' },
  { id: 'windows-temp', kind: 'contains', pattern: 'AppData\\Local\\Temp', risky: true, short: 'a temporary folder (Temp)',
    note: 'A temporary folder. Installed software doesn’t normally run from here.',
    source: 'guides/remediation/audit_windows_autoruns.md', quote: 'not a scratch/download location' },
  { id: 'downloads', kind: 'contains', pattern: 'Downloads', risky: true, short: 'your Downloads folder',
    note: 'Your Downloads folder, where files from the internet land. Installed software doesn’t normally run from here.',
    source: 'rescue/attribution.py', quote: 'where files from the internet land' },
  { id: 'program-files', kind: 'contains', pattern: 'Program Files', risky: false, short: 'Program Files',
    note: 'Where Windows programs are normally installed.',
    source: 'guides/remediation/audit_windows_autoruns.md', quote: 'legitimate installed software runs from `Program Files`' },
];

export const READING = {
  verified: { text: 'Verified signature: the maker’s seal is real and names who made it. It tells you who made it, not that it’s safe or that you wanted it.',
    source: 'desktop/renderer/app.js', quote: 'means the seal is real and names the maker' },
  unverified: { text: 'Not verified: nobody has vouched for who made it. That isn’t proof of anything bad, so look at where it lives too.',
    source: 'desktop/renderer/app.js', quote: 'is not proof of anything bad, but nobody has vouched for it' },
  apple: { text: 'Part of macOS: this file comes with the operating system.',
    source: 'desktop/renderer/app.js', quote: "'Apple system file': 'part of macOS'" },
  place: { text: 'Where something lives often tells you more than its name. A temporary or hidden folder is a stronger warning sign than an app’s own install folder.',
    source: 'guides/remediation/review_launch_persistence.md', quote: 'a program path in `/tmp`, `/var/tmp`, or a hidden directory' },
  placeUnknown: { text: 'This is where the scan found it. Reclaim City has no note about this place, so the other clues matter more.',
    source: 'guides/remediation/review_launch_persistence.md', quote: 'reported in the finding' },
  went: { text: 'Who runs an address is usually a hosting or cloud company, not the app’s maker. Lookups sent the addresses, not what was in them.',
    source: 'docs/cli.md', quote: 'only the address is sent' },
  when: { text: 'The date the scan recorded for it. Did you install something around then? If you didn’t, something else may have.',
    source: 'guides/remediation/review_changes_since_baseline.md', quote: "did I install something around then? If you didn't, something else may have." },
};

export const CLUE_LABEL = { maker: 'WHO MADE IT', where: 'WHERE IT LIVES', went: 'WHERE THEY WENT', what: 'WHAT IT DOES', when: 'WHEN IT SHOWED UP',
  conn: 'THE CONNECTION', listen: 'WHAT’S LISTENING', who: 'WHO’S ON THE OTHER END', next: 'WHAT TO DO NEXT' };
export const COULDNT_READ = 'Noted. This check couldn’t run, so nothing here was looked at. That doesn’t mean it’s safe.';

// Data fields that hold the path of the thing a finding names, most useful first.
const PATH_KEYS = ['program', 'path', 'plist', 'file', 'executable', 'target'];
// Only dates the scan recorded. Most findings have none, and then there's no clue.
const DATE_KEYS = ['first_seen', 'created', 'installed', 'modified', 'date'];
const looksLikePath = (v) => typeof v === 'string' && v.length < 1024 && (/^[~/]/.test(v) || /^[A-Za-z]:\\/.test(v));

export function homeRelative(p) {
  return String(p == null ? '' : p).trim()
    .replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)/, '~')
    .replace(/^\/private(?=\/(?:tmp|var\/tmp)(?:\/|$))/, '');
}

const underPrefix = (p, prefix) => p === prefix || p.startsWith(`${prefix}/`);
const hasFolder = (p, part) => `/${p.replace(/\\/g, '/').toLowerCase()}/`.includes(`/${part.replace(/\\/g, '/').toLowerCase()}/`);

export function placeFor(path) {
  if (typeof path !== 'string' || path === '') return null;
  const p = homeRelative(path);
  return PLACES.find((pl) => (pl.kind === 'prefix' ? underPrefix(p, pl.pattern) : hasFolder(p, pl.pattern))) || null;
}

const dataOf = (finding) => (finding && finding.data && typeof finding.data === 'object' ? finding.data : {});

export function pathOf(finding) {
  const d = dataOf(finding);
  for (const k of PATH_KEYS) if (looksLikePath(d[k])) return d[k];
  return null;
}

export function whenOf(finding) {
  const d = dataOf(finding);
  for (const k of DATE_KEYS) {
    const v = d[k];
    if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v) && !Number.isNaN(Date.parse(v))) return v.slice(0, 10);
  }
  return null;
}

function makerClue(entries) {
  const several = entries.length > 1;
  const lines = [];
  for (const e of entries) {
    const name = typeof e.name === 'string' && e.name.trim() ? e.name.trim() : 'Unknown maker';
    const how = typeof e.how === 'string' && e.how.trim() ? ` (${e.how.trim()})` : '';
    const sub = several && typeof e.subject === 'string' ? (e.subject.split(/[\\/]/).filter(Boolean).pop() || '') : '';
    lines.push(`${sub ? `${sub}: ` : ''}${name}, ${e.verified === true ? 'verified' : 'not verified'}${how}`);
    // The engine only says what a program is for when its signature proved which program it is.
    if (e.verified === true && typeof e.what === 'string' && e.what.trim()) lines.push(e.what.trim());
  }
  const allVerified = entries.every((e) => e.verified === true);
  const reading = allVerified && entries.some((e) => e.how === 'Apple system file') ? READING.apple
    : allVerified ? READING.verified : READING.unverified;
  return { kind: 'maker', label: CLUE_LABEL.maker, lines, reading };
}

// --- WHERE THEY WENT: the connection watch, grouped (signals.js) -----------
// Names from registries and reverse DNS are whatever their owners typed:
// control characters go, and each is cut short. The view escapes them.
const SHOWN_MAX = 80;
const MAX_APPS = 25;
const MAX_PLACES = 8;
const MAX_OWNERS = 5;
const UNNAMED = 'unknown'; // rescue/watch.py _UNKNOWN
// rescue/watch.py _look_up's reason when lookups are off; the clue says it once, its own way.
const TURNED_OFF = 'Looking up who runs each address was turned off.';
const shown = (v, max = SHOWN_MAX) => {
  const s = String(v).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};
const textOf = (v) => (typeof v === 'string' && v.trim() ? shown(v) || null : null);
const whole = (n) => Math.max(0, Math.floor(Number(n) || 0));
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// rescue/watch.py _holder_company: "HANDLE - Company" or "HANDLE Company" → "Company".
const HANDLE = /^[A-Z0-9-]*[0-9-][A-Z0-9-]*$/;
export function holderCompany(name) {
  if (typeof name !== 'string' || !name) return null;
  const dash = name.indexOf(' - ');
  if (dash >= 0) return name.slice(dash + 3).trim() || name;
  const space = name.indexOf(' ');
  if (space >= 0 && name.slice(space + 1).trim() && HANDLE.test(name.slice(0, space))) return name.slice(space + 1).trim();
  return name;
}

// rescue/watch.py _owner: the holder's company, else the registrant, else a
// hostname that leads back to the address. Never an unconfirmed hostname.
export function ownerOf(who) {
  if (!who || typeof who !== 'object') return null;
  return textOf(holderCompany(who.as_name)) || textOf(who.registrant)
    || (who.hostname_confirmed === true ? textOf(who.hostname) : null);
}

function placeOf(x) {
  const address = textOf(x.address) || 'an address';
  const at = Number.isInteger(x.port) ? `${address.includes(':') ? `[${address}]` : address}:${x.port}` : address;
  const who = x.who && typeof x.who === 'object' ? x.who : null;
  const host = who && textOf(who.hostname);
  const name = ownerOf(who) || (host ? `${host} (unverified)` : null);
  return name ? `${name} (${at})` : at;
}

// `notes`: the watch_summary findings; `gaps`: watch_incomplete's reasons.
function wentClue(notes, gaps) {
  const apps = notes.filter((n) => n && n.code === WATCH_SUMMARY_CODE).map((n) => {
    const d = dataOf(n);
    const places = (Array.isArray(d.destinations) ? d.destinations : []).filter((x) => x && typeof x === 'object');
    const name = typeof d.target === 'string' && d.target.trim() && d.target !== UNNAMED ? shown(d.target)
      : 'A program Reclaim City couldn’t name';
    return { name, places, unlisted: whole(d.more) + whole(d.not_stored), busy: places.reduce((t, x) => t + whole(x.snapshots), 0),
      sources: d.lookup_sources };
  }).sort((a, b) => (b.busy - a.busy) || a.name.localeCompare(b.name));
  const lines = [];
  // Owners by how many apps talked to them; ties keep the busiest app's order.
  const owners = new Map();
  apps.forEach((a, i) => {
    for (const x of a.places) {
      const o = ownerOf(x.who);
      if (o) owners.set(o, (owners.get(o) || new Set()).add(i));
    }
  });
  const top = [...owners].sort((a, b) => b[1].size - a[1].size).slice(0, MAX_OWNERS);
  if (top.length) lines.push(`Talked to: ${top.map(([o, s], i) => `${o} (${i ? s.size : plural(s.size, 'app')})`).join(', ')}`);
  for (const a of apps.slice(0, MAX_APPS)) {
    const more = a.places.length - Math.min(a.places.length, MAX_PLACES) + a.unlisted;
    const listed = a.places.slice(0, MAX_PLACES).map(placeOf).join(', ');
    lines.push(`${a.name}: ${listed || 'no places listed'}${more ? `, and ${more} more` : ''}`);
  }
  if (apps.length > MAX_APPS) lines.push(`And ${plural(apps.length - MAX_APPS, 'more app')}.`);
  for (const r of gaps) if (typeof r === 'string' && r.trim() && r.trim() !== TURNED_OFF) lines.push(shown(r, 400));
  const said = apps.filter((a) => Array.isArray(a.sources));
  const sources = [...new Set(said.flatMap((a) => a.sources).filter((x) => typeof x === 'string' && x.trim()).map((x) => shown(x, 200)))];
  if (sources.length) lines.push(`Looked up with: ${sources.join('; ')}.`);
  else if (said.length) lines.push('Not looked up (turned off).');
  return { kind: 'went', label: CLUE_LABEL.went, lines, reading: READING.went };
}

export function cluesFor(finding) {
  if (!finding || typeof finding !== 'object') return [];
  if (finding.code === WATCH_GROUP_CODE) {
    return [wentClue(Array.isArray(finding.watch) ? finding.watch : [], Array.isArray(finding.incomplete) ? finding.incomplete : [])];
  }
  const out = [];
  const entries = Array.isArray(finding.made_by) ? finding.made_by.filter((e) => e && typeof e === 'object') : [];
  const net = networkClues(finding, entries);
  if (net) return net;
  if (entries.length) out.push(makerClue(entries));
  const where = pathOf(finding);
  if (where) {
    const place = placeFor(where);
    out.push({ kind: 'where', label: CLUE_LABEL.where, lines: place ? [where, place.note] : [where],
      reading: place ? READING.place : READING.placeUnknown });
  }
  // The description's first paragraph, before any "What to do".
  const what = String(finding.description || '').split(/\n\s*\n/)[0].split(/what to do:?/i)[0].trim().slice(0, 400);
  if (what) out.push({ kind: 'what', label: CLUE_LABEL.what, lines: [what], reading: null });
  const when = whenOf(finding);
  if (when) out.push({ kind: 'when', label: CLUE_LABEL.when, lines: [when], reading: READING.when });
  const next = genericNextClue(finding);
  if (next) out.push(next);
  return out;
}

// --- Network evidence: direction, program, who, next step -----------------
// The engine's connection and listener items (network_connections_monitor
// and open_ports_scan `data.items`). Every next-step sentence and command
// comes from a walkthrough; desktop/test/game-clues.test.js checks each quote
// and each command template is in its file.
const NET_GUIDE = 'guides/remediation/review_network_connections.md';
const PORTS_GUIDE = 'guides/remediation/review_open_ports.md';
export const NET_NEXT = {
  sshMine: { text: 'If you started this SSH session, it’s yours: tag it MINE. To end it, type exit in the Terminal window running it, or close that window.',
    source: NET_GUIDE, quote: "If you started it, it's yours; to end it, type `exit` in the Terminal window running it, or close that window." },
  outMine: { text: 'If you started this program, or it’s one you use, it’s yours: tag it MINE.',
    source: NET_GUIDE, quote: 'Check whether the program and its documented behavior explain the port choice' },
  inbound: { text: 'Another computer started this connection. If you don’t expect anything to connect to this computer, tag it THREAT and look closer before you change anything.',
    source: NET_GUIDE, quote: 'A connection that came in deserves more care than one your own program started.' },
  listenMine: { text: 'If it’s a program you use and you need it reachable this way, it’s yours: tag it MINE.',
    source: PORTS_GUIDE, quote: 'Ask whether you actually need this service reachable from other devices' },
  look: { text: 'If you don’t recognise it, see its full command and the program that started it:',
    source: NET_GUIDE, quote: 'for its full command and its parent (the program that started it)' },
  lookListen: { text: 'If you don’t recognise it, check what it is:',
    source: PORTS_GUIDE, quote: 'For each one you don\'t immediately recognize, check what it is' },
};
// Commands per platform, as the walkthrough writes them; <PID> and <port> are filled in.
export const NET_COMMANDS = {
  conn: { source: NET_GUIDE, darwin: ['ps -p <PID> -o pid,ppid,command', 'lsof -i :<port>'], linux: ['ps -p <PID> -o args=', 'ss -tnap'],
    win32: 'In Resource Monitor’s Network tab, look under TCP Connections for the program using the port.',
    win32Quote: 'in Resource Monitor\'s Network tab, look under TCP Connections for the program using the port' },
  listen: { source: PORTS_GUIDE, darwin: ['lsof -i :<port>', 'ps -p <pid> -o pid,ppid,command'], linux: ['ss -tlnp'],
    win32: 'Open Resource Monitor, go to the Network tab and look under Listening Ports.',
    win32Quote: 'go to the Network tab and look under Listening Ports' },
};
const ITEMS_SHOWN = 5;
const code = (text) => ({ text, code: true });
const portOf = (n) => (Number.isInteger(n) && n > 0 ? n : null);
const addrOf = (a, port) => {
  const s = textOf(a) || 'an unknown address';
  return port ? `${s.includes(':') ? `[${s}]` : s}:${port}` : s;
};
const itemsOf = (finding) => (Array.isArray(dataOf(finding).items) ? dataOf(finding).items.filter((x) => x && typeof x === 'object') : []);
const isConn = (x) => x.direction === 'in' || x.direction === 'out';
const isListen = (x) => portOf(x.port) && !isConn(x);
const programOf = (x) => {
  const name = textOf(x.process) || 'A program Reclaim City couldn’t name';
  const pid = Number.isInteger(x.pid) ? ` (PID ${x.pid})` : '';
  const parent = Number.isInteger(x.ppid) ? `, started by PID ${x.ppid}` : '';
  return `${name}${pid}${parent}`;
};
function fill(cmd, x, port) {
  return cmd.replace(/<PID>|<pid>/g, Number.isInteger(x.pid) ? String(x.pid) : '<PID>').replace('<port>', port ? String(port) : '<port>');
}
function commandLines(kind, platform, x, port) {
  const c = NET_COMMANDS[kind];
  if (platform === 'win32') return [c.win32];
  return (c[platform] || c.darwin).map((cmd) => code(fill(cmd, x, port)));
}

function connClue(items) {
  const lines = [];
  for (const x of items.slice(0, ITEMS_SHOWN)) {
    const remote = addrOf(x.remote_addr);
    lines.push(x.direction === 'in'
      ? `Something is connecting IN to your computer on port ${portOf(x.local_port) || '?'}, from ${remote}.`
      : `Your computer is connecting OUT to ${remote}, port ${portOf(x.remote_port) || '?'}.`);
    lines.push(`Program: ${programOf(x)}`);
    if (textOf(x.command)) lines.push(code(shown(x.command, 300)));
    const local = addrOf(x.local_addr, portOf(x.local_port));
    const far = addrOf(x.remote_addr, portOf(x.remote_port));
    const state = textOf(x.state) ? ` · ${textOf(x.state)}` : '';
    lines.push(code(x.direction === 'in' ? `${far} → ${local}${state}` : `${local} → ${far}${state}`));
  }
  if (items.length > ITEMS_SHOWN) lines.push(`And ${plural(items.length - ITEMS_SHOWN, 'more connection')}.`);
  return { kind: 'conn', label: CLUE_LABEL.conn, lines, reading: null };
}

const SCOPE_LINE = { public: 'an address on the internet', 'local network': 'a device on your own network', 'this computer': 'this computer itself' };
function whoClue(items) {
  const seen = new Set();
  const lines = [];
  for (const x of items) {
    const a = textOf(x.remote_addr);
    if (!a || seen.has(a) || seen.size >= ITEMS_SHOWN) continue;
    seen.add(a);
    if (textOf(x.ssh_host)) lines.push(`${a}: this matches “${textOf(x.ssh_host)}” in your SSH settings (~/.ssh/config).`);
    else lines.push(`${a}: ${SCOPE_LINE[x.remote_scope] || 'an address the checkup couldn’t place'}.`);
  }
  if (!lines.length) return null;
  if (items.some((x) => x.remote_scope === 'public' && !textOf(x.ssh_host))) {
    lines.push('A checkup doesn’t look up who runs an address. A connection watch can.');
  }
  return { kind: 'who', label: CLUE_LABEL.who, lines, reading: null };
}

function connNextClue(items, platform) {
  const x = items.find((i) => textOf(i.ssh_host)) || items.find((i) => i.direction === 'in') || items[0];
  const port = x.direction === 'in' ? portOf(x.local_port) : portOf(x.remote_port);
  const first = textOf(x.ssh_host) ? NET_NEXT.sshMine : x.direction === 'in' ? NET_NEXT.inbound : NET_NEXT.outMine;
  // One finding can hold both kinds: an incoming connection is never left out.
  const also = first !== NET_NEXT.inbound && items.some((i) => i.direction === 'in') ? [NET_NEXT.inbound.text] : [];
  return { kind: 'next', label: CLUE_LABEL.next, reading: null, move: true,
    lines: [first.text, ...also, NET_NEXT.look.text, ...commandLines('conn', platform, x, port)] };
}

const REACH_LINE = {
  network: (x) => `Listening on port ${x.port} for other devices on your network (${textOf(x.address) || '?'}).`,
  'this computer': (x) => `Listening on port ${x.port}, for this computer only (${textOf(x.address) || '?'}).`,
};
function listenClue(items) {
  const lines = [];
  for (const x of items.slice(0, ITEMS_SHOWN)) {
    const said = REACH_LINE[x.reach];
    lines.push(said ? said(x) : `Listening on port ${x.port}.`);
    lines.push(`Program: ${programOf(x)}${textOf(x.service) ? ` · port ${x.port} is usually ${textOf(x.service)}` : ''}`);
  }
  if (items.length > ITEMS_SHOWN) lines.push(`And ${plural(items.length - ITEMS_SHOWN, 'more listening port')}.`);
  return { kind: 'listen', label: CLUE_LABEL.listen, lines, reading: null };
}

function listenNextClue(items, platform) {
  const x = items.find((i) => i.reach === 'network') || items[0];
  return { kind: 'next', label: CLUE_LABEL.next, reading: null, move: true,
    lines: [NET_NEXT.listenMine.text, NET_NEXT.lookListen.text, ...commandLines('listen', platform, x, portOf(x.port))] };
}

// Network findings with items: their own clues in place of the engine's raw text.
function networkClues(finding, entries) {
  const items = itemsOf(finding);
  const platform = textOf(dataOf(finding).platform) || 'darwin';
  const conns = items.filter(isConn);
  const listens = items.filter(isListen);
  if (!conns.length && !listens.length) return null;
  const out = conns.length ? [connClue(conns)] : [listenClue(listens)];
  if (conns.length) { const who = whoClue(conns); if (who) out.push(who); }
  if (entries.length) out.push(makerClue(entries));
  out.push(conns.length ? connNextClue(conns, platform) : listenNextClue(listens, platform));
  return out;
}

// Any other finding with a walkthrough: one plain next step, and the steps one press away.
function genericNextClue(finding) {
  const rem = finding.remediation && typeof finding.remediation === 'object' ? finding.remediation : null;
  const steps = rem && Array.isArray(rem.steps) ? rem.steps.filter((s) => s && textOf(s.title)) : [];
  if (!steps.length) return null;
  return { kind: 'next', label: CLUE_LABEL.next, reading: null, move: true,
    lines: ['If you recognise it, it’s yours: tag it MINE.', `If you don’t, start with: ${textOf(steps[0].title)}.`] };
}

export function drillClues(drill) {
  const c = (drill && drill.clues) || {};
  return cluesFor({ made_by: c.maker ? [c.maker] : [], data: { path: c.path || undefined, first_seen: c.when || undefined }, description: c.what || '' });
}

// The scan's own view of a signal, in tag terms: critical leans THREAT, a
// warning leans LOOK CLOSER, info leans MINE, and a real mark is MINE.
const VIEW = { critical: 'threat', warning: 'closer', info: 'mine' };
const VIEW_LINE = { critical: 'The checkup marked this critical', warning: 'The checkup marked this worth a look', info: 'The checkup only noted this' };
const TAG_WORD = { mine: 'yours', threat: 'a threat', closer: 'worth a closer look' };

function clueReason(sig) {
  const f = sig.finding || {};
  const mb = Array.isArray(f.made_by) ? f.made_by.filter((e) => e && typeof e === 'object') : [];
  if (sig.marked) return 'you told Reclaim City it’s yours';
  const net = netReason(f);
  if (net) return net;
  if (mb.some((e) => e.verified !== true)) return 'nobody has vouched for who made it';
  const place = placeFor(pathOf(f));
  if (place && place.risky) return `it lives in ${place.short}`;
  if (mb.length) return 'its maker’s signature checked out, which says who made it, not that it’s safe';
  return '';
}

// A connection's own evidence, in Scout's words.
function netReason(f) {
  const conns = itemsOf(f).filter(isConn);
  const ssh = conns.find((x) => textOf(x.ssh_host));
  if (ssh) return `it matches “${textOf(ssh.ssh_host)}” in your SSH settings`;
  if (conns.some((x) => x.direction === 'in')) return 'another computer connected in to this one';
  if (conns.length) return `your computer started it${textOf(conns[0].process) ? `, with ${textOf(conns[0].process)}` : ''}`;
  return '';
}

// Never "wrong": the person's call stands, and a tag only sorts the game.
// When it agrees and has no clue to add, Scout says nothing ('').
export function scoutRead(sig, tag) {
  const view = sig.marked ? 'mine' : VIEW[sig.severity] || 'closer';
  const head = sig.marked ? 'You marked this as yours on this computer' : VIEW_LINE[sig.severity] || 'The checkup flagged this';
  const why = clueReason(sig);
  const clue = why ? ` One clue: ${why}.` : '';
  if (tag === view && !sig.marked && !why) return '';
  if (tag === view) return `${head}, so the scan sees it the same way.${clue}`;
  return `${head}.${clue} You called it ${TAG_WORD[tag] || 'something else'}. Your call stands; it only changes how the game sorts it.`;
}

export function drillRead(drill, right) {
  const why = (drill && drill.why) || '';
  return right ? `Right. ${why}` : `Not this time, and it costs you nothing. The tell: ${why}`;
}
