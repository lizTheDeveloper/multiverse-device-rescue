// How much detail the person wants: one stored preference, kept as `new`,
// `everyday` or `technical` and nothing else. Unset reads as `everyday`, which
// is the app as it always was. A level changes only how much is shown and in
// what form, never what is safe: every fix still asks first, monitoring
// software is still held at every level, and "mine" never clears it.
//
// Also, for `technical`: the evidence a finding carries, laid out as plain
// key/value rows, and read-only commands to check it yourself. Pure.
import { HELD_MODULES } from './held.js';
import { commandLines } from './clues.js';

export const LEVEL_KEY = 'device-rescue.level';
export const LEVELS = ['new', 'everyday', 'technical'];
export const DEFAULT_LEVEL = 'everyday';

// The three cards. Plain, short, and none of them sounds like a test.
export const LEVEL_CHOICES = [
  { id: 'new', title: 'I’m new to this', line: 'Plain words, one step at a time. The technical bits stay folded away.' },
  { id: 'everyday', title: 'I use a computer every day', line: 'The usual amount of detail.' },
  { id: 'technical', title: 'I’m technical', line: 'Evidence up front: paths, process ids, ports, signers, and commands to check it yourself.' },
];

// The stored level, or null when none was chosen (or storage is blocked).
export function readLevel(storage) {
  try {
    const v = storage ? storage.getItem(LEVEL_KEY) : null;
    return LEVELS.includes(v) ? v : null;
  } catch (_) {
    return null;
  }
}

export function levelOf(storage) {
  return readLevel(storage) || DEFAULT_LEVEL;
}

export function writeLevel(storage, level) {
  if (!LEVELS.includes(level)) return false;
  try {
    storage.setItem(LEVEL_KEY, level);
    return true;
  } catch (_) {
    return false;
  }
}

// What a level changes. Everything here is about showing; nothing here may
// ever decide whether something is safe, markable or fixable.
export function levelPolicy(level) {
  const lv = LEVELS.includes(level) ? level : DEFAULT_LEVEL;
  return {
    level: lv,
    // Raw paths, maker details and command-line steps start under DETAILS.
    foldRaw: lv === 'new',
    // A finding's evidence rows and check-it-yourself commands, always open.
    evidence: lv === 'technical',
    // The Training Grounds call the lessons optional refreshers, put the
    // checkup first, and offer a test-out where a lesson has item banks.
    lessonsOptional: lv === 'technical',
  };
}

// --- Test-out (technical) ---------------------------------------------------
// A lesson can be tested out of when every question is one concept with an
// item bank (training.js: a `concept` and its `variants`). The test asks one
// variant per concept, never the question as the lesson writes it, with no
// WHAT TO KNOW; every answer right marks the lesson done, and a miss costs
// nothing and offers the lesson itself.
export function canTestOut(lesson) {
  const qs = lesson && Array.isArray(lesson.questions) ? lesson.questions : [];
  return qs.length > 0 && qs.every((q) => q && typeof q.concept === 'string' && q.concept.trim()
    && Array.isArray(q.variants) && q.variants.length > 0);
}

// --- Evidence (technical) ---------------------------------------------------
const MAX_VALUE = 300;
const shown = (v) => {
  const s = String(v).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > MAX_VALUE ? `${s.slice(0, MAX_VALUE - 1)}…` : s;
};
const dataOf = (f) => (f && f.data && typeof f.data === 'object' ? f.data : {});
const pidOf = (v) => (Number.isInteger(v) && v > 0 && v < 2 ** 31 ? v : null);
const portOf = (v) => (Number.isInteger(v) && v > 0 && v < 65536 ? v : null);
const textOf = (v) => (typeof v === 'string' && v.trim() ? shown(v) : null);
const looksLikePath = (v) => typeof v === 'string' && v.length < 1024 && (/^[~/]/.test(v) || /^[A-Za-z]:\\/.test(v));
const PATH_KEYS = ['program', 'path', 'plist', 'file', 'executable', 'target'];
// The engine's check names that say which way a connection goes.
const DIRECTION = { unusual_listening_port: 'listening (inbound)', unusual_outbound_connection: 'outbound' };

function portsOf(d) {
  const list = Array.isArray(d.ports) ? d.ports.map(portOf).filter(Boolean) : [];
  const one = portOf(d.port);
  if (one && !list.includes(one)) list.unshift(one);
  return [...new Set(list)].slice(0, 20);
}

function pathsOf(d) {
  const out = [];
  for (const k of PATH_KEYS) if (looksLikePath(d[k]) && !out.some((x) => x[1] === d[k])) out.push([k, d[k]]);
  return out;
}

// [label, value] rows, in the order a developer reads them. Never for
// monitoring software (held.js): that is never shown as a signal at all.
export function evidenceRows(finding) {
  if (!finding || typeof finding !== 'object' || HELD_MODULES.has(finding.module)) return [];
  const d = dataOf(finding);
  const rows = [];
  for (const [k, p] of pathsOf(d)) rows.push([k, shown(p)]);
  const pid = pidOf(d.pid);
  if (pid) rows.push(['pid', String(pid)]);
  const ppid = pidOf(d.ppid);
  if (ppid) rows.push(['ppid', String(ppid)]);
  const proc = textOf(d.process) || textOf(d.process_name) || textOf(d.name);
  if (proc) rows.push(['process', proc]);
  const cmd = textOf(d.command) || textOf(d.cmdline);
  if (cmd) rows.push(['command', cmd]);
  const ports = portsOf(d);
  if (ports.length) rows.push([ports.length > 1 ? 'ports' : 'port', ports.join(', ')]);
  if (typeof d.check === 'string' && DIRECTION[d.check]) rows.push(['direction', DIRECTION[d.check]]);
  if (Array.isArray(d.connections)) {
    const c = d.connections.map(textOf).filter(Boolean).slice(0, 8);
    if (c.length) rows.push(['connections', c.join('; ')]);
  }
  for (const e of Array.isArray(finding.made_by) ? finding.made_by.filter((x) => x && typeof x === 'object').slice(0, 4) : []) {
    const name = textOf(e.name) || 'unknown';
    const how = textOf(e.how);
    rows.push(['signer', `${name}${e.verified === true ? ' (verified' : ' (not verified'}${how ? `, ${how}` : ''})`]);
  }
  if (textOf(finding.module)) rows.push(['module', shown(finding.module)]);
  if (textOf(finding.code)) rows.push(['code', shown(finding.code)]);
  return rows;
}

// A path in single quotes for a POSIX shell: no expansion inside, and a
// quote in the path is closed, escaped and reopened.
export function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

const MODULE_NAME = /^[a-z][a-z0-9_]{0,63}$/;

// Read-only commands that show the same thing the check saw. The clues come
// first: a NEXT STEP clue's commands are the walkthrough's own (clues.js
// NET_COMMANDS), so they're reused as they are. A finding that names one
// process without connection items gets the same walkthrough commands for its
// pid and port. Then a path's owner and signature, and the engine's own
// read-only single-module re-check (docs/cli.md: `--module`). Nothing here
// changes the computer: no sudo, no kill, no mv, no launchctl.
const FROM_WALKTHROUGH = 'From the walkthrough for this kind of finding.';
const CHECK_KIND = { unusual_listening_port: 'listen', unusual_outbound_connection: 'conn' };
export function checkCommands(finding, platform, clues = []) {
  if (!finding || typeof finding !== 'object' || HELD_MODULES.has(finding.module)) return [];
  const d = dataOf(finding);
  const posix = platform === 'darwin' || platform === 'linux';
  const out = [];
  const seen = new Set();
  const add = (cmd, what) => { if (!seen.has(cmd)) { seen.add(cmd); out.push({ cmd, what }); } };
  for (const c of Array.isArray(clues) ? clues : []) {
    if (!c || c.kind !== 'next' || !Array.isArray(c.lines)) continue;
    for (const l of c.lines) if (l && typeof l === 'object' && l.code && typeof l.text === 'string') add(l.text, FROM_WALKTHROUGH);
  }
  const pid = pidOf(d.pid);
  if (!out.length && pid && posix) {
    const kind = CHECK_KIND[d.check] || 'conn';
    // A template left with a <placeholder> (no port recorded) is left out, not shown half-filled.
    for (const l of commandLines(kind, platform, { pid }, portOf(d.port))) if (l && l.code && !/<[A-Za-z]+>/.test(l.text)) add(l.text, FROM_WALKTHROUGH);
  }
  const [first] = pathsOf(d);
  if (first && posix && !/^[A-Za-z]:\\/.test(first[1])) {
    const p = first[1].startsWith('~/') ? `~/${shQuote(first[1].slice(2))}` : shQuote(first[1]);
    add(`ls -la ${p}`, 'Owner, permissions and dates.');
    if (platform === 'darwin') add(`codesign -dv --verbose=4 ${p}`, 'Who signed it, and whether the signature holds.');
  }
  if (typeof finding.module === 'string' && MODULE_NAME.test(finding.module)) {
    add(`rescue scan --module ${finding.module}`, 'Runs just this check again, read-only (command-line tool).');
  }
  return out;
}

// The same, for a check that couldn't run: only the re-run.
export function fogCommand(module) {
  return typeof module === 'string' && MODULE_NAME.test(module) && !HELD_MODULES.has(module) ? `rescue scan --module ${module}` : null;
}

export const COMMANDS_NOTE = 'All of these only look. docs/commands.md lists every command each check can run.';
