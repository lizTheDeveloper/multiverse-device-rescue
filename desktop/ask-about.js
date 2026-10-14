// "Ask about this": main-process side. Validates one finding from the renderer,
// redacts it, and sends ONLY title/description/severity/category/code to The
// Multiverse School's AI helper. Nothing is stored or logged here.
//
// The network call lives in the main process because the renderer's CSP is
// `default-src 'self'`; the renderer never talks to the internet.
const os = require('os');
const { execFileSync } = require('child_process');

const ASK_ENDPOINT = 'https://themultiverse.school/api/device-rescue/explain';
const ASK_TIMEOUT_MS = 60000;
const WARMING_RETRY_DELAY_MS = 20000;
const MAX_ANSWER_CHARS = 6000;

// Same limits the server enforces (device_rescue_explain.py). Longer text is
// truncated rather than rejected: a long description should still be askable.
const FIELD_LIMITS = { title: 300, description: 2000, severity: 20, category: 80, code: 100 };
const REQUIRED = ['title', 'description'];

// Fields are read at most PRE_CAP_FACTOR x their final limit before redaction (so
// regex work stays bounded), redacted, and only THEN cut to the final limit. Cutting
// first could slice a secret in half and leave a recognisable prefix behind.
const PRE_CAP_FACTOR = 4;

function readFields(payload, factor) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const f = payload.finding;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return null;
  const clean = {};
  for (const [key, limit] of Object.entries(FIELD_LIMITS)) {
    const v = f[key];
    if (v == null) continue;
    if (typeof v !== 'string') return null;
    clean[key] = factor === 1 ? v.slice(0, limit) : cutAtBoundary(v, limit * factor);
  }
  for (const key of REQUIRED) {
    if (!clean[key] || !clean[key].trim()) return null;
  }
  return clean;
}

/** Cut to `max` chars, backing up to whitespace so no token is left half-cut. */
function cutAtBoundary(s, max) {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const ws = cut.search(/\s\S*$/);
  return ws > max / 2 ? cut.slice(0, ws) : cut;
}

/** Returns a clean {title, description, severity?, category?, code?} or null. */
function validateAskPayload(payload) {
  return readFields(payload, 1);
}

// JS port of the credential/email patterns in rescue/case.py (_REDACTION_PATTERNS),
// extended. Ordered most-specific first.
const R = '[redacted]';
const KEY_WORDS = 'api[_-]?key|secret|passw(?:or)?d|pwd|token|access[_-]?key|credential|cookie|session[_-]?id';
const REDACTION_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/gs, `${R} private key`],
  [/\b(authorization|proxy-authorization)\s*[:=].*/gi, `$1: ${R}`],
  [/\bBearer\s+[A-Za-z0-9._~+\/=-]{8,}/gi, `Bearer ${R}`],
  [new RegExp(`\\b([\\w-]{0,30}(?:${KEY_WORDS})[\\w-]{0,30})["']?\\s*[:=]\\s*("[^"\\n]*"|'[^'\\n]*'|\\S+)`, 'gi'), `$1=${R}`],
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/:@]+:[^\s\/@]+@/gi, `$1${R}@`],
  [/\bgh[pousr]_[A-Za-z0-9]{16,}/g, `${R} code-host token`],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, `${R} code-host token`],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, `${R} code-host token`],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, `${R} api key`],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, `${R} api key`],
  [/\bAIza[0-9A-Za-z_-]{30,}/g, `${R} api key`],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, `${R} slack token`],
  [/\bxapp-[A-Za-z0-9-]{10,}/g, `${R} slack token`],
  [/\bya29\.[A-Za-z0-9_-]{20,}/g, `${R} google token`],
  [/\bnpm_[A-Za-z0-9]{30,}/g, `${R} npm token`],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, `${R} jwt`],
  [/\bAKIA[0-9A-Z]{16}\b/g, `${R} aws key id`],
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, `${R} email`],
  // Wi-Fi network names.
  [/\b(ssid|network name)\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|[^\n,;)]+)/gi, `$1=${R}`],
  [/\b(ssid|wi-?fi(?: network)?|wireless network|hotspot|network)\s*["'“‘][^"'”’\n]{1,64}["'”’]/gi, `$1 "${R}"`],
  // Hardware and network identifiers.
  [/\b(serial(?:[ _-]?(?:number|no\.?))?|IOPlatformSerialNumber|IOPlatformUUID|hardware[ _-]?uuid|provisioning[ _-]?udid|udid)\b["']?\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|\S+)/gi, `$1=${R}`],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, `${R} id`],
  [/\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi, `${R} mac address`],
  [/\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b/gi, `${R} mac address`],
  // Private / local IPv4: RFC1918, link-local, carrier-grade NAT.
  [/(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}(?![\d])/g, `${R} ip`],
  // IPv6 (ULA, link-local and global): full or compressed form.
  [/(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?:%[\w.-]+)?(?![\w:])/gi, `${R} ipv6`],
  [/(?<![\w:])(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?(?:%[\w.-]+)?(?![\w:])/gi, `${R} ipv6`],
  [/(?<![\w:])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?:%[\w.-]+)?(?![\w:])/gi, `${R} ipv6`],
];

// Other people's (and our own) names inside paths, whatever the spelling.
const NAME_END = '[^/\\\\\\s"\'<>:;,)\\]\\[|*?]+';
const PATH_PATTERNS = [
  [new RegExp(`/users/(?!(?:Shared|Public|Default)(?:[/\\\\]|\\s|$))${NAME_END}`, 'gi'), '/Users/[user]'],
  [new RegExp(`/home/${NAME_END}`, 'g'), '/home/[user]'],
  [new RegExp(`([A-Za-z]:\\\\+users\\\\+)(?!(?:Public|Default|All Users)(?:[/\\\\]|$))${NAME_END}`, 'gi'), '$1[user]'],
  [/(^|[\s"'=:(,;])~(?=[A-Za-z_])[\w.-]*/g, '$1~[user]'],
];

// Long opaque strings (hashes, keys of unknown shape) are rarely useful to an
// explanation and often secret.
const LONG_BLOB = [/(?<![\w-])[A-Za-z0-9_-]{40,}(?![\w-])/g, `${R} long value`];

// Invisible / control characters that can hide or split text.
const INVISIBLE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

const COMMON_NAMES = new Set(['localhost', 'mac', 'macbook', 'macbookpro', 'macbookair', 'imac', 'computer', 'pc', 'desktop', 'laptop', 'windows']);

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A regex matching a computer name however punctuation/spacing is spelled. */
function hostnamePattern(name) {
  const first = String(name || '').replace(/\.local$/i, '').split('.')[0];
  const chars = Array.from(first.normalize('NFKC')).filter((c) => /[\p{L}\p{N}]/u.test(c));
  if (chars.length < 4 || COMMON_NAMES.has(chars.join('').toLowerCase())) return null;
  return new RegExp(chars.map((c) => escapeRegExp(c)).join("[\\s'’._-]*"), 'giu');
}

let cachedHostnames = null;
function systemHostnames() {
  if (cachedHostnames) return cachedHostnames;
  const names = [safe(() => os.hostname())];
  if (process.platform === 'darwin') {
    for (const key of ['ComputerName', 'LocalHostName']) {
      names.push(safe(() => execFileSync('scutil', ['--get', key], {
        timeout: 2000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      }).trim()));
    }
  }
  cachedHostnames = names.filter(Boolean);
  return cachedHostnames;
}

/**
 * Remove personal data from one string: invisible characters, the home directory,
 * user names in any path spelling, the computer name, credentials, e-mail and
 * local-network / hardware identifiers, Wi-Fi names. `env` is injectable for tests.
 */
function redactText(text, env = {}) {
  if (typeof text !== 'string' || !text) return text;
  const home = env.home !== undefined ? env.home : safe(() => os.homedir());
  const user = env.user !== undefined ? env.user : safe(() => os.userInfo().username);
  const hostnames = env.hostnames !== undefined ? env.hostnames : systemHostnames();
  const caseFlag = (env.platform || process.platform) === 'win32' ? 'i' : '';
  let out = text.normalize('NFKC').replace(INVISIBLE, '');
  if (home && home !== '/' && home.length > 1) {
    // Also match the forward-slash spelling of a Windows path.
    const variants = new Set([home, home.replace(/\\/g, '/')]);
    for (const v of variants) out = out.replace(new RegExp(escapeRegExp(v), `g${caseFlag}`), '~');
  }
  for (const [pattern, replacement] of REDACTION_PATTERNS) out = out.replace(pattern, replacement);
  for (const [pattern, replacement] of PATH_PATTERNS) out = out.replace(pattern, replacement);
  // Very short usernames would match far too much text.
  if (user && user.length >= 3) {
    out = out.replace(new RegExp(`\\b${escapeRegExp(user)}\\b`, `g${caseFlag}`), '[you]');
  }
  for (const name of hostnames) {
    const pattern = hostnamePattern(name);
    if (pattern) out = out.replace(pattern, '[this computer]');
  }
  return out.replace(LONG_BLOB[0], LONG_BLOB[1]);
}

function safe(fn) {
  try { return fn(); } catch (_e) { return ''; }
}

/**
 * Validate, redact, then cap. Returns the exact object that will be POSTed, or
 * null. Every string field takes the same path; nothing else is ever copied.
 */
function buildAskBody(payload, env) {
  const clean = readFields(payload, PRE_CAP_FACTOR);
  if (!clean) return null;
  const finding = {};
  for (const [k, v] of Object.entries(clean)) {
    finding[k] = redactText(v, env).slice(0, FIELD_LIMITS[k]);
  }
  for (const key of REQUIRED) {
    if (!finding[key] || !finding[key].trim()) return null;
  }
  return { finding };
}

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * One POST with a hard timeout. Resolves to {status, body} or {error}.
 * `fetchImpl` is electron's net.fetch in the app and a stub in tests.
 */
async function postOnce(fetchImpl, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(ASK_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: controller.signal,
    });
    let json = null;
    try { json = await res.json(); } catch (_e) { json = null; }
    return { status: res.status, body: json };
  } catch (_e) {
    return { error: true };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask the helper about one finding.
 * Result: {ok:true, answer} | {ok:false, reason}
 * reason is one of: invalid | warming_up | unavailable | rate_limited | network
 * On a "warming_up" reply it calls onWarming(), waits, and retries exactly once.
 */
async function askAbout(payload, deps = {}) {
  const fetchImpl = deps.fetch;
  const sleep = deps.sleep || defaultSleep;
  const timeoutMs = deps.timeoutMs || ASK_TIMEOUT_MS;
  const retryDelayMs = deps.retryDelayMs == null ? WARMING_RETRY_DELAY_MS : deps.retryDelayMs;
  const body = buildAskBody(payload, deps.env);
  if (!body) return { ok: false, reason: 'invalid' };

  let res = await postOnce(fetchImpl, body, timeoutMs);
  if (isWarming(res)) {
    if (deps.onWarming) deps.onWarming();
    await sleep(retryDelayMs);
    res = await postOnce(fetchImpl, body, timeoutMs);
  }
  return interpret(res);
}

function isWarming(res) {
  return res.status === 503 && res.body && res.body.status === 'warming_up';
}

function interpret(res) {
  if (res.error) return { ok: false, reason: 'network' };
  if (res.status === 200 && res.body && typeof res.body.answer === 'string' && res.body.answer.trim()) {
    return { ok: true, answer: res.body.answer.slice(0, MAX_ANSWER_CHARS) };
  }
  if (isWarming(res)) return { ok: false, reason: 'warming_up' };
  if (res.status === 429) return { ok: false, reason: 'rate_limited' };
  return { ok: false, reason: 'unavailable' };
}

module.exports = {
  ASK_ENDPOINT,
  ASK_TIMEOUT_MS,
  WARMING_RETRY_DELAY_MS,
  validateAskPayload,
  redactText,
  buildAskBody,
  askAbout,
};
