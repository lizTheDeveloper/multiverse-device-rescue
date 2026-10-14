// "Ask about this": main-process side. Validates one finding from the renderer,
// redacts it, and sends ONLY title/description/severity/category/code to The
// Multiverse School's AI helper. Nothing is stored or logged here.
//
// The network call lives in the main process because the renderer's CSP is
// `default-src 'self'`; the renderer never talks to the internet.
const os = require('os');

const ASK_ENDPOINT = 'https://themultiverse.school/api/device-rescue/explain';
const ASK_TIMEOUT_MS = 60000;
const WARMING_RETRY_DELAY_MS = 20000;
const MAX_ANSWER_CHARS = 6000;

// Same limits the server enforces (device_rescue_explain.py). Longer text is
// truncated rather than rejected: a long description should still be askable.
const FIELD_LIMITS = { title: 300, description: 2000, severity: 20, category: 80, code: 100 };
const REQUIRED = ['title', 'description'];

/** Returns a clean {title, description, severity?, category?, code?} or null. */
function validateAskPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const f = payload.finding;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return null;
  const clean = {};
  for (const [key, limit] of Object.entries(FIELD_LIMITS)) {
    const v = f[key];
    if (v == null) continue;
    if (typeof v !== 'string') return null;
    clean[key] = v.slice(0, limit);
  }
  for (const key of REQUIRED) {
    if (!clean[key] || !clean[key].trim()) return null;
  }
  return clean;
}

// JS port of the credential/email patterns in rescue/case.py (_REDACTION_PATTERNS).
// Keep in sync with that list. Ordered most-specific first.
const R = '[redacted]';
const REDACTION_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/gs, `${R} private key`],
  [/\b(authorization|proxy-authorization)\s*[:=].*/gi, `$1: ${R}`],
  [/\b(api[_-]?key|secret|password|passwd|token|access[_-]?key)\b\s*[:=]\s*\S+/gi, `$1=${R}`],
  [/\bgh[pousr]_[A-Za-z0-9]{16,}/g, `${R} github token`],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, `${R} api key`],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, `${R} slack token`],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, `${R} jwt`],
  [/\bAKIA[0-9A-Z]{16}\b/g, `${R} aws key id`],
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, `${R} email`],
];

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Replace the home directory with `~`, the OS username with `[you]`, then run
 * the credential/email patterns. `env` is injectable for tests.
 */
function redactText(text, env = {}) {
  if (typeof text !== 'string' || !text) return text;
  const home = env.home !== undefined ? env.home : safe(() => os.homedir());
  const user = env.user !== undefined ? env.user : safe(() => os.userInfo().username);
  const caseFlag = (env.platform || process.platform) === 'win32' ? 'i' : '';
  let out = text;
  if (home && home !== '/' && home.length > 1) {
    // Also match the forward-slash spelling of a Windows path.
    const variants = new Set([home, home.replace(/\\/g, '/')]);
    for (const v of variants) out = out.replace(new RegExp(escapeRegExp(v), `g${caseFlag}`), '~');
  }
  // Very short usernames would match far too much text.
  if (user && user.length >= 3) {
    out = out.replace(new RegExp(`\\b${escapeRegExp(user)}\\b`, `g${caseFlag}`), '[you]');
  }
  for (const [pattern, replacement] of REDACTION_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function safe(fn) {
  try { return fn(); } catch (_e) { return ''; }
}

/** Validate then redact. Returns the exact object that will be POSTed, or null. */
function buildAskBody(payload, env) {
  const clean = validateAskPayload(payload);
  if (!clean) return null;
  const finding = {};
  for (const [k, v] of Object.entries(clean)) finding[k] = redactText(v, env);
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
