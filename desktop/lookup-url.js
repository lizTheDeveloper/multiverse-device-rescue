// Allowlist for the 'open-lookup' IPC channel: only the URLs research.js's
// look-up templates produce (renderer/missions/research.js lookupUrl). Main
// checks the template again here, on the exact string, so a renderer that was
// talked into anything else (another host, an extra parameter, a fragment, a
// query that isn't one quoted name) opens nothing.
//
//   https://duckduckgo.com/?q=<encodeURIComponent('"name"')>
//   https://duckduckgo.com/?q=<encodeURIComponent('site:support.apple.com "name"')>      (and support.microsoft.com)
//   https://chromewebstore.google.com/detail/<32 letters a-p>
//
// The name: 1-120 characters, no quote, no control, format or separator
// characters (newlines, bidi overrides, zero-width), no leading, trailing or
// doubled spaces: research.js cleanQuery's output.

const SEARCH = /^https:\/\/duckduckgo\.com\/\?q=([A-Za-z0-9\-_.!~*'()%]+)$/;
const STORE = /^https:\/\/chromewebstore\.google\.com\/detail\/[a-p]{32}$/;
const QUERY = /^(?:site:support\.(?:apple|microsoft)\.com )?"([^"]+)"$/;
const MAX_QUERY = 120;

function cleanName(q) {
  return q.length <= MAX_QUERY && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(q) && q === q.trim() && !/\s{2}/.test(q) && q.length > 0;
}

function isAllowedLookupUrl(url) {
  if (typeof url !== 'string' || url.length > 2048) return false;
  if (STORE.test(url)) return true;
  const m = SEARCH.exec(url);
  if (!m) return false;
  let decoded;
  try { decoded = decodeURIComponent(m[1]); } catch (_) { return false; }
  // research.js encodes with encodeURIComponent: anything else isn't its output.
  if (encodeURIComponent(decoded) !== m[1]) return false;
  const q = QUERY.exec(decoded);
  return !!q && cleanName(q[1]);
}

module.exports = { isAllowedLookupUrl };
