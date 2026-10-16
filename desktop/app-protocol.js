// The app:// scheme the window loads from.
//
// app://rescue/<path> serves desktop/renderer/<path>. Two prefixes are mapped
// into the vendored Reclaim City game (desktop/vendor/reclaim-city/src), because
// its components use page-relative art paths ("assets/...") and game mode is ES
// modules, which need a real origin:
//   assets/<png>   -> the game's art
//   rc/<allowed>   -> only the game sources listed in rc-files.json
// Everything else is refused, and so is any path that tries to climb out.
const fs = require('fs');
const path = require('path');

const APP_ORIGIN = 'app://rescue/';
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};
const RC = require('./rc-files.json');
// Game sources game mode may load: exactly the files in rc-files.json, which a
// test keeps equal to the real import graph. Overrides are served from renderer/.
const RC_FILES = new Set(RC.files);
const RC_OVERRIDES = RC.overrides || {};
const RC_ALLOW = [...RC_FILES].map((f) => new RegExp(`^${f.replace(/[.]/g, '\\.')}$`));
const SAFE_PATH = /^[A-Za-z0-9._\-/]+$/;

function within(root, file) {
  const r = path.resolve(root) + path.sep;
  return path.resolve(file).startsWith(r);
}

function resolveAppPath(url, baseDir) {
  let u;
  try { u = new URL(url); } catch (_) { return null; }
  if (u.protocol !== 'app:' || u.host !== 'rescue') return null;
  let rel;
  try { rel = decodeURIComponent(u.pathname); } catch (_) { return null; }
  rel = rel.replace(/^\/+/, '');
  if (rel === '') rel = 'index.html';
  if (!SAFE_PATH.test(rel)) return null;
  const parts = rel.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..')) return null;
  const mime = MIME[path.extname(rel).toLowerCase()];
  if (!mime) return null;

  const vendorSrc = path.join(baseDir, 'vendor', 'reclaim-city', 'src');
  let root;
  let file;
  if (parts[0] === 'assets') {
    if (path.extname(rel).toLowerCase() !== '.png') return null;
    root = path.join(vendorSrc, 'assets');
    file = path.join(vendorSrc, rel);
  } else if (parts[0] === 'rc') {
    const inner = parts.slice(1).join('/');
    if (!RC_FILES.has(inner)) return null;
    if (RC_OVERRIDES[inner]) {
      root = path.join(baseDir, 'renderer');
      file = path.join(root, RC_OVERRIDES[inner]);
    } else {
      root = vendorSrc;
      file = path.join(vendorSrc, inner);
    }
  } else {
    root = path.join(baseDir, 'renderer');
    file = path.join(root, rel);
  }
  return within(root, file) ? { file, mime } : null;
}

async function serveApp(url, baseDir, readFile = fs.promises.readFile) {
  const hit = resolveAppPath(url, baseDir);
  if (!hit) return new Response('Not found', { status: 404 });
  try {
    const body = await readFile(hit.file);
    return new Response(body, { status: 200, headers: { 'content-type': hit.mime } });
  } catch (_) {
    return new Response('Not found', { status: 404 });
  }
}

module.exports = { APP_ORIGIN, RC_ALLOW, RC_FILES, RC_OVERRIDES, MIME, resolveAppPath, serveApp };
