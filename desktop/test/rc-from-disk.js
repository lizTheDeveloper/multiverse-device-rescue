// Test helper: loads Reclaim City modules from the vendored checkout, the way the
// app serves them, so any module importing components/hud.js gets the stand-in
// (the real HUD carries the game's payment links).
const path = require('path');
const { register } = require('node:module');
const { pathToFileURL } = require('url');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const STAND_IN = pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'rc-overrides', 'hud.js')).href;
const REAL_HUD = pathToFileURL(path.join(SRC, 'components', 'hud.js')).href;

const hook = `
export async function resolve(specifier, context, next) {
  const r = await next(specifier, context);
  return r.url === ${JSON.stringify(REAL_HUD)} ? { ...r, url: ${JSON.stringify(STAND_IN)} } : r;
}`;
register(`data:text/javascript,${encodeURIComponent(hook)}`);

const fromDisk = (rel) => import(pathToFileURL(path.join(SRC, rel)).href);
const loadRcFromDisk = async () => (await import('../renderer/game/rc-load.js')).loadRc(fromDisk);

module.exports = { fromDisk, loadRcFromDisk };
