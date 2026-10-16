// Writes desktop/mission-links.json: every https link in Reclaim City's
// missions (any "url" field, at any depth, so stepsByManager and reportSteps
// count too) and every account's securityUrl. The main process opens exactly
// these and nothing else. Re-run after bumping the game submodule; a test fails
// if the file is out of date.
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SRC = path.join(here, '..', 'vendor', 'reclaim-city', 'src');

export async function collectMissionLinks(srcDir = DEFAULT_SRC) {
  const load = (rel) => import(pathToFileURL(path.join(srcDir, rel)).href);
  const [{ MISSIONS }, { ACCOUNTS }] = await Promise.all([load('data/missions.js'), load('data/accounts.js')]);
  const out = new Set();
  const walk = (v) => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (!v || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      if (k === 'url' && typeof x === 'string') out.add(x);
      else walk(x);
    }
  };
  walk(MISSIONS);
  for (const a of Object.values(ACCOUNTS)) if (typeof a.securityUrl === 'string') out.add(a.securityUrl);
  return [...out].filter((u) => u.startsWith('https://')).sort();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const links = await collectMissionLinks();
  writeFileSync(path.join(here, '..', 'mission-links.json'), `${JSON.stringify({ links }, null, 2)}\n`);
  console.log(`wrote ${links.length} links`);
}
