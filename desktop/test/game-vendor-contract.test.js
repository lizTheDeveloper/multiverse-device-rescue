const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const need = (rel) => path.join(SRC, rel);

test('the Reclaim City submodule is checked out (run: git submodule update --init)', () => {
  assert.ok(fs.existsSync(need('components/scout.js')),
    'desktop/vendor/reclaim-city is empty. Run: git submodule update --init');
});

test('every file game mode loads from the game exists', () => {
  for (const rel of ['components/scout.js', 'style.css', 'assets/characters/scout_0.png',
    'assets/iso_occupied.png', 'assets/iso_progress.png', 'assets/iso_liberated.png',
    'assets/iso_tower_occ.png', 'assets/iso_tower_lib.png']) {
    assert.ok(fs.existsSync(need(rel)), `missing ${rel}`);
  }
});

test('scoutSprite renders a sheet that exists on disk, for every feeling game mode uses', async () => {
  const { scoutSprite, FEELINGS } = await import(path.join(SRC, 'components', 'scout.js'));
  for (const feeling of ['happy', 'proud', 'wave', 'thinkingA', 'worried']) {
    assert.ok(FEELINGS[feeling], `feeling ${feeling} gone upstream`);
    const html = scoutSprite(feeling, { size: 64 });
    const m = html.match(/url\((assets\/characters\/scout\/[a-z-]+\.png)\)/);
    assert.ok(m, `no sheet url in: ${html}`);
    assert.ok(fs.existsSync(need(m[1])), `sheet missing on disk: ${m[1]}`);
  }
});

test('scout.js imports nothing (game mode relies on it being self-contained)', () => {
  const text = fs.readFileSync(need('components/scout.js'), 'utf8');
  assert.doesNotMatch(text, /^\s*import\s/m);
});

const { loadRcFromDisk } = require('./rc-from-disk');

test('loadRc gives every name game mode uses', async () => {
  const rc = await loadRcFromDisk();
  for (const name of ['renderDistrict', 'renderBriefing', 'renderDebrief', 'debriefReaction', 'renderMilestone',
    'loadState', 'saveState', 'createInitialState', 'markMissionStarted', 'toggleAccount', 'updateStreak',
    'streakAfterFiling', 'missionDistrict', 'fileDebrief', 'recordNotNeeded', 'visibleQuestions', 'ensureBurst',
    'startBurst', 'applyCategoryAction', 'noteFirstTwoFactor', 'markTwoFactorHugSeen', 'isMissionDone',
    'calcDistrictProgress', 'parseRoute', 'keyActivationTarget', 'newScreenVisit']) {
    assert.strictEqual(typeof rc[name], 'function', name);
  }
  assert.ok(Array.isArray(rc.MISSIONS) && rc.MISSIONS.length > 100);
  assert.ok(Array.isArray(rc.DISTRICTS) && rc.DISTRICTS.some((d) => d.type === 'facility'));
  assert.ok(rc.ACCOUNTS.gmail);
  assert.ok(rc.DONE_STATUSES.has('completed'));
});

test('the account screens render in Node for a real account and a facility district', async () => {
  const rc = await loadRcFromDisk();
  const st = rc.createInitialState();
  const district = rc.renderDistrict(st, 'master-keys');
  assert.match(district, /data-action="toggle-account"/);
  assert.ok(rc.renderDistrict(st, 'perimeter').length > 1000);
  assert.match(rc.renderBriefing(st, 'gmail-recon-breach'), /data-action="go-do-it"/);
  assert.match(rc.renderDebrief(st, 'device_security-fortify-computer'), /data-action="submit-debrief"/);
  assert.ok(rc.renderMilestone(st, 'master-keys').length > 1000);
});

test('screens draw the HUD stand-in, not the game HUD with its payment links', async () => {
  const rc = await loadRcFromDisk();
  const html = rc.renderDistrict(rc.createInitialState(), 'master-keys');
  assert.doesNotMatch(html, /RECLAIM CITY|buy\.stripe\.com|patreon\.com/);
});

test('loadState rebuilds from defaults when storage throws or holds junk', async () => {
  const rc = await loadRcFromDisk();
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.ok(rc.loadState(throwing).accounts.gmail);
  assert.ok(rc.loadState({ getItem: () => '{not json' }).accounts.gmail);
  assert.doesNotThrow(() => rc.saveState(rc.createInitialState(), throwing));
});

test('every account building is served through app://rescue/assets/ and exists', async () => {
  const { resolveAppPath, APP_ORIGIN } = require('../app-protocol');
  const rc = await loadRcFromDisk();
  const paths = new Set(Object.values(rc.ACCOUNTS).flatMap((a) => [a.building, a.buildingDark]).filter(Boolean));
  assert.ok(paths.size > 50);
  for (const p of paths) {
    const hit = resolveAppPath(`${APP_ORIGIN}${p}`, path.join(__dirname, '..'));
    assert.ok(hit, `not served: ${p}`);
    assert.ok(fs.existsSync(hit.file), `missing on disk: ${p}`);
  }
});
