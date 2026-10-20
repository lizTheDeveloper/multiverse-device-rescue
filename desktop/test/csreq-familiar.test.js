// Keyboard access for familiar apps named by bundle id (a TCC row's client)
// leaves the help district only on the engine's own proof: the grant's code
// requirement, which macOS enforces, pinned the expected company's Team ID
// (data.verified_apps + a made_by entry with the requirement's `how`). Never
// by name, never by a made_by entry alone.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const NC = require('../renderer/not-checked.js');
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

const KB = 'security.keylogger_indicators.suspicious_input_monitoring';
const HOW = 'macOS permission record (code requirement)';
const VSC = 'com.microsoft.VSCode';
const STM = 'com.valvesoftware.steam';
const proof = (bundle_id, team_id, maker) => ({ bundle_id, team_id, maker, verified_by: 'macos_code_requirement' });
const entry = (subject, name, extra = {}) => ({ subject, name, verified: true, how: HOW, location_note: '', ...extra });
const VS_E = entry(VSC, 'Microsoft Corporation', { what: 'Visual Studio Code: Microsoft’s code editor.' });
const ST_E = entry(STM, 'Valve Corporation (Steam)', { what: 'Steam: Valve’s game store.' });
const VS_P = proof(VSC, 'UBF8T346G9', 'Microsoft Corporation');
const ST_P = proof(STM, 'MXGJJ98X76', 'Valve Corporation (Steam)');

function kb({ apps = [VSC, STM], verified_apps = [VS_P, ST_P], made_by = [VS_E, ST_E], severity = 'info',
  check = 'claimed_vendor_input_monitoring', makers_verified = true } = {}) {
  const data = { check, apps };
  if (verified_apps) data.verified_apps = verified_apps;
  return { title: 'Keyboard access: 2 app(s) with familiar names, maker confirmed by macOS', severity, code: KB,
    data, made_by, makers_verified };
}

test('engine-verified bundle-id apps (code requirement) are familiar and verified', () => {
  assert.strictEqual(NC.familiarVerified(kb(), 'keylogger_indicators'), true);
  // No `what` needed: the requirement pinned a known maker's Team ID.
  const noWhat = kb({ made_by: [entry(VSC, 'Microsoft Corporation'), entry(STM, 'Valve Corporation (Steam)')] });
  assert.strictEqual(NC.familiarVerified(noWhat, 'keylogger_indicators'), true);
  // Mixed with a verified, known path app.
  const p = '/Applications/Zoom.app';
  const mixed = kb({ apps: [VSC, p], verified_apps: [VS_P],
    made_by: [VS_E, { subject: p, name: 'Zoom', verified: true, how: 'Developer ID signature', what: 'Zoom: video calls.' }] });
  assert.strictEqual(NC.familiarVerified(mixed, 'keylogger_indicators'), true);
});

test('name-only, made_by-only or forged evidence stays held', () => {
  const cases = [
    ['name only: no verified_apps, no made_by', kb({ verified_apps: null, made_by: [] })],
    ['a verified made_by entry by name, without the engine proof', kb({ verified_apps: null })],
    ['a verified Developer ID entry under a bundle id', kb({ verified_apps: null,
      made_by: [{ ...VS_E, how: 'Developer ID signature' }, { ...ST_E, how: 'Developer ID signature' }] })],
    ['proof without a requirement made_by entry', kb({ made_by: [] })],
    ['proof for one app only', kb({ verified_apps: [VS_P] })],
    ['proof by something else', kb({ verified_apps: [{ ...VS_P, verified_by: 'bundle_id' }, ST_P] })],
    ['proof with a malformed team', kb({ verified_apps: [{ ...VS_P, team_id: 'microsoft' }, ST_P] })],
    ['proof with no maker', kb({ verified_apps: [{ ...VS_P, maker: '' }, ST_P] })],
    ['requirement entry not verified', kb({ made_by: [{ ...VS_E, verified: false }, ST_E] })],
    ['requirement entry with no name', kb({ made_by: [{ ...VS_E, name: '' }, ST_E] })],
    ['the engine says not verified', kb({ makers_verified: false })],
    ['warning', kb({ severity: 'warning' })],
    ['the borrowed-name warning', kb({ severity: 'warning', check: 'familiar_name_other_signer' })],
    ['another check', kb({ check: 'suspicious_input_monitoring' })],
    ['an unproven app mixed in', kb({ apps: [VSC, STM, 'com.microsoft.Keys'] })],
    ['verified_apps not a list', kb({ verified_apps: { [VSC]: VS_P } })],
  ];
  for (const [why, f] of cases) {
    assert.strictEqual(NC.familiarVerified(f, 'keylogger_indicators'), false, why);
    assert.strictEqual(NC.isHeld(f, 'keylogger_indicators'), true, why);
  }
  assert.strictEqual(NC.familiarVerified(kb(), 'stalkerware_scan'), false);
});

test('game/held.js lets the engine-verified finding out and holds the rest', async () => {
  const { splitHeld, familiarVerified } = await game('held.js');
  assert.strictEqual(familiarVerified, NC.familiarVerified);
  const doc = (f) => ({ modules: [{ name: 'keylogger_indicators', category: 'security', status: 'ok', supported: true, findings: [f] }] });
  let r = splitHeld(doc(kb()));
  assert.deepStrictEqual(r.held, []);
  assert.strictEqual(r.doc.modules[0].findings.length, 1);
  r = splitHeld(doc(kb({ verified_apps: null })));
  assert.strictEqual(r.held.length, 1);
});
