'use strict';
// I4: a card shows a maker only for the item's own program, and "verified" only when that
// program's own made_by entry verifies (made_by is one entry per program a finding names).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const M = path.join(__dirname, '..', 'renderer', 'missions');
const imp = (rel) => import(pathToFileURL(path.join(M, rel)).href);
const text = (html) => String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const OTHER = { subject: '/Applications/Other.app', name: 'Other Verified Co', verified: true, what: 'Other: a different program.' };

test('makerFor: the subject’s own entry; several programs give no single maker unless every one verified', async () => {
  const C = await imp('contract.js');
  const f = { data: { apps: ['/Applications/A.app', '/Applications/Other.app'] }, made_by: [OTHER, { subject: '/Applications/A.app', name: 'A Co', verified: false }] };
  assert.strictEqual(C.makerFor(f), null);
  assert.deepStrictEqual([C.makerFor(f, '/Applications/A.app').name, C.makerFor(f, '/Applications/A.app').verified], ['A Co', false]);
  assert.strictEqual(C.makerFor(f, '/Applications/Other.app').verified, true);
  assert.strictEqual(C.makerFor(f, '/nope'), null);
  const same = { makers_verified: true, data: { apps: ['/a', '/b'] }, made_by: [{ subject: '/a', name: 'Apple Inc.', verified: true }, { subject: '/b', name: 'Apple Inc.', verified: true }] };
  assert.deepStrictEqual([C.makerFor(same).name, C.makerFor(same).verified], ['Apple Inc.', true]);
  // One program, one entry: its own.
  const one = { data: { path: '/opt/x' }, made_by: [{ subject: '/opt/x', name: 'X Co', verified: true, what: 'X: a tool.' }] };
  assert.deepStrictEqual([C.makerFor(one).name, C.makerFor(one).verified, C.makerFor(one).what], ['X Co', true, 'X: a tool.']);
});

test('door: another program’s verified entry is never the badge (no entries[0] fallback for verified)', async () => {
  const D = await imp('games/door.js');
  const f = { module: 'launch_agent_audit', severity: 'warning', data: { program: '/opt/evil/agent', plist: '/Library/LaunchAgents/x.plist' },
    made_by: [{ ...OTHER, subject: '/Library/LaunchAgents/x.plist' }] };
  const m = D.makerOf(f);
  assert.strictEqual(m.verified, false);
  assert.strictEqual(D.whatOf(f), '', 'no "what it is" from another program');
  const own = { ...f, made_by: [{ subject: '/opt/evil/agent', name: 'Agent Co', verified: true, what: 'Agent: a helper.' }] };
  assert.strictEqual(D.makerOf(own).verified, true);
});

test('locker and seal: no verified maker borrowed from another program', async () => {
  const C = await imp('contract.js');
  const L = await imp('games/locker.js');
  const ctx = C.testContext();
  const lf = { module: 'malware_scan_indicators', code: 'security.malware_scan_indicators.suspicious_file', severity: 'warning', title: 'x', data: { path: '/tmp/x.bin' },
    made_by: [OTHER] };
  const tag = L.tagOf(C.makeItem(lf), ctx);
  assert.ok(!tag.maker || tag.maker.verified === false, 'not verified');
  assert.ok(!tag.maker || !tag.maker.what);
  const S = (await imp('games/seal.js')).default;
  const sf = { module: 'code_signature_audit', code: 'security.code_signature_audit.unsigned_apps', severity: 'warning', title: 'Unsigned apps',
    data: { apps: ['/Applications/A.app', '/Applications/Other.app'] }, made_by: [OTHER, { subject: '/Applications/A.app', name: 'A Co', verified: false }] };
  const item = C.makeItem(sf);
  const html = S.render({ item, research: S.research(item, ctx), decisions: S.decisions(item, ctx), index: 0, total: 1 }, ctx);
  assert.doesNotMatch(text(html), /Other Verified Co/);
  assert.doesNotMatch(text(html), /a different program/);
});
