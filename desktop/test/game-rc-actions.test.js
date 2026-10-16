const test = require('node:test');
const assert = require('node:assert');

const { loadRcFromDisk } = require('./rc-from-disk.js');
const setup = async () => ({ rc: await loadRcFromDisk(), ...(await import('../renderer/game/rc-actions.js')) });
const snapshot = (s) => JSON.stringify(s);

test('routes this plan supports pass through; everything else goes to the map', async () => {
  const { rc, routeFor } = await setup();
  assert.deepStrictEqual(routeFor('#/district/master-keys?tab=fortify', rc.parseRoute), { screen: 'district', params: { id: 'master-keys', tab: 'fortify' } });
  assert.strictEqual(routeFor('#/mission/gmail-recon-breach/briefing', rc.parseRoute).screen, 'briefing');
  assert.strictEqual(routeFor('#/mission/gmail-recon-breach/debrief', rc.parseRoute).screen, 'debrief');
  assert.strictEqual(routeFor('#/milestone/vault', rc.parseRoute).screen, 'milestone');
  for (const h of ['#/city', '#/garage', '#/timeline', '#/quiz/phishing', '#/quickquest', '#/stats', '#/city-together', '#/ghost', '#/ghost/done', '#/nope', '', null]) {
    assert.deepStrictEqual(routeFor(h, rc.parseRoute), { screen: 'map', params: {} }, String(h));
  }
});

test('go-do-it remembers the start, opens only https, and goes to the debrief', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const before = snapshot(st);
  const r = applyRcAction(rc, st, 'go-do-it', { mission: 'gmail-recon-breach', url: 'https://haveibeenpwned.com/' });
  assert.ok(r.state.startedMissions['gmail-recon-breach']);
  assert.strictEqual(r.open, 'https://haveibeenpwned.com/');
  assert.strictEqual(r.route, '#/mission/gmail-recon-breach/debrief');
  assert.strictEqual(snapshot(st), before, 'input state not mutated');
  assert.strictEqual(applyRcAction(rc, st, 'go-do-it', { mission: 'gmail-recon-breach', url: '#' }).open, undefined);
  assert.strictEqual(applyRcAction(rc, st, 'go-do-it', { mission: 'x', url: 'javascript:alert(1)' }).open, undefined);
});

test('mission-step remembers the start and opens its link; i-did-it goes to the debrief', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const r = applyRcAction(rc, st, 'mission-step', { mission: 'gmail-recon-breach', href: 'https://example.org/a' });
  assert.ok(r.state.startedMissions['gmail-recon-breach']);
  assert.strictEqual(r.open, 'https://example.org/a');
  assert.strictEqual(r.route, undefined);
  assert.strictEqual(applyRcAction(rc, st, 'i-did-it', { mission: 'gmail-recon-breach' }).route, '#/mission/gmail-recon-breach/debrief');
});

test('the survey toggle, intro, password manager and custom accounts change state without mutating it', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const before = snapshot(st);
  const was = st.accounts.gmail.enabled;
  assert.strictEqual(applyRcAction(rc, st, 'toggle-account', { account: 'gmail' }).state.accounts.gmail.enabled, !was);
  assert.strictEqual(applyRcAction(rc, st, 'toggle-account', { account: 'nope' }).state, st);
  assert.strictEqual(applyRcAction(rc, st, 'dismiss-intro', { district: 'vault' }).state.seenIntros.vault, true);
  assert.strictEqual(applyRcAction(rc, st, 'set-password-manager', { pm: 'bitwarden' }).state.passwordManager, 'bitwarden');
  const added = applyRcAction(rc, st, 'add-custom-account', { district: 'vault', name: '  Credit Union  ' }).state;
  assert.deepStrictEqual(added.customAccounts.vault, ['Credit Union']);
  assert.strictEqual(applyRcAction(rc, st, 'add-custom-account', { district: 'vault', name: '   ' }).state, st);
  const removed = applyRcAction(rc, added, 'remove-custom-account', { district: 'vault', index: '0' }).state;
  assert.deepStrictEqual(removed.customAccounts.vault, []);
  assert.deepStrictEqual(added.customAccounts.vault, ['Credit Union'], 'remove does not mutate');
  assert.strictEqual(snapshot(st), before);
});

test('reset-anyway is a view flag; share-card and unknown actions change nothing', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  assert.deepStrictEqual(applyRcAction(rc, st, 'reset-anyway', { mission: 'gmail-fortify-password' }).ui, { resetAnyway: 'gmail-fortify-password' });
  for (const action of ['share-card', 'share-stat', 'toggle-analytics', 'go-ghost', 'begin-game', 'whatever']) {
    const r = applyRcAction(rc, st, action, {});
    assert.strictEqual(r.state, st, action);
    assert.strictEqual(r.route, undefined, action);
    assert.strictEqual(r.open, undefined, action);
  }
});

test('filing a debrief records it and lands on the district tab', async () => {
  const { rc, fileRc } = await setup();
  const st = rc.createInitialState();
  const r = fileRc(rc, st, 'device_security-fortify-computer', { action: 'completed' });
  assert.strictEqual(r.state.missions['device_security-fortify-computer'].status, 'completed');
  assert.ok(r.state.missions['device_security-fortify-computer'].completedAt);
  assert.strictEqual(r.route, '#/district/perimeter?tab=fortify');
  assert.strictEqual(st.missions['device_security-fortify-computer'], undefined, 'input not mutated');
});

test('an incomplete debrief files nothing; an unknown mission goes to the map', async () => {
  const { rc, fileRc } = await setup();
  const st = rc.createInitialState();
  const r = fileRc(rc, st, 'device_security-fortify-computer', {});
  assert.strictEqual(r.incomplete, true);
  assert.strictEqual(r.state, st);
  assert.strictEqual(fileRc(rc, st, 'no-such-mission', {}).route, '#/city');
});

test('filing, pm-category and not-needed actions never mutate the state they were given', async () => {
  const { rc, fileRc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const before = snapshot(st);
  fileRc(rc, st, 'device_security-fortify-computer', { action: 'completed' });
  applyRcAction(rc, st, 'pm-cat-flag', { district: 'vault', raw: '0' });
  applyRcAction(rc, st, 'password-not-needed', { mission: 'gmail-fortify-password' });
  applyRcAction(rc, st, 'line-up-burst', {});
  assert.strictEqual(snapshot(st), before);
});
