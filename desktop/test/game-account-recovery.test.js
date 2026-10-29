const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const GAME = path.join(__dirname, '..', 'renderer', 'game');
const load = () => import(pathToFileURL(path.join(GAME, 'account-recovery.js')).href);
const loadView = () => import(pathToFileURL(path.join(GAME, 'views', 'account-recovery.js')).href);

function memStorage(init = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), map: m };
}

// Official help and settings pages only: the person always acts at the provider.
const OFFICIAL = new Set(['support.google.com', 'myaccount.google.com', 'accounts.google.com',
  'support.microsoft.com', 'account.microsoft.com', 'account.live.com',
  'support.apple.com', 'account.apple.com', 'www.icloud.com', 'iforgot.apple.com']);

test('triage order: safety, a trusted device, then the email account before anything else', async () => {
  const { STEPS } = await load();
  const ids = STEPS.map((s) => s.id);
  assert.deepStrictEqual(ids.slice(0, 3), ['safety', 'device', 'email-provider']);
  const lastEmail = Math.max(...STEPS.map((s, i) => (s.section === 'email' ? i : -1)));
  const firstOther = STEPS.findIndex((s) => s.section !== 'email' && !['safety', 'device'].includes(s.id));
  assert.ok(lastEmail < firstOther, 'every email step comes before the other accounts');
  for (const want of ['email-signin', 'email-password', 'email-signout', 'email-recovery', 'email-forwarding',
    'email-apps', 'email-app-passwords', 'email-2sv', 'password-manager', 'money', 'record']) {
    assert.ok(ids.includes(want), `missing step ${want}`);
  }
  assert.ok(ids.indexOf('password-manager') < ids.indexOf('money'), 'password manager, then money');
  assert.strictEqual(new Set(ids).size, ids.length);
});

test('every provider link is https on an official provider site, and every step has a way forward', async () => {
  const { STEPS, PROVIDERS, allLinks } = await load();
  for (const s of STEPS) {
    assert.ok(s.title && s.short, `${s.id} has a title and a short line`);
    if (!s.perProvider) continue;
    for (const p of PROVIDERS.filter((x) => x.id !== 'other')) {
      const at = s.perProvider[p.id];
      assert.ok(at, `${s.id}: nothing for ${p.id}`);
      assert.ok((at.links || []).length >= 1, `${s.id}/${p.id}: at least the official help page`);
      for (const l of at.links) {
        const u = new URL(l.url);
        assert.strictEqual(u.protocol, 'https:', l.url);
        assert.ok(OFFICIAL.has(u.hostname), `${s.id}/${p.id}: ${u.hostname} is not an official provider site`);
        assert.ok(l.label, `${s.id}/${p.id}: a link needs a label`);
      }
    }
  }
  assert.ok(allLinks().length > 10);
});

test('every link the checklist opens is on the main process allowlist', async () => {
  const { allLinks } = await load();
  const { isAllowedMissionLink } = require('../mission-links');
  for (const url of allLinks()) assert.ok(isAllowedMissionLink(url), `not allowed: ${url}`);
});

test('nothing asks the person to type a password or code into the app', async () => {
  const { STEPS } = await load();
  const text = JSON.stringify(STEPS).toLowerCase();
  for (const bad of ['type your password here', 'enter your password', 'enter the code', 'paste the code', 'tell us your']) {
    assert.ok(!text.includes(bad), bad);
  }
  const { renderAccountList, renderAccountStep } = await loadView();
  const { emptyAccounts, STEPS: S } = await load();
  const scout = () => '';
  const html = renderAccountList({ store: emptyAccounts(), safety: null, devicePrereqs: [], scout })
    + S.map((s) => renderAccountStep({ step: s, store: emptyAccounts(), safety: 'no', devicePrereqs: [], scout })).join('');
  assert.doesNotMatch(html, /<input(?![^>]*type="checkbox")/i, 'no text inputs anywhere');
  assert.doesNotMatch(html, /<textarea/i);
});

test('progress is stored with no account names: only the provider kind and each step’s answer', async () => {
  const { loadAccounts, saveAccounts, setAnswer, setProvider, emptyAccounts, ACCOUNTS_KEY } = await load();
  const st = memStorage();
  let a = emptyAccounts();
  a = setProvider(a, 'google', '2026-10-27T00:00:00Z');
  a = setAnswer(a, 'email-password', 'done', '2026-10-27T00:00:00Z');
  a = setAnswer(a, 'safety', 'done', 'x'); // never stored
  a = setAnswer(a, 'not-a-step', 'done', 'x');
  a = setAnswer(a, 'email-signout', 'banana', 'x');
  saveAccounts(st, a);
  const raw = JSON.parse(st.getItem(ACCOUNTS_KEY));
  assert.deepStrictEqual(Object.keys(raw).sort(), ['provider', 'steps', 'version']);
  assert.deepStrictEqual(Object.keys(raw.steps), ['email-password']);
  assert.deepStrictEqual(raw.steps['email-password'], { a: 'done', at: '2026-10-27T00:00:00Z' });
  assert.strictEqual(raw.provider, 'google');
  assert.deepStrictEqual(loadAccounts(st), raw);
});

test('a garbled or tampered store loads as empty, and stray fields are dropped', async () => {
  const { loadAccounts, ACCOUNTS_KEY } = await load();
  assert.deepStrictEqual(loadAccounts(memStorage({ [ACCOUNTS_KEY]: '{nope' })).steps, {});
  const tampered = { version: 1, provider: 'alex@example.com', name: 'Alex',
    steps: { 'email-password': { a: 'done', at: 'x', email: 'alex@example.com' }, safety: { a: 'help', at: 'x' } } };
  const got = loadAccounts(memStorage({ [ACCOUNTS_KEY]: JSON.stringify(tampered) }));
  assert.strictEqual(got.provider, null);
  assert.deepStrictEqual(got.steps, { 'email-password': { a: 'done', at: 'x' } });
  assert.strictEqual(JSON.stringify(got).includes('alex'), false);
  assert.deepStrictEqual(loadAccounts({ getItem() { throw new Error('blocked'); } }).steps, {});
});

test('answering again with the same answer clears it (an unticked box again)', async () => {
  const { setAnswer, emptyAccounts } = await load();
  let a = setAnswer(emptyAccounts(), 'money', 'done', 't');
  assert.strictEqual(a.steps.money.a, 'done');
  a = setAnswer(a, 'money', 'done', 't');
  assert.strictEqual(a.steps.money, undefined);
});

test('counts and the next step: done and not-applicable count, need-help stays open', async () => {
  const { accountCounts, nextStep, setAnswer, setProvider, emptyAccounts, STEPS } = await load();
  let a = emptyAccounts();
  // Without the safety answer (memory only), the next step is the safety question.
  assert.strictEqual(nextStep(a, null).id, 'safety');
  assert.strictEqual(nextStep(a, 'no').id, 'device');
  a = setAnswer(a, 'device', 'done', 't');
  assert.strictEqual(nextStep(a, 'no').id, 'email-provider');
  a = setProvider(a, 'microsoft', 't');
  assert.strictEqual(nextStep(a, 'no').id, 'email-signin');
  a = setAnswer(a, 'email-signin', 'help', 't');
  assert.strictEqual(nextStep(a, 'no').id, 'email-signin', 'need help keeps the step open');
  a = setAnswer(a, 'email-signin', 'done', 't');
  a = setAnswer(a, 'email-password', 'na', 't');
  const c = accountCounts(a);
  // device, provider, signin, password
  assert.strictEqual(c.done, 4);
  assert.strictEqual(c.total, STEPS.filter((s) => s.id !== 'safety').length);
  assert.strictEqual(c.help, 0);
});

test('offered for "I think I’ve been hacked" only', async () => {
  const { offeredFor } = await load();
  assert.strictEqual(offeredFor({ id: 'hacked' }), true);
  for (const id of ['watched', 'wifi', 'phone', 'unsure', 'city']) assert.strictEqual(offeredFor({ id }), false, id);
  assert.strictEqual(offeredFor(null), false);
});

test('device prerequisites: open missions from the checks that matter for a hack, never monitoring software', async () => {
  const { devicePrereqs } = await load();
  const city = { districts: [
    { id: 'gatehouse', missions: [
      { id: 'a', module: 'remote_login_check', title: 'Screen Sharing is turned on', districtId: 'gatehouse' },
      { id: 'b', module: 'browser_extension_audit', title: 'Extension with broad access', districtId: 'gatehouse' },
      { id: 'c', module: 'app_permissions', title: 'Apps can control your Mac', districtId: 'gatehouse' },
      { id: 'd', module: 'stalkerware_scan', title: 'Monitoring app', districtId: 'gatehouse' },
    ] },
    { id: 'wires', missions: [{ id: 'e', module: 'network_proxy_check', title: 'Local proxy', districtId: 'wires' }] },
  ] };
  const progress = { missions: { b: { status: 'yours' } } };
  assert.deepStrictEqual(devicePrereqs(city, progress).map((m) => m.id), ['a', 'e']);
  assert.deepStrictEqual(devicePrereqs(null, progress), []);
});

test('the list: unticked boxes at first, one row per step, the lesson linked once, no explanations', async () => {
  const { renderAccountList } = await loadView();
  const { emptyAccounts, STEPS, setAnswer } = await load();
  const scout = () => '';
  const html = renderAccountList({ store: emptyAccounts(), safety: null, devicePrereqs: [], scout });
  const boxes = html.match(/role="checkbox"/g) || [];
  assert.strictEqual(boxes.length, STEPS.length - 1, 'every step but the safety question has a box');
  assert.strictEqual((html.match(/aria-checked="true"/g) || []).length, 0);
  assert.match(html, /data-go="lesson:taking-accounts-back"/);
  for (const s of STEPS) assert.ok(!s.teach || !html.includes(s.teach), `${s.id}: its explanation belongs in the lesson`);
  const after = renderAccountList({ store: setAnswer(emptyAccounts(), 'money', 'done', 't'), safety: 'no', devicePrereqs: [], scout });
  assert.strictEqual((after.match(/aria-checked="true"/g) || []).length, 1);
});

test('a step: the chosen provider’s path and links, three answers, and the advocate note when it may be someone close', async () => {
  const { renderAccountStep } = await loadView();
  const { STEPS, emptyAccounts, setProvider } = await load();
  const scout = () => '';
  const step = STEPS.find((s) => s.id === 'email-forwarding');
  const html = renderAccountStep({ step, store: setProvider(emptyAccounts(), 'google', 't'), safety: 'no', devicePrereqs: [], scout });
  assert.match(html, /Forwarding and POP\/IMAP/);
  assert.match(html, /support\.google\.com/);
  for (const a of ['done', 'na', 'help']) assert.match(html, new RegExp(`data-act="acct-answer:email-forwarding:${a}"`));
  assert.doesNotMatch(html, /1-800-799-7233/);
  const worried = renderAccountStep({ step, store: setProvider(emptyAccounts(), 'google', 't'), safety: 'maybe', devicePrereqs: [], scout });
  assert.match(worried, /1-800-799-7233/);
  // No provider picked yet: say so, and offer the choice, never a made-up path.
  const none = renderAccountStep({ step, store: emptyAccounts(), safety: 'no', devicePrereqs: [], scout });
  assert.match(none, /data-act="acct-provider:google"/);
});

test('the "other" provider gets no invented menu names, only what to look for', async () => {
  const { renderAccountStep } = await loadView();
  const { STEPS, emptyAccounts, setProvider } = await load();
  const step = STEPS.find((s) => s.id === 'email-signout');
  const html = renderAccountStep({ step, store: setProvider(emptyAccounts(), 'other', 't'), safety: 'no', devicePrereqs: [], scout: () => '' });
  assert.doesNotMatch(html, / › /);
  assert.ok(html.includes(step.generic), 'the generic wording');
});
