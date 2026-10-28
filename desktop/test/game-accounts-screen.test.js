// "Take your accounts back" inside the game: reached from the deck for the
// "hacked" worry, answers saved to their own store, links opened through main.
const test = require('node:test');
const assert = require('node:assert');

const f = (title, extra = {}) => ({ title, description: 'd', severity: 'warning', category: 'security', data: {}, ...extra });
const mod = (name, findings, category = 'security') => ({ name, category, status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const memStore = () => { const s = {}; return { s, getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };

function stubWin() {
  const listeners = [];
  const calls = { opened: [] };
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { innerHTML: '', activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, mode: () => 'standard' },
    rescue: { recheckModule: async () => null, openMissionLink: async (url) => { calls.opened.push(url); return true; } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el }, preventDefault() {} }));
  };
  return { win, frame, click, calls };
}

async function setup({ situation = { id: 'hacked' }, doc, storage = memStore() } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const stub = stubWin();
  const ctl = createController({ win: stub.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: () => [], loadDrillBank: () => [] });
  ctl.show(doc || scan(mod('remote_login_check', [f('Screen Sharing is turned on', { code: 'security.remote_login_check.screen_sharing_enabled' })])), situation);
  return { ...stub, ctl, storage, html: () => stub.frame.innerHTML };
}

test('the deck shows YOUR ACCOUNTS FIRST for "I think I’ve been hacked", above the map, and not for other worries', async () => {
  const t = await setup();
  const html = t.html();
  assert.match(html, /data-go="accounts"[\s\S]*YOUR ACCOUNTS FIRST/);
  assert.ok(html.indexOf('YOUR ACCOUNTS FIRST') < html.indexOf('THE GATEHOUSE'), 'before the districts');
  const other = await setup({ situation: { id: 'wifi' } });
  assert.doesNotMatch(other.html(), /YOUR ACCOUNTS FIRST/);
});

test('the list, then a step: the safety question first, then the device step names what’s open on this computer', async () => {
  const t = await setup();
  t.click({ 'data-go': 'accounts' });
  assert.match(t.html(), /Take your accounts back/);
  assert.match(t.html(), /NEXT: COULD THIS BE SOMEONE YOU KNOW\?/);
  t.click({ 'data-go': 'acct-step:safety' });
  t.click({ 'data-act': 'acct-safety:no' });
  assert.match(t.html(), /NEXT: USE A DEVICE YOU TRUST/);
  t.click({ 'data-go': 'acct-step:device' });
  assert.match(t.html(), /1 thing open/);
  assert.match(t.html(), /Screen Sharing is turned on/);
  assert.match(t.html(), /data-go="mission:remote_login_check\|/);
});

test('answers are saved to their own store, with no names, and a done step is YOU REPORTED once', async () => {
  const t = await setup();
  t.click({ 'data-go': 'acct-step:email-provider' });
  t.click({ 'data-act': 'acct-provider:google' });
  t.click({ 'data-go': 'acct-step:email-forwarding' });
  assert.match(t.html(), /Forwarding and POP\/IMAP/);
  t.click({ 'data-act': 'acct-answer:email-forwarding:done' });
  const saved = JSON.parse(t.storage.getItem('device-rescue.game.accounts.v1'));
  assert.strictEqual(saved.provider, 'google');
  assert.strictEqual(saved.steps['email-forwarding'].a, 'done');
  // Untick and tick again: still reported once (the ledger's key pays once, ever).
  t.click({ 'data-act': 'acct-toggle:email-forwarding' });
  t.click({ 'data-act': 'acct-toggle:email-forwarding' });
  const deck = JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck;
  assert.deepStrictEqual(Object.keys(deck.once).filter((k) => k.startsWith('report:accounts:')), ['report:accounts:email-forwarding']);
  t.click({ 'data-go': 'map' });
  assert.match(t.html(), /1<\/b>\s*<small>YOU REPORTED|1 YOU REPORTED|YOU REPORTED[^<]*<\/[^>]+>\s*<[^>]+>1/);
});

test('a provider link opens through main’s allowlist, and only that URL', async () => {
  const t = await setup();
  t.click({ 'data-go': 'acct-step:email-provider' });
  t.click({ 'data-act': 'acct-provider:apple' });
  t.click({ 'data-go': 'acct-step:email-signout' });
  t.click({ 'data-act': 'acct-link', 'data-url': 'https://support.apple.com/en-us/102649' });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepStrictEqual(t.calls.opened, ['https://support.apple.com/en-us/102649']);
});

test('the safety answer is never stored, and monitoring software shows the advocate note on every account screen', async () => {
  const t = await setup();
  t.click({ 'data-go': 'acct-step:safety' });
  t.click({ 'data-act': 'acct-safety:maybe' });
  assert.match(t.html(), /Talk to an advocate before you change account settings/);
  for (const v of Object.values(t.storage.s)) assert.doesNotMatch(v, /maybe|safety/);
  const held = await setup({ doc: scan(mod('stalkerware_scan', [f('Monitoring app found (test)', { severity: 'critical' })])) });
  held.click({ 'data-go': 'accounts' });
  assert.match(held.html(), /Talk to an advocate before you change account settings/);
  assert.doesNotMatch(held.html(), /Monitoring app found/, 'the held finding is never listed here');
});

test('the lesson link from the list comes back to the list when finished', async () => {
  const lesson = { id: 'taking-accounts-back', title: 'Taking your accounts back', briefing: 'b', whatTheScanLooksFor: 'w', modules: [], districts: [],
    questions: [{ teach: 't', prompt: 'p', options: [{ text: 'a', correct: true, feedback: 'f' }, { text: 'b', correct: false, feedback: 'f' }] }] };
  const { createController } = await import('../renderer/game/controller.js');
  const stub = stubWin();
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: () => [lesson], loadDrillBank: () => [] });
  await new Promise((r) => setTimeout(r, 0));
  ctl.show(scan(mod('remote_login_check', [])), { id: 'hacked' });
  stub.click({ 'data-go': 'accounts' });
  stub.click({ 'data-go': 'lesson:taking-accounts-back' });
  assert.match(stub.frame.innerHTML, /QUESTION 1 OF 1/);
  stub.click({ 'data-act': 'answer:0' });
  stub.click({ 'data-act': 'finish-lesson' });
  assert.match(stub.frame.innerHTML, /Take your accounts back/);
});
