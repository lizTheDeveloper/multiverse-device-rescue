// The controller against a stubbed window (no DOM library): just enough of
// document, the shadow root and the frame to drive clicks and FixFlow results.
const test = require('node:test');
const assert = require('node:assert');

const QID = '20261016T120000Z-com.example.a';
const finding = (title) => ({ title, description: 'd', severity: 'critical', category: 'security', data: {} });
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));

function stubWin(recheckDocs) {
  const listeners = [];
  const choices = { outerHTML: '' };
  const calls = { recheck: [], showList: 0 };
  // Focus: `shadow.activeElement` is whatever the test says is focused. After a
  // redraw, the controller looks it up again by its stable attribute; any
  // selector naming a button in the current HTML "finds" one, whose focus() is
  // recorded in `focused`.
  const focused = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: (sel) => {
      if (sel === '.choices') return choices;
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      if (m && frame.innerHTML.includes(`${m[1]}="${m[2]}"`)) return { focus: () => focused.push(sel) };
      return null;
    },
    querySelectorAll: () => [] };
  const shadow = { innerHTML: '', activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: {
      attach: (_root, _api, h) => { hooks.fix = h; },
      fixControlsHtml: () => '',
      resultHtml: (r) => `<button data-fix-undo data-quarantine-id="${r.quarantine_id}">Undo</button>`,
    },
    MarkFlow: { attach: (_root, _api, h) => { hooks.mark = h; }, markControlsHtml: () => '' },
    RescueHost: { showList() { calls.showList += 1; }, docChanged: () => true, wantsSafety: () => false },
    // Each entry is a scan doc, or a function returning one (or a promise of one).
    rescue: { recheckModule: async (name) => {
      calls.recheck.push(name);
      const next = recheckDocs.shift();
      const doc = typeof next === 'function' ? await next(name) : next;
      return { ok: true, doc, module: doc.modules.find((m) => m.name === name) };
    } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const focusOn = (attrs) => { shadow.activeElement = attrs ? { getAttribute: (k) => (k in attrs ? attrs[k] : null) } : null; };
  return { win, frame, shadow, hooks, click, choices, calls, focused, focusOn };
}

async function setup(recheckDocs, before = scan(mod('mod_a', [finding('A')]), mod('mod_b', [finding('B')]))) {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const ids = findingsToCity(before).districts[0].missions.map((m) => m.id);
  const stub = stubWin(recheckDocs);
  // Reclaim City never arrives here: these are Plan A's device-only screens.
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}) });
  ctl.show(before, { id: 'unsure' });
  return { ...stub, ctl, before, idA: ids.find((i) => i.startsWith('mod_a')), idB: ids.find((i) => i.startsWith('mod_b')) };
}

test('Undo for a fix shows on that mission’s RECLAIMED screen only', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const afterB = scan(mod('mod_a', []), mod('mod_b', []));
  const t = await setup([afterA, afterB]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(t.frame.innerHTML.includes(QID), 'A’s own RECLAIMED screen offers its Undo');

  t.click({ 'data-go': `mission:${t.idB}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(!t.frame.innerHTML.includes(QID), 'B’s RECLAIMED screen must not offer A’s Undo');
});

test('a fresh show() forgets the last fix', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const t = await setup([afterA, afterA]);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.ok(t.frame.innerHTML.includes(QID));

  t.ctl.show(t.before, { id: 'unsure' });
  t.click({ 'data-go': `mission:${t.idA}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(!t.frame.innerHTML.includes(QID), 'a new city doesn’t carry an old Undo');
});

test('fixing every mission in a district leads to its milestone, which lists them', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const afterB = scan(mod('mod_a', []), mod('mod_b', []));
  const t = await setup([afterA, afterB]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  t.click({ 'data-act': 'debrief:easy' });
  assert.match(t.choices.outerHTML, /BACK TO THE DISTRICT/, 'B is still open: no milestone yet');

  // The district still shows A, lit and RECLAIMED, though the scan no longer reports it.
  t.click({ 'data-go': 'district:gatehouse' });
  assert.match(t.frame.innerHTML, /mission-row lit[\s\S]*RECLAIMED[\s\S]*>A</);

  t.click({ 'data-go': `mission:${t.idB}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  t.click({ 'data-act': 'debrief:easy' });
  assert.match(t.choices.outerHTML, /data-go="milestone:gatehouse"/);

  t.click({ 'data-go': 'milestone:gatehouse' });
  const html = t.frame.innerHTML;
  assert.match(html, /DISTRICT TAKEN BACK/);
  assert.match(html, /FIXED AND CHECKED[\s\S]*<li>A<\/li>[\s\S]*<li>B<\/li>/);

  t.click({ 'data-go': 'map' });
  assert.match(t.frame.innerHTML, /2 RECLAIMED/);
  assert.doesNotMatch(t.frame.innerHTML, /NOTHING FOUND/);
});

test('Undo: a neutral "put back" line, never "came back", and the checking screen while it runs', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const before = scan(mod('mod_a', [finding('A')]), mod('mod_b', [finding('B')]));
  let release;
  const held = () => new Promise((r) => { release = () => r(before); });
  const t = await setup([afterA, held]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);

  t.hooks.fix.onResult({ kind: 'undo', module: 'mod_a', result: { restored: true }, described: { restored: true } });
  await tick();
  assert.match(t.frame.innerHTML, /Checking again/, 'the reclaimed mission still shows its checking screen');
  assert.doesNotMatch(t.frame.innerHTML, /aria-label="Your computer as a city"/);

  release();
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /PUT BACK/);
  assert.match(t.frame.innerHTML, /Put back\. It’s showing again\./);
  assert.doesNotMatch(t.frame.innerHTML, /NOT YET|put themselves back/);

  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.frame.innerHTML, /came back/);
});

test('"Stop treating this as mine" gets the same neutral line', async () => {
  const marked = { ...finding('A'), severity: 'info', code: 'security.mod_a.x', data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k1', original_severity: 'critical' } };
  const open = { ...finding('A'), code: 'security.mod_a.x', data: { plist: '/a.plist' } };
  const before = scan(mod('mod_a', [marked]), mod('mod_b', [finding('B')]));
  const after = scan(mod('mod_a', [open]), mod('mod_b', [finding('B')]));
  const t = await setup([after], before);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.mark.onResult({ kind: 'removed', result: { status: 'removed', ids: ['k1'] }, described: { done: true } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /Put back\. It’s showing again\./);
  assert.doesNotMatch(t.frame.innerHTML, /NOT YET/);
});

test('a mark that covers findings in two checks re-checks both', async () => {
  const fa = { ...finding('A'), code: 'security.mod_a.x', markable: { id: 'k1' }, data: { plist: '/a.plist' } };
  const fc = { ...finding('A too'), code: 'security.mod_c.x', markable: { id: 'k2' }, data: { plist: '/a.plist' } };
  const ma = { ...fa, severity: 'info', markable: undefined, data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k1', original_severity: 'critical' } };
  const mc = { ...fc, severity: 'info', markable: undefined, data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k2', original_severity: 'critical' } };
  const before = scan(mod('mod_a', [fa]), mod('mod_b', [finding('B')]), mod('mod_c', [fc]));
  const after = scan(mod('mod_a', [ma]), mod('mod_b', [finding('B')]), mod('mod_c', [mc]));
  const t = await setup([after, after], before);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.mark.onResult({ kind: 'marked', result: { status: 'marked', ids: ['k1', 'k2'] }, described: { done: true } });
  await tick(); await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, ['mod_a', 'mod_c']);
  assert.match(t.frame.innerHTML, /MARKED AS YOURS/);
});

test('LIST works while a re-check is running', async () => {
  let release;
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const t = await setup([() => new Promise((r) => { release = () => r(afterA); })]);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick();
  assert.match(t.frame.innerHTML, /Checking again/);
  t.click({ 'data-act': 'list' });
  assert.strictEqual(t.calls.showList, 1);
  t.click({ 'data-go': 'map' });
  assert.match(t.frame.innerHTML, /Checking again/, 'other clicks still wait for the re-check');
  release();
  await tick(); await tick();
});

test('a late re-check result doesn’t take over the screen after the city was shown again', async () => {
  let release;
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const t = await setup([() => new Promise((r) => { release = () => r(afterA); })]);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick();
  t.click({ 'data-act': 'list' });
  t.ctl.show(t.before, { id: 'unsure' });
  release();
  await tick(); await tick();
  assert.doesNotMatch(t.frame.innerHTML, /RECLAIMED!|class="outcome/, 'no outcome screen');
  assert.match(t.frame.innerHTML, /aria-label="Your computer as a city"/, 'still on the map they came back to');
});

// ---------------------------------------------------------------------------
// Account mode: the real Reclaim City modules (from the vendored checkout), a
// stub frame that answers the selectors the controller uses.
// ---------------------------------------------------------------------------
const { loadRcFromDisk } = require('./rc-from-disk.js');
const FC = 'device_security-fortify-computer';
const RC_KEY = 'reclaim-city-state';
const SCAN_KEY = 'device-rescue.game.scan-confirmed.v1';
const okMod = (name, findings = []) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const macBase = [okMod('launch_agents_audit', [finding('Unsigned helper')])];
// Positive evidence for every Mac step of Harden Your Computer.
const allMac = { schema_version: 1, platform: 'darwin', modules: [...macBase,
  okMod('encryption_check'),
  okMod('filevault_recovery', [{ title: 'FV', severity: 'info', category: 'security', data: { check: 'fv_status' } }]),
  okMod('screen_lock_check', [{ title: 'SL', severity: 'info', category: 'security', data: { check: 'screen_lock_required', value: 'enabled' } }]),
  okMod('lock_screen_check'),
  okMod('find_my_mac_check', [{ title: 'FM', severity: 'info', category: 'security', code: 'security.find_my_mac_check.configured_ok', data: {} }]),
] };
const brokenMac = { ...allMac, modules: allMac.modules.map((m) => (m.name === 'encryption_check'
  ? okMod('encryption_check', [{ title: 'FileVault is off', description: 'd', severity: 'warning', category: 'security', data: {} }]) : m)) };
const PAYMENT = /buy\.stripe|patreon|ko-fi|SUPPORT \$|donate/i;

function rcStub({ allowed = [] } = {}) {
  const listeners = { click: [], keydown: [] };
  const calls = { opened: [], scrolled: 0, removed: 0, showList: 0 };
  const form = {};
  const inputs = {};
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    contains: () => true,
    querySelector: (sel) => {
      if (sel === '[data-focus]') return frame.innerHTML.includes('data-focus') ? { scrollIntoView: () => { calls.scrolled += 1; } } : null;
      if (sel in inputs) return { value: inputs[sel] };
      return null;
    },
    querySelectorAll: (sel) => {
      const m = /^input\[name="q_([^"]+)"\]:checked$/.exec(sel);
      if (m) return [].concat(form[m[1]] || []).map((value) => ({ value }));
      // remove() really takes the element's markup out, like the DOM would.
      const cut = (re) => [...frame.innerHTML.matchAll(re)].map(([html]) => ({
        html, remove: () => { frame.innerHTML = frame.innerHTML.replace(html, ''); calls.removed += 1; },
      }));
      if (sel.includes('share-card')) {
        return [...cut(/<button[^>]*data-action="share-card"[^>]*>[\s\S]*?<\/button>/g), ...cut(/<div id="milestone-card-preview"[\s\S]*?<\/div>/g)];
      }
      if (sel === '.section-label') {
        // The allies block is the label's parent: <div …><div class="section-label">…</div> … links … </div>
        const sections = cut(/<div[^>]*>\s*<div class="section-label"[^>]*>[^<]*<\/div>[\s\S]*?<\/a>\s*<\/div>/g);
        return [...frame.innerHTML.matchAll(/<div class="section-label"[^>]*>([^<]*)<\/div>/g)].map(([html, text]) => ({
          textContent: text, parentElement: sections.find((x) => x.html.includes(html)) || { remove: () => { throw new Error(`no stub parent for ${text}`); } },
        }));
      }
      if (sel === 'a[target="_blank"]:not([data-action])') {
        return cut(/<a [^>]*target="_blank"[^>]*>[\s\S]*?<\/a>/g).filter((x) => !/^<a [^>]*data-action=/.test(x.html));
      }
      return [];
    },
  };
  const shadow = { getElementById: () => frame, addEventListener: () => {} };
  const win = {
    location: { hash: '#/start' },
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { showList() { calls.showList += 1; }, docChanged: () => true, wantsSafety: () => false },
    rescue: {
      recheckModule: async () => ({ ok: false }),
      openMissionLink: async (url) => { calls.opened.push(url); return allowed.includes(url); },
    },
  };
  const el = (attrs, tag = 'BUTTON') => {
    const dataset = {};
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('data-')) dataset[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
    }
    const node = { tagName: tag, dataset, getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    node.closest = (sel) => {
      if (sel === '[data-go],[data-act]') return 'data-go' in attrs || 'data-act' in attrs ? node : null;
      if (sel === '[data-action]') return 'data-action' in attrs ? node : null;
      if (sel === 'a[href]') return tag === 'A' && 'href' in attrs ? node : null;
      return null;
    };
    return node;
  };
  const click = (attrs, tag) => {
    const target = el(attrs, tag);
    listeners.click.forEach((fn) => fn({ target, preventDefault() {} }));
  };
  return { win, frame, form, inputs, calls, click };
}

async function rcSetup({ doc = scan(...macBase), situation = { id: 'hacked' }, storage = memStore(), allowed } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const rc = await loadRcFromDisk();
  const stub = rcStub({ allowed });
  const ctl = createController({ win: stub.win, storage, scoutSprite: () => '', loadGame: async () => rc });
  await tick();
  ctl.show(doc, situation);
  return { ...stub, ctl, rc, storage, html: () => stub.frame.innerHTML };
}
const hudCount = (html, label) => Number((new RegExp(`<b>(\\d+)</b> <small>${label}</small>`).exec(html) || [])[1]);

test('one map: the computer’s districts, then the accounts’, scrolled to the starting point', async () => {
  const t = await rcSetup();
  const html = t.html();
  assert.match(html, /RECLAIM CITY/);
  assert.match(html, /YOUR COMPUTER · FROM THE CHECKUP[\s\S]*YOUR ACCOUNTS/);
  assert.match(html, /data-go="rc:#\/district\/master-keys" data-focus/);
  assert.strictEqual(t.calls.scrolled, 1);
  assert.strictEqual(hudCount(html, 'CONFIRMED'), 0);
  assert.strictEqual(hudCount(html, 'YOU REPORTED'), 0);
  assert.doesNotMatch(html, /<small>RECLAIMED<\/small>/);
  assert.doesNotMatch(html, PAYMENT);
});

test('if the game can’t load, the computer’s districts still work', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const stub = rcStub();
  const errors = [];
  const orig = console.error; console.error = (...a) => errors.push(a.join(' '));
  try {
    const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => Promise.reject(new Error('nope')) });
    ctl.show(scan(...macBase), { id: 'hacked' });
    await tick();
  } finally { console.error = orig; }
  assert.match(stub.frame.innerHTML, /couldn’t load\. Your computer’s districts still work/);
  assert.match(stub.frame.innerHTML, /data-go="filter:/, 'the deck’s city filters the queue');
  assert.strictEqual(errors.length, 1);
});

test('blocked storage: the map still renders from the scan, with the game starting empty', async () => {
  const throwing = { getItem: () => { throw new Error('denied'); }, setItem: () => { throw new Error('denied'); } };
  // The game's own loadState/saveState log the storage error to the console.
  const logged = [];
  const orig = console.error; console.error = (e) => logged.push(String(e && e.message));
  try {
    const t = await rcSetup({ storage: throwing });
    assert.match(t.html(), /YOUR ACCOUNTS/);
    assert.match(t.html(), /data-go="filter:/);
    t.click({ 'data-go': 'rc:#/district/master-keys' });
    assert.match(t.html(), /data-action="toggle-account"/);
    t.click({ 'data-action': 'toggle-account', 'data-account': 'gmail' });
    assert.match(t.html(), /data-action="toggle-account"/, 'a failed save doesn’t break the screen');
  } finally { console.error = orig; }
  assert.ok(logged.length && logged.every((m) => m === 'denied'), logged.join());
});

test('game routes the plan doesn’t include, and unknown ids, land on the one-city map', async () => {
  const t = await rcSetup();
  for (const hash of ['#/district/nope', '#/mission/nope/briefing', '#/mission/nope/debrief', '#/milestone/nope',
    '#/quiz/phishing', '#/garage', '#/stats', '#/city']) {
    t.click({ 'data-go': 'rc:#/district/master-keys' });
    assert.doesNotMatch(t.html(), /aria-label="Your computer and your accounts as one city"/);
    t.click({ href: hash }, 'A');
    assert.match(t.html(), /aria-label="Your computer and your accounts as one city"/, hash);
  }
  assert.strictEqual(t.win.location.hash, '#/start', 'the page’s real hash is never changed');
});

test('the survey toggle changes the game state', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': 'rc:#/district/master-keys' });
  const before = t.rc.loadState(t.storage).accounts.gmail.enabled;
  t.click({ 'data-action': 'toggle-account', 'data-account': 'gmail' });
  assert.strictEqual(t.rc.loadState(t.storage).accounts.gmail.enabled, !before);
});

test('GO DO IT opens the page through the allowlist and moves to the debrief; a refused link is shown to copy', async () => {
  const url = 'https://haveibeenpwned.com';
  const t = await rcSetup({ allowed: [url] });
  t.click({ 'data-go': 'rc:#/mission/gmail-recon-breach/briefing' });
  t.click({ 'data-action': 'go-do-it', 'data-mission': 'gmail-recon-breach', 'data-url': url });
  await tick();
  assert.deepStrictEqual(t.calls.opened, [url]);
  assert.match(t.html(), /data-debrief="gmail-recon-breach"/);
  assert.doesNotMatch(t.html(), /link-notice/);

  t.click({ href: 'https://evil.example/haveibeenpwned.com' }, 'A');
  await tick();
  assert.match(t.html(), /can’t be opened from here[\s\S]*<code>https:\/\/evil\.example\/haveibeenpwned\.com<\/code>/);
});

test('a step link that isn’t https opens nothing and shows the URL to copy', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': 'rc:#/mission/browser_fingerprint-fortify-harden/briefing' });
  t.click({ 'data-action': 'mission-step', 'data-mission': 'browser_fingerprint-fortify-harden', href: 'about:preferences#privacy' }, 'A');
  await tick();
  assert.deepStrictEqual(t.calls.opened, []);
  assert.match(t.html(), /can’t be opened from here[\s\S]*<code>about:preferences#privacy<\/code>/);
});

test('SUBMIT REPORT files the answer, lands on the district, and YOU REPORTED goes up', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': `rc:#/mission/${FC}/debrief` });
  const page = t.html();
  t.click({ 'data-action': 'submit-debrief', 'data-mission': FC });
  assert.strictEqual(t.html(), page, 'an unanswered form is left as it was');
  assert.strictEqual(t.storage.getItem(RC_KEY), null, 'nothing filed');

  t.form.action = 'completed';
  t.click({ 'data-action': 'submit-debrief', 'data-mission': FC });
  assert.strictEqual(t.rc.loadState(t.storage).missions[FC].status, 'completed');
  assert.match(t.html(), /data-action="toggle-account"|perimeter/i);
  assert.strictEqual(hudCount(t.html(), 'YOU REPORTED'), 1);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 0);
});

test('the first-2FA hug is marked seen, so it doesn’t replay', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': 'rc:#/mission/gmail-fortify-2fa/debrief' });
  t.form.method = 'authenticator';
  t.click({ 'data-action': 'submit-debrief', 'data-mission': 'gmail-fortify-2fa' });
  const hug = t.rc.loadState(t.storage).scoutHugs.twoFactor;
  assert.deepStrictEqual(hug, { mission: 'gmail-fortify-2fa', seen: true });
});

test('FINISH FROM THE CHECKUP shows only when every step is confirmed, and counts as CONFIRMED', async () => {
  const broken = await rcSetup({ doc: brokenMac });
  broken.click({ 'data-go': `rc:#/mission/${FC}/briefing` });
  assert.doesNotMatch(broken.html(), /confirm-from-scan/);
  broken.click({ 'data-act': 'confirm-from-scan' });
  assert.strictEqual(broken.storage.getItem(RC_KEY), null, 'a forged click changes nothing');
  assert.strictEqual(broken.storage.getItem(SCAN_KEY), null);

  const t = await rcSetup({ doc: allMac });
  t.click({ 'data-go': `rc:#/mission/${FC}/briefing` });
  assert.match(t.html(), /data-act="confirm-from-scan"/);
  t.click({ 'data-act': 'confirm-from-scan' });
  assert.strictEqual(t.rc.loadState(t.storage).missions[FC].status, 'completed');
  assert.ok(JSON.parse(t.storage.getItem(SCAN_KEY)).missions[FC]);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 1);
  assert.strictEqual(hudCount(t.html(), 'YOU REPORTED'), 0);

  // Without the scan's record it's the person's report, not the computer's.
  const again = await rcSetup({ doc: allMac, storage: (() => { const st = memStore(); st.setItem(RC_KEY, t.storage.getItem(RC_KEY)); return st; })() });
  assert.strictEqual(hudCount(again.html(), 'CONFIRMED'), 0);
  assert.strictEqual(hudCount(again.html(), 'YOU REPORTED'), 1);
});

test('SUBMIT REPORT is logged as YOU REPORTED and pays the smaller amount, once', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': `rc:#/mission/${FC}/debrief` });
  t.form.action = 'completed';
  t.click({ 'data-action': 'submit-debrief', 'data-mission': FC });
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 20);
  t.click({ href: '#/city' }, 'A');
  assert.match(t.html(), /YOU REPORTED<\/span> [^<]+/);
  assert.strictEqual(hudCount(t.html(), 'YOU REPORTED'), 1);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 0);
});

test('FINISH FROM THE CHECKUP is logged as CONFIRMED and pays the fix amount', async () => {
  const t = await rcSetup({ doc: allMac });
  t.click({ 'data-go': `rc:#/mission/${FC}/briefing` });
  t.click({ 'data-act': 'confirm-from-scan' });
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 50);
  t.click({ href: '#/city' }, 'A');
  assert.match(t.html(), /CONFIRMED<\/span> [^<]+/);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 1);
});

test('the person filed Done and the scan disagrees: both show, and the game state is unchanged', async () => {
  const storage = memStore();
  const rc = await loadRcFromDisk();
  const filed = rc.fileDebrief(rc.createInitialState(), rc.MISSIONS.find((m) => m.id === FC), { action: 'completed' });
  rc.saveState(filed.state, storage);
  const saved = storage.getItem(RC_KEY);
  const t = await rcSetup({ doc: brokenMac, storage });
  assert.match(t.html(), /CHECK AGAIN/);
  t.click({ 'data-go': `rc:#/mission/${FC}/briefing` });
  assert.match(t.html(), /You reported this done[\s\S]*FileVault is off[\s\S]*Your answer is kept/);
  assert.match(t.html(), /PROBLEM FOUND/);
  assert.doesNotMatch(t.html(), /confirm-from-scan/);
  t.click({ href: '#/district/perimeter' }, 'A');
  t.click({ href: '#/city' }, 'A');
  assert.strictEqual(storage.getItem(RC_KEY), saved, 'byte-for-byte the same');
  assert.strictEqual(hudCount(t.html(), 'YOU REPORTED'), 1);
});

test('the set-password-manager chip accepts only the game’s own choices', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': 'rc:#/district/master-keys' });
  t.click({ 'data-action': 'set-password-manager', 'data-pm': 'not-a-manager' });
  assert.strictEqual(t.storage.getItem(RC_KEY), null);
  t.click({ 'data-action': 'set-password-manager', 'data-pm': 'bitwarden' });
  assert.strictEqual(t.rc.loadState(t.storage).passwordManager, 'bitwarden');
});

test('a milestone never carries a share card', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': 'rc:#/milestone/perimeter' });
  assert.match(t.html(), /CONFIRMED BY YOUR COMPUTER[\s\S]*YOU REPORTED/);
  assert.ok(t.calls.removed > 0, 'the vendored milestone has a share card, and it was taken out');
  assert.doesNotMatch(t.html(), /data-action="share-card"|milestone-card-preview/);
  t.click({ 'data-action': 'share-card', 'data-district': 'perimeter' });
  assert.strictEqual(t.storage.getItem(RC_KEY), null, 'share-card does nothing');
  assert.doesNotMatch(t.html(), PAYMENT);
});

test('a district at 100% shows no allied organizations and no donation links', async () => {
  const rc = await loadRcFromDisk();
  for (const id of ['perimeter', 'reclamation', 'vault']) { // two facility districts and an account district
    const storage = memStore();
    const state = rc.createInitialState();
    for (const m of rc.MISSIONS.filter((x) => rc.missionDistrict(x) === id)) {
      state.missions[m.id] = { status: 'completed', action: 'completed', completedAt: '2026-10-09T10:00:00Z' };
    }
    assert.strictEqual(rc.calcDistrictProgress(state, id).percent, 100, `${id} is at 100%`);
    assert.match(rc.renderDistrict(state, id), /ALLIED ORGANIZATIONS/, 'the vendored screen does render the allies here');
    rc.saveState(state, storage);
    const t = await rcSetup({ storage });
    for (const tab of ['', '?tab=reclaim']) {
      t.click({ href: `#/district/${id}${tab}` }, 'A');
      assert.match(t.html(), new RegExp(`data-district="${id}"|${id}`, 'i'));
      assert.doesNotMatch(t.html(), /ALLIED ORGANIZATIONS/, `${id}${tab}`);
      assert.doesNotMatch(t.html(), PAYMENT, `${id}${tab}`);
      assert.doesNotMatch(t.html(), /signal\.org\/donate|\/donate\b/i, `${id}${tab}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Training mode (Plan C): the Training Grounds, lessons, and the scan as the
// final boss. The real lesson files, loaded the way the controller loads them.
// ---------------------------------------------------------------------------
const pathT = require('path');
const { pathToFileURL } = require('url');
const GAME_DIR = pathT.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = pathT.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importLesson = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : pathT.join(GAME_DIR, spec)).href);
const WIFI = { id: 'wifi', title: 'Someone is on my Wi-Fi, or my computer is hot and slow' };
const prog = (phase, index, total, category = 'security', findings = 0) => ({ type: 'progress', phase, index, total, module: 'm', category, findings });

async function trainingSetup({ storage = memStore(), situation = WIFI } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const { loadLessons } = await import('../renderer/game/training.js');
  const lessons = await loadLessons(importLesson);
  const stub = stubWin([]);
  const host = { startCheckup: 0, leaveGame: 0, tips: [{ title: 'Allow <b>access</b>', body: 'A pop-up may ask.' }] };
  Object.assign(stub.win.RescueHost, {
    startCheckup() { host.startCheckup += 1; },
    leaveGame() { host.leaveGame += 1; },
    scanTips: async () => host.tips,
  });
  const ctl = createController({ win: stub.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons });
  await tick();
  ctl.showTraining(situation);
  return { ...stub, ctl, host, storage, lessons, html: () => stub.frame.innerHTML, lesson: (id) => lessons.find((l) => l.id === id) };
}
const correctIndex = (q) => q.options.findIndex((o) => o.correct);
const wrongIndex = (q) => q.options.findIndex((o) => !o.correct);
function finishLesson(t, id) {
  t.click({ 'data-go': `lesson:${id}` });
  t.lesson(id).questions.forEach((q, n, all) => {
    t.click({ 'data-act': `answer:${correctIndex(q)}` });
    t.click({ 'data-act': n === all.length - 1 ? 'finish-lesson' : 'next-question' });
  });
}

test('a worry opens the Training Grounds: password-asker first, the scan one click away, no city HUD', async () => {
  const t = await trainingSetup();
  const html = t.html();
  assert.match(html, /THE TRAINING GROUNDS/);
  assert.doesNotMatch(html, /YOUR COMPUTER|RECLAIM CITY/, 'no city HUD before there is a city');
  const order = [...html.matchAll(/data-go="lesson:([^"]+)"/g)].map((m) => m[1]);
  assert.deepStrictEqual(order.slice(0, 2), ['password-asker', 'whos-on-wifi']);
  assert.match(html, /data-act="start-checkup"[^>]*>SKIP TO THE CHECKUP ▶/);
  assert.match(html, new RegExp(`<b>0/${t.lessons.length}</b> <small>LESSONS`));
});

test('a wrong answer gets feedback; leaving part-way records nothing; finishing marks DONE', async () => {
  const t = await trainingSetup();
  const q0 = t.lesson('whos-on-wifi').questions[0];
  t.click({ 'data-go': 'lesson:whos-on-wifi' });
  t.click({ 'data-act': `answer:${wrongIndex(q0)}` });
  assert.match(t.html(), /class="opt wrong"/);
  assert.match(t.html(), /NEXT QUESTION|FINISH LESSON/);
  t.click({ 'data-act': `answer:${correctIndex(q0)}` });
  assert.match(t.html(), /class="opt wrong"/, 'the first pick stands');
  t.click({ 'data-go': 'training' });
  assert.doesNotMatch(t.html(), /DONE/);
  assert.doesNotMatch(String(t.storage.getItem('device-rescue.game.v1') || ''), /whos-on-wifi/);

  finishLesson(t, 'password-asker');
  assert.match(t.html(), /THE TRAINING GROUNDS/);
  assert.match(t.html(), /data-go="lesson:password-asker"[\s\S]*?DONE/);
  assert.match(t.html(), new RegExp(`<b>1/${t.lessons.length}</b> <small>LESSONS`));
  const saved = JSON.parse(t.storage.getItem('device-rescue.game.v1'));
  assert.ok(saved.lessons['password-asker'].completedAt);
  assert.deepStrictEqual(saved.missions, {}, 'a lesson never counts as a fix');
});

test('the checkup as the boss: one start, the meter and the skip bar agree, tips show', async () => {
  const t = await trainingSetup();
  t.click({ 'data-act': 'start-checkup' });
  assert.strictEqual(t.host.startCheckup, 1);
  t.ctl.showBoss();
  t.click({ 'data-act': 'start-checkup' });
  assert.strictEqual(t.host.startCheckup, 1, 'no second scan while one runs');
  await tick(); await tick();
  assert.match(t.html(), /THE SWEEP/);
  assert.match(t.html(), /POP-UPS YOU MIGHT SEE[\s\S]*Allow &lt;b&gt;access&lt;\/b&gt;/);
  t.ctl.scanEvent(prog('start', 1, 4));
  t.ctl.scanEvent(prog('done', 1, 4, 'security', 2));
  t.ctl.scanEvent(prog('start', 2, 4, 'network'));
  assert.match(t.html(), /1 \/ 4 CHECKS/);
  assert.match(t.html(), /SWEEPING/);
  assert.doesNotMatch(t.html(), /\bsafe\b|\bclear\b/i);
  t.click({ 'data-go': 'training' });
  assert.match(t.html(), /running: 1 of 4 checks/);
  assert.match(t.html(), /data-go="boss"/);
  assert.doesNotMatch(t.html(), /data-act="start-checkup"/);
  t.click({ 'data-go': 'boss' });
  assert.match(t.html(), /THE SWEEP/);
});

test('the scan finishes mid-lesson: still in the lesson, the pick kept, the city one click away', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  t.click({ 'data-go': 'training' });
  const q0 = t.lesson('whos-on-wifi').questions[0];
  t.click({ 'data-go': 'lesson:whos-on-wifi' });
  t.click({ 'data-act': `answer:${wrongIndex(q0)}` });
  t.ctl.scanDone(scan(mod('mod_a', [finding('A')])), WIFI);
  assert.match(t.html(), /Your checkup is done\./);
  assert.match(t.html(), /class="opt wrong"/, 'the picked answer is still shown');
  assert.match(t.html(), /QUESTION 1 OF/);
  t.ctl.scanEvent(prog('done', 9, 9));
  assert.match(t.html(), /QUESTION 1 OF/, 'a late event changes nothing');
  t.click({ 'data-go': 'city' });
  assert.match(t.html(), /aria-label="Your computer as a city"/);
  assert.match(t.html(), /YOUR COMPUTER/);
});

test('the scan finishes on the boss screen: straight to the city', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('mod_a', [finding('A')])), WIFI);
  assert.match(t.html(), /aria-label="Your computer as a city"/);
  // Back to the Training Grounds from the city's HUD: the city is still one click away.
  t.click({ 'data-go': 'training' });
  assert.match(t.html(), /Your checkup is done\.[\s\S]*data-go="city"/);
  assert.match(t.html(), /data-act="start-checkup"[^>]*>RUN THE CHECKUP AGAIN ▶/);
  // A new worry: no city yet, so back to skipping.
  t.ctl.showTraining(WIFI);
  assert.match(t.html(), /SKIP TO THE CHECKUP ▶/);
});

test('the lessons couldn’t load only once loading has finished', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const stub = stubWin([]);
  let finish;
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: () => new Promise((r) => { finish = r; }) });
  ctl.showTraining(WIFI);
  assert.doesNotMatch(stub.frame.innerHTML, /couldn’t load/);
  assert.match(stub.frame.innerHTML, /Getting the lessons ready/);
  finish([]);
  await tick();
  assert.match(stub.frame.innerHTML, /The lessons couldn’t load/);
});

test('the scan fails on the boss screen: back to the Training Grounds, never a frozen boss', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  t.ctl.scanEvent(prog('start', 1, 4));
  t.ctl.scanFailed('engine exited <b>1</b>');
  const html = t.html();
  assert.match(html, /THE TRAINING GROUNDS/);
  assert.match(html, /THE CHECKUP STOPPED[\s\S]*engine exited &lt;b&gt;1&lt;\/b&gt;/);
  assert.match(html, /data-act="start-checkup"[^>]*>START THE CHECKUP ▶/);
  assert.doesNotMatch(html, /Your checkup is done/);
  t.click({ 'data-go': 'boss' });
  assert.doesNotMatch(t.html(), /THE SWEEP/, 'no way back to a boss that isn’t running');
  t.click({ 'data-act': 'start-checkup' });
  assert.strictEqual(t.host.startCheckup, 1);
});

test('PLAIN VIEW hands back to Device Rescue from the training, lesson and boss screens', async () => {
  const t = await trainingSetup();
  t.click({ 'data-act': 'leave' });
  t.click({ 'data-go': 'lesson:password-asker' });
  t.click({ 'data-act': 'leave' });
  t.ctl.showBoss();
  t.click({ 'data-act': 'leave' });
  assert.strictEqual(t.host.leaveGame, 3);
});

test('after leaving the boss mid-scan, a city shown from the list isn’t stuck on a running scan', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  t.ctl.show(scan(mod('mod_a', [finding('A')])), WIFI);
  t.click({ 'data-go': 'training' });
  assert.doesNotMatch(t.html(), /data-go="boss"/);
  assert.match(t.html(), /data-act="start-checkup"/);
});

test('a briefing links the lesson the person finished for that check', async () => {
  const t = await trainingSetup({ situation: { id: 'unsure', title: 'Not sure' } });
  const doc = scan(mod('launch_agent_audit', [finding('Unsigned helper')]));
  t.ctl.showBoss();
  t.ctl.scanDone(doc, { id: 'unsure' });
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = findingsToCity(doc).districts[0].missions[0].id;
  t.click({ 'data-go': `mission:${id}` });
  assert.doesNotMatch(t.html(), /You learned about this/);
  t.click({ 'data-go': 'training' });
  finishLesson(t, 'starts-on-its-own');
  t.click({ 'data-go': 'city' });
  t.click({ 'data-go': `mission:${id}` });
  assert.match(t.html(), /data-go="lesson:starts-on-its-own"[^>]*>You learned about this in the Training Grounds/);
});

test('when a screen fails to render, the controller hands back to the list and says so', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const stub = stubWin([]);
  let leave = 0;
  stub.win.RescueHost.leaveGame = () => { leave += 1; };
  stub.win.RescueHost.scanTips = async () => [];
  let broken = true;
  const ctl = createController({ win: stub.win, storage: memStore(), loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], scoutSprite: () => { if (broken) throw new Error('sprite broke'); return ''; } });
  await tick();
  const orig = console.error; console.error = () => {};
  try {
    assert.strictEqual(ctl.showTraining(WIFI), false);
    assert.strictEqual(ctl.scanFailed('x'), false);
    const doc = scan(mod('mod_a', [finding('A')]));
    assert.strictEqual(ctl.scanDone(doc, WIFI), false);
    assert.strictEqual(ctl.show(doc, WIFI), false);
    assert.strictEqual(leave, 4, 'each failure goes back to Device Rescue’s own screens');
    assert.match(stub.frame.innerHTML, /same thing as a list/);
  } finally { console.error = orig; }
  broken = false;
  assert.strictEqual(ctl.showTraining(WIFI), true);
  assert.strictEqual(ctl.show(scan(mod('mod_a', [finding('A')])), WIFI), true);
  assert.strictEqual(leave, 4);
});

test('a progress event on the boss screen keeps keyboard focus where it was', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  await tick(); await tick();
  t.focusOn({ 'data-go': 'training' });
  t.ctl.scanEvent(prog('start', 1, 4));
  assert.deepStrictEqual(t.focused, ['[data-go="training"]'], 'ALL LESSONS keeps focus');
  t.focusOn({ 'data-act': 'leave' });
  t.ctl.scanEvent(prog('done', 1, 4));
  assert.deepStrictEqual(t.focused.slice(1), ['[data-act="leave"]']);
  // Nothing focused: nothing to put back.
  t.focusOn(null);
  t.ctl.scanEvent(prog('start', 2, 4));
  assert.strictEqual(t.focused.length, 2);
});

test('focus isn’t carried to a different screen', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  t.focusOn({ 'data-go': 'training' });
  t.click({ 'data-go': 'training' });
  assert.match(t.html(), /THE TRAINING GROUNDS/);
  assert.deepStrictEqual(t.focused, []);
});

test('the boss screen’s pop-up tips stay closed once the person closes them', async () => {
  const t = await trainingSetup();
  t.ctl.showBoss();
  await tick(); await tick();
  assert.match(t.html(), /<details class="panel" open>/);
  // The summary's own click toggles the <details>; the controller only remembers it.
  t.click({ 'data-act': 'toggle-tips' });
  t.ctl.scanEvent(prog('start', 1, 4));
  assert.match(t.html(), /<details class="panel">[\s\S]*POP-UPS YOU MIGHT SEE/, 'closed stays closed after a redraw');
  t.click({ 'data-act': 'toggle-tips' });
  t.ctl.scanEvent(prog('done', 1, 4));
  assert.match(t.html(), /<details class="panel" open>/);
});

// The new flow: a worry starts its scan at once; the sweep's districts open the lessons.
async function sweepSetup(opts) {
  const t = await trainingSetup(opts);
  t.ctl.newWorry(opts && opts.situation || WIFI);
  t.ctl.showBoss();
  await tick(); await tick();
  return t;
}

test('the sweep: districts with a lesson are buttons with a cue; the one being checked is suggested', async () => {
  const t = await sweepSetup();
  let html = t.html();
  assert.match(html, /<button[^>]*data-go="learn:gatehouse"[^>]*aria-label="Learn about The Gatehouse"/);
  assert.match(html, /data-go="learn:wires"/);
  assert.match(html, /data-go="learn:foundations"/);
  assert.doesNotMatch(html, /data-go="learn:(engine-room|junkyard|outskirts)"/, 'no lesson teaches these');
  assert.match(html, /<div class="district waiting"><h4>THE ENGINE ROOM/);
  assert.match(html, /LEARN ▶/);
  assert.match(html, /data-go="training"[^>]*>ALL LESSONS/);
  assert.match(html, /POP-UPS YOU MIGHT SEE/, 'the pop-up tips still show as soon as the scan starts');
  assert.doesNotMatch(html, /Scanning now/);
  t.ctl.scanEvent(prog('start', 1, 4, 'network'));
  html = t.html();
  assert.match(html, /class="district learnable sweeping suggested"[^>]*data-go="learn:wires"[\s\S]*?Scanning now — learn about it/);
  assert.strictEqual((html.match(/Scanning now/g) || []).length, 1);
});

test('clicking a district opens its lesson; finishing it mid-scan goes back to the sweep, marked DONE ✓', async () => {
  const t = await sweepSetup();
  t.click({ 'data-go': 'learn:wires' });
  assert.match(t.html(), /Who’s on your Wi-Fi/);
  assert.match(t.html(), /data-go="boss"[^>]*>BACK TO THE CHECKUP ▶/);
  t.lesson('whos-on-wifi').questions.forEach((q, n, all) => {
    t.click({ 'data-act': `answer:${correctIndex(q)}` });
    t.click({ 'data-act': n === all.length - 1 ? 'finish-lesson' : 'next-question' });
  });
  assert.match(t.html(), /THE SWEEP/);
  assert.match(t.html(), /<h4>THE WIRES[\s\S]*?DONE ✓[\s\S]*?data-go="review:wires"/);
  assert.doesNotMatch(t.html(), /data-go="learn:wires"/, 'a DONE district is no longer a lesson button');
  // The Gatehouse has several lessons, in this worry's order: the next unfinished one each time.
  t.click({ 'data-go': 'learn:gatehouse' });
  assert.match(t.html(), /The tool that asks for your password/);
  t.click({ 'data-go': 'learn:engine-room' });
  assert.match(t.html(), /The tool that asks for your password/, 'a district with no lesson does nothing');
});

test('the scan finishes while in a lesson opened from the sweep: stay there, pick kept, the city banner', async () => {
  const t = await sweepSetup();
  t.click({ 'data-go': 'learn:wires' });
  const q0 = t.lesson('whos-on-wifi').questions[0];
  t.click({ 'data-act': `answer:${wrongIndex(q0)}` });
  t.ctl.scanDone(scan(mod('mod_a', [finding('A')])), WIFI);
  assert.match(t.html(), /QUESTION 1 OF/);
  assert.match(t.html(), /class="opt wrong"/);
  assert.match(t.html(), /Your checkup is done\.[\s\S]*SEE YOUR CITY ▶/);
  t.click({ 'data-go': 'city' });
  assert.match(t.html(), /aria-label="Your computer as a city"/);
});

test('a progress redraw keeps focus on the district button the person is on', async () => {
  const t = await sweepSetup();
  t.focusOn({ 'data-go': 'learn:gatehouse' });
  t.ctl.scanEvent(prog('start', 1, 4, 'security'));
  t.ctl.scanEvent(prog('done', 1, 4, 'security'));
  assert.deepStrictEqual(t.focused, ['[data-go="learn:gatehouse"]', '[data-go="learn:gatehouse"]']);
});

test('lessons that arrive after the sweep is drawn make its districts clickable', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const { loadLessons } = await import('../renderer/game/training.js');
  const lessons = await loadLessons(importLesson);
  const stub = stubWin([]);
  stub.win.RescueHost.scanTips = async () => [];
  let finish;
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: () => new Promise((r) => { finish = r; }) });
  ctl.newWorry(WIFI);
  ctl.showBoss();
  assert.doesNotMatch(stub.frame.innerHTML, /data-go="learn:/);
  finish(lessons);
  await tick();
  assert.match(stub.frame.innerHTML, /data-go="learn:wires"/);
});

test('a lesson’s OPEN IN SYSTEM SETTINGS opens that pane through window.rescue, on a Mac only', async () => {
  const t = await trainingSetup();
  const opened = [];
  t.win.SettingPanes = require('../renderer/setting-panes.js');
  t.win.rescue.openSetting = async (url) => { opened.push(url); return true; };
  t.win.rescue.platform = 'win32';
  t.click({ 'data-go': 'lesson:locked-door' });
  assert.doesNotMatch(t.html(), /open-setting/, 'no button before a scan on Windows');
  t.win.rescue.platform = 'darwin';
  t.click({ 'data-go': 'lesson:locked-door' });
  assert.match(t.html(), /data-act="open-setting:softwareUpdate"/, 'preload’s platform is enough before any scan');
  t.click({ 'data-act': 'open-setting:softwareUpdate' });
  t.click({ 'data-act': 'open-setting:notAPane' });
  await tick();
  assert.deepStrictEqual(opened, ['x-apple.systempreferences:com.apple.Software-Update-Settings.extension']);
  assert.match(t.html(), /data-act="open-setting:softwareUpdate"/, 'opening a page leaves the lesson as it was');
});

// The tester: "It keeps taking me back to the lessons even when I have done them before."
const HACKED = { id: 'hacked', title: 'I think I’ve been hacked' };
const answerAll = (t, id, { finish = true } = {}) => t.lesson(id).questions.forEach((q, n, all) => {
  t.click({ 'data-act': `answer:${correctIndex(q)}` });
  if (n < all.length - 1) t.click({ 'data-act': 'next-question' });
  else if (finish) t.click({ 'data-act': 'finish-lesson' });
});
const GATEHOUSE = ['password-asker', 'starts-on-its-own', 'browser-add-ons', 'locked-door', 'poisoned-packages', 'taking-accounts-back'];

test('a DONE ✓ district mid-scan opens no quiz; the review is a separate, optional button', async () => {
  const storage = memStore();
  let t = await sweepSetup({ storage, situation: HACKED });
  // The Gatehouse's lessons, each opened from its card ("the next unfinished one").
  for (let i = 0; i < GATEHOUSE.length; i += 1) {
    t.click({ 'data-go': 'learn:gatehouse' });
    const open = t.lessons.find((l) => GATEHOUSE.includes(l.id) && t.html().includes(l.title.replace(/[<>&"]/g, '')));
    answerAll(t, open.id);
  }
  // An app restart, the same storage, the same worry: the sweep is running again.
  t = await sweepSetup({ storage, situation: HACKED });
  t.ctl.scanEvent(prog('done', 1, 4, 'security'));
  const html = t.html();
  assert.match(html, /class="district learned[^"]*"><h4>THE GATEHOUSE[\s\S]*?DONE ✓/);
  assert.doesNotMatch(html, /data-go="learn:gatehouse"/, 'the DONE card is not a lesson button');
  assert.match(html, /data-go="review:gatehouse"[^>]*>REVIEW ONE\? \(OPTIONAL\)/);
  assert.match(html, /data-go="review:gatehouse" aria-label="Review one\? \(optional\): a lesson about/i, 'the accessible name starts with the visible words');
  t.click({ 'data-go': 'learn:gatehouse' }); // a stale click
  assert.match(t.html(), /THE SWEEP/);
  assert.doesNotMatch(t.html(), /QUESTION \d+ OF/, 'no quiz');
  t.click({ 'data-go': 'review:gatehouse' });
  assert.match(t.html(), /QUESTION 1 OF/, 'reviewing is still possible, when asked for');
  t.click({ 'data-go': 'boss' });
  assert.match(t.html(), /THE SWEEP/);
});

test('REVIEW rotates through a district’s done lessons, least recently reviewed first, in memory only', async () => {
  const storage = memStore();
  let t = await sweepSetup({ storage, situation: HACKED });
  for (let i = 0; i < GATEHOUSE.length; i += 1) {
    t.click({ 'data-go': 'learn:gatehouse' });
    const open = t.lessons.find((l) => GATEHOUSE.includes(l.id) && t.html().includes(l.title.replace(/[<>&"]/g, '')));
    answerAll(t, open.id);
  }
  t = await sweepSetup({ storage, situation: HACKED });
  t.ctl.scanEvent(prog('done', 1, 4, 'security'));
  const before = storage.getItem('device-rescue.game.v1');
  const seen = [];
  for (let i = 0; i < GATEHOUSE.length + 1; i += 1) {
    t.click({ 'data-go': 'review:gatehouse' });
    const open = t.lessons.find((l) => GATEHOUSE.includes(l.id) && t.html().includes(l.title.replace(/[<>&"]/g, '')));
    seen.push(open.id);
    t.click({ 'data-go': 'boss' });
  }
  assert.strictEqual(new Set(seen.slice(0, GATEHOUSE.length)).size, GATEHOUSE.length, 'each lesson once before any repeats');
  assert.strictEqual(seen[GATEHOUSE.length], seen[0], 'then the least recently reviewed again');
  assert.strictEqual(storage.getItem('device-rescue.game.v1'), before, 'nothing saved');
});

test('answering every question counts as done, even when the person leaves before FINISH, and survives a restart', async () => {
  const storage = memStore();
  let t = await sweepSetup({ storage });
  t.click({ 'data-go': 'learn:wires' });
  answerAll(t, 'whos-on-wifi', { finish: false });
  t.click({ 'data-go': 'boss' }); // BACK TO THE CHECKUP, no FINISH
  assert.match(t.html(), /data-go="review:wires"/);
  assert.ok(JSON.parse(storage.getItem('device-rescue.game.v1')).lessons['whos-on-wifi'].completedAt);
  // The scan finishes mid-lesson; the person answers the last one and takes SEE YOUR CITY.
  t.click({ 'data-go': 'learn:gatehouse' });
  t.ctl.scanDone(scan(mod('mod_a', [finding('A')])), WIFI);
  answerAll(t, 'password-asker', { finish: false });
  t.click({ 'data-go': 'city' });
  t = await sweepSetup({ storage });
  assert.match(t.html(), /data-go="review:wires"/, 'remembered after a restart');
  const saved = JSON.parse(storage.getItem('device-rescue.game.v1'));
  assert.deepStrictEqual(Object.keys(saved.lessons).sort(), ['password-asker', 'whos-on-wifi']);
});

test('finishing a sweep lesson after the checkup is done goes to the city, not the Training Grounds', async () => {
  const t = await sweepSetup();
  t.click({ 'data-go': 'learn:gatehouse' });
  t.ctl.scanDone(scan(mod('mod_a', [finding('A')])), WIFI);
  answerAll(t, 'password-asker');
  assert.doesNotMatch(t.html(), /THE TRAINING GROUNDS/);
  assert.match(t.html(), /YOUR COMPUTER/);
  assert.doesNotMatch(t.html(), /Your checkup is done\./, 'the banner has done its job');
});

// "Open your router's settings" on a router mission: only the address goes to window.rescue.
async function routerSetup(extraMods = []) {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const net = (check, severity, data = {}) => ({ title: check, description: 'd', severity, category: 'network',
    code: `network.router_security_audit.${check}`, data: { check, gateway_ip: '192.168.0.1', ...data } });
  const doc = scan({ ...mod('router_security_audit', [net('upnp_enabled', 'warning'), net('router_manual_review', 'info')]), category: 'network' }, ...extraMods);
  const city = findingsToCity(doc);
  const m = city.districts.flatMap((d) => d.missions).find((x) => x.module === 'router_security_audit');
  const stub = stubWin([]);
  stub.win.RouterLink = require('../renderer/router-link.js');
  const opened = [];
  stub.win.rescue.openRouter = async (ip) => { opened.push(ip); return true; };
  stub.win.rescue.defaultBrowser = async () => 'Safari';
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}) });
  await tick();
  ctl.show(doc, { id: 'wifi' });
  stub.click({ 'data-go': `mission:${m.id}` });
  return { ...stub, opened, html: () => stub.frame.innerHTML };
}

test('a router mission offers OPEN YOUR ROUTER and sends only the address', async () => {
  const t = await routerSetup();
  assert.match(t.html(), /data-act="open-router"/);
  assert.match(t.html(), /in Safari/);
  t.click({ 'data-act': 'open-router' });
  await tick();
  assert.deepStrictEqual(t.opened, ['192.168.0.1']);
});

test('no router button when the ARP check says the router may be impersonated', async () => {
  const arp = { title: 'imp', description: 'd', severity: 'critical', category: 'network',
    code: 'network.arp_spoof_check.gateway_impersonation', data: { check: 'gateway_impersonation' } };
  const t = await routerSetup([{ ...mod('arp_spoof_check', [arp]), category: 'network' }]);
  assert.doesNotMatch(t.html(), /data-act="open-router"/);
  assert.match(t.html(), /pretending to be your router/);
  t.click({ 'data-act': 'open-router' });
  await tick();
  assert.deepStrictEqual(t.opened, []);
});

// The WATCH CONNECTIONS instrument on the deck (views/watch.js). `results` are
// what runWatch resolves with, in order (or functions returning a promise of one).
const watchF = (target) => ({ title: `${target} connected to 3 places`, description: 'What it connected to.', severity: 'info',
  category: 'network', code: 'network.connection_watch.watch_summary',
  data: { target, destinations: ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map((address) => ({ address, port: 443, protocol: 'tcp', snapshots: 1, who: null })) } });
// Everything the watch noted is one signal (signals.js).
const WATCH_TITLE = 'Connection watch: 1 app talked to 3 places';
async function watchSetup({ before = scan(mod('mod_a', [finding('A')])), results = [], docChanged = () => true, show = true } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const stub = stubWin([]);
  const storage = memStore();
  const calls = { runWatch: [], stopWatch: 0, docChanged: [], startCheckup: 0 };
  stub.win.RescueHost.startCheckup = () => { calls.startCheckup += 1; };
  let onEvent = null;
  stub.win.rescue.runWatch = (...args) => {
    calls.runWatch.push(args);
    const next = results.shift();
    return typeof next === 'function' ? next() : Promise.resolve(next);
  };
  stub.win.rescue.stopWatch = async () => { calls.stopWatch += 1; return { ok: true }; };
  stub.win.rescue.onWatchEvent = (cb) => { onEvent = cb; return () => {}; };
  stub.win.RescueHost.docChanged = (doc) => { calls.docChanged.push(doc); return docChanged(doc); };
  // The live progress line, found by its attribute, records what's written to it.
  const line = { textContent: '' };
  const q = stub.frame.querySelector;
  stub.frame.querySelector = (sel) => (sel === '[data-watch="progress"]' && stub.frame.innerHTML.includes('data-watch="progress"') ? line : q(sel));
  const ctl = createController({ win: stub.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  if (show) ctl.show(before, { id: 'unsure' });
  return { ...stub, ctl, storage, calls, line, before, event: (ev) => onEvent(ev), html: () => stub.frame.innerHTML };
}
const withWatch = (doc, ...findings) => ({ ...doc, modules: [...doc.modules, { ...mod('connection_watch', findings), category: 'network' }] });

test('watch: no instrument before a checkup has finished', async () => {
  const t = await watchSetup({ show: false });
  assert.doesNotMatch(t.html(), /WATCH CONNECTIONS/);
  assert.doesNotMatch(t.html(), /data-act="watch-start"/);
});

test('watch: no instrument while the checkup has found monitoring software', async () => {
  const stalker = { ...finding('Monitoring app'), severity: 'warning' };
  const t = await watchSetup({ before: scan(mod('mod_a', [finding('A')]), mod('stalkerware_scan', [stalker])) });
  assert.match(t.html(), /INCOMING SIGNALS/);
  assert.doesNotMatch(t.html(), /WATCH CONNECTIONS/);
  t.click({ 'data-act': 'watch-start' });
  await tick();
  assert.deepStrictEqual(t.calls.runWatch, [], 'a stale click starts nothing');
});

test('watch: on the deck after a checkup; start sends only the minutes picked', async () => {
  let release;
  const t = await watchSetup({ results: [() => new Promise((r) => { release = r; })] });
  assert.match(t.html(), /WATCH CONNECTIONS[\s\S]*for 5 minutes/);
  t.click({ 'data-act': 'watch-minutes:10' });
  assert.match(t.html(), /for 10 minutes/);
  t.click({ 'data-act': 'watch-minutes:7' });
  assert.match(t.html(), /for 10 minutes/, 'a value off the list is ignored');
  t.click({ 'data-act': 'watch-start' });
  assert.deepStrictEqual(t.calls.runWatch, [[10, true]]);
  assert.match(t.html(), /Watching… 0 of 10 minutes, 0 snapshots\./);
  t.click({ 'data-act': 'watch-start' });
  assert.strictEqual(t.calls.runWatch.length, 1, 'one watch at a time');
  // Main refuses a checkup while a watch runs, so the deck doesn't offer one.
  assert.doesNotMatch(t.html(), /data-act="resweep"/);
  assert.match(t.html(), /RE-SWEEP AFTER THE WATCH/);
  t.click({ 'data-act': 'resweep' });
  assert.strictEqual(t.calls.startCheckup, 0);
  // Progress events update the line in place, and the next redraw keeps it.
  t.event({ progress: { phase: 'watch', elapsed: 125, total: 600, snapshots: 25 } });
  assert.strictEqual(t.line.textContent, 'Watching… 2 of 10 minutes, 25 snapshots.');
  t.click({ 'data-act': 'toggle-low' });
  assert.match(t.html(), /Watching… 2 of 10 minutes, 25 snapshots\./);
  release({ ok: false, reason: 'busy', message: 'Something is already running.' });
  await tick();
});

test('watch: the lookups switch goes to main as a boolean, on unless the person turned it off', async () => {
  const t = await watchSetup({ results: [{ ok: false, reason: 'busy', message: 'Busy.' }, { ok: false, reason: 'busy', message: 'Busy.' }] });
  assert.match(t.html(), /data-act="watch-lookups" checked/);
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  t.click({ 'data-act': 'watch-lookups' });
  assert.match(t.html(), /data-act="watch-lookups">/);
  assert.match(t.html(), /Nothing leaves this computer/);
  t.click({ 'data-act': 'watch-minutes:2' });
  assert.match(t.html(), /data-act="watch-lookups">/, 'picking minutes keeps the switch');
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.runWatch, [[5, true], [2, false]]);
  // Lookup progress replaces the watching line in place.
  t.win.rescue.runWatch = () => new Promise(() => {});
  t.click({ 'data-act': 'watch-start' });
  t.event({ progress: { phase: 'lookup', done: 4, total: 9 } });
  assert.strictEqual(t.line.textContent, 'Looking up who runs each address… 4 of 9.');
});

test('watch: STOP calls stopWatch, even while a re-check runs', async () => {
  const t = await watchSetup({ results: [() => new Promise(() => {})] });
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = findingsToCity(t.before).districts.flatMap((d) => d.missions).find((m) => m.module === 'mod_a').id;
  t.click({ 'data-act': 'watch-start' });
  // A re-check that doesn't finish: the controller is busy until it does.
  let rechecking = 0;
  t.win.rescue.recheckModule = () => { rechecking += 1; return new Promise(() => {}); };
  t.click({ 'data-go': `mission:${id}` });
  t.click({ 'data-act': 'i-did-it' });
  assert.strictEqual(rechecking, 1, 'a re-check is running');
  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.html(), /INCOMING SIGNALS/, 'busy: other clicks wait for the re-check');
  t.click({ 'data-act': 'watch-stop' });
  await tick();
  assert.strictEqual(t.calls.stopWatch, 1);
});

test('watch: after STOP the line says it is stopping until the result arrives', async () => {
  let release;
  const t = await watchSetup({ results: [() => new Promise((r) => { release = r; })] });
  const STOPPING = 'Stopping… finishing what was gathered.';
  t.click({ 'data-act': 'watch-start' });
  t.click({ 'data-act': 'watch-stop' });
  await tick();
  assert.strictEqual(t.calls.stopWatch, 1);
  assert.strictEqual(t.line.textContent, STOPPING, 'updated in place');
  t.event({ progress: { phase: 'lookup', done: 1, total: 3 } });
  assert.strictEqual(t.line.textContent, STOPPING, 'later progress keeps it');
  t.click({ 'data-act': 'toggle-low' });
  assert.ok(t.html().includes(STOPPING), 'the next redraw keeps it');
  release({ ok: false, reason: 'busy', message: 'Busy.' });
  await tick(); await tick();
  assert.ok(!t.html().includes(STOPPING));
});

test('watch: a result that can’t be shown is the failed state, not an unhandled rejection', async () => {
  const merged = withWatch(scan(mod('mod_a', [finding('A')])), watchF('Mail'));
  const t = await watchSetup({ results: [{ ok: true, doc: merged }], docChanged: () => { throw new Error('boom'); } });
  const unhandled = [];
  const onUnhandled = (e) => unhandled.push(e);
  process.on('unhandledRejection', onUnhandled);
  const logged = [];
  const error = console.error;
  console.error = (...a) => logged.push(a);
  try {
    t.click({ 'data-act': 'watch-start' });
    await tick(); await tick(); await tick();
  } finally {
    console.error = error;
    process.off('unhandledRejection', onUnhandled);
  }
  assert.deepStrictEqual(unhandled, []);
  assert.match(String(logged[0] && logged[0][0]), /connection watch/);
  assert.match(t.html(), /couldn’t finish/);
  assert.match(t.html(), /data-act="watch-start"/);
});

test('watch: its findings arrive in INCOMING SIGNALS the way a re-check’s do', async () => {
  const t = await watchSetup();
  const merged = withWatch(t.before, watchF('Safari'));
  t.calls.runWatch.length = 0;
  const results = [{ ok: true, doc: merged }];
  t.win.rescue.runWatch = (...a) => { t.calls.runWatch.push(a); return Promise.resolve(results.shift()); };
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.docChanged, [merged], 'app.js hears of the new document first');
  assert.match(t.html(), /Watch finished\. What it saw is in INCOMING SIGNALS\./);
  assert.match(t.html(), /data-act="resweep"/, 'RE-SWEEP is back');
  t.click({ 'data-act': 'toggle-low' });
  const queue = t.html().split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.ok(queue.includes(WATCH_TITLE), 'the watch is one signal');
  assert.doesNotMatch(queue, /Safari connected/);
  // Going to the list and back shows the same document: that's not a new sweep.
  const sweeps = JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.sweeps.length;
  t.ctl.show(merged, { id: 'unsure' });
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.sweeps.length, sweeps);
});

test('watch: findings score nothing and nothing about them is stored', async () => {
  const merged = withWatch(scan(mod('mod_a', [finding('A')])), watchF('Signal'));
  const t = await watchSetup({ results: [{ ok: true, doc: merged }] });
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  t.click({ 'data-go': 'signal:connection_watch|group' });
  assert.match(t.html(), new RegExp(`id="sig-title"[^>]*>${WATCH_TITLE}`));
  t.click({ 'data-act': 'clue:went' });
  assert.match(t.html(), /WHERE THEY WENT[\s\S]*Signal: 1\.1\.1\.1:443, 2\.2\.2\.2:443, 3\.3\.3\.3:443/);
  for (const m of t.html().matchAll(/data-act="(clue:[a-z]+)"/g)) t.click({ 'data-act': m[1] });
  t.click({ 'data-act': 'tag:closer' });
  const saved = t.storage.getItem('device-rescue.game.v1');
  assert.strictEqual(JSON.parse(saved).deck.points, 0);
  assert.doesNotMatch(saved, /connection_watch|Signal connected/);
  // The tag holds for this session: it's sorted on the deck, LOOK CLOSER.
  t.click({ 'data-act': 'close-signal' });
  t.click({ 'data-act': 'toggle-low' });
  assert.match(t.html(), /LOOK CLOSER<\/span><\/span><span class="sig-title">Connection watch: /);
  // "These are all fine" sorts them too, still without storing anything.
  t.click({ 'data-act': 'batch-fine' });
  assert.match(t.html(), /KNOWN AND NOTED \(\d+\)[\s\S]*Connection watch: /);
  assert.doesNotMatch(t.storage.getItem('device-rescue.game.v1'), /connection_watch|Signal connected/);
});

test('watch: a refusal or failure shows main’s message; a closed gate leaves the city alone', async () => {
  const t = await watchSetup({ results: [{ ok: false, reason: 'monitoring', message: 'The connection watch is off <now>.' }, null] });
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  assert.match(t.html(), /The connection watch is off &lt;now&gt;\./);
  assert.deepStrictEqual(t.calls.docChanged, []);
  t.click({ 'data-act': 'watch-start' });
  await tick(); await tick();
  assert.match(t.html(), /couldn’t finish/);

  const merged = withWatch(scan(mod('mod_a', [finding('A')])), watchF('Mail'));
  const g = await watchSetup({ results: [{ ok: true, doc: merged }], docChanged: () => false });
  const drawn = g.html();
  g.click({ 'data-act': 'watch-start' });
  const running = g.html();
  await tick(); await tick();
  assert.notStrictEqual(running, drawn);
  assert.strictEqual(g.html(), running, 'the gate closed: app.js showed the list, nothing redrawn');
  assert.doesNotMatch(g.storage.getItem('device-rescue.game.v1'), /Mail connected/);
});
