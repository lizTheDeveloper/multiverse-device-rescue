'use strict';
// Seal Check: the `seal` mini-game (app signatures, Gatekeeper, added root
// certificates, Windows Authenticode and unsigned drivers).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const url = (rel) => pathToFileURL(path.join(MISSIONS, rel)).href;
const load = async () => ({ C: await import(url('contract.js')), G: (await import(url('games/seal.js'))).default });
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', name), 'utf8')).findings;

function items(C, name) {
  return fixture(name).map((f) => C.makeItem(f));
}
const byCode = (list, suffix) => list.find((i) => String(i.finding.code || '').endsWith(suffix) || (!i.finding.code && i.finding.module === suffix));
const ids = (ds) => ds.map((d) => d.id);
const strip = (html) => String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

// ---- Task 1: shape and contract --------------------------------------------

test('seal passes every contract check over the Mac and Windows fixtures and its practice', async () => {
  const { C, G } = await load();
  assert.deepStrictEqual(C.runContractChecks(G, [...items(C, 'seal-mac.json'), ...items(C, 'seal-win.json')]), []);
});

test('seal is the seal type with both titles and the concepts it trains', async () => {
  const { G } = await load();
  assert.strictEqual(G.type, 'seal');
  assert.deepStrictEqual(G.title, { standard: 'App seals', city: 'Seal Check' });
  assert.deepStrictEqual(G.concepts, ['who-made-it', 'couldnt-check']);
});

test('covers claims real modules, narrowed where a module is shared', async () => {
  const { G } = await load();
  assert.deepStrictEqual(G.covers, [
    { module: 'code_signature_audit' },
    { module: 'gatekeeper_quarantine_check' },
    { module: 'suspicious_processes', codes: ['security.suspicious_processes.unsigned_apps'] },
    { module: 'certificate_audit' },
    { module: 'certificate_trust_audit' },
    { module: 'win_rootkit_check', codes: ['security.win_rootkit_check.unsigned_drivers'] },
    { module: 'win_driver_check', checks: ['unsigned_drivers'] },
    { module: 'win_suspicious_processes', codes: ['security.win_suspicious_processes.suspicious_path', 'security.win_suspicious_processes.no_file_path'] },
  ]);
  // Every claimed code is one the engine really emits.
  const root = path.join(__dirname, '..', '..', 'modules');
  for (const c of G.covers) {
    const dir = ['security', 'integrity', 'performance', 'network'].map((d) => path.join(root, d, c.module)).find((d) => fs.existsSync(d));
    assert.ok(dir, `${c.module} is a real engine module`);
    const src = fs.readFileSync(path.join(dir, '__init__.py'), 'utf8');
    for (const code of c.codes || []) assert.ok(src.includes(`"${code}"`), `${code} is emitted by ${c.module}`);
    for (const check of c.checks || []) assert.ok(src.includes(`"check": "${check}"`), `${check} is a data.check of ${c.module}`);
  }
});

// ---- Task 2: verdicts and decisions ----------------------------------------

test('each finding gets its plain verdict', async () => {
  const { C, G } = await load();
  const mac = items(C, 'seal-mac.json');
  const win = items(C, 'seal-win.json');
  const v = (i) => G.classify(i.finding).verdict;
  assert.strictEqual(v(byCode(mac, 'tampered_binary')), 'tampered');
  assert.strictEqual(v(byCode(mac, 'old_signature_format')), 'old-format');
  assert.strictEqual(v(byCode(mac, 'unsigned_system_app')), 'unsigned');
  assert.strictEqual(v(byCode(mac, 'gatekeeper_rejected')), 'unknown-maker');
  assert.strictEqual(v(byCode(mac, 'unsigned_apps')), 'unknown-maker');
  assert.strictEqual(v(byCode(mac, 'user_root_cas')), 'unknown-maker');
  assert.strictEqual(v(byCode(mac, 'suspicious_certificates')), 'unknown-maker');
  assert.strictEqual(v(byCode(mac, 'trust_audit.expired_certificates')), 'expired');
  assert.strictEqual(v(byCode(mac, 'gatekeeper_disabled')), 'checker-off');
  assert.strictEqual(v(byCode(mac, 'sip_disabled')), 'checker-off');
  assert.strictEqual(v(byCode(mac, 'gatekeeper_assessment_failed')), 'checker-unsure');
  assert.strictEqual(v(byCode(win, 'tampered_binary')), 'tampered');
  assert.strictEqual(v(byCode(win, 'unsigned_system_app')), 'unsigned');
  assert.strictEqual(v(byCode(win, 'gatekeeper_rejected')), 'unknown-maker');
  assert.strictEqual(v(byCode(win, 'unsigned_drivers')), 'unsigned');
  assert.strictEqual(v(byCode(win, 'win_driver_check')), 'unsigned');
  assert.strictEqual(v({ code: 'security.something_else.x', data: {} }).length > 0, true);
});

test('a tampered critical never leads with the reinstall, even without removal_alert on the item', async () => {
  const { C, G } = await load();
  for (const name of ['seal-mac.json', 'seal-win.json']) {
    const base = byCode(items(C, name), 'tampered_binary');
    for (const item of [base, { ...base, removal_alert: false, finding: { ...base.finding, removal_alert: false } }]) {
      for (const mode of ['standard', 'city']) {
        const d = G.decisions(item, C.testContext({ mode }));
        assert.deepStrictEqual(ids(d), ['closer', 'mine', 'reinstall'], `${name} ${mode}`);
        assert.strictEqual(d[2].effect.kind, 'link');
        assert.strictEqual(d[2].effect.removal, true, 'the reinstall confirm carries the removal warning');
        assert.strictEqual(d[2].effect.warning, true, 'R6: the runner shows the removal warning before acting');
      }
    }
  }
});

test('labels: Reinstall from the maker / Mine, I know why / Look closer', async () => {
  const { C, G } = await load();
  const d = G.decisions(byCode(items(C, 'seal-mac.json'), 'old_signature_format'), C.testContext());
  assert.deepStrictEqual(ids(d), ['reinstall', 'mine', 'closer']);
  assert.deepStrictEqual(d.map((x) => x.label.standard), ['Reinstall from the maker', 'Mine, I know why', 'Look closer']);
  assert.strictEqual(d[0].effect.removal, false);
  assert.strictEqual(d[0].effect.warning, false);
});

test('reinstall looks up the maker’s site only when the maker is verified, else the app’s name', async () => {
  const { C, G } = await load();
  const mac = items(C, 'seal-mac.json');
  const verified = G.decisions(byCode(mac, 'gatekeeper_rejected'), C.testContext())[0].effect;
  assert.deepStrictEqual(verified.link, { kind: 'lookup', source: 'maker-site', query: 'Example Paint Co' });
  const claimed = G.decisions(byCode(mac, 'tampered_binary'), C.testContext()).find((d) => d.id === 'reinstall').effect;
  assert.deepStrictEqual(claimed.link, { kind: 'lookup', source: 'web', query: 'Example Notes' }, 'an unverified "claims to be" maker is not trusted for the look-up');
  assert.ok(Array.isArray(claimed.steps.standard) && claimed.steps.standard.length >= 2);
  assert.ok(Array.isArray(claimed.steps.city) && claimed.steps.city.length >= 2);
});

test('Mine, I know why marks when the finding is markable, else keeps it', async () => {
  const { C, G } = await load();
  const item = byCode(items(C, 'seal-mac.json'), 'unsigned_system_app');
  assert.strictEqual(G.decisions(item, C.testContext()).find((d) => d.id === 'mine').effect.kind, 'keep');
  const markable = { ...item, finding: { ...item.finding, markable: { kind: 'x' } } };
  assert.strictEqual(G.decisions(markable, C.testContext()).find((d) => d.id === 'mine').effect.kind, 'mark');
});

test('Look closer carries a checklist in both modes', async () => {
  const { C, G } = await load();
  for (const f of items(C, 'seal-mac.json')) {
    for (const mode of ['standard', 'city']) {
      const closer = G.decisions(f, C.testContext({ mode })).find((d) => d.effect.kind === 'closer');
      assert.ok(closer, `${f.key} has Look closer`);
      assert.ok(closer.effect.checklist.length >= 2, `${f.key} ${mode} checklist`);
      if (mode === 'city') for (const line of closer.effect.checklist) assert.deepStrictEqual(C.checkCityWords(line), []);
    }
  }
});

test('added root certificates: Look closer first, Not mine last with the removal warning', async () => {
  const { C, G } = await load();
  for (const suffix of ['user_root_cas', 'suspicious_certificates']) {
    const d = G.decisions(byCode(items(C, 'seal-mac.json'), suffix), C.testContext());
    assert.deepStrictEqual(ids(d), ['closer', 'mine', 'not-mine']);
    assert.strictEqual(d[2].effect.removal, true);
    assert.strictEqual(d[2].effect.warning, true);
    assert.notStrictEqual(d[2].effect.kind, 'fix');
  }
});

test('the seal checker switched off: Turn it back on first; unsure: Check again', async () => {
  const { C, G } = await load();
  const mac = items(C, 'seal-mac.json');
  assert.deepStrictEqual(ids(G.decisions(byCode(mac, 'gatekeeper_disabled'), C.testContext())), ['turn-on', 'mine', 'closer']);
  const unsure = G.decisions(byCode(mac, 'gatekeeper_assessment_failed'), C.testContext());
  assert.deepStrictEqual(ids(unsure), ['recheck', 'closer']);
  assert.strictEqual(unsure[0].effect.kind, 'recheck');
});

test('Windows: a driver gets Update the driver (Windows Update); an app gets the Installed apps pane', async () => {
  const { C, G } = await load();
  const win = items(C, 'seal-win.json');
  const ctx = C.testContext({ platform: 'win32' });
  const drv = G.decisions(byCode(win, 'unsigned_drivers'), ctx);
  assert.strictEqual(drv[0].label.standard, 'Update the driver');
  assert.deepStrictEqual(drv[0].effect.link, { kind: 'settings', pane: 'windows-update' });
  const app = G.research(byCode(win, 'unsigned_system_app'), ctx);
  assert.ok(app.links.some((l) => l.kind === 'settings' && l.pane === 'windows-apps'));
});

test('every decision label is four words or fewer in both modes', async () => {
  const { C, G } = await load();
  for (const item of [...items(C, 'seal-mac.json'), ...items(C, 'seal-win.json'), ...G.practice.items]) {
    for (const mode of ['standard', 'city']) {
      for (const d of G.decisions(item, C.testContext({ mode }))) {
        for (const m of ['standard', 'city']) assert.ok(d.label[m].split(/\s+/).length <= 4, `${d.id} ${m}`);
      }
    }
  }
});

// ---- Task 3: research and honesty -------------------------------------------

test('research: rows from ctx.evidenceRows, what from a verified maker, lesson link', async () => {
  const { C, G } = await load();
  const mac = items(C, 'seal-mac.json');
  const seen = [];
  const ctx = C.testContext({ evidenceRows: (f, o) => { seen.push([f.code, o.mode]); return [{ label: 'Path', value: f.data.path || '' }]; } });
  const r = G.research(byCode(mac, 'gatekeeper_rejected'), ctx);
  assert.deepStrictEqual(seen, [['security.code_signature_audit.gatekeeper_rejected', 'standard']]);
  assert.strictEqual(r.rows.length, 1);
  assert.strictEqual(r.what, 'Example Paint: a drawing app.');
  assert.ok(r.links.some((l) => l.kind === 'lesson' && l.concept === 'who-made-it'));
  assert.strictEqual(G.research(byCode(mac, 'tampered_binary'), C.testContext()).what, 'Unknown maker');
  assert.strictEqual(G.research(byCode(mac, 'tampered_binary'), C.testContext({ mode: 'city' })).what, 'Maker not known');
  // A certificate or a system switch is not a program: no "Unknown maker" line.
  assert.strictEqual(G.research(byCode(mac, 'gatekeeper_disabled'), C.testContext()).what, '');
  assert.strictEqual(G.research(byCode(mac, 'user_root_cas'), C.testContext()).what, '');
});

test('honesty: a partial app list says how many were checked', async () => {
  const { C, G } = await load();
  const mac = items(C, 'seal-mac.json');
  const r = G.research(byCode(mac, 'old_signature_format'), C.testContext());
  assert.match(r.coverage, /looked at 40 of 120 apps/);
  assert.match(r.coverage, /weren.t checked/);
  assert.strictEqual(G.research(byCode(mac, 'unsigned_system_app'), C.testContext()).coverage, '');
  const html = G.render({ item: byCode(mac, 'old_signature_format'), research: r, decisions: [], index: 0, total: 1 }, C.testContext());
  assert.match(strip(html), /looked at 40 of 120 apps/);
});

test('honesty: an item from a check that didn’t finish says so', async () => {
  const { C, G } = await load();
  const base = byCode(items(C, 'seal-mac.json'), 'unsigned_system_app');
  for (const item of [{ ...base, complete: false }, { ...base, unfinished: true }, { ...base, finding: { ...base.finding, complete: false } }]) {
    const r = G.research(item, C.testContext());
    assert.strictEqual(r.unfinished, true);
    assert.match(strip(G.render({ item, research: r, decisions: [], index: 0, total: 1 }, C.testContext())), /This check didn.t finish/);
  }
});

test('summaries never say all clear', async () => {
  const { C, G } = await load();
  for (const mode of ['standard', 'city']) {
    for (const results of [[], [{ decision: 'mine' }], [{ decision: { id: 'reinstall' } }, { id: 'closer' }]]) {
      assert.doesNotMatch(G.summary(results, C.testContext({ mode })), /all clear|all good|nothing wrong|you.re safe|clean/i);
    }
  }
});

// ---- Task 4: render, city words, practice, summary -------------------------

test('render: both sides of the seal and the verdict, standard and city words', async () => {
  const { C, G } = await load();
  const item = byCode(items(C, 'seal-mac.json'), 'tampered_binary');
  const std = G.render({ item, research: G.research(item, C.testContext()), decisions: [], index: 0, total: 1 }, C.testContext());
  assert.match(std, /What the maker signed/);
  assert.match(std, /What&#39;s on disk|What’s on disk/);
  assert.match(strip(std), /Changed after signing/);
  assert.match(std, /data-verdict="tampered"/);
  const ctxC = C.testContext({ mode: 'city' });
  const city = G.render({ item, research: G.research(item, ctxC), decisions: [], index: 0, total: 1 }, ctxC);
  assert.match(city, /The maker’s seal/);
  assert.match(city, /What’s here now/);
  assert.match(strip(city), /Broken seal/);
});

test('render never shows the engine’s own description (it can carry help-line text)', async () => {
  const { C, G } = await load();
  for (const item of items(C, 'seal-mac.json')) {
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode });
      const html = G.render({ item, research: G.research(item, ctx), decisions: G.decisions(item, ctx), index: 0, total: 1 }, ctx);
      assert.doesNotMatch(html, /799-7233|advocate/i);
    }
  }
});

test('city output (fixtures, practice items, practice steps, effects) uses game words only', async () => {
  const { C, G } = await load();
  const ctx = C.testContext({ mode: 'city' });
  const all = [...items(C, 'seal-mac.json'), ...items(C, 'seal-win.json'), ...G.practice.items];
  for (const item of all) {
    const d = G.decisions(item, ctx);
    const html = G.render({ item, research: G.research(item, ctx), decisions: d, index: 0, total: 1, practice: true, step: G.practice.script[0] }, ctx);
    assert.deepStrictEqual(C.checkCityWords(html), [], item.key);
    assert.deepStrictEqual(C.checkCityWords(JSON.stringify(d)), [], `${item.key} decisions`);
  }
  for (const s of G.practice.script) assert.deepStrictEqual(C.checkCityWords(s.say.city), []);
  assert.deepStrictEqual(C.checkCityWords(G.summary([{ decision: 'reinstall' }], ctx)), []);
});

test('practice: an old-format game, a tampered app, an unsigned developer build; steps point at real moves', async () => {
  const { C, G } = await load();
  const verdicts = G.practice.items.map((i) => G.classify(i.finding).verdict);
  assert.deepStrictEqual(verdicts, ['old-format', 'tampered', 'unsigned']);
  for (const i of G.practice.items) {
    assert.ok(i.practice === true || i.finding.synthetic === true, 'practice items are marked synthetic');
    assert.doesNotMatch(JSON.stringify(i), /\/Users\/(?!example\b)/, 'no real home folders');
  }
  assert.ok(G.practice.script.length >= 3);
  for (const step of G.practice.script) {
    const item = G.practice.items[step.item];
    assert.ok(item, 'step points at an item');
    if (step.expect) assert.ok(ids(G.decisions(item, C.testContext())).includes(step.expect), `${step.expect} is a move on item ${step.item}`);
  }
  const expects = G.practice.script.filter((s) => s.expect).map((s) => [G.classify(G.practice.items[s.item].finding).verdict, s.expect]);
  assert.deepStrictEqual(expects, [['old-format', 'reinstall'], ['tampered', 'closer'], ['unsigned', 'mine']]);
});

test('render shows a practice step’s words when given one', async () => {
  const { C, G } = await load();
  const step = G.practice.script[0];
  const item = G.practice.items[step.item];
  const html = G.render({ item, research: G.research(item, C.testContext()), decisions: [], index: 0, total: 3, practice: true, step }, C.testContext());
  assert.ok(strip(html).includes(strip(C.testContext().esc(step.say.standard)).trim()));
});

test('summary counts the moves and names partial coverage', async () => {
  const { C, G } = await load();
  const partial = byCode(items(C, 'seal-mac.json'), 'old_signature_format');
  const s = strip(G.summary([
    { item: partial, decision: 'reinstall' }, { decision: { id: 'mine' } }, { id: 'closer' }, { decision: 'closer' },
  ], C.testContext()));
  assert.match(s, /4 seals/);
  assert.match(s, /1 to reinstall/);
  assert.match(s, /1 yours/);
  assert.match(s, /2 to look closer/);
  assert.match(s, /not every app was checked/i);
});

test('seal.css exists, closes its blocks, and uses the game’s variables', () => {
  const css = fs.readFileSync(path.join(MISSIONS, 'games', 'seal.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  let depth = 0;
  for (const ch of css) { if (ch === '{') depth += 1; else if (ch === '}') depth -= 1; assert.ok(depth >= 0); }
  assert.strictEqual(depth, 0);
  assert.match(css, /var\(--cyan\)/);
  assert.match(css, /\.seal-compare/);
});

test('R1: render draws only the seal card, no buttons, evidence rows, links or the warning line', async () => {
  const { C, G } = await load();
  const ctx = C.testContext({ evidenceRows: () => [{ label: 'Checked with', value: 'codesign-marker-xyz' }] });
  for (const item of [...items(C, 'seal-mac.json'), ...items(C, 'seal-win.json')]) {
    const r = G.research(item, ctx);
    const html = G.render({ item, research: r, decisions: G.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.doesNotMatch(html, /<button|<a\b|href=|<details|codesign-marker-xyz/i, item.key);
    assert.doesNotMatch(html, /Reinstall from the maker|Look closer/, item.key);
    assert.match(html, /seal-compare/);
  }
});
