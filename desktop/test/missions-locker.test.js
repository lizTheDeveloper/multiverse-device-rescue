'use strict';
// The Evidence Locker mini-game (missions/games/locker.js): contract, file tags, decisions, Windows, stealth words,
// near-identical sets, practice and summary. Fixtures are synthetic (test/fixtures/missions/locker-*.json).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const loadContract = () => import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
const loadGame = () => import(pathToFileURL(path.join(MISSIONS, 'games', 'locker.js')).href);
const FIX = path.join(__dirname, 'fixtures', 'missions');
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(FIX, name), 'utf8'));

async function setup() {
  const C = await loadContract();
  const G = await loadGame();
  const items = (name) => {
    const doc = fixture(name);
    return doc.findings.map((f) => C.makeItem(f, { key: `${f.module}:${f.id}` }));
  };
  const byId = (name, id) => items(name).find((i) => i.key.endsWith(`:${id}`));
  return { C, G, game: G.default, items, byId };
}

const root0 = () => path.join(__dirname, '..', '..', 'modules');
const ids = (ds) => ds.map((d) => d.id);
const strip = (html) => String(html).replace(/<wbr>/g, '').replace(/<[^>]+>/g, ' ').replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const effectText = (ds) => ds.flatMap((d) => [...(d.effect.steps || []), ...(d.effect.checklist || []), d.hint || '', d.label.standard, d.label.city]).join('\n');

test('locker passes every contract check on mac, windows and group fixtures', async () => {
  const { C, game, items } = await setup();
  const all = [...items('locker-mac.json'), ...items('locker-win.json'), ...items('locker-group.json')];
  assert.deepStrictEqual(C.runContractChecks(game, all), []);
});

test('covers: the locker modules on macOS and their Windows equivalents, each a real engine module', async () => {
  const { game } = await setup();
  const mods = game.covers.map((c) => c.module);
  for (const m of ['ai_worm_filesystem', 'ai_worm_git_ssh', 'ai_worm_lateral', 'ai_worm_network', 'ai_threat_indicators',
    'malware_scan_indicators', 'clamav_scanner', 'crypto_miner_detect', 'rootkit_check',
    'win_malware_indicators', 'win_crypto_miner_detect', 'win_rootkit_check']) assert.ok(mods.includes(m), m);
  assert.strictEqual(new Set(mods).size, mods.length, 'no module listed twice');
  // win_rootkit_check is shared: unsigned_drivers is the seal game's.
  const wr = game.covers.find((c) => c.module === 'win_rootkit_check');
  assert.ok(Array.isArray(wr.codes) && wr.codes.length > 0);
  assert.ok(!wr.codes.some((c) => 'security.win_rootkit_check.unsigned_drivers'.startsWith(c)), 'unsigned_drivers is not claimed');
  assert.ok(wr.codes.includes('security.win_rootkit_check.hidden_services'));
  const src = fs.readFileSync(path.join(root0(), 'security', 'win_rootkit_check', '__init__.py'), 'utf8');
  for (const c of wr.codes) assert.ok(src.includes(`code="${c}"`), `${c} is a real code`);
  const root = path.join(__dirname, '..', '..', 'modules');
  for (const m of mods) {
    const found = fs.readdirSync(root).some((cat) => fs.existsSync(path.join(root, cat, m, '__init__.py')));
    assert.ok(found, `${m} is an engine module`);
  }
  // Settings-only and storage modules belong to other games.
  for (const m of ['temp_file_scanner', 'win_temp_files', 'antivirus_status', 'ai_worm_persistence', 'crypto_miner_persistence']) assert.ok(!mods.includes(m), m);
});

test('file tag: path, when, what matched and maker; hidden and temporary folders flagged', async () => {
  const { G, game, byId, C } = await setup();
  const ctx = C.testContext();
  const ssh = byId('locker-mac.json', 'ssh-keys');
  const text = strip(game.render({ item: ssh, research: game.research(ssh, ctx), decisions: game.decisions(ssh, ctx), index: 1, total: 4 }, ctx));
  assert.match(text, /File 2 of 4/);
  assert.match(text, /Where ~\/\.ssh\/authorized_keys/);
  assert.match(text, /hidden folder/);
  assert.match(text, /Changed 3 days before this checkup/);
  assert.match(text, /What matched The list of keys that can log in remotely changed/);
  assert.match(text, /Made by Unknown maker/);

  const drop = byId('locker-mac.json', 'temp-dropper');
  const t = G.tagOf(drop, ctx);
  assert.deepStrictEqual([t.kind, t.flags.hidden, t.flags.temp], ['file', true, true]);
  assert.strictEqual(t.matched, 'eval(atob(');

  const app = byId('locker-mac.json', 'signed-app');
  const html = strip(game.render({ item: app, research: game.research(app, ctx), decisions: game.decisions(app, ctx), index: 0, total: 1 }, ctx));
  assert.match(html, /Made by Example Software Ltd verified/);
  assert.match(html, /Example Cleaner: a disk cleaning app\./);
  assert.strictEqual(game.research(app, ctx).what, 'Example Cleaner: a disk cleaning app.');
  assert.strictEqual(game.research(drop, ctx).what, 'Unknown maker');
});

test('size shows when the engine recorded one; a list finding shows its names', async () => {
  const { G, C } = await setup();
  const ctx = C.testContext();
  const sized = C.makeItem({ module: 'ai_worm_lateral', code: 'security.ai_worm_lateral.supply_chain_artifact', data: { path: '/tmp/x/a.js', size_bytes: 2500000, threat: 'Example' } });
  assert.strictEqual(G.tagOf(sized, ctx).size, '2.5 MB');
  const list = C.makeItem({ module: 'rootkit_check', code: 'security.rootkit_check.hidden_files', data: { files: ['.a', '.b', '.c', '.d', '.e', '.f', '.g', '.h'] } });
  const tag = G.tagOf(list, ctx);
  assert.deepStrictEqual([tag.kind, tag.entries.length, tag.moreEntries], ['system', 6, 2]);
});

test('decisions: Mine / Quarantine / Look closer for a file; a critical match puts Look closer first', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext();
  assert.deepStrictEqual(ids(game.decisions(byId('locker-mac.json', 'dev-script'), ctx)), ['mine', 'quarantine', 'closer']);
  assert.deepStrictEqual(ids(game.decisions(byId('locker-mac.json', 'known-hash'), ctx)), ['closer', 'quarantine', 'mine']);
  const labels = game.decisions(byId('locker-mac.json', 'dev-script'), ctx).map((d) => d.label);
  assert.deepStrictEqual(labels.map((l) => l.standard), ['Mine', 'Quarantine', 'Look closer']);
  assert.deepStrictEqual(labels.map((l) => l.city), ['Mine', 'Bag it', 'Look closer']);
});

test('Quarantine uses the engine fix when offered, else move-aside steps that never delete', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext();
  const fixable = game.decisions(byId('locker-mac.json', 'launchagent-fixable'), ctx).find((d) => d.id === 'quarantine');
  assert.deepStrictEqual(fixable.effect, { kind: 'fix', module: 'ai_threat_indicators', action: 'disable_launch_agent' });

  const q = game.decisions(byId('locker-mac.json', 'temp-dropper'), ctx).find((d) => d.id === 'quarantine');
  assert.strictEqual(q.effect.kind, 'closer');
  assert.strictEqual(q.effect.focus, 'move-aside');
  const steps = q.effect.steps.join('\n');
  assert.match(steps, /Command-Shift-G and paste \/private\/var\/tmp\/\.cache-x1/);
  assert.match(steps, /Command-Shift-\. \(period\)/);
  assert.match(steps, /folder named Quarantine/);
  assert.match(steps, /Nothing is deleted/);
  for (const item of [...(await setup()).items('locker-mac.json'), ...(await setup()).items('locker-win.json')]) {
    for (const mode of ['standard', 'city']) {
      const all = effectText(game.decisions(item, C.testContext({ mode, platform: item.finding.module.startsWith('win_') ? 'win32' : 'darwin' })));
      assert.doesNotMatch(all, /\bdelete it\b|\brm\b|\bTrash\b|Recycle Bin|Empty/i, `${item.key} ${mode}`);
    }
  }
});

test('an item with a removal warning never gets a removing default, and its steps point at the note', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext();
  const item = byId('locker-mac.json', 'ssh-keys');
  const d = game.decisions(item, ctx);
  assert.notStrictEqual(d[0].effect.kind, 'fix');
  assert.match(d.find((x) => x.id === 'quarantine').effect.steps[1], /Read the note above/);
  assert.deepStrictEqual(C.checkDecisions(d, item), []);
  assert.strictEqual(d.find((x) => x.id === 'quarantine').effect.warning, true);
  assert.strictEqual(game.decisions(byId('locker-win.json', 'win-drivers'), ctx).find((x) => x.id === 'mine').effect.warning, undefined);
  assert.strictEqual(game.decisions(byId('locker-mac.json', 'dev-script'), ctx).find((x) => x.id === 'quarantine').effect.warning, undefined);
});

test('Mine marks only when the engine offers a mark; otherwise it is kept as mine', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext();
  const marked = game.decisions(byId('locker-mac.json', 'cron-markable'), ctx).find((d) => d.id === 'mine');
  assert.deepStrictEqual(marked.effect, { kind: 'mark', id: 'ai_tooling:0000000000000000' });
  const kept = game.decisions(byId('locker-mac.json', 'dev-script'), ctx).find((d) => d.id === 'mine');
  assert.deepStrictEqual(kept.effect, { kind: 'keep', as: 'mine' });
});

test('programs, add-ons, settings and core parts get their own moves', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext();
  const miner = game.decisions(byId('locker-mac.json', 'known-miner'), ctx);
  assert.deepStrictEqual(ids(miner), ['closer', 'stop', 'mine']);
  assert.match(miner[1].effect.steps.join('\n'), /Activity Monitor[\s\S]*xmrig \(ID 4242\)[\s\S]*Stop button/);
  const ext = game.decisions(byId('locker-mac.json', 'safari-ext'), ctx);
  assert.deepStrictEqual(ids(ext), ['mine', 'turn-off', 'closer']);
  assert.match(ext[1].effect.steps[0], /Safari > Settings > Extensions, and untick Example Search Helper/);
  assert.deepStrictEqual(ids(game.decisions(byId('locker-mac.json', 'clamav-missing'), ctx)), ['mine', 'closer', 'later']);
  const sip = game.decisions(byId('locker-mac.json', 'sip-off'), ctx);
  assert.deepStrictEqual(ids(sip), ['closer', 'mine', 'later']);
  assert.ok(!sip.some((d) => d.effect.kind === 'fix' || d.effect.focus === 'move-aside'), 'core parts are never moved by hand');
  assert.match(sip[0].effect.checklist.join('\n'), /ask someone you trust/);
});

test('Windows: File Explorer and Task Manager steps, Startup apps for a startup entry, Windows Security link', async () => {
  const { game, byId, C } = await setup();
  const ctx = C.testContext({ platform: 'win32' });
  const drop = game.decisions(byId('locker-win.json', 'win-dropper'), ctx).find((d) => d.id === 'quarantine');
  const steps = drop.effect.steps.join('\n');
  assert.match(steps, /File Explorer, click the address bar, paste C:\\Users\\example\\AppData\\Local\\Temp\\x1/);
  assert.match(steps, /Hidden items/);
  assert.match(steps, /Task Manager \(Ctrl\+Shift\+Esc\)/);
  assert.doesNotMatch(steps, /Finder|Command-/);
  const miner = game.decisions(byId('locker-win.json', 'win-miner'), ctx).find((d) => d.id === 'stop');
  assert.match(miner.effect.steps.join('\n'), /Details[\s\S]*xmrig\.exe \(ID 5150\)[\s\S]*End task/);
  const reg = game.decisions(byId('locker-win.json', 'win-registry'), ctx).find((d) => d.id === 'quarantine');
  assert.deepStrictEqual([reg.effect.kind, reg.effect.pane], ['settings', 'startup-apps']);
  const r = game.research(byId('locker-win.json', 'win-drivers'), ctx);
  assert.ok(r.links.some((l) => l.kind === 'settings' && l.pane === 'windows-security'));
  // A code-less Windows finding is read from data.check.
  assert.strictEqual((await loadGame()).kindOf(byId('locker-win.json', 'win-pool')), 'process');
});

test('research: rows from ctx.evidenceRows, a lesson and a quoted look-up, intents only', async () => {
  const { game, byId, C } = await setup();
  const rows = [{ label: 'Where', value: '/x', mono: true }];
  const ctx = C.testContext({ evidenceRows: () => rows });
  const r = game.research(byId('locker-mac.json', 'known-hash'), ctx);
  assert.strictEqual(r.rows, rows);
  assert.ok(r.links.some((l) => l.kind === 'lesson' && l.concept === 'poisoned-packages'));
  assert.ok(r.links.some((l) => l.kind === 'lookup' && l.source === 'web' && l.query === '"Example Worm"'));
  assert.ok(game.research(byId('locker-mac.json', 'known-miner'), ctx).links.some((l) => l.concept === 'wifi-and-mining'));
  assert.ok(game.research(byId('locker-mac.json', 'signed-app'), ctx).links.some((l) => l.source === 'maker-site' && l.query === 'Example Software Ltd'));
  assert.deepStrictEqual(C.checkResearch(r), []);
  // R1: the runner draws evidence rows, links and buttons; the card does not.
  const html = game.render({ item: byId('locker-mac.json', 'known-hash'), research: r, decisions: game.decisions(byId('locker-mac.json', 'known-hash'), ctx), index: 0, total: 1 }, ctx);
  assert.doesNotMatch(html, /<button|<a\b|evidence/i);
});

test('city mode: game words only in render, summary, hints, steps and checklists', async () => {
  const { game, items, C } = await setup();
  const all = [...items('locker-mac.json'), ...items('locker-win.json'), ...game.practice.items];
  for (const item of all) {
    const ctx = C.testContext({ mode: 'city', platform: item.finding.module.startsWith('win_') ? 'win32' : 'darwin' });
    const d = game.decisions(item, ctx);
    const r = game.research(item, ctx);
    const html = game.render({ item, research: r, decisions: d, index: 0, total: 1, practice: true, step: game.practice.script[0] }, ctx);
    assert.deepStrictEqual(C.checkCityWords(html + effectText(d) + r.what), [], item.key);
  }
  const results = all.map((item, i) => ({ item, decision: ['mine', 'quarantine', 'closer', 'later'][i % 4] }));
  assert.deepStrictEqual(C.checkCityWords(game.summary(results, C.testContext({ mode: 'city' }))), []);
  assert.match(strip(game.render({ item: all[0], research: game.research(all[0], C.testContext({ mode: 'city' })), decisions: [], index: 0, total: 1 }, C.testContext({ mode: 'city' }))), /Exhibit 1 of 1/);
});

test('copy: no time estimates, and never "all clear"', async () => {
  const { game, items, C } = await setup();
  const all = [...items('locker-mac.json'), ...items('locker-win.json'), ...game.practice.items];
  const TIME = /\b(minutes?|seconds?|hours?|quick(ly)?|soon|right away|straight away|instantly)\b/i;
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    for (const item of all) {
      const d = game.decisions(item, ctx);
      const html = strip(game.render({ item, research: game.research(item, ctx), decisions: d, index: 0, total: 1 }, ctx));
      assert.doesNotMatch(html.replace(item.finding.title, '') + effectText(d), TIME, `${mode} ${item.key}`);
    }
    for (const s of [game.summary([], ctx), game.summary(all.map((item) => ({ item, decision: 'mine' })), ctx)]) {
      assert.doesNotMatch(strip(s), /all clear|clean|no threats|safe now/i);
    }
    for (const step of game.practice.script) assert.doesNotMatch(step.say[mode], TIME);
  }
});

test('a check that did not finish says so on the tag', async () => {
  const { game, C } = await setup();
  const item = C.makeItem({ module: 'ai_worm_filesystem', code: 'security.ai_worm_filesystem.obfuscated_script', data: { path: '/tmp/a.sh', pattern: 'x' } }, { unfinished: true });
  for (const [mode, re] of [['standard', /This check didn't finish/], ['city', /This sweep didn't finish/]]) {
    const ctx = C.testContext({ mode });
    assert.match(strip(game.render({ item, research: game.research(item, ctx), decisions: [], index: 0, total: 1 }, ctx)), re);
  }
});

test('ten near-identical files: one group, each decided on its own, summed up together', async () => {
  const { game, G, items, C } = await setup();
  const ctx = C.testContext();
  const group = items('locker-group.json');
  assert.strictEqual(group.length, 10);
  assert.strictEqual(new Set(group.map(G.groupKey)).size, 1, 'they read as one group');
  assert.strictEqual(new Set(group.map((i) => i.key)).size, 10, 'each keeps its own key');
  const sets = group.map((i) => game.decisions(i, ctx));
  for (const d of sets) assert.deepStrictEqual(ids(d), ['mine', 'quarantine', 'closer']);
  // Each item's move-aside steps name that item's own file.
  sets.forEach((d, i) => assert.match(d[1].effect.steps.join('\n'), new RegExp(`postinstall-${i}\\.js`)));
  const part = group.slice(0, 4);
  const html = strip(game.render({ item: part[1], research: game.research(part[1], ctx), decisions: sets[1], index: 1, total: 4, siblings: part,
    results: [{ item: part[0], decision: 'quarantine' }] }, ctx));
  assert.match(html, /3 more in this set look the same\. Decide each one on its own\./);
  assert.match(html, /For the last one like this, you chose Quarantine ?\./);
  assert.notStrictEqual(G.groupKey(group[0]), G.groupKey(fixture('locker-mac.json') && items('locker-mac.json')[1]));
  const s = strip(game.summary(group.map((item, i) => ({ item, decision: i < 7 ? 'quarantine' : 'mine' })), ctx));
  assert.match(s, /Files tagged: 10/);
  assert.match(s, /Yours 3/);
  assert.match(s, /Set aside or stopped 7/);
  assert.match(s, /10 of these matched the same sign\. You decided each one on its own\./);
  assert.match(s, /Nothing was deleted/);
});

test('practice: a developer script (Mine), a dropped temp script (Quarantine), a cache file (Look closer)', async () => {
  const { game, G, C } = await setup();
  const ctx = C.testContext({ practice: true });
  const { items, script } = game.practice;
  assert.strictEqual(items.length, 3);
  assert.deepStrictEqual(script.map((s) => s.expect), ['mine', 'quarantine', 'closer']);
  for (const step of script) {
    assert.ok(ids(game.decisions(items[step.item], ctx)).includes(step.expect), step.expect);
    assert.ok(game.concepts.includes(step.concept), step.concept);
    assert.ok(step.say.standard && step.say.city);
  }
  assert.deepStrictEqual(Object.values(G.placeFlags(items[1].finding.data.path)).slice(0, 2), [true, true]);
  assert.strictEqual(G.placeFlags(items[2].finding.data.path).cache, true);
  const html = strip(game.render({ item: items[2], research: game.research(items[2], ctx), decisions: [], index: 2, total: 3, practice: true, step: script[2] }, ctx));
  assert.match(html, /an app's cache/);
  assert.match(html, /Look closer before you decide/);
  // Synthetic: no real home folders.
  const txt = JSON.stringify(items);
  assert.doesNotMatch(txt, /\/Users\/(?!example\/)/);
});

test('fixtures are synthetic: only example home folders, documentation addresses', () => {
  for (const name of fs.readdirSync(FIX).filter((n) => /^locker-.*\.json$/.test(n))) {
    const txt = fs.readFileSync(path.join(FIX, name), 'utf8');
    assert.doesNotMatch(txt, /\/Users\/(?!example\b)/, name);
    assert.doesNotMatch(txt, /C:\\\\Users\\\\(?!example\b)/, name);
    for (const ip of txt.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []) assert.match(ip, /^192\.0\.2\./, `${name}: ${ip}`);
  }
});

test('paste steps only ever offer a plain absolute folder; command lines are reduced to their program path', async () => {
  const { G, game, C } = await setup();
  const win = C.testContext({ platform: 'win32' });
  const mac = C.testContext();
  const steps = (data, ctx, module = 'win_malware_indicators', code = 'security.win_malware_indicators.suspicious_service') =>
    game.decisions(C.makeItem({ module, code, data }), ctx).find((d) => d.id === 'quarantine').effect.steps.join('\n');
  // ImagePath parsing.
  assert.strictEqual(G.exePath('"C:\\Program Files\\Ex\\svc.exe" -k netsvcs'), 'C:\\Program Files\\Ex\\svc.exe');
  assert.strictEqual(G.exePath('C:\\ex\\svc.exe & calc.exe'), 'C:\\ex\\svc.exe');
  assert.match(steps({ binary_path: '"C:\\Program Files\\Ex\\svc.exe" -k netsvcs' }, win), /paste C:\\Program Files\\Ex and press Enter/);
  const amp = steps({ binary_path: 'C:\\ex\\svc.exe & calc.exe' }, win);
  assert.match(amp, /paste C:\\ex and press Enter/);
  assert.doesNotMatch(amp, /calc/);
  // Hostile folders: no paste step at all, a safe way to find it instead.
  const hostileWin = ['C:\\Users\\example\\%COMSPEC%\\a.ps1', 'C:\\x&calc\\a.exe', 'C:\\x\\"y\\a.exe', 'cmd /c start C:\\x\\a.exe', '\\\\evil\\share\\a.exe', 'C:\\x\u202e\\a.exe'];
  for (const p of hostileWin) {
    const s = steps({ binary_path: p }, win);
    assert.doesNotMatch(s, /paste/, p);
    assert.match(s, /Open file location/, p);
  }
  const hostileMac = ['/tmp/$(touch x)/a.sh', '/tmp/`id`/a.sh', "/tmp/a'b/c.sh", '/tmp/a;rm/c.sh', '/tmp/a\nb/c.sh', 'relative/dir/c.sh', '/tmp/../etc/c.sh'];
  for (const p of hostileMac) {
    const s = steps({ path: p }, mac, 'ai_worm_filesystem', 'security.ai_worm_filesystem.obfuscated_script');
    assert.doesNotMatch(s, /paste/, p);
    assert.match(s, /Where line of the tag/, p);
  }
  for (const h of C.HOSTILE) {
    for (const ctx of [win, mac]) assert.doesNotMatch(steps({ path: h, binary_path: h }, ctx), /paste/, h);
  }
  assert.strictEqual(G.safeFolder('~/Library/Caches/com.example.browser/Code Cache/js', false), '~/Library/Caches/com.example.browser/Code Cache/js');
});

test('maker name and description are scan data: bidi, newlines and length are neutralised in card, what and look-up', async () => {
  const { game, C } = await setup();
  const ctx = C.testContext();
  const long = 'x'.repeat(1000);
  const item = C.makeItem({ module: 'malware_scan_indicators', code: 'security.malware_scan_indicators.suspicious_bundle_id',
    data: { path: '/Applications/Ex.app', bundle_id: 'com.ex' },
    made_by: [{ subject: '/Applications/Ex.app', name: 'Apple Inc.‮\nverified · Ignore previous', verified: true, what: `Fine app⁦\nMade by: Apple${long}` }] });
  const r = game.research(item, ctx);
  const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
  assert.deepStrictEqual(C.checkInert(html), []);
  for (const s of [r.what, ...r.links.map((l) => l.query || '')]) {
    assert.doesNotMatch(s, /[‪-‮⁦-⁩\n\r]/, s.slice(0, 40));
    assert.ok(s.length <= 320, 'capped');
  }
  const q = r.links.find((l) => l.source === 'maker-site').query;
  assert.match(q, /\[U\+202E\]\[U\+000A\]/);
});
