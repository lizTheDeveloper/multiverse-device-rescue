'use strict';
// The Junkyard mini-game (storage and clutter): size-first cards, Keep / Clear / Later,
// crashes get "Update it" (a maker look-up), and the summary adds up the space Clear would free.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const root = path.join(__dirname, '..', 'renderer', 'missions');
const loadGame = () => import(pathToFileURL(path.join(root, 'games', 'junkyard.js')).href);
const loadContract = () => import(pathToFileURL(path.join(root, 'contract.js')).href);
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', name), 'utf8'));

async function setup() {
  const [G, C] = await Promise.all([loadGame(), loadContract()]);
  const items = (name) => fixture(name).findings.map((f) => C.makeItem(f));
  const byTitle = (list, re) => list.find((i) => re.test(i.finding.title));
  return { G, C, game: G.default, items, byTitle };
}

const ids = (d) => d.map((x) => x.id);
const pickId = (d, id) => d.find((x) => x.id === id);

test('passes every contract check for Mac and Windows fixtures and its practice items', async () => {
  const { C, game, items } = await setup();
  assert.deepStrictEqual(C.runContractChecks(game, items('junkyard-mac.json')), []);
  assert.deepStrictEqual(C.runContractChecks(game, items('junkyard-win.json')), []);
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode, platform: 'win32' });
    for (const item of items('junkyard-win.json')) {
      assert.deepStrictEqual(C.checkResearch(game.research(item, ctx)), [], item.key);
    }
  }
});

test('covers the storage, crash, energy and clutter checks on Mac and Windows', async () => {
  const { game } = await setup();
  const mods = game.covers.map((c) => c.module);
  for (const m of ['storage_cleanup', 'large_files_finder', 'library_cache_cleanup', 'browser_cache_cleanup', 'trash_cleanup',
    'docker_cleanup', 'xcode_cleanup', 'mail_attachment_cleanup', 'crash_log_analyzer', 'app_crash_analyzer',
    'energy_saver_check', 'energy_settings', 'resource_hog_identifier', 'system_log_errors', 'process_scanner',
    'win_disk_cleanup', 'win_temp_cleanup', 'win_temp_files', 'win_power_plan', 'win_pagefile', 'win_visual_effects',
    'win_bloatware', 'win_bsod_analysis', 'win_event_errors', 'temp_file_scanner']) {
    assert.ok(mods.includes(m), `covers ${m}`);
  }
  assert.strictEqual(new Set(mods).size, mods.length, 'each module once');
  // Shared or other games' modules are left to them.
  for (const m of ['startup_optimizer', 'win_startup', 'win_startup_programs_audit']) assert.ok(!mods.includes(m), m);
  // Every claimed module exists in the engine.
  const modulesDir = path.join(__dirname, '..', '..', 'modules');
  const all = new Set(fs.readdirSync(modulesDir).flatMap((cat) => {
    const p = path.join(modulesDir, cat);
    return fs.statSync(p).isDirectory() ? fs.readdirSync(p) : [];
  }));
  for (const m of mods) assert.ok(all.has(m), `engine module ${m} exists`);
});

test('space items: on a note Keep leads; on a warning the safe move leads and Keep goes last', async () => {
  const { C, game, items, byTitle } = await setup();
  const ctx = C.testContext();
  const m = items('junkyard-mac.json');
  const cache = byTitle(m, /4\.2 GB of caches/);
  // A cache rebuilds itself: Clear it leads on a warning.
  assert.deepStrictEqual(ids(game.decisions(cache, ctx)), ['clear', 'later', 'keep']);
  // Your own files (old downloads, the big total): Later leads, never Keep and never a clear.
  assert.deepStrictEqual(ids(game.decisions(byTitle(m, /12\.0 GB/), ctx)), ['later', 'clear', 'keep']);
  const note = { ...cache, severity: 'info', finding: { ...cache.finding, severity: 'info' } };
  const d = game.decisions(note, ctx);
  assert.deepStrictEqual(ids(d), ['keep', 'clear', 'later']);
  assert.strictEqual(d[0].effect.kind, 'keep');
  assert.strictEqual(d[2].effect.kind, 'later');
});

test('Clear uses the fix flow only when the engine offers a fix', async () => {
  const { C, game, items, byTitle } = await setup();
  const ctx = C.testContext();
  const trash = byTitle(items('junkyard-mac.json'), /Trash/);
  assert.notStrictEqual(pickId(game.decisions(trash, ctx), 'clear').effect.kind, 'fix');
  const offered = { ...trash, finding: { ...trash.finding, fixable: { will_change: 'Empties the Trash.', how_to_undo: ['Nothing to undo.'] } } };
  assert.strictEqual(pickId(game.decisions(offered, ctx), 'clear').effect.kind, 'fix');
});

test('without a fix, Clear gives real steps, and opens Storage settings where that is where it happens', async () => {
  const { C, game, items, byTitle } = await setup();
  const mac = C.testContext();
  const total = byTitle(items('junkyard-mac.json'), /12\.0 GB/);
  const e1 = pickId(game.decisions(total, mac), 'clear').effect;
  assert.strictEqual(e1.kind, 'settings');
  assert.strictEqual(e1.pane, 'storage');
  assert.ok(e1.steps.length >= 2);
  const safari = byTitle(items('junkyard-mac.json'), /Safari/);
  const e2 = pickId(game.decisions(safari, mac), 'clear').effect;
  assert.strictEqual(e2.kind, 'closer');
  assert.ok(e2.steps.some((s) => /Empty Caches/.test(s)), 'Safari steps');
  const docker = byTitle(items('junkyard-mac.json'), /Docker/);
  assert.ok(pickId(game.decisions(docker, mac), 'clear').effect.steps.some((s) => /docker system prune/.test(s)));
  const win = C.testContext({ platform: 'win32' });
  const temp = byTitle(items('junkyard-win.json'), /Temporary files/);
  const e3 = pickId(game.decisions(temp, win), 'clear').effect;
  assert.strictEqual(e3.kind, 'settings');
  assert.strictEqual(e3.pane, 'windows-storage');
  const winsxs = byTitle(items('junkyard-win.json'), /Component store/);
  assert.ok(pickId(game.decisions(winsxs, win), 'clear').effect.steps.some((s) => /Disk Cleanup/.test(s)));
});

test('crash items get Update it: a maker look-up intent, not Clear', async () => {
  const { C, game, items, byTitle } = await setup();
  const ctx = C.testContext();
  const mac = items('junkyard-mac.json');
  const crash = byTitle(mac, /SampleNotes/);
  const d = game.decisions(crash, ctx);
  assert.deepStrictEqual(ids(d), ['update', 'later', 'keep'], 'a warning leads with the look-up, Keep last');
  assert.deepStrictEqual(pickId(d, 'update').effect, { kind: 'link', link: { kind: 'lookup', source: 'web', query: '"SampleNotes" update' } });
  // A verified maker: look it up on the maker's site.
  const verified = byTitle(mac, /memory errors/);
  assert.deepStrictEqual(pickId(game.decisions(verified, ctx), 'update').effect.link, { kind: 'lookup', source: 'maker-site', query: 'SampleDraw', maker: 'Sample Studio Ltd' });
  // Parts of the system: Apple support.
  assert.strictEqual(pickId(game.decisions(byTitle(mac, /System processes/), ctx), 'update').effect.link.source, 'apple-support');
  // Windows blue screens: Microsoft support with the stop code.
  const bsod = byTitle(items('junkyard-win.json'), /crashed in the last 24 hours/);
  assert.deepStrictEqual(pickId(game.decisions(bsod, C.testContext({ platform: 'win32' })), 'update').effect.link, { kind: 'lookup', source: 'microsoft-support', query: 'stop code 0x0000SAMPLE' });
  // Research offers the update pane for the platform.
  assert.ok(game.research(crash, ctx).links.some((l) => l.kind === 'settings' && l.pane === 'software-update'));
  assert.ok(game.research(bsod, C.testContext({ platform: 'win32' })).links.some((l) => l.kind === 'settings' && l.pane === 'windows-update'));
});

test('settings and programs: Change it / Quit it / Remove it with the right pane or steps', async () => {
  const { C, game, items, byTitle } = await setup();
  const mac = C.testContext();
  const win = C.testContext({ platform: 'win32' });
  const m = items('junkyard-mac.json');
  const w = items('junkyard-win.json');
  const sleep = game.decisions(byTitle(m, /never goes to sleep/), mac);
  assert.deepStrictEqual(ids(sleep), ['change', 'later', 'keep']);
  assert.strictEqual(pickId(sleep, 'change').effect.pane, 'battery');
  assert.strictEqual(pickId(game.decisions(byTitle(m, /Display never/), mac), 'change').effect.pane, 'lock-screen');
  assert.ok(pickId(game.decisions(byTitle(w, /Power saver/), win), 'change').effect.steps.some((s) => /Balanced/.test(s)));
  assert.ok(pickId(game.decisions(byTitle(w, /Virtual memory/), win), 'change').effect.steps.some((s) => /Automatically manage paging file/.test(s)));
  assert.ok(pickId(game.decisions(byTitle(w, /Transparency/), win), 'change').effect.steps.some((s) => /Transparency effects/.test(s)));
  const hog = game.decisions(byTitle(m, /SampleRender/), mac);
  assert.deepStrictEqual(ids(hog), ['later', 'quit', 'keep']);
  assert.ok(pickId(hog, 'quit').effect.steps.some((s) => /Activity Monitor/.test(s)));
  const bloat = game.decisions(byTitle(w, /SampleGames/), win);
  assert.deepStrictEqual(ids(bloat), ['later', 'remove', 'keep']);
  assert.strictEqual(pickId(bloat, 'remove').effect.pane, 'windows-apps');
});

test('cards are size first, in both display modes', async () => {
  const { C, G, game, items, byTitle } = await setup();
  const m = items('junkyard-mac.json');
  const cache = byTitle(m, /4\.2 GB of caches/);
  assert.deepStrictEqual(G.headline(cache, 'standard'), { size: '4.2 GB', rest: 'of caches in your Library folder' });
  const html = game.render({ item: cache, research: game.research(cache, C.testContext()), decisions: [], index: 0, total: 1 }, C.testContext());
  assert.ok(html.indexOf('4.2 GB') < html.indexOf('of caches'), 'size comes first');
  assert.match(html, /Safe to clear/);
  const city = C.testContext({ mode: 'city' });
  const cityHtml = game.render({ item: cache, research: game.research(cache, city), decisions: [], index: 0, total: 1 }, city);
  assert.match(cityHtml, /4\.2 GB/);
  assert.match(cityHtml, /Scrap pile/);
  assert.doesNotMatch(cityHtml, /Safe to clear/);
  // Counts, not bytes, where the check counts things.
  assert.deepStrictEqual(G.headline(byTitle(m, /Docker/), 'standard'), { size: '17', rest: 'unused Docker images' });
  assert.strictEqual(G.headline(byTitle(m, /SampleNotes/), 'standard').size, '6');
  assert.strictEqual(G.headline(byTitle(m, /memory errors/), 'standard').size, '4');
  assert.strictEqual(G.headline(byTitle(items('junkyard-win.json'), /93% full/), 'standard').size, '93%');
});

test('a card from a check that did not finish says so', async () => {
  const { C, game, items } = await setup();
  const item = { ...items('junkyard-mac.json')[0], unfinished: true };
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const r = game.research(item, ctx);
    assert.strictEqual(r.unfinished, true);
    const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.match(html, /This check didn&#39;t finish/);
  }
});

test('research carries ctx.evidenceRows; the card leaves rows, buttons and links to the runner (R1)', async () => {
  const { C, game, items } = await setup();
  const calls = [];
  const rows = [{ label: 'Folder', value: 'ROW-VALUE-MARKER', mono: true }];
  const ctx = C.testContext({ evidenceRows: (f, o) => { calls.push(o.mode); return rows; } });
  const item = items('junkyard-mac.json')[1];
  const r = game.research(item, ctx);
  assert.deepStrictEqual(calls, ['standard']);
  assert.strictEqual(r.rows, rows);
  const d = game.decisions(item, ctx);
  const html = game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx);
  assert.doesNotMatch(html, /ROW-VALUE-MARKER/);
  assert.doesNotMatch(html, /<button|<a\b|href/);
  for (const x of d) assert.ok(!html.includes(`>${x.label.standard}<`), `no ${x.id} button`);
});

test('the biggest file shows by name only, escaped', async () => {
  const { C, game, items, byTitle } = await setup();
  const ctx = C.testContext();
  const dl = byTitle(items('junkyard-mac.json'), /Old downloads/);
  assert.match(game.render({ item: dl, research: game.research(dl, ctx), decisions: [], index: 0, total: 1 }, ctx), /Biggest file: <span class="jy-name">example-installer\.dmg<\/span>/);
  const evil = C.makeItem({ module: 'large_files_finder', title: 't', data: { type: 'desktop_files', size_bytes: 1, files: [{ path: '/x/<img src=x onerror=alert(1)>', size: 5 }] } });
  const html = game.render({ item: evil, research: game.research(evil, ctx), decisions: [], index: 0, total: 1 }, ctx);
  assert.deepStrictEqual(C.checkInert(html), []);
});

test('on an item with a removal warning, Later leads (never Keep, never an acting move) and acting effects carry warning: true (R6)', async () => {
  const { C, game, items, byTitle } = await setup();
  const ctx = C.testContext();
  const w = items('junkyard-win.json');
  for (const base of [byTitle(w, /SampleGames/), byTitle(w, /Temporary files/), byTitle(w, /crashed in the last/)]) {
    const item = { ...base, removal_alert: true };
    const d = game.decisions(item, ctx);
    assert.strictEqual(d[0].id, 'later');
    assert.deepStrictEqual(C.checkDecisions(d, item), []);
    for (const x of d) assert.strictEqual(x.effect.warning === true, !['keep', 'later'].includes(x.effect.kind), x.id);
  }
  // No warning flag on ordinary items.
  assert.ok(game.decisions(byTitle(w, /SampleGames/), ctx).every((x) => !x.effect.warning));
});

test('summary adds up the space the Clear choices would free, without counting a total twice', async () => {
  const { C, G, game, items, byTitle } = await setup();
  const m = items('junkyard-mac.json');
  const total = byTitle(m, /4\.2 GB of caches/); // library total: 4.2 GB
  const one = byTitle(m, /SampleSync/); // inside it: 1.5 GB
  const trash = byTitle(m, /Trash/); // 3.1 GB
  const mail = byTitle(m, /Mail/); // kept
  const results = [
    { item: total, decision: 'clear' },
    { item: one, decision: { id: 'clear' } },
    { item: trash, decisionId: 'clear' },
    { item: mail, decision: 'keep' },
    { item: byTitle(m, /SampleNotes/), decision: 'later' },
  ];
  assert.strictEqual(G.freedBytes(results), 4509715660 + 3328599654);
  const s = game.summary(results, C.testContext());
  assert.match(s, /7\.3 GB/);
  assert.match(s, /your Clear choices would free/);
  assert.match(s, /An estimate/);
  assert.match(s, /1 kept/);
  assert.match(s, /1 for later/);
  assert.doesNotMatch(s, /all clear/i);
  const city = game.summary(results, C.testContext({ mode: 'city' }));
  assert.match(city, /7\.3 GB/);
  assert.match(city, /haul-off/);
  assert.deepStrictEqual(C.checkCityWords(city), []);
  // Nothing cleared: no number made up.
  assert.match(game.summary([{ item: mail, decision: 'keep' }], C.testContext()), /Nothing cleared this round/);
  // Clear on a crash or a full drive frees nothing countable.
  assert.strictEqual(G.freedBytes([{ item: byTitle(items('junkyard-win.json'), /93% full/), decision: 'clear' }]), 0);
});

test('practice: a browser cache, a video you made, an app that keeps crashing', async () => {
  const { C, game } = await setup();
  const p = game.practice;
  assert.strictEqual(p.items.length, 3);
  assert.deepStrictEqual(p.items.map((i) => i.finding.module), ['browser_cache_cleanup', 'large_files_finder', 'app_crash_analyzer']);
  const ctx = C.testContext();
  const expected = p.script.filter((s) => s.expect).map((s) => [s.item, s.expect]);
  assert.deepStrictEqual(expected, [[0, 'clear'], [1, 'keep'], [2, 'update']]);
  for (const [i, want] of expected) assert.ok(ids(game.decisions(p.items[i], ctx)).includes(want), `item ${i} offers ${want}`);
  for (const s of p.script) {
    assert.ok(s.say.standard && s.say.city);
    assert.deepStrictEqual(C.checkCityWords(s.say.city), []);
    assert.ok(!/minute|second|hour|quick/i.test(s.say.standard + s.say.city), 'no time words');
  }
  // The step's part is highlighted.
  const html = game.render({ item: p.items[0], research: game.research(p.items[0], ctx), decisions: [], index: 0, total: 3, practice: true, step: p.script[0] }, ctx);
  assert.match(html, /jy-head jy-look/);
  assert.match(html, /Start with the size/);
  // Synthetic only: no real home folders.
  assert.doesNotMatch(JSON.stringify(p.items), /\/Users\//);
});

test('labels stay short and words stay calm, with no time estimates', async () => {
  const { C, game, items } = await setup();
  const all = [...items('junkyard-mac.json'), ...items('junkyard-win.json'), ...game.practice.items];
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    for (const item of all) {
      const d = game.decisions(item, ctx);
      for (const x of d) {
        assert.ok(x.label[mode].split(/\s+/).length <= 4);
        for (const s of x.effect.steps || []) assert.ok(!/\b(minutes?|seconds?|hours?|quickly)\b/i.test(s), s);
      }
      const html = game.render({ item, research: game.research(item, ctx), decisions: d, index: 0, total: 1 }, ctx);
      assert.ok(!/\b(minutes?|seconds?|hours?|quickly)\b/i.test(html.replace(/<[^>]+>/g, '').replace(/in the last 24 hours/g, '')), item.key);
    }
  }
});

test('the game module is pure: no DOM, storage, clipboard, network or globals', async () => {
  const src = fs.readFileSync(path.join(root, 'games', 'junkyard.js'), 'utf8');
  for (const re of [/\bdocument\b/, /\bwindow\b/, /localStorage|sessionStorage|indexedDB/, /clipboard/, /\bfetch\(/, /XMLHttpRequest/, /globalThis/, /\bimport\s*\(/, /^import /m, /href=/]) {
    assert.doesNotMatch(src, re, String(re));
  }
});
