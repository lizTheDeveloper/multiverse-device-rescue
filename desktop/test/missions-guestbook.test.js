'use strict';
// The Guest Book (remote-access tools, the Think Back walk-through): missions/games/guestbook.js.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { execFileSync } = require('child_process');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const FIXTURE = path.join(__dirname, 'fixtures', 'missions', 'guestbook-items.json');

async function load() {
  const C = await import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
  const mod = await import(pathToFileURL(path.join(MISSIONS, 'games', 'guestbook.js')).href);
  const fixtures = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')).findings;
  const items = fixtures.map((f) => C.makeItem(f));
  const by = (tool) => items.find((i) => i.finding.data.tool === tool);
  const several = items.find((i) => i.finding.data.check === 'several_tools');
  return { C, mod, game: mod.default, items, by, several };
}
const ids = (ds) => ds.map((d) => d.id);
const byId = (ds, id) => ds.find((d) => d.id === id);
const ctxOf = (C, extra = {}) => C.testContext({ today: '2026-10-22', ...extra });
const STAGES = ['offline', 'q1', 'q2', 'q3', 'q4', 'mine', 'notneeded', 'scam', 'known', 'unsure'];
// Answers that reach each stage, for an item that isn't running (prefix 'continue' when it is).
const PATHS = {
  q1: [], q2: ['installed'], q3: ['helped'], q4: ['dontknow'],
  mine: ['installed', 'use'], notneeded: ['installed', 'nouse'], scam: ['helped', 'contacted'], known: ['helped', 'knows'], unsure: ['dontknow', 'no'],
};
const answersFor = (item, stage) => (stage === 'offline' ? [] : [...(item.finding.data.running_now === true ? ['continue'] : []), ...PATHS[stage]]);
const RELATIONSHIP = /partner|\bex\b|abuser|stalk|\bspy\b/i;
const view = (game, item, ctx, extra = {}) => ({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1, answers: ctx.answers || [], ...extra });

test('every path reaches its outcome', async () => {
  const { mod, by } = await load();
  const item = by('AnyDesk');
  const want = [
    [['installed', 'use'], 'mine'], [['installed', 'nouse'], 'notneeded'], [['helped', 'asked'], 'mine'],
    [['helped', 'contacted'], 'scam'], [['helped', 'knows'], 'known'], [['dontknow', 'yes'], 'scam'],
    [['dontknow', 'no'], 'unsure'], [['dontknow', 'notsure'], 'unsure'],
  ];
  for (const [a, stage] of want) assert.strictEqual(mod.stageOf(item, a), stage, a.join(','));
  assert.strictEqual(mod.stageOf(item, []), 'q1');
  assert.strictEqual(mod.stageOf(item, ['installed']), 'q2');
  assert.strictEqual(mod.stageOf(item, ['helped']), 'q3');
  assert.strictEqual(mod.stageOf(item, ['dontknow']), 'q4');
  // An unknown answer never jumps ahead.
  assert.strictEqual(mod.stageOf(item, ['zap']), 'q1');
  assert.strictEqual(mod.stageOf(item, ['installed', 'zap']), 'q2');
});

test('each answer is a question step (ask) until the outcome', async () => {
  const { C, game, by } = await load();
  const item = by('AnyDesk');
  for (const stage of ['q1', 'q2', 'q3', 'q4']) {
    const d = game.decisions(item, ctxOf(C, { answers: answersFor(item, stage) }));
    assert.ok(d.every((x) => x.effect.kind === 'ask'), stage);
  }
  assert.deepStrictEqual(ids(game.decisions(item, ctxOf(C))), ['installed', 'helped', 'dontknow']);
  assert.deepStrictEqual(ids(game.decisions(item, ctxOf(C, { answers: ['installed'] }))), ['use', 'nouse']);
  assert.deepStrictEqual(ids(game.decisions(item, ctxOf(C, { answers: ['helped'] }))), ['asked', 'contacted', 'knows']);
  assert.deepStrictEqual(ids(game.decisions(item, ctxOf(C, { answers: ['dontknow'] }))), ['yes', 'no', 'notsure']);
});

test('offline comes first only when running and unanswered', async () => {
  const { C, mod, game, by } = await load();
  const running = by('RustDesk');
  assert.strictEqual(mod.stageOf(running, []), 'offline');
  const d = game.decisions(running, ctxOf(C));
  assert.deepStrictEqual(ids(d), ['offline', 'continue']);
  assert.strictEqual(d[0].effect.kind, 'settings');
  assert.strictEqual(d[0].effect.pane, 'network');
  assert.ok(d[0].effect.steps.standard.length >= 2);
  assert.strictEqual(d[1].effect.kind, 'ask');
  assert.strictEqual(mod.stageOf(running, ['continue']), 'q1');
  assert.strictEqual(mod.stageOf(running, ['continue', 'installed', 'use']), 'mine');
  const html = game.render(view(game, running, ctxOf(C)), ctxOf(C));
  assert.ok(html.indexOf('Running now') < html.indexOf('Added on'), 'the card says it first');
  // Not running, or running unknown: no offline step.
  assert.strictEqual(mod.stageOf(by('AnyDesk'), []), 'q1');
  assert.strictEqual(mod.stageOf(by('TeamViewer'), []), 'q1');
  // The research offers the network settings while it's running.
  assert.ok(game.research(running, ctxOf(C)).links.some((l) => l.kind === 'settings' && l.pane === 'network'));
});

test('q1 names the added date; undated says "Think back." with no date', async () => {
  const { C, game, by } = await load();
  const dated = game.render(view(game, by('AnyDesk'), ctxOf(C)), ctxOf(C));
  assert.match(dated, /Think back to around March 3\. How did this get here\?/);
  assert.match(dated, /Added on March 3/);
  assert.match(dated, /Last let someone in: March 12 \(4 times\)/);
  assert.match(dated, /Can let someone in without you clicking yes/);
  const undated = game.render(view(game, by('TeamViewer'), ctxOf(C)), ctxOf(C));
  assert.match(undated, /Think back\. How did this get here\?/);
  assert.doesNotMatch(undated, /Think back to around/);
  assert.match(undated, /Couldn’t tell when this was added/);
  assert.match(undated, /Couldn’t tell when it last let someone in/);
  assert.match(undated, /Couldn’t tell if it’s running now/);
  // The year shows when it isn't this year's.
  const old = game.render(view(game, by('Zoho Assist'), ctxOf(C)), ctxOf(C));
  assert.match(old, /Added on November 20, 2025/);
  assert.match(old, /Made by Zoho Corporation \(checked\)/);
});

test('known outcome: every effect unpaid, no fix, no removing decision', async () => {
  const { C, game, items } = await load();
  for (const item of items.filter((i) => i.finding.data.check !== 'several_tools')) {
    for (const mode of ['standard', 'city']) {
      const d = game.decisions(item, ctxOf(C, { mode, answers: answersFor(item, 'known') }));
      assert.ok(d.length >= 2);
      assert.ok(d.every((x) => x.effect.unpaid === true), `${item.key}: unpaid`);
      assert.ok(!d.some((x) => x.effect.kind === 'fix' || x.effect.kind === 'recheck' || x.effect.warning === true), 'no removal offered');
      const steps = d.flatMap((x) => (x.effect.steps ? x.effect.steps[mode] : [])).join(' ');
      if (mode === 'standard') {
        assert.match(steps, /advocate/);
        assert.match(steps, /1-800-799-7233/);
        assert.match(steps, /88788/);
        assert.match(steps, /dates/);
      } else assert.deepStrictEqual(C.checkCityWords(steps), []);
    }
  }
});

test('notneeded and scam: removal is never first and carries warning', async () => {
  const { C, game, items } = await load();
  for (const item of items.filter((i) => i.finding.data.check !== 'several_tools')) {
    for (const stage of ['notneeded', 'scam']) {
      for (const fixable of [false, true]) {
        const it = fixable ? C.makeItem({ ...item.finding, fixable: { will_change: 'Removes it.', how_to_undo: ['Install it again.'] } }) : item;
        const d = game.decisions(it, ctxOf(C, { answers: answersFor(it, stage) }));
        const rm = byId(d, 'remove');
        assert.ok(rm, `${stage}: a way to remove it`);
        assert.notStrictEqual(d[0].id, 'remove', `${stage}: removal never leads`);
        assert.ok(!C.REMOVING_KINDS.has(d[0].effect.kind));
        if (fixable) assert.strictEqual(rm.effect.kind, 'fix', 'the engine’s fix, whose confirm shows the warning');
        else {
          assert.strictEqual(rm.effect.kind, 'closer');
          assert.strictEqual(rm.effect.warning, true, 'the removal warning first');
        }
      }
    }
    const nn = game.decisions(item, ctxOf(C, { answers: answersFor(item, 'notneeded') }));
    assert.strictEqual(nn[0].id, 'later');
    assert.deepStrictEqual(byId(nn, 'did').effect, { kind: 'recheck', module: 'remote_access_tools' });
    const scam = game.decisions(item, ctxOf(C, { answers: answersFor(item, 'scam') }));
    const now = scam[0].effect.steps.standard;
    assert.match(now[0], /another phone or computer.*bank.*number on your card/i);
    assert.match(now[1], /email password/i);
    assert.match(now[2], /second one/);
    assert.match(now[3], /Report/);
  }
});

test('played through the runner: answers stay on the item, BACK undoes one, and the scam steps keep the removal second', async () => {
  const { C, game, by } = await load();
  const Run = await import(pathToFileURL(path.join(MISSIONS, 'runner.js')).href);
  const ctx = ctxOf(C);
  let run = Run.startRun({ id: 'guestbook:gatehouse:1', type: 'guestbook', items: [by('RustDesk'), by('AnyDesk')] });
  assert.deepStrictEqual(ids(Run.viewFor(run, game, ctx, {}).decisions), ['offline', 'continue']);
  for (const a of ['continue', 'helped', 'contacted']) run = Run.choose(run, a, game, ctx).run;
  assert.strictEqual(run.index, 0);
  assert.deepStrictEqual(run.answers[by('RustDesk').key], ['continue', 'helped', 'contacted']);
  assert.strictEqual(Run.doneCount(run), 0, 'questions record nothing');
  run = Run.unask(run);
  assert.deepStrictEqual(ids(Run.viewFor(run, game, ctx, {}).decisions), ['asked', 'contacted', 'knows']);
  run = Run.choose(run, 'contacted', game, ctx).run;
  run = Run.choose(run, 'closer', game, ctx).run;
  const v = Run.viewFor(run, game, ctx, {});
  assert.ok(v.guide && v.guide.steps.length === 4, 'the scam steps are on screen');
  assert.deepStrictEqual(ids(v.decisions), ['later', 'remove', 'did'], 'the removal still isn’t first; then a recheck');
  const r = Run.choose(run, 'remove', game, ctx);
  assert.strictEqual(r.run.phase, 'confirm', 'the removal warning first');
  assert.strictEqual(Run.viewFor(r.run, game, ctx, {}).warning, Run.REMOVAL_WARNING);
  // Removed by hand: the recheck (which also looks for a second tool) confirms it, and pays the confirmed bonus.
  const did = Run.choose(run, 'did', game, ctx);
  assert.deepStrictEqual(did.act && [did.act.kind, did.act.modules], ['recheck', ['remote_access_tools']]);
  const settled = Run.settle(did.run, 'done');
  assert.strictEqual(settled.results.length, 1);
  assert.strictEqual(settled.results[0].decision, 'did');
  assert.strictEqual(settled.results[0].effect.kind, 'recheck', 'a recheck: what the confirmed bonus pays for (missions-city.js)');
  // Someone I know: answered, and unpaid, so never remembered.
  run = Run.startRun({ id: 'guestbook:gatehouse:1', type: 'guestbook', items: [by('AnyDesk')] });
  for (const a of ['helped', 'knows', 'talk']) run = Run.choose(run, a, game, ctx).run;
  assert.strictEqual(run.results[0].effect.unpaid, true);
  assert.strictEqual(Run.remembers(run.results[0]), false);
});

test('scam: before its steps are open, Do these now / Later / Remove it; after, Later / Remove it / I removed it', async () => {
  const { C, game, items } = await load();
  for (const item of items.filter((i) => i.finding.data.check !== 'several_tools')) {
    const answers = answersFor(item, 'scam');
    const before = game.decisions(item, ctxOf(C, { answers }));
    assert.deepStrictEqual(ids(before), ['closer', 'later', 'remove']);
    const after = game.decisions(item, ctxOf(C, { answers, closer: true }));
    assert.deepStrictEqual(ids(after), ['later', 'remove', 'did']);
    assert.deepStrictEqual(byId(after, 'did').effect, { kind: 'recheck', module: 'remote_access_tools' });
    for (const d of [before, after]) assert.deepStrictEqual(C.checkDecisions(d, item).filter((p) => !/removal warning/.test(p)), []);
  }
});

test('scam links are lookup/lesson intents only', async () => {
  const { C, game, by } = await load();
  const item = by('AnyDesk');
  for (const mode of ['standard', 'city']) {
    const r = game.research(item, ctxOf(C, { mode, answers: answersFor(item, 'scam') }));
    assert.deepStrictEqual(C.checkResearch(r), []);
    assert.ok(r.links.every((l) => l.kind === 'lookup' || l.kind === 'lesson' || l.kind === 'settings'));
    assert.ok(!r.links.some((l) => 'url' in l || 'href' in l));
    // One report search: research.js shows one look-up per label, so it must be the only one (it survives).
    const R = await import(pathToFileURL(path.join(MISSIONS, 'research.js')).href);
    const shown = R.resolveLinks(r.links, { mode, platform: 'darwin' }).filter((l) => l.kind === 'lookup');
    assert.strictEqual(shown.length, 1);
    assert.match(mode === 'city' ? shown[0].text : decodeURIComponent(shown[0].url).replace(/\+/g, ' '), /report a tech support scam/);
    const steps = game.decisions(item, ctxOf(C, { mode, answers: answersFor(item, 'scam') }))[0].effect.steps.standard.join(' ');
    for (const who of ['FTC', 'Action Fraud', 'Canadian Anti-Fraud Centre']) assert.match(steps, new RegExp(who));
    assert.ok(r.links.some((l) => l.kind === 'lesson' && l.concept === 'remote-access-scams'));
  }
  // Only the scam outcome carries the report look-ups.
  const q1 = game.research(item, ctxOf(C)).links.filter((l) => l.kind === 'lookup' && /report/i.test(l.query));
  assert.deepStrictEqual(q1, []);
});

test('labels ≤ 4 words, 2–3 decisions at every stage', async () => {
  const { C, game, items, several } = await load();
  for (const item of items) {
    for (const stage of STAGES) {
      if (stage === 'offline' && item.finding.data.running_now !== true) continue;
      for (const mode of ['standard', 'city']) for (const platform of ['darwin', 'win32']) {
        const ctx = ctxOf(C, { mode, platform, answers: item === several ? [] : answersFor(item, stage) });
        const d = game.decisions(item, ctx);
        assert.deepStrictEqual(C.checkDecisions(d, item), [], `${item.key} ${stage} ${mode}`);
        assert.deepStrictEqual(C.checkResearch(game.research(item, ctx)), [], `${item.key} ${stage}`);
        assert.ok(d.every((x) => x.id !== 'remove') || d[0].id !== 'remove');
      }
    }
  }
});

test('more than one tool: its own card names them, and each tool’s card names the others', async () => {
  const { C, mod, game, items, several, by } = await load();
  assert.strictEqual(mod.stageOf(several, []), 'several');
  const ctx = ctxOf(C);
  const d = game.decisions(several, ctx);
  assert.strictEqual(d[0].id, 'closer');
  assert.ok(d.some((x) => x.effect.kind === 'recheck' && x.effect.module === 'remote_access_tools'));
  const html = game.render(view(game, several, ctx), ctx);
  for (const t of ['AnyDesk', 'TeamViewer', 'RustDesk']) assert.match(html, new RegExp(t));
  // After one is removed and checked again, the card of the one left names the other.
  const left = game.render(view(game, by('AnyDesk'), ctx, { siblings: items.filter((i) => i !== by('AnyDesk')) }), ctx);
  assert.match(left, /Also on this computer: TeamViewer, RustDesk, Zoho Assist/);
});

test('contract checks pass, with hostile values escaped in render', async () => {
  const { C, game, items } = await load();
  assert.deepStrictEqual(C.runContractChecks(game, items), []);
  for (const h of C.HOSTILE) {
    const f = { module: 'remote_access_tools', code: 'security.remote_access_tools.tool_found', title: h, removal_alert: true,
      data: { check: 'tool_found', tool: h, path: h, added_on: h, last_incoming: h, incoming_count: 2, running_now: true, tools: [h] },
      made_by: [{ subject: h, name: h, verified: true }] };
    for (const mode of ['standard', 'city']) {
      const item = C.makeItem(f);
      for (const answers of [[], ['continue'], ['continue', 'helped', 'contacted'], ['continue', 'helped', 'knows']]) {
        const ctx = ctxOf(C, { mode, answers });
        const html = game.render(view(game, item, ctx), ctx);
        assert.deepStrictEqual(C.checkInert(html), [], `${mode} ${JSON.stringify(h)}`);
        assert.deepStrictEqual(C.checkResearch(game.research(item, ctx)), []);
      }
    }
  }
});

test('no relationship words on any standard screen except the known outcome’s advocate steps', async () => {
  const { C, game, items } = await load();
  for (const item of items) {
    for (const stage of STAGES) {
      if (stage === 'offline' && item.finding.data.running_now !== true) continue;
      for (const platform of ['darwin', 'win32']) {
        const ctx = ctxOf(C, { platform, answers: answersFor(item, stage) });
        const d = game.decisions(item, ctx);
        const r = game.research(item, ctx);
        const text = [game.render(view(game, item, ctx), ctx), r.what, ...d.map((x) => x.label.standard),
          ...d.flatMap((x) => [...(x.effect.steps ? x.effect.steps.standard : []), x.hint || ''])].join(' ');
        assert.doesNotMatch(text, RELATIONSHIP, `${item.key} ${stage}`);
        // The helpline words are only on the known outcome's steps.
        if (stage !== 'known') assert.doesNotMatch(text, /advocate|799-7233|88788/, `${item.key} ${stage}`);
      }
    }
  }
  for (const p of [game.practice, game.practiceByPlatform.win32]) {
    for (const st of p.script) assert.doesNotMatch(`${st.say.standard} ${(st.why && st.why.standard) || ''}`, RELATIONSHIP);
  }
});

test('CITY_FORBIDDEN passes in city render', async () => {
  const { C, game, items } = await load();
  for (const item of [...items, ...game.practice.items]) {
    for (const stage of STAGES) {
      if (stage === 'offline' && item.finding.data.running_now !== true) continue;
      const ctx = ctxOf(C, { mode: 'city', answers: answersFor(item, stage) });
      const d = game.decisions(item, ctx);
      const r = game.research(item, ctx);
      const text = [game.render(view(game, item, ctx), ctx), r.what, ...d.map((x) => x.label.city),
        ...d.flatMap((x) => (x.effect.steps ? x.effect.steps.city : []))].join(' ');
      assert.deepStrictEqual(C.checkCityWords(text), [], `${item.key} ${stage}`);
    }
  }
  const s = game.summary([{ decision: 'talk', effect: { kind: 'closer', unpaid: true } }], ctxOf(C, { mode: 'city' }));
  assert.deepStrictEqual(C.checkCityWords(s), []);
});

test('date of 2026-03-03 renders March 3 in any timezone', () => {
  const script = `import(${JSON.stringify(pathToFileURL(path.join(MISSIONS, 'day.js')).href)}).then((D) => {
    process.stdout.write(JSON.stringify([D.dayWords('2026-03-03', { today: '2026-10-22' }), D.dayWords('2026-03-03T23:30:00+00:00', { today: '2026-10-22' }), D.dayWords('2026-02-31')]));
  });`;
  for (const TZ of ['America/Los_Angeles', 'Pacific/Kiritimati', 'UTC']) {
    const out = JSON.parse(execFileSync(process.execPath, ['-e', script], { env: { ...process.env, TZ, LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' } }).toString());
    assert.deepStrictEqual(out, ['March 3', 'March 3', ''], TZ);
  }
});

test('practice and win32 practice have the same step count and each expect is offered', async () => {
  const { C, game } = await load();
  const win = game.practiceByPlatform.win32;
  assert.strictEqual(win.script.length, game.practice.script.length);
  assert.strictEqual(game.practice.script.length, 3);
  for (const [p, platform] of [[game.practice, 'darwin'], [win, 'win32']]) {
    assert.deepStrictEqual(p.script.map((s) => [s.item, s.answers, s.expect]),
      [[0, [], 'dontknow'], [0, ['dontknow'], 'yes'], [1, ['installed'], 'use']]);
    for (const st of p.script) {
      const d = game.decisions(p.items[st.item], ctxOf(C, { platform, practice: true, answers: st.answers }));
      assert.ok(ids(d).includes(st.expect), `${platform}: ${st.expect} is offered`);
    }
    assert.strictEqual(p.items[0].finding.data.tool, 'TeamViewer');
    assert.strictEqual(p.items[0].finding.data.added_on, '2026-03-03');
    assert.strictEqual(p.items[0].finding.data.lets_in_unattended, true);
    assert.strictEqual(p.items[1].finding.data.tool, 'RustDesk');
  }
  assert.match(win.items[0].finding.data.path, /^C:\\/);
  assert.deepStrictEqual(C.validateGame(game), []);
});

test('no double claims', async () => {
  const { C, game } = await load();
  const I = await import(pathToFileURL(path.join(MISSIONS, 'games', 'index.js')).href);
  const reg = await I.loadGames();
  assert.ok(reg.own.has('guestbook'));
  assert.deepStrictEqual(reg.problems, []);
  assert.deepStrictEqual(C.noDoubleClaims(I.ownGames(reg)), []);
  assert.deepStrictEqual(game.covers, [{ module: 'remote_access_tools' }]);
  const T = await import(pathToFileURL(path.join(MISSIONS, 'types.js')).href);
  assert.deepStrictEqual(T.doubleClaims(T.buildTable(I.ownGames(reg))), []);
  assert.strictEqual(T.typeOf({ module: 'remote_access_tools', code: 'security.remote_access_tools.tool_found', severity: 'warning' }, T.buildTable(I.ownGames(reg))), 'guestbook');
  assert.strictEqual(T.typeOf({ module: 'remote_access_tools', severity: 'warning' }), 'guestbook', 'the base table too');
  assert.deepStrictEqual(T.TYPE_TITLES.guestbook, { standard: 'Remote access', city: 'The Guest Book' });
  assert.strictEqual(T.IMPORTANCE.indexOf('guestbook'), T.IMPORTANCE.indexOf('locker') + 1);
  assert.ok(C.TYPE_IDS.indexOf('guestbook') < C.TYPE_IDS.indexOf('switchboard'));
  // Its look lives in its own stylesheet.
  assert.ok(fs.existsSync(path.join(MISSIONS, 'games', 'guestbook.css')));
});

test('render draws only the card: no buttons, links or evidence rows (the runner draws those)', async () => {
  const { C, game, items } = await load();
  const rows = [{ label: 'Program', value: 'ROWVALUE' }];
  for (const item of items) {
    const ctx = ctxOf(C, { evidenceRows: () => rows });
    const html = game.render(view(game, item, ctx), ctx);
    assert.doesNotMatch(html, /<button|<a\b|href=|ROWVALUE/, item.key);
  }
});

test('summary says what was decided, and that an unpaid answer earns nothing on purpose', async () => {
  const { C, game } = await load();
  const s = game.summary([{ decision: 'mine', effect: { kind: 'mark' }, points: 5 }, { decision: 'talk', effect: { kind: 'closer', unpaid: true }, points: 0 },
    { decision: 'later', effect: { kind: 'later' }, points: 0 }], ctxOf(C));
  assert.match(s, /3 remote-access tools/);
  assert.match(s, /1 saved for later/);
  assert.match(s, /no points/i);
  assert.doesNotMatch(game.summary([], ctxOf(C)), /no points/i);
});

test('a tool that is running now is the first card of its mission, before worse ones (nothing else shows while someone may watch)', async () => {
  const T = await import(pathToFileURL(path.join(MISSIONS, 'types.js')).href);
  const findings = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')).findings.map(({ module, ...f }) => f);
  const doc = { schema_version: 1, platform: 'darwin', modules: [
    { name: 'remote_access_tools', category: 'security', status: 'ok', error: null, supported: true, findings }] };
  const gb = T.groupMissions(doc, { mode: 'standard' }).find((m) => m.type === 'guestbook');
  assert.ok(gb, 'a Remote access mission');
  assert.strictEqual(gb.items[0].finding.data.tool, 'RustDesk', 'the running tool leads, though AnyDesk is critical');
  assert.strictEqual(gb.items.filter((i) => i.finding.data.running_now === true).length, 1);
});

test('Not sure: a tool the card says has no way in without a click is never told to turn that off', async () => {
  const { C, game, by } = await load();
  const rust = by('RustDesk');
  assert.strictEqual(rust.finding.data.lets_in_unattended, false);
  for (const mode of ['standard', 'city']) {
    const ctx = ctxOf(C, { mode, answers: answersFor(rust, 'unsure') });
    const d = game.decisions(rust, ctx);
    assert.ok(!ids(d).includes('unattended'), `${mode}: ${ids(d)}`);
    assert.ok(ids(d).includes('connections'));
    const html = game.render(view(game, rust, ctx), ctx);
    assert.doesNotMatch(html, /unattended access|side door/i, mode);
  }
  // Can, or couldn't tell: the step stays.
  for (const tool of ['AnyDesk', 'TeamViewer']) {
    const item = by(tool);
    const ctx = ctxOf(C, { answers: answersFor(item, 'unsure') });
    assert.ok(ids(game.decisions(item, ctx)).includes('unattended'), tool);
    assert.match(game.render(view(game, item, ctx), ctx), /unattended access/, tool);
  }
});

test('Go offline first: the steps describe the settings page the button opens, on Mac and Windows', async () => {
  const { C, game, by } = await load();
  const R = await import(pathToFileURL(path.join(MISSIONS, 'research.js')).href);
  const rust = by('RustDesk');
  const PAGE = { darwin: /Network settings/, win32: /Network & internet settings/ };
  const SWITCH = { darwin: /Wi-Fi/, win32: /Airplane mode/ };
  for (const platform of ['darwin', 'win32']) {
    for (const mode of ['standard', 'city']) {
      const d = game.decisions(rust, ctxOf(C, { mode, platform }));
      const off = byId(d, 'offline');
      assert.strictEqual(off.effect.kind, 'settings');
      assert.strictEqual(off.effect.pane, 'network');
      assert.ok(R.PANE_URLS.network[platform], `${platform}: the network pane opens`);
      const steps = off.effect.steps[mode].join(' ');
      if (mode === 'standard') assert.match(steps, PAGE[platform], `${platform}: names the page that opens`);
      assert.match(steps, SWITCH[platform], `${platform} ${mode}`);
      assert.doesNotMatch(steps, /Control Center|Quick Settings/, `${platform} ${mode}: not a different place than the one that opened`);
    }
  }
});
