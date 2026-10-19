const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');
const fs = require('node:fs');
const path = require('node:path');

const NOW = '2026-10-18T12:00:00.000Z';
const TIME_WORDS = /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i;
const load = async () => {
  const [views, pp, ib, pub] = await Promise.all([
    Promise.all([import('../renderer/game/views/profile.js'), import('../renderer/game/views/profile-core.js')]).then(([a, b]) => ({ ...a, ...b })),
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
    import('../renderer/game/profile/publish.js'),
  ]);
  const bank = ib.buildBank(LESSONS, DRILLS);
  let p = pp.salvage(V3, NOW).profile;
  p = pp.recordAnswer(p, bank, 'b1', true, NOW);
  p = pp.markKnown(p, ['where-it-lives'], NOW);
  for (let i = 0; i < 3; i += 1) p = pp.recordDrillCall(p, bank, DRILLS[1], 'threat', `${NOW}${i}`);
  return { ...views, pub, summary: pp.summary(p, bank) };
};

test('both themes show rank, lessons, drills and city counts (skills in the game), with a heading the section is named by', async () => {
  const { renderProfile, summary } = await load();
  for (const theme of ['game', 'plain']) {
    const html = renderProfile({ summary, theme });
    assert.match(html, /aria-labelledby="profile-title"/);
    assert.match(html, /<h2 id="profile-title" tabindex="-1">/);
    assert.ok(html.includes('Lesson A') && html.includes('Lesson B'));
    if (theme === 'game') {
      assert.ok(html.includes('Honest results'));
      assert.match(html, /<span>[^<]+ \(step [123] of 3\)<\/span>/, 'the meter has a text equivalent');
    } else {
      // P3-34: Skills repeats Lessons, and none can be started from Plain view: it says where they are.
      assert.ok(!html.includes('Honest results') && !/<h3 class="label">Skills</.test(html));
      assert.ok(html.includes('Lessons are played in the city view.'));
    }
    assert.ok(!html.includes('Developer packages'), 'a skill with nothing to measure in this bank is left out');
    assert.ok(html.includes('1 set aside for later'));
    assert.doesNotMatch(html, TIME_WORDS);
  }
  assert.ok(renderProfile({ summary, theme: 'plain' }).includes('340 points (level 3 of 5)'));
  assert.ok(renderProfile({ summary, theme: 'game' }).includes('NETRUNNER'));
});

test('calibration is said kindly, and only with enough calls behind it', async () => {
  const { renderProfile, summary } = await load();
  assert.ok(renderProfile({ summary }).includes('You flag things as threats more often than they are (3 times).'));
  const few = { ...summary, drills: { ...summary.drills, total: 2, over: 2, under: 0 } };
  assert.ok(!renderProfile({ summary: few }).includes('more often than they are'));
});

test('game rows open their lesson; plain rows have no button (no lesson host there yet)', async () => {
  const { renderProfile, summary } = await load();
  assert.match(renderProfile({ summary, theme: 'game' }), /data-go="lesson:lesson-a"/);
  assert.doesNotMatch(renderProfile({ summary, theme: 'plain' }), /data-go="lesson:/);
});

test('the publish control is absent unless offered', async () => {
  const { renderProfile, createProfileRenderer, summary } = await load();
  assert.doesNotMatch(renderProfile({ summary }), /profile-publish/);
  assert.match(createProfileRenderer(true)({ summary, publish: true }), /data-act="profile-publish"/);
  assert.doesNotMatch(createProfileRenderer(true)({ summary }), /profile-publish/);
});

test('titles are escaped', async () => {
  const { renderProfile, summary } = await load();
  const evil = { ...summary, lessons: [{ ...summary.lessons[0], title: '<img src=x onerror=alert(1)>' }] };
  assert.ok(!renderProfile({ summary: evil }).includes('<img src=x'));
});

test('the consent sheet: every box unticked to start, the exact payload previewed, nothing to save until one is ticked', async () => {
  const { createPublishSheet, summary, pub } = await load();
  const renderPublishSheet = createPublishSheet(true);
  const empty = renderPublishSheet({ summary });
  assert.doesNotMatch(empty, /checked/);
  assert.match(empty, /data-act="publish-save" disabled/);
  assert.ok(empty.includes(pub.STAYS_HERE));
  assert.strictEqual((empty.match(/type="checkbox"/g) || []).length, pub.PUBLISH_FIELDS.length);
  assert.strictEqual((empty.match(/<label for="pub-/g) || []).length, pub.PUBLISH_FIELDS.length, 'every box has a label');
  const payload = pub.buildPayload(summary, ['lessons'], { mode: 'standard', now: NOW });
  const one = renderPublishSheet({ summary, ticked: ['lessons'], payload });
  assert.match(one, /id="pub-lessons" data-act="pub-toggle:lessons" checked/);
  assert.ok(one.includes('city_lessons_learned'));
  assert.doesNotMatch(one, /data-act="publish-save" disabled/);
});

test('Start over asks first, and says nothing on the computer changes', async () => {
  const { renderProfile, summary, START_OVER } = await load();
  assert.doesNotMatch(renderProfile({ summary }), /profile-start-over-yes/);
  const html = renderProfile({ summary, confirming: true });
  assert.ok(html.includes(START_OVER));
  assert.match(html, /role="alertdialog"/);
  assert.match(html, /data-act="profile-start-over-yes"/);
  assert.match(html, /data-act="profile-start-over-no"/);
});

test('the consent sheet speaks plain view’s words in plain view', async () => {
  const { createPublishSheet, summary } = await load();
  const renderPublishSheet = createPublishSheet(true);
  assert.ok(renderPublishSheet({ summary, theme: 'plain' }).includes('>Save a file<'));
  assert.ok(renderPublishSheet({ summary }).includes('>SAVE A FILE<'));
});

const q = (key, concept) => ({
  key, concept, teach: `Teach ${key}`, prompt: `Prompt ${key}`,
  options: [{ text: 'Right one', correct: true, feedback: 'Right.' }, { text: 'Wrong one', correct: false, feedback: 'No.' }],
  variants: [],
});
const withHidden = async () => {
  const [views, pp, ib, pub] = await Promise.all([
    import('../renderer/game/views/profile.js'), import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'), import('../renderer/game/profile/publish.js'),
  ]);
  const lessons = [
    { id: 'only-hidden', title: 'Hidden Only', modules: [], recommendedFor: [], questions: [q('h1', 'cut-off-order')] },
    { id: 'mixed', title: 'Mixed Lesson', modules: [], recommendedFor: [], questions: [q('m1', 'who-made-it'), q('m2', 'cut-off-order')] },
    { id: 'plain-one', title: 'Plain One', modules: [], recommendedFor: [], questions: [q('p1', 'couldnt-check')] },
  ];
  const bank = ib.buildBank(lessons, []);
  let p = pp.salvage(V3, NOW).profile;
  return { views, pp, pub, bank, p };
};

test('hidden concepts never count: no hidden-only lesson row, and the headline matches what would be published', async () => {
  const { views, pp, pub, bank, p } = await withHidden();
  // The hidden concept is known; the shown one is not. The lesson must not read as learned or skipped.
  const p1 = pp.markKnown(p, ['cut-off-order'], NOW);
  const s1 = pp.summary(p1, bank);
  for (const theme of ['game', 'plain']) {
    const html = views.renderProfile({ summary: s1, theme });
    assert.ok(!html.includes('Hidden Only'), 'a lesson with only a hidden concept is not listed');
    assert.ok(!html.includes('cut-off-order') && !html.includes('The order to do things in'));
    assert.match(html, /0 of 2 learned/);
  }
  // Mark the shown concepts known and learned-by-evidence: headline equals the publish total.
  let p2 = pp.markKnown(p, ['who-made-it', 'couldnt-check'], NOW);
  const s2 = pp.summary(p2, bank);
  const html2 = views.renderProfile({ summary: s2 });
  const n = pub.lessonsLearned(s2);
  assert.ok(html2.includes(`${n} of 2 learned`), `headline ${n} equals publish total`);
  assert.ok(n <= 2);
});

test('a mixed lesson is judged on its shown concept; the hidden one cannot hold it back or push it forward', async () => {
  const { views, pp, bank, p } = await withHidden();
  const s = pp.summary(pp.markKnown(p, ['who-made-it'], NOW), bank);
  const mixed = s.lessons.find((l) => l.id === 'mixed');
  // Whatever the full lesson state says, the app shows the shown-concept state.
  const html = views.renderProfile({ summary: { ...s, lessons: [{ ...mixed, state: 'not-yet' }] } });
  assert.ok(html.includes('SKIPPED — YOU SAID YOU KNOW THIS'), 'shown concept skipped, hidden ignored');
  assert.doesNotMatch(html, /class="profile-lesson learned"/);
});

test('a skipped concept is shown as skipped, never as learned, with a way to take the lesson', async () => {
  const { renderProfile, summary } = await load();
  const skipped = { ...summary, lessons: [{ ...summary.lessons[0], state: 'skipped', concepts: [{ id: 'who-made-it', state: 'skipped' }] }] };
  const game = renderProfile({ summary: skipped, theme: 'game' });
  assert.ok(game.includes('SKIPPED — YOU SAID YOU KNOW THIS'));
  assert.match(game, /class="profile-lesson skipped"/);
  assert.match(game, /data-go="lesson:lesson-a"/);
  assert.ok(game.includes('TAKE THE LESSON'));
  assert.doesNotMatch(game, /class="profile-lesson learned"/);
  assert.match(game, /0 of 1 learned/);
  assert.ok(renderProfile({ summary: skipped, theme: 'plain' }).includes('Skipped — you said you know this'));
});

test('the publish button and the consent sheet stay hidden while publishing is switched off', async () => {
  const { renderProfile, renderPublishSheet, summary, pub } = await load();
  assert.strictEqual(pub.PUBLISH_READY, false);
  assert.doesNotMatch(renderProfile({ summary, publish: true }), /profile-publish/);
  assert.strictEqual(renderPublishSheet({ summary, ticked: ['lessons'] }), '');
});

test('accessible: heading takes focus, Escape maps to a close, every bar has text, no motion of its own', async () => {
  const { renderProfile, focusProfile, profileKeyAct, summary } = await load();
  assert.match(renderProfile({ summary }), /<h2 id="profile-title" tabindex="-1">/);
  let focused = null;
  const heading = { focus() { focused = 'heading'; } };
  const no = { focus() { focused = 'no'; } };
  focusProfile({ querySelector: (sel) => (sel === '#profile-title' ? heading : null) });
  assert.strictEqual(focused, 'heading');
  focusProfile({ querySelector: (sel) => (sel === '[data-autofocus]' ? no : heading) });
  assert.strictEqual(focused, 'no');
  assert.match(renderProfile({ summary, confirming: true }), /profile-start-over-no" data-autofocus/);
  assert.strictEqual(profileKeyAct('Escape'), 'profile-close');
  assert.strictEqual(profileKeyAct('Escape', { confirming: true }), 'profile-start-over-no');
  assert.strictEqual(profileKeyAct('Escape', { sheet: true }), 'publish-close');
  assert.strictEqual(profileKeyAct('a'), null);
  const html = renderProfile({ summary });
  assert.strictEqual((html.match(/class="meter" aria-hidden="true"/g) || []).length, (html.match(/\(step [123] of 3\)/g) || []).length);
  assert.ok((html.match(/<h3 /g) || []).length >= 5, 'real headings for each section');
  const css = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');
  assert.match(css, /prefers-reduced-motion: reduce[^}]*animation: none !important; transition: none !important/);
});

test('short copy: no panel is a wall of text', async () => {
  const { renderProfile, summary } = await load();
  const text = renderProfile({ summary }).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  assert.ok(text.length < 1800, `profile text stays short (${text.length})`);
});

// Fix round 1.

test('fix 1: only profile.js binds the gate; nothing else names the creators or passes a true literal', () => {
  const root = path.join(__dirname, '..');
  const core = path.join(root, 'renderer', 'game', 'views', 'profile-core.js');
  const bound = path.join(root, 'renderer', 'game', 'views', 'profile.js');
  const named = [];
  const literal = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!['node_modules', 'test', 'dist', '.git', 'vendor'].includes(e.name)) walk(full); continue; }
      if (!/\.(c|m)?js$|\.html$/.test(e.name)) continue;
      const src = fs.readFileSync(full, 'utf8');
      if (full !== core && full !== bound && /createProfileRenderer|createPublishSheet/.test(src)) named.push(path.relative(root, full));
      if (/create(ProfileRenderer|PublishSheet)\(\s*(true|1|'[^']*')/.test(src)) literal.push(path.relative(root, full));
    }
  };
  walk(root);
  assert.deepStrictEqual(named, []);
  assert.deepStrictEqual(literal, []);
  const bsrc = fs.readFileSync(bound, 'utf8');
  assert.match(bsrc, /createProfileRenderer\(PUBLISH_READY\)/);
  assert.match(bsrc, /createPublishSheet\(PUBLISH_READY\)/);
  assert.doesNotMatch(bsrc, /export \{[^}]*create/);
});

test('fix 2: plain view promises no action on a skipped lesson; game view keeps TAKE THE LESSON', async () => {
  const { renderProfile, summary } = await load();
  const skipped = { ...summary, lessons: [{ ...summary.lessons[0], state: 'skipped', concepts: [{ id: 'who-made-it', state: 'skipped' }] }] };
  const plain = renderProfile({ summary: skipped, theme: 'plain' });
  assert.doesNotMatch(plain, /take it/i);
  assert.ok(plain.includes('Not counted as learned yet.'));
  assert.doesNotMatch(plain, /<button[^>]*data-go/);
  const game = renderProfile({ summary: skipped, theme: 'game' });
  assert.ok(game.includes('TAKE THE LESSON'));
});

test('fix 3: the data-history lines (real migration strings) pass the time-word and diagnostic checks', async () => {
  const { renderProfile, summary } = await load();
  const pp = await import('../renderer/game/profile/player-profile.js');
  const { DIAGNOSTIC_PHRASES } = await import('../renderer/game/training.js');
  const changes = [
    ...pp.salvage('junk', NOW).changes,
    ...pp.salvage({ version: 9 }, NOW).changes,
    ...pp.salvage({ version: 3, missions: { a: { status: 'weird' }, b: 1 }, lessons: { x: { done: true } } }, NOW).changes,
    'deck: award record unreadable, folded awards treated as paid',
  ];
  assert.ok(changes.length >= 3);
  const html = renderProfile({ summary: { ...summary, migrations: [{ v: 4, from: 3, at: NOW, changes }] } });
  const history = html.slice(html.indexOf('<details>'), html.indexOf('</details>'));
  assert.ok(history.includes('Moved to this version from version 3'));
  assert.doesNotMatch(history, TIME_WORDS);
  for (const ph of DIAGNOSTIC_PHRASES) assert.ok(!history.toLowerCase().includes(String(ph).toLowerCase()), ph);
});

test('fix 4: city mode shows nothing that is forbidden on disk and nothing from the hidden concept', async () => {
  const { views, pp, bank, p } = await withHidden();
  const { FORBIDDEN_ON_DISK } = require('./disk-words.js');
  const { CONCEPTS, SKILLS } = await import('../renderer/game/profile/skills.js');
  const s = pp.summary(pp.markKnown(p, ['cut-off-order', 'who-made-it'], NOW), bank);
  for (const theme of ['game', 'plain']) {
    const html = views.renderProfile({ summary: s, theme, publish: true });
    const visible = html.replace(/<[^>]+>/g, ' ');
    assert.doesNotMatch(visible, FORBIDDEN_ON_DISK);
    assert.ok(!html.includes('cut-off-order') && !html.includes('The order to do things in') && !html.includes('Hidden Only'));
    assert.doesNotMatch(html, /profile-publish/);
  }
  // Every shipped skill and concept title the screen can print is clean.
  for (const t of [...CONCEPTS.filter((c) => !c.hidden).map((c) => c.title), ...SKILLS.map((k) => k.title)]) assert.doesNotMatch(t, FORBIDDEN_ON_DISK, t);
});
