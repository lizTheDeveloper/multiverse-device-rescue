const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { isAllowedGuideUrl } = require('../setting-urls.js');

const REPO = path.join(__dirname, '..', '..');
const SOURCES = {
  'six-roses': path.join(__dirname, 'fixtures', 'six-roses-excerpt.txt'),
  'guides/remediation/respond_to_monitoring_software.md': path.join(REPO, 'guides', 'remediation', 'respond_to_monitoring_software.md'),
  'guides/remediation/preserve_evidence_first.md': path.join(REPO, 'guides', 'remediation', 'preserve_evidence_first.md'),
  'modules/security/stalkerware_scan/__init__.py': path.join(REPO, 'modules', 'security', 'stalkerware_scan', '__init__.py'),
};
// Beyond punctuation, every word of ours is listed here, word for word, with
// why: joining words, a pointer or a label, never a step, a resource or a
// number. So an invented sentence, however short, fails until someone adds it
// here on purpose.
const JOINING = 0;
const OWN_WORDING = {
  'to look these up.': 'OPEN_NOTE: joins the library-computer advice to the list above',
  'first.': 'HELD.heading / HELD_LINE: the one word around its two quotes',
  // Not "it reads like a recipe": only the title does. Right under it the page
  // says it is a safety guide, with the hotline, so the person is told when to open it.
  "it opens in your web browser. the title looks like a recipe, but the page is a safety guide, so open it when you're alone or on a device that's yours. .":
    'what the guide button does, and that only the title looks like a recipe',
  'open the city to see how to keep a quiet record of it.': 'HELD_MORE: where the record steps are',
  'how to keep a quiet record, and who can help': 'HELD_HELP_TITLE: the label of the details',
  'if someone close to you may have installed it, talk to an . , .': 'DEFAULT_FULL: who the hotline sentence is for',
};
const leftover = (rest) => rest.replace(/\s+/g, ' ').replace(/^[\s.,;:]+/, '').trim();
function ownWordsOk(item, rest) {
  const letters = rest.replace(/[^a-z0-9]/g, '').length;
  return letters <= JOINING || Object.prototype.hasOwnProperty.call(OWN_WORDING, leftover(rest));
}
const norm = (s) => String(s).toLowerCase().replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/\s+/g, ' ').trim();
const source = (key) => norm(fs.readFileSync(SOURCES[key], 'utf8'));
const load = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

async function everything() {
  const c = await load('side-district.js');
  return [...c.FIRST_STEPS, ...c.HELP, c.OPEN_NOTE, c.SIX_ROSES, c.SIX_ROSES.note, c.LEAVING, c.HELD.heading, ...c.HELD.steps];
}

test('every line is the source’s own words, with only a few joining words of ours', async () => {
  for (const item of await everything()) {
    assert.ok(item.source in SOURCES, `${item.text}: unknown source ${item.source}`);
    const src = source(item.source);
    const text = norm(item.text);
    let rest = text;
    for (const q of item.quotes) {
      assert.ok(src.includes(norm(q)), `not in ${item.source}: "${q}"`);
      assert.ok(text.includes(norm(q)), `quote not in the text: "${q}"`);
      rest = rest.replace(norm(q), '');
    }
    assert.ok(ownWordsOk(item, rest), `our own wording in "${item.text}" isn't listed in OWN_WORDING: "${leftover(rest)}"`);
  }
});

test('every address is on a line of its source that links it: the Six Roses link lines, verbatim from the page', async () => {
  const fs2 = fs.readFileSync(SOURCES['six-roses'], 'utf8').split('\n');
  const c = await load('side-district.js');
  const code = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'side-district.js'), 'utf8');
  const urls = [...new Set(code.match(/https?:\/\/[^\s'"`)]+/g).map((u) => u.replace(/[.,;:]+$/, '')))];
  assert.ok(urls.length >= 5, urls.join(' '));
  for (const url of urls) {
    if (url === c.SIX_ROSES.url) {
      // The guide's own address: the page this excerpt was fetched from.
      assert.ok(fs2.some((l) => l === `# Source: ${url} (text fetched 2026-10-18).`), url);
      continue;
    }
    const r = c.HELP.find((x) => x.url === url);
    assert.ok(r, `${url} belongs to a resource`);
    const line = fs2.find((l) => !l.startsWith('#') && l.includes(`<a href="${url}">${r.name}</a>`));
    assert.ok(line, `${url}: no page line links it as "${r.name}"`);
  }
});

test('every number and every address is in the source', async () => {
  for (const item of await everything()) {
    const src = source(item.source) + ' ' + source('six-roses');
    for (const n of norm(item.text).match(/\d[\d-]*\d|\d/g) || []) assert.ok(src.includes(n), `${n} in "${item.text}"`);
    if (item.url) assert.ok(src.includes(norm(item.url)), item.url);
  }
});

test('it holds what the spec lists, and nothing tells the person how long anything takes', async () => {
  const c = await load('side-district.js');
  const { TIME_WORDS } = await load('training.js');
  assert.deepStrictEqual(c.FIRST_STEPS.map((x) => x.id), ['record', 'phone', 'code-words', 'freedom-email', 'evidence-first']);
  assert.deepStrictEqual(c.HELP.map((x) => x.id), ['911', 'hotline', 'techsafety', 'safety-net', 'womenslaw', 'ceta']);
  assert.strictEqual(c.SIX_ROSES.url, 'https://themultiverse.school/x/six-roses');
  assert.strictEqual(c.LEAVING.text, 'Leaving is the most dangerous time. Plan carefully with DV advocates.');
  assert.strictEqual(c.HELD.heading.text, 'Don’t remove it yet. Talk to an advocate first.');
  assert.strictEqual(c.HELD.heading.text, Q.HELD_LINE, 'the list and the district say the same');
  for (const item of await everything()) assert.doesNotMatch(item.text, TIME_WORDS, item.text);
  for (const s of c.HELD.steps) assert.doesNotMatch(s.text, /^(remove|uninstall|delete|turn off|reset)/i, s.text);
  for (const s of c.FIRST_STEPS) assert.ok(s.title.length <= 50 && !/\d/.test(s.title), s.title);
});

test('only the guide opens, through the guide allowlist; every other address is text', async () => {
  const { renderSide } = await load('views/side-district.js');
  const { pickDistrict } = await load('district-names.js');
  const c = await load('side-district.js');
  const html = renderSide({ district: pickDistrict(7), held: [], notice: false });
  assert.strictEqual((html.match(/data-act="side-open-guide"/g) || []).length, 1);
  assert.strictEqual((html.match(/data-act="side-back"/g) || []).length, 1);
  assert.doesNotMatch(html, /<a\s/);
  for (const r of c.HELP) if (r.url) assert.ok(html.includes(`<code>${r.url}</code>`), r.url);
  assert.ok(isAllowedGuideUrl(c.SIX_ROSES.url));
  for (const bad of [`${c.SIX_ROSES.url}/`, `${c.SIX_ROSES.url}?x=1`, `${c.SIX_ROSES.url}-evil`, c.SIX_ROSES.url.replace('https', 'http'), 'https://themultiverse.school/x/']) {
    assert.strictEqual(isAllowedGuideUrl(bad), false, bad);
  }
});

test('the district screen: its name and voice, the held findings escaped, BACK TO THE GAME', async () => {
  const { renderSide, sideTileHtml, heldNoticeHtml } = await load('views/side-district.js');
  const { pickDistrict } = await load('district-names.js');
  const d = pickDistrict(424242);
  const html = renderSide({ district: d, held: [{ module: 'stalkerware_scan', title: '<img src=x onerror=alert(1)>' }], notice: true });
  assert.ok(html.includes(d.name.toUpperCase().replace(/’/g, '&#39;')) || html.includes(d.name.toUpperCase()));
  assert.ok(html.includes(d.voice.hello.replace(/’/g, '’')));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(html, /BACK TO THE GAME/);
  assert.match(html, /It couldn’t be opened from here\./);
  assert.doesNotMatch(renderSide({ district: d, held: [] }), /Don’t remove it yet/);
  assert.match(sideTileHtml(d, 0), /data-go="side"/);
  assert.match(sideTileHtml(d, 2), /NEW/);
  // One way there: the tile, marked NEW; the notice has no button of its own (P3-6).
  assert.doesNotMatch(heldNoticeHtml(d), /data-go="side"/);
  assert.match(sideTileHtml(d, 1), /data-go="side"[\s\S]*NEW/);
  assert.doesNotMatch(sideTileHtml(d, 1) + heldNoticeHtml(d), /advocate|remove|monitor|watch/i, 'the deck names only the place');
});

test('every look has its colours in game.css', async () => {
  const { LOOKS } = await load('district-names.js');
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'game.css'), 'utf8');
  for (const look of LOOKS) assert.ok(css.includes(`.look-${look} {`), look);
});

// The list's own help (QuietNotes), shown behind the hold line when the city
// can't be reached, and the hold line and pointer themselves: the same rule as
// the district. Adding a line to HELD_HELP means adding it here with its source.
const RESPOND_KEY = 'guides/remediation/respond_to_monitoring_software.md';
function listHelp() {
  assert.strictEqual(Q.HELD_HELP.length, 3, 'every line of HELD_HELP is listed below with its source');
  return [
    { text: Q.HELD_HELP[0], source: RESPOND_KEY, quotes: [Q.HELD_HELP[0]] },
    { text: Q.HELD_HELP[1], source: RESPOND_KEY,
      quotes: ['advocate before you remove anything', 'In the US: National Domestic Violence Hotline', '1-800-799-7233, or text START to 88788'] },
    { text: Q.HELD_HELP[2], source: RESPOND_KEY, quotes: [Q.HELD_HELP[2]] },
    { text: Q.HELD_LINE, source: 'modules/security/stalkerware_scan/__init__.py', quotes: ["Don't remove it yet", 'talk to an advocate'] },
    { text: Q.HELD_MORE, source: RESPOND_KEY, quotes: [] },
    { text: Q.HELD_HELP_TITLE, source: RESPOND_KEY, quotes: [] },
  ];
}

test('the list’s interim help is the sources’ own words too, every number in them, and no time words', async () => {
  const { TIME_WORDS } = await load('training.js');
  for (const item of listHelp()) {
    const src = source(item.source);
    const text = norm(item.text);
    let rest = text;
    for (const q of item.quotes) {
      assert.ok(src.includes(norm(q)), `not in ${item.source}: "${q}"`);
      assert.ok(text.includes(norm(q)), `quote not in the text: "${q}"`);
      rest = rest.replace(norm(q), '');
    }
    assert.ok(ownWordsOk(item, rest), `our own wording in "${item.text}" isn't listed in OWN_WORDING: "${leftover(rest)}"`);
    for (const n of text.match(/\d[\d-]*\d|\d/g) || []) assert.ok(src.includes(n) || source('six-roses').includes(n), `${n} in "${item.text}"`);
    assert.doesNotMatch(item.text, TIME_WORDS, item.text);
    assert.doesNotMatch(item.text, /^(remove|uninstall|delete|turn off|reset)/i, item.text);
  }
});

// Fix round 2: the page only looks like a recipe by its title. Its next lines
// say what it is, so the district says so, and when to open it.
test('the guide button tells the truth about the page: only its title looks like a recipe', async () => {
  const c = await load('side-district.js');
  const note = c.SIX_ROSES.note.text;
  assert.doesNotMatch(note, /reads like a recipe/i);
  assert.match(note, /The title looks like a recipe, but the page is a safety guide, so open it when you’re alone or on a device that’s yours\./);
  const page = source('six-roses');
  assert.ok(page.includes(norm('a Digital Safety Guide for Domestic Violence Survivors')), 'the page says it is a safety guide');
  assert.ok(page.includes(norm('How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life')), 'its title is the recipe');
});
