const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { isAllowedMissionLink } = require('../mission-links');
const { links } = require('../mission-links.json');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');

test('mission-links.json is current (run: node desktop/scripts/build-mission-links.mjs)', async () => {
  const { collectMissionLinks } = await import('../scripts/build-mission-links.mjs');
  assert.deepStrictEqual(links, await collectMissionLinks(SRC));
});

test('every link is https, and there are plenty of them', () => {
  assert.ok(links.length > 100);
  for (const l of links) assert.ok(l.startsWith('https://'), l);
});

test('an exact link from the game is allowed', () => {
  assert.strictEqual(isAllowedMissionLink(links[0]), true);
  assert.strictEqual(isAllowedMissionLink(links[links.length - 1]), true);
});

test('anything else is refused', () => {
  const l = links[0];
  for (const url of [
    `${l}x`, `${l}/extra`, `${l}${l.includes('?') ? '&' : '?'}a=1`, ` ${l}`, `${l} `,
    l.replace('https://', 'http://'), l.replace('https://', 'https://evil.example/?'),
    l.replace(/^https:\/\/([^/]+)/, 'https://$1.evil.example'),
    'about:preferences#privacy', 'javascript:alert(1)', 'file:///etc/passwd', '', null, undefined, 42, {},
  ]) {
    assert.strictEqual(isAllowedMissionLink(url), false, String(url));
  }
});
