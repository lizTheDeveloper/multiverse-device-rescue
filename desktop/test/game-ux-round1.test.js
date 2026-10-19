// UX round 1, city side (group B): the fixes the audit asked for.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const game = (f) => import(`../renderer/game/${f}`);
const CSS = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');

test('P1-1: [hidden] wins over component display rules inside the city', () => {
  // .fix-panel { display: grid } used to beat the attribute, so both confirm boxes showed.
  assert.match(CSS, /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/);
  const FixFlow = require('../renderer/fix-flow.js');
  const html = FixFlow.fixControlsHtml({ module: 'firewall_check', title: 't',
    fixable: { will_change: 'Turns on the firewall.', how_to_undo: ['Open System Settings.'] } }, {});
  assert.ok(html.includes('data-fix-confirm'));
  // The confirm button sits inside the panel, which is drawn hidden.
  assert.ok(html.indexOf('data-fix-panel hidden') >= 0 && html.indexOf('data-fix-panel') < html.indexOf('data-fix-confirm'));
});

test('P1-9: steps get the scan’s values, words for check ids, real Markdown, and commands behind FOR TECH HELPERS', async () => {
  const { stepsHtml, fillPlaceholders, wordsForModules, descriptionHtml } = await game('views/steps.js');
  const data = { label: 'ai.hermes.gateway', plist: '/Users/a/Library/LaunchAgents/ai.hermes.gateway.plist', program: '/Users/a/.hermes/py' };
  assert.strictEqual(fillPlaceholders('cat <path-to-plist> | grep <label>', data), 'cat /Users/a/Library/LaunchAgents/ai.hermes.gateway.plist | grep ai.hermes.gateway');
  assert.strictEqual(fillPlaceholders('file <path>', { path: '/Applications/My App.app' }), 'file \'/Applications/My App.app\'');
  assert.strictEqual(fillPlaceholders('kill <pid> <unknown>', {}), 'kill <pid> <unknown>', 'unknown values stay as they were');
  assert.strictEqual(wordsForModules('findings from `launchd_persistence_audit` and `my_check`', ['my_check']),
    'findings from the startup-task check and this checkup');
  assert.strictEqual(wordsForModules('a `program` path, snake_case words'), 'a `program` path, snake_case words');
  const body = 'These are from `launchd_persistence_audit`.\n\nFor each flagged label:\n\n1. Inspect: `cat <path-to-plist>`\n2. Unload it.';
  const html = stepsHtml([{ number: 1, title: 'Remove **high-risk** tasks', body },
    { number: 2, title: 'Open settings', body: 'Go to **Settings > Apps** and look.' }], { data, modules: [] });
  assert.doesNotMatch(html, /launchd_persistence_audit|<path-to-plist>|&lt;path-to-plist&gt;|\*\*/);
  assert.match(html, /Remove high-risk tasks/);
  assert.match(html, /<details class="tech"><summary>FOR TECH HELPERS<\/summary>[\s\S]*For each flagged label:[\s\S]*<code>cat \/Users\/a\/Library\/LaunchAgents\/ai.hermes.gateway.plist<\/code>/);
  assert.match(html, /<strong>Settings &gt; Apps<\/strong>/, 'plain guidance shows, with bold drawn');
  const evil = stepsHtml([{ number: 1, title: '<img src=x>', body: '<script>x</script> `<b>`' }]);
  assert.doesNotMatch(evil, /<img|<script|<b>/);
  assert.match(descriptionHtml('It runs. What to do: Open **Settings**.'), /<p class="intel">It runs\.<\/p><p class="intel todo"><strong>What to do:<\/strong> Open <strong>Settings<\/strong>\.<\/p>/);
});

test('P1-9: a code span wrapped across a list item’s lines stays one span', async () => {
  const { miniMarkdown } = await game('views/steps.js');
  assert.strictEqual(miniMarkdown('1. Move it: `mkdir -p x &&\n   mv y z/`.\n2. Done.'), '<ol><li>Move it: <code>mkdir -p x &amp;&amp; mv y z/</code>.</li><li>Done.</li></ol>');
});
