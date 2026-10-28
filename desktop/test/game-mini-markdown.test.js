const test = require('node:test');
const assert = require('node:assert');

const md = async () => (await import('../renderer/game/mini-markdown.js')).miniMarkdown;

test('hard-wrapped lines join into one paragraph; blank lines split paragraphs', async () => {
  const m = await md();
  assert.strictEqual(m('Stop and read\nthis first.\n\nThen carry on.'), '<p>Stop and read this first.</p><p>Then carry on.</p>');
});

test('numbered and bulleted lists, with indented continuation lines', async () => {
  const m = await md();
  assert.strictEqual(m('1. Note the port.\n2. Confirm it:\n   with lsof.\n- **Mac:** `lsof -i`'),
    '<ol><li>Note the port.</li><li>Confirm it: with lsof.</li></ol><ul><li><strong>Mac:</strong> <code>lsof -i</code></li></ul>');
});

test('fenced blocks keep their lines', async () => {
  const m = await md();
  assert.strictEqual(m('Run:\n```\nls -l\nwhoami\n```'), '<p>Run:</p><pre><code>ls -l\nwhoami</code></pre>');
});

test('everything is escaped first, so walkthrough text never becomes markup', async () => {
  const m = await md();
  const html = m('<img src=x onerror=alert(1)> `<b>` **<i>**\n- <script>');
  assert.doesNotMatch(html, /<img|<b>|<i>|<script/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('empty or missing text renders nothing', async () => {
  const m = await md();
  assert.strictEqual(m(''), '');
  assert.strictEqual(m(null), '');
});
