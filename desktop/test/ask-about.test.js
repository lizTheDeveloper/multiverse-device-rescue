const test = require('node:test');
const assert = require('node:assert');
const {
  ASK_ENDPOINT, validateAskPayload, redactText, buildAskBody, askAbout,
} = require('../ask-about');
const { renderAnswerHtml } = require('../renderer/ask.js');

const ENV = { home: '/Users/jsmith', user: 'jsmith', platform: 'darwin' };
const GOOD = { finding: { title: 'Odd agent', description: 'Runs /Users/jsmith/Library/x', severity: 'warning' } };

test('redacts home path and username', () => {
  assert.strictEqual(
    redactText('/Users/jsmith/Library/LaunchAgents/x.plist owned by jsmith', ENV),
    '~/Library/LaunchAgents/x.plist owned by [you]'
  );
});

test('redacts a Windows home path in both slash styles, case-insensitively', () => {
  const env = { home: 'C:\\Users\\Pat', user: 'Pat', platform: 'win32' };
  assert.strictEqual(redactText('c:\\users\\pat\\AppData\\a.exe', env), '~\\AppData\\a.exe');
  assert.strictEqual(redactText('C:/Users/Pat/AppData/a.exe', env), '~/AppData/a.exe');
});

test('does not redact very short usernames or a root home', () => {
  assert.strictEqual(redactText('al is at /x', { home: '/', user: 'al', platform: 'darwin' }), 'al is at /x');
});

test('redacts credentials and emails like the engine does', () => {
  const none = { home: '', user: '' };
  assert.strictEqual(redactText('mail me at a.b@example.com', none), 'mail me at [redacted] email');
  assert.strictEqual(redactText('Authorization: Bearer abc.def', none), 'Authorization: [redacted]');
  assert.strictEqual(redactText('password=hunter2 ok', none), 'password=[redacted] ok');
  assert.strictEqual(redactText('API_KEY: zzz', none), 'API_KEY=[redacted]');
  assert.ok(!redactText('ghp_' + 'a'.repeat(30), none).includes('ghp_a'));
  assert.ok(!redactText('sk-' + 'b'.repeat(24), none).includes('sk-b'));
  assert.ok(!redactText('AK' + 'IA' + 'ABCDEFGHIJKLMNOP', none).includes('AKIA'));
  assert.ok(!redactText(['ey' + 'JhbGciOiJIUzI1NiJ9', 'ey' + 'JzdWIiOiIxMjM0NTY3', 'abcdefghijklmn'].join('.'), none).includes('eyJ'));
  assert.strictEqual(
    redactText('-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----', none),
    '[redacted] private key'
  );
});

test('validate accepts a good finding and strips unknown fields', () => {
  const clean = validateAskPayload({
    finding: { title: 't', description: 'd', code: 'C', data: { path: '/secret' }, module: 'm' },
  });
  assert.deepStrictEqual(clean, { title: 't', description: 'd', code: 'C' });
});

test('validate rejects bad shapes', () => {
  for (const bad of [
    null, 'x', [], {}, { finding: null }, { finding: [] },
    { finding: { title: 't' } },
    { finding: { title: 't', description: '   ' } },
    { finding: { title: 5, description: 'd' } },
    { finding: { title: 't', description: { a: 1 } } },
  ]) {
    assert.strictEqual(validateAskPayload(bad), null, JSON.stringify(bad));
  }
});

test('validate truncates over-long text to the server limits', () => {
  const clean = validateAskPayload({ finding: { title: 'a'.repeat(999), description: 'b'.repeat(9999) } });
  assert.strictEqual(clean.title.length, 300);
  assert.strictEqual(clean.description.length, 2000);
});

test('buildAskBody sends only whitelisted, redacted fields', () => {
  const body = buildAskBody({ finding: { ...GOOD.finding, data: { x: 1 }, module: 'm' } }, ENV);
  assert.deepStrictEqual(body, {
    finding: { title: 'Odd agent', description: 'Runs ~/Library/x', severity: 'warning' },
  });
  assert.strictEqual(buildAskBody({ finding: {} }, ENV), null);
});

function fakeFetch(responses) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    const r = responses.shift();
    if (r instanceof Error) throw r;
    return { status: r.status, json: async () => r.body };
  };
  fn.calls = calls;
  return fn;
}

test('posts redacted JSON to the one endpoint and returns the answer', async () => {
  const f = fakeFetch([{ status: 200, body: { answer: 'What this is\nFine.' } }]);
  const r = await askAbout(GOOD, { fetch: f, env: ENV, sleep: async () => {} });
  assert.deepStrictEqual(r, { ok: true, answer: 'What this is\nFine.' });
  assert.strictEqual(f.calls.length, 1);
  assert.strictEqual(f.calls[0].url, ASK_ENDPOINT);
  assert.strictEqual(f.calls[0].init.method, 'POST');
  assert.strictEqual(f.calls[0].init.redirect, 'error');
  assert.ok(f.calls[0].init.signal);
  const sent = f.calls[0].init.body;
  assert.ok(!sent.includes('jsmith'));
  assert.ok(sent.includes('~/Library/x'));
});

test('warming_up: notifies, waits, retries once, then succeeds', async () => {
  const f = fakeFetch([
    { status: 503, body: { status: 'warming_up' } },
    { status: 200, body: { answer: 'ok' } },
  ]);
  const events = [];
  const r = await askAbout(GOOD, {
    fetch: f, env: ENV,
    onWarming: () => events.push('warming'),
    sleep: async (ms) => { events.push(`sleep:${ms}`); },
  });
  assert.deepStrictEqual(r, { ok: true, answer: 'ok' });
  assert.deepStrictEqual(events, ['warming', 'sleep:20000']);
  assert.strictEqual(f.calls.length, 2);
  assert.strictEqual(f.calls[0].init.body, f.calls[1].init.body);
});

test('warming_up twice gives up after exactly one retry', async () => {
  const f = fakeFetch([
    { status: 503, body: { status: 'warming_up' } },
    { status: 503, body: { status: 'warming_up' } },
    { status: 200, body: { answer: 'never reached' } },
  ]);
  const r = await askAbout(GOOD, { fetch: f, env: ENV, sleep: async () => {} });
  assert.deepStrictEqual(r, { ok: false, reason: 'warming_up' });
  assert.strictEqual(f.calls.length, 2);
});

test('unavailable, rate limit and network failure do not retry', async () => {
  const cases = [
    [{ status: 503, body: { status: 'unavailable' } }, 'unavailable'],
    [{ status: 429, body: { error: 'x' } }, 'rate_limited'],
    [{ status: 502, body: null }, 'unavailable'],
    [{ status: 200, body: { answer: '   ' } }, 'unavailable'],
    [new Error('offline'), 'network'],
  ];
  for (const [resp, reason] of cases) {
    const f = fakeFetch([resp]);
    const r = await askAbout(GOOD, { fetch: f, env: ENV, sleep: async () => {} });
    assert.deepStrictEqual(r, { ok: false, reason });
    assert.strictEqual(f.calls.length, 1);
  }
});

test('invalid payload never reaches the network', async () => {
  const f = fakeFetch([]);
  const r = await askAbout({ finding: { title: 'x' } }, { fetch: f, env: ENV });
  assert.deepStrictEqual(r, { ok: false, reason: 'invalid' });
  assert.strictEqual(f.calls.length, 0);
});

test('a hung request is aborted by the timeout', async () => {
  const fetchImpl = (url, init) => new Promise((_res, rej) => {
    init.signal.addEventListener('abort', () => rej(new Error('aborted')));
  });
  const r = await askAbout(GOOD, { fetch: fetchImpl, env: ENV, timeoutMs: 20 });
  assert.deepStrictEqual(r, { ok: false, reason: 'network' });
});

test('answer rendering escapes HTML and formats headings and lists', () => {
  const html = renderAnswerHtml(
    'What this is\nA <script>alert(1)</script> thing with **bold**.\n\n## Is it normal?\nUsually.\n\n**What to do**\n1. Check who installed it.\n2. Read the guide.\n- extra'
  );
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes('<h4>What this is</h4>'));
  assert.ok(html.includes('<h4>Is it normal?</h4>'));
  assert.ok(html.includes('<h4>What to do</h4>'));
  assert.ok(html.includes('<ol><li>Check who installed it.</li><li>Read the guide.</li></ol>'));
  assert.ok(html.includes('<ul><li>extra</li></ul>'));
  assert.ok(html.includes('<strong>bold</strong>'));
});
