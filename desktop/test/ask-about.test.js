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

// --- hardening: what leaves the machine ------------------------------------------------

const NONE = { home: '', user: '', hostnames: [] };

test('redacts other spellings of user paths', () => {
  const out = (t) => redactText(t, NONE);
  assert.strictEqual(out('/Users/maria/Library/x'), '/Users/[user]/Library/x');
  assert.strictEqual(out('/users/maria/x'), '/Users/[user]/x');
  assert.strictEqual(out('/home/maria/.config'), '/home/[user]/.config');
  assert.strictEqual(out('C:\\Users\\maria\\AppData'), 'C:\\Users\\[user]\\AppData');
  assert.strictEqual(out('c:/users/maria/a.exe'), 'c:/Users/[user]/a.exe');
  assert.strictEqual(out('runs ~maria/bin/x'), 'runs ~[user]/bin/x');
  assert.strictEqual(out('/Users/Shared/x'), '/Users/Shared/x');
  assert.strictEqual(out('C:\\Users\\Public\\x'), 'C:\\Users\\Public\\x');
});

test('redacts the computer name in several spellings', () => {
  const env = { home: '', user: '', hostnames: ["Maria's MacBook Pro", 'Marias-MacBook-Pro.local'] };
  for (const t of ["Maria's MacBook Pro", 'Marias-MacBook-Pro', 'marias-macbook-pro.local', 'Marias MacBook Pro']) {
    const r = redactText(`host ${t} connected`, env);
    assert.ok(!/maria/i.test(r), `${t} -> ${r}`);
  }
  assert.strictEqual(redactText('localhost is fine', { home: '', user: '', hostnames: ['localhost'] }), 'localhost is fine');
});

test('redacts private IPv4, IPv6, MAC addresses and hardware ids', () => {
  const out = (t) => redactText(t, NONE);
  for (const ip of ['192.168.1.20', '10.0.0.5', '172.16.4.9', '172.31.255.1', '169.254.10.2', '100.64.1.1']) {
    assert.ok(!out(`to ${ip}:443`).includes(ip), ip);
  }
  assert.ok(out('to 8.8.8.8').includes('8.8.8.8'));
  assert.ok(out('to 172.32.1.1').includes('172.32.1.1'));
  for (const ip of ['fd12:3456:789a::1', 'fe80::1c2b:3dff:fe4e:5f6a%en0', 'fdab:cd:ef:1:2:3:4:5', '2001:db8:1:2:3:4:5:6']) {
    assert.ok(!out(`addr ${ip} up`).match(/fe80|fd12|fdab|2001/), ip);
  }
  assert.strictEqual(out('at 12:30:45 today'), 'at 12:30:45 today');
  assert.ok(!out('mac aa:bb:cc:dd:ee:ff x').includes('aa:bb'));
  assert.ok(!out('mac AA-BB-CC-DD-EE-FF x').includes('AA-BB'));
  assert.ok(!out('mac aabb.ccdd.eeff x').includes('aabb.'));
  assert.ok(!out('Serial Number: C02XK1ABJGH5').includes('C02XK'));
  assert.ok(!out('IOPlatformSerialNumber = "C02XK1ABJGH5"').includes('C02XK'));
  assert.ok(!out('uuid 4F1C2A3B-1234-4ABC-9DEF-0123456789AB').includes('4F1C2A3B'));
});

test('redacts more token and key shapes', () => {
  const out = (t) => redactText(t, NONE);
  const secrets = [
    ['refresh_token=abc123xyz', 'abc123xyz'], ['client_secret: s3cr3tvalue', 's3cr3tvalue'],
    ['"password": "hunter2"', 'hunter2'], ['Bearer abcdef0123456789xyz', 'abcdef0123'],
    ['github_pat_' + 'A'.repeat(30), 'AAAAAAAA'], ['glpat-' + 'b'.repeat(20), 'bbbbbbbb'],
    ['AIza' + 'c'.repeat(35), 'cccccccc'], ['sk_live_' + 'd'.repeat(24), 'dddddddd'],
    ['xapp-1-' + 'e'.repeat(20), 'eeeeeeee'], ['ya29.' + 'f'.repeat(30), 'ffffffff'],
    ['https://user:pw123@host.example/x', 'pw123'], ['a'.repeat(64), 'aaaaaaaa'],
    ['0123456789abcdef'.repeat(3), '01234567'],
  ];
  for (const [s, probe] of secrets) {
    const r = out(`found ${s} here`);
    assert.ok(!r.includes(probe), `${s} -> ${r}`);
  }
});

test('redacts Wi-Fi network names', () => {
  const out = (t) => redactText(t, NONE);
  assert.ok(!out('Joined SSID: Maria Home Wifi, secured').includes('Maria'));
  assert.ok(!out('SSID "Linksys Kitchen" is open').includes('Kitchen'));
  assert.ok(!out("Wi-Fi network 'CoffeeShop5G' is open").includes('CoffeeShop'));
  assert.ok(out('The Wi-Fi network is open').includes('is open'));
});

test('zero-width characters cannot split a secret past redaction', () => {
  const r = redactText('gh\u200Bp_' + 'a'.repeat(30) + ' and pass\u200Bword=hunter2', NONE);
  assert.ok(!r.includes('aaaa') && !r.includes('hunter2'));
});

test('control and bidi characters are stripped', () => {
  const r = redactText('a\u0000b\u001bc\u202Ed', NONE);
  assert.strictEqual(r, 'abcd');
});

test('redaction runs before truncation so a cut secret cannot leak a prefix', () => {
  const secret = 'ghp_' + 'Z'.repeat(40);
  const desc = 'a '.repeat(990) + secret;
  const body = buildAskBody({ finding: { title: 't', description: desc } }, NONE);
  assert.ok(!body.finding.description.includes('ghp_'));
  assert.ok(body.finding.description.length <= 2000);
});

test('every sent field is redacted and capped, whatever its size', () => {
  const huge = 'x '.repeat(2_500_000) + ' password=hunter2';
  const t0 = Date.now();
  const body = buildAskBody({
    finding: {
      title: 'mail a@b.com ' + huge, description: huge,
      severity: 'critical', category: '/Users/maria/x', code: 'C-1 10.0.0.9',
    },
  }, NONE);
  assert.ok(Date.now() - t0 < 3000);
  assert.ok(body.finding.title.length <= 300 && body.finding.description.length <= 2000);
  const sent = JSON.stringify(body);
  assert.ok(!sent.includes('a@b.com') && !sent.includes('maria') && !sent.includes('10.0.0.9'));
  assert.deepStrictEqual(Object.keys(body.finding).sort(), ['category', 'code', 'description', 'severity', 'title']);
});

test('IPC input of other shapes is rejected or ignored, never sent', () => {
  const bad = [
    { finding: { title: ['a'], description: 'd' } },
    { finding: { title: 't', description: { toString: () => 'x' } } },
    { finding: { title: 't', description: 'd', severity: { a: 1 } } },
    { finding: { title: 't', description: 'd', code: ['x'] } },
    { finding: [{ title: 't', description: 'd' }] },
    [{ finding: { title: 't', description: 'd' } }],
    'finding',
    { finding: { title: 5, description: 'd' } },
  ];
  for (const p of bad) assert.strictEqual(buildAskBody(p, NONE), null, JSON.stringify(p));
  const body = buildAskBody({ finding: { title: 't', description: 'd', data: { path: '/Users/m' }, extra: 'e' } }, NONE);
  assert.deepStrictEqual(Object.keys(body.finding).sort(), ['description', 'title']);
});

test('redaction is applied by askAbout to the exact bytes sent', async () => {
  const f = fakeFetch([{ status: 200, body: { answer: 'ok' } }]);
  await askAbout({ finding: { title: 'host 192.168.1.5', description: 'see /home/maria/x token=abc' } }, {
    fetch: f, env: NONE, sleep: async () => {},
  });
  const sent = f.calls[0].init.body;
  assert.ok(!/192\.168|maria|abc/.test(sent), sent);
});

test('the preview shows the redacted fields and the destination, escaped', () => {
  const { renderPreviewHtml } = require('../renderer/ask.js');
  const body = buildAskBody({ finding: { title: 'Job <b>x</b>', description: 'runs /Users/maria/a.sh token=abc123' } }, ENV);
  const html = renderPreviewHtml({ endpoint: ASK_ENDPOINT, body });
  assert.ok(html.includes(ASK_ENDPOINT));
  assert.ok(html.includes('&lt;b&gt;'));
  assert.ok(!html.includes('<b>x'));
  assert.ok(!html.includes('maria'));
  assert.ok(!html.includes('abc123'));
});
