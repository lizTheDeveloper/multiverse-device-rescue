const test = require('node:test');
const assert = require('node:assert');
const { buildAiPrompt, cleanEvidence, MAX_TOTAL_CHARS } = require('../ai-prompt');
const { copyAiPanelHtml } = require('../renderer/copy-ai.js');

const ENV = { home: '/Users/jsmith', user: 'jsmith', platform: 'darwin', hostnames: ['Janes-MacBook-Pro'] };

const FINDING = {
  title: 'Background job runs a missing script in /tmp',
  description: 'com.example.poster runs /tmp/post.sh every 2 hours.',
  severity: 'critical',
  category: 'security',
  code: 'security.launch_agent_audit.tmp_program',
  module: 'launch_agent_audit',
  confidence: 0.9,
  made_by: [{ subject: '/tmp/post.sh', name: 'Unknown', verified: false, how: 'no signature', location_note: 'in a folder anyone can write to' }],
  remediation: { steps: [{ title: 'Turn the job off', body: 'long body' }] },
  data: {
    plist: '/Users/jsmith/Library/LaunchAgents/com.example.poster.plist',
    program: '/tmp/post.sh',
    host: 'Janes-MacBook-Pro.local',
    lan_ip: '192.168.1.20',
    env: { API_TOKEN: 'sk-abcdefghijklmnopqrstuvwxyz' },
    args: ['--token', 'hunter2'],
    ProgramArguments: ['/usr/bin/curl', '-H', 'X-Key: hunter2'],
    command: '/usr/local/bin/sync --key hunter2',
    api_token: 'plainsecretvalue',
    other_users: ['maria', 'tomas'],
    owner: 'tomas',
    ssid: 'HomeNet',
    detail: 'started as helper --password plainsecretvalue --user tomas --verbose',
    url: 'https://example.com/hook?sig=plainsecretvalue',
    note: 'contact jane@example.com password=hunter2',
    nested: { a: { b: { c: { d: { e: 'deep' } } } } },
  },
};

test('includes the useful detail', () => {
  const t = buildAiPrompt({ findings: [FINDING], situation: 'I think someone is watching me', platform: 'darwin', couldNotCheck: ['firewall_audit'] }, ENV);
  for (const s of ['Background job runs a missing script', 'Needs attention now', 'launch_agent_audit',
    'security.launch_agent_audit.tmp_program', '/tmp/post.sh', 'NOT verified', 'Turn the job off',
    '~/Library/LaunchAgents/com.example.poster.plist', 'someone is watching me', 'firewall_audit',
    'Never ask me for a password', '1-800-799-7233']) {
    assert.ok(t.includes(s), `missing: ${s}`);
  }
});

test('removes personal and secret data', () => {
  const t = buildAiPrompt({ findings: [FINDING] }, ENV);
  for (const s of ['jsmith', 'Janes', '192.168.1.20', 'jane@example.com', 'hunter2', 'sk-abc', 'plainsecretvalue', 'tomas', 'maria', 'HomeNet']) {
    assert.ok(!t.includes(s), `leaked: ${s}`);
  }
  assert.ok(t.includes('[left out: may contain private data]'));
  assert.ok(t.includes('/usr/bin/curl [2 argument(s) left out]'));
  assert.ok(t.includes('/usr/local/bin/sync [2 argument(s) left out]'));
  assert.ok(t.includes('https://example.com/hook?[left out]'));
  assert.ok(t.includes('--password [left out]'));
  assert.ok(t.includes('--verbose'));
});

test('caps depth, list length and total size', () => {
  const ev = cleanEvidence({ list: Array.from({ length: 100 }, (_, i) => `item${i}`) }, ENV);
  assert.strictEqual(ev.list.length, 41);
  assert.match(ev.list[40], /60 more left out/);
  assert.ok(buildAiPrompt({ findings: [FINDING] }, ENV).includes('[nested data left out]'));
  const many = Array.from({ length: 60 }, () => ({ ...FINDING, description: 'x '.repeat(300) }));
  const t = buildAiPrompt({ findings: many }, ENV);
  assert.ok(t.length <= MAX_TOTAL_CHARS + 200);
  assert.match(t, /more item\(s\) left out/);
});

test('rejects junk input', () => {
  for (const p of [null, 'x', {}, { findings: 'x' }, { findings: [] }, { findings: [null, 5, []] }]) {
    assert.strictEqual(buildAiPrompt(p, ENV), null);
  }
});

test('a verified maker line includes what the program is', () => {
  const what = 'Loom: records your screen and camera to make video messages you can share with a link.';
  const f = { ...FINDING, made_by: [
    { subject: 'com.loom.desktop', name: 'Loom, Inc', verified: true, how: 'Developer ID signature', location_note: '', what },
    { subject: '/tmp/x', name: 'Loom, Inc', verified: false, how: 'unsigned', what: 'Loom: should not appear.' },
  ] };
  const t = buildAiPrompt({ findings: [f] }, ENV);
  assert.ok(t.includes(`com.loom.desktop: made by Loom, Inc, verified (Developer ID signature) — what it is: ${what}`));
  assert.ok(!t.includes('should not appear'));
});

test('the copy panel escapes the text', () => {
  const html = copyAiPanelHtml('</textarea><script>alert(1)</script>', 3);
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;/textarea&gt;'));
});

test('saved-key comments never leave the app: Copy for any AI, one card or the whole report', () => {
  const comments = ['mark@marks-macbook', 'mark@laptop', 'Marks MacBook Pro key'];
  const keyFinding = {
    title: '3 saved key(s) could let another computer log in to this one',
    description: 'This computer keeps a list of 3 key(s).',
    severity: 'warning',
    code: 'security.session_revocation_scan.ssh_authorized_keys',
    data: {
      key_count: 3,
      keys: comments.map((comment, i) => ({ type: 'ssh-ed25519', sha256: String(i).repeat(64), line_sha256: 'f'.repeat(64), comment })),
      nested: { keys: [{ type: 'ssh-rsa', comment: 'mark@laptop' }] },
    },
  };
  const one = buildAiPrompt({ findings: [keyFinding] }, ENV);
  const all = buildAiPrompt({ findings: [FINDING, keyFinding], situation: 'Something is wrong' }, ENV);
  for (const text of [one, all]) {
    for (const c of comments) assert.ok(!text.includes(c), `${c} leaked`);
    assert.match(text, /left out: key comment/);
    assert.match(text, /ssh-ed25519/); // the rest of the key's evidence stays
  }
  const ev = cleanEvidence(keyFinding.data, ENV);
  assert.strictEqual(ev.keys.length, 3);
  assert.ok(ev.keys.every((k) => k.comment === '[left out: key comment]'));
  // A key with no comment stays without one.
  assert.strictEqual(cleanEvidence({ keys: [{ type: 'ssh-rsa', comment: '' }] }, ENV).keys[0].comment, '');
});
