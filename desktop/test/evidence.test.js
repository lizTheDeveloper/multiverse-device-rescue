const test = require('node:test');
const assert = require('node:assert');
const E = require('../renderer/evidence.js');

// Findings as the engine reported them on a real scan (trimmed).
const F = {
  tampered: {
    module: 'code_signature_audit', severity: 'critical', title: 'App Amazon Photos was changed after it was signed',
    code: 'security.code_signature_audit.tampered_binary',
    data: { check: 'tampered_binary', path: '/Applications/Amazon Photos.app', name: 'Amazon Photos',
      detail: 'codesign --verify failed on a signed object: /Applications/Amazon Photos.app: a sealed resource is missing or invalid' },
    made_by: [{ subject: '/Applications/Amazon Photos.app', name: 'AMZN Mobile LLC', verified: false, how: "claims to be made by AMZN Mobile LLC; couldn't verify", location_note: '' }],
  },
  agent: {
    module: 'launch_agent_audit', severity: 'warning', title: "Background task 'ai.hermes.gateway-deflock' runs from a hidden folder",
    data: { check: 'suspicious_path', label: 'ai.hermes.gateway-deflock', program: '/Users/ann/.hermes/hermes-agent/venv/bin/python',
      plist: '/Users/ann/Library/LaunchAgents/ai.hermes.gateway-deflock.plist',
      arguments_sha256: '78eb25a05b222855488b6d1369beadb4a5695779698d736bc964c84d1daca7f0',
      content_sha256: 'e98959b0ca1a63c6ee80503709fc7405a0f411f2d7fbd4824be9b49aec4f442a' },
    made_by: [{ subject: '/Users/ann/.hermes/hermes-agent/venv/bin/python', name: 'Unknown maker', verified: false, how: 'ad-hoc signed', location_note: '' }],
  },
  ssh: { module: 'session_revocation_scan', severity: 'warning', title: '1 saved key could let another computer log in to this one',
    data: { check: 'ssh_authorized_keys', key_count: 1, list_sha256: 'd51827eaf7d732158af595b45c1b700d05dbb7f6c6a2695524aa960cf8a88d4d' } },
  hosts: { module: 'hosts_file_check', severity: 'warning', title: '1 website name is being redirected',
    data: { check: 'suspicious_ip_redirect', count: 1, entries: [{ ip: '166.117.29.222', hostname: 'detect-ccd.creativecloud.adobe.com' }] } },
  node: { module: 'suspicious_connections', severity: 'warning', title: 'node is waiting for connections on port 8765, 8766',
    data: { check: 'unusual_listening_port', pid: 61084, process: 'node', port: 8765, ports: [8765, 8766] } },
  cpu: { module: 'resource_hog_identifier', severity: 'warning', title: 'opencode is using a lot of power',
    data: { pid: 6538, name: 'opencode', cpu_percent: 203.7, memory_bytes: 2591555584, command: '/Users/ann/.bun/bin/opencode --port 4096' } },
  baseline: { module: 'security_baseline_diff', severity: 'warning', title: '1 new persistence item since 10 Oct',
    data: { check: 'new_persistence', added: ['/Users/ann/Library/LaunchAgents/ai.hermes.gateway-deflock.plist'], baseline_captured_at: '2026-10-10T18:44:55+00:00' } },
  keyboard: { module: 'keylogger_indicators', severity: 'info', title: 'Keyboard access: 2 apps with familiar names',
    code: 'security.keylogger_indicators.suspicious_input_monitoring',
    data: { check: 'claimed_vendor_input_monitoring', apps: ['/Applications/Visual Studio Code.app', '/Applications/Steam.app'] },
    made_by: [
      { subject: '/Applications/Visual Studio Code.app', name: 'Microsoft Corporation', verified: true, how: 'Developer ID signature', location_note: '' },
      { subject: '/Applications/Steam.app', name: 'Valve Corporation (Steam)', verified: true, how: 'Developer ID signature', location_note: '' },
    ] },
  mspy: { module: 'stalkerware_scan', severity: 'critical', title: 'mSpy is on this computer (app)',
    data: { check: 'monitoring_software_found', stalkerware_name: 'mSpy', stalkerware_category: 'stalkerware', detected_as: 'app', location: '/Applications/mSpy.app', confidence: 'high' },
    made_by: [{ subject: '/Applications/mSpy.app', name: 'Unknown maker', verified: false, how: 'unrecognised signature', location_note: '' }] },
};

const get = (rows, label) => rows.find((r) => r.label === label);
const labels = (rows) => rows.map((r) => r.label);

test('every row has label, value, mono and copy; no row is ever raw JSON', () => {
  for (const [name, f] of Object.entries(F)) {
    for (const mode of ['standard', 'city']) {
      const rows = E.evidenceRows(f, { mode });
      assert.ok(rows.length > 0, name);
      for (const r of rows) {
        assert.deepStrictEqual(Object.keys(r).sort(), ['copy', 'label', 'mono', 'value'], name);
        assert.strictEqual(typeof r.value, 'string');
        assert.strictEqual(typeof r.copy, 'string');
        assert.doesNotMatch(r.value, /^[{[]|":/, `${name}: ${r.value}`);
      }
    }
  }
});

test('code signature: app, where, what the signature check said, maker not verified', () => {
  const rows = E.evidenceRows(F.tampered, { checkName: 'Checking app signatures' });
  assert.strictEqual(get(rows, 'App').value, 'Amazon Photos');
  assert.strictEqual(get(rows, 'Where').value, '/Applications/Amazon Photos.app');
  assert.ok(get(rows, 'Where').mono);
  assert.strictEqual(get(rows, 'Signature check said').value, 'a sealed resource is missing or invalid');
  assert.match(get(rows, 'Signature check said').copy, /^codesign --verify failed/);
  assert.strictEqual(get(rows, 'Made by').value, 'AMZN Mobile LLC · not verified');
  assert.strictEqual(get(rows, 'Check').value, 'Checking app signatures');
  assert.ok(!labels(rows).includes('Check id'), 'the internal "check" key is not evidence');
});

test('background task: label, program, settings file, hashes shortened with the full hash on copy', () => {
  const rows = E.evidenceRows(F.agent);
  assert.deepStrictEqual(labels(rows).slice(0, 5), ['Background task', 'Runs', 'Settings file', 'Arguments hash', 'Script hash']);
  assert.strictEqual(get(rows, 'Runs').value, '~/.hermes/hermes-agent/venv/bin/python');
  assert.strictEqual(get(rows, 'Settings file').value, '~/Library/LaunchAgents/ai.hermes.gateway-deflock.plist');
  assert.strictEqual(get(rows, 'Arguments hash').value, '78eb25a0…ca7f0');
  assert.strictEqual(get(rows, 'Arguments hash').copy, F.agent.data.arguments_sha256);
  assert.match(get(rows, 'Made by').value, /Unknown maker · not verified \(ad-hoc signed\)/);
  for (const r of rows) assert.doesNotMatch(r.copy, /\/Users\/ann/, 'the account name is never copied');
  // The same adapter for every check that reports background tasks.
  for (const m of ['launchd_persistence_audit', 'scheduled_tasks_audit', 'ai_worm_persistence']) {
    assert.strictEqual(E.evidenceRows({ ...F.agent, module: m })[0].label, 'Background task', m);
  }
});

test('ssh keys: names the file, the count and the list hash', () => {
  const rows = E.evidenceRows(F.ssh);
  assert.strictEqual(get(rows, 'File').value, '~/.ssh/authorized_keys');
  assert.strictEqual(get(rows, 'Keys in it').value, '1');
  assert.strictEqual(get(rows, 'List hash').value, 'd51827ea…a88d4d'.replace('a88d4d', '88d4d'));
  // Another session_revocation finding falls back to the generic rows.
  const other = E.evidenceRows({ module: 'session_revocation_scan', data: { check: 'browser_sessions', profile_count: 18,
    browsers: [{ browser: 'Brave', profiles: 7 }, { browser: 'Safari', profiles: 1 }] } });
  assert.strictEqual(get(other, 'Profiles').value, '18');
  assert.strictEqual(get(other, 'Browsers').value, 'Brave, profiles 7, Safari, profiles 1');
});

test('hosts: the file and each redirect', () => {
  const rows = E.evidenceRows(F.hosts);
  assert.strictEqual(get(rows, 'File').value, '/etc/hosts');
  assert.strictEqual(get(rows, 'Sends').value, 'detect-ccd.creativecloud.adobe.com → 166.117.29.222');
  assert.ok(!get(rows, 'Entries'), 'the count matches the list, so it is not repeated');
});

test('listening program: program, process id, ports', () => {
  const rows = E.evidenceRows(F.node);
  assert.strictEqual(get(rows, 'Program').value, 'node');
  assert.strictEqual(get(rows, 'Process id').value, '61084');
  assert.strictEqual(get(rows, 'Ports').value, '8765, 8766');
  assert.ok(!get(rows, 'Port'));
});

test('busy program: process id, processor, memory, command line', () => {
  const rows = E.evidenceRows(F.cpu);
  assert.strictEqual(get(rows, 'Processor use').value, '203.7%');
  assert.strictEqual(get(rows, 'Memory').value, '2.6 GB');
  assert.strictEqual(get(rows, 'Command line').value, '~/.bun/bin/opencode --port 4096');
});

test('baseline: what is new since the snapshot day, never a raw ISO time', () => {
  const rows = E.evidenceRows(F.baseline);
  assert.strictEqual(get(rows, 'New since 10 Oct 2026').value, '~/Library/LaunchAgents/ai.hermes.gateway-deflock.plist');
  assert.strictEqual(get(rows, 'Last snapshot').value, '10 Oct 2026');
  for (const r of rows) assert.doesNotMatch(r.value, /T\d\d:\d\d/);
});

test('keyboard access: one row per app with its maker and whether it was verified', () => {
  const rows = E.evidenceRows(F.keyboard);
  const apps = rows.filter((r) => r.label === 'Keyboard access');
  assert.deepStrictEqual(apps.map((r) => r.value), [
    '/Applications/Visual Studio Code.app — Microsoft Corporation · verified (Developer ID signature)',
    '/Applications/Steam.app — Valve Corporation (Steam) · verified (Developer ID signature)',
  ]);
  assert.ok(!get(rows, 'Made by'), 'makers are on the app rows, not repeated');
  assert.strictEqual(E.makersVerified(F.keyboard), true);
  assert.strictEqual(E.makersVerified({ ...F.keyboard, made_by: [F.keyboard.made_by[0]] }), false, 'an app with no maker');
  assert.strictEqual(E.makersVerified({ ...F.keyboard, made_by: [F.keyboard.made_by[0], { ...F.keyboard.made_by[1], verified: false }] }), false);
  assert.strictEqual(E.makersVerified({ ...F.keyboard, makers_verified: false }), false, "the engine's answer wins");
  assert.strictEqual(E.makersVerified(F.mspy), false);
  assert.strictEqual(E.makersVerified({}), false);
});

test('stalkerware in Plain view: name, where found, found as, maker', () => {
  const rows = E.evidenceRows(F.mspy, { mode: 'standard' });
  assert.strictEqual(get(rows, 'Name').value, 'mSpy');
  assert.strictEqual(get(rows, 'Where found').value, '/Applications/mSpy.app');
  assert.strictEqual(get(rows, 'Found as').value, 'app');
  assert.match(get(rows, 'Made by').value, /not verified/);
});

test('city, held: exactly what to write down; nothing else', () => {
  const seen = '2026-10-18T23:03:00+00:00';
  const rows = E.evidenceRows(F.mspy, { mode: 'city', seen, commands: [['codesign', '-dv', '/Applications/mSpy.app']] });
  assert.deepStrictEqual(labels(rows), ['Name', 'Where found', 'How detected', 'Made by', 'Date']);
  assert.deepStrictEqual(rows.map((r) => r.value), ['mSpy', '/Applications/mSpy.app', 'Found as app',
    'Unknown maker · not verified (unrecognised signature)', '18 Oct 2026']);
  const kb = E.evidenceRows({ ...F.keyboard, severity: 'warning', made_by: [] }, { mode: 'city', seen });
  assert.deepStrictEqual(labels(kb), ['Where found', 'How detected', 'Made by', 'Date']);
  assert.strictEqual(get(kb, 'Made by').value, 'Not known');
  // Not held: the full rows, even in city.
  assert.ok(E.evidenceRows(F.keyboard, { mode: 'city', held: false }).some((r) => r.label === 'Keyboard access'));
  // Held is the default for a monitoring check in city, and never in Plain.
  assert.strictEqual(E.evidenceRows(F.mspy, { mode: 'city', seen }).length, 5);
  assert.ok(E.evidenceRows(F.mspy, { mode: 'standard', held: true }).length > 5);
});

test('the commands the check ran: short names shown, full lines copied, home folder redacted', () => {
  const commands = [
    { argv: ['/usr/bin/codesign', '--verify', '--deep', '/Applications/Amazon Photos.app'], returncode: 1 },
    { argv: ['/usr/bin/codesign', '--verify', '--deep', '/Applications/Baba Is You.app'], returncode: 1 },
    ['plutil', '-p', '/Users/ann/Library/LaunchAgents/x.plist'],
    'mdfind kMDItemKind',
    ['spctl', '-a', 'x'], ['ls'],
  ];
  const r = get(E.evidenceRows(F.tampered, { commands }), 'Checked with');
  // Only commands on this app (and ones that name no file); the last path
  // each was given stays in view: what it looked at.
  assert.strictEqual(r.value, 'codesign --verify … /Applications/Amazon Photos.app, mdfind …, spctl -a …, and 1 more');
  assert.ok(r.mono);
  assert.match(r.copy, /^\/usr\/bin\/codesign --verify --deep '\/Applications\/Amazon Photos.app'\n/);
  assert.ok(!/Baba|x\.plist/.test(r.copy), 'never a command run on another app (N1)');
  assert.ok(!get(E.evidenceRows(F.tampered), 'Checked with'), 'no commands, no row');
  // A finding that names nothing: commands on files show as their program only.
  const bare = get(E.evidenceRows({ module: 'x', data: {} }, { commands }), 'Checked with');
  assert.ok(!/Applications|Library/.test(bare.value + bare.copy), bare.copy);
  assert.match(bare.copy, /\ncodesign\nplutil$/);
  // The finding's label or home-relative path counts as its subject too.
  const task = { module: 'launch_agent_audit', data: { label: 'com.x.task', plist: '/Users/ann/Library/LaunchAgents/com.x.task.plist' } };
  const got = E.commandsFor(task, [['launchctl', 'print', 'gui/501/com.x.task'], ['plutil', '-p', '~/Library/LaunchAgents/com.x.task.plist'],
    ['plutil', '-p', '/Library/LaunchAgents/other.plist']]);
  assert.strictEqual(got.commands.length, 2);
  assert.deepStrictEqual(got.names, []);
});

test('generic fallback: scalars, lists, small maps, dates, bytes; bookkeeping keys left out', () => {
  const rows = E.evidenceRows({ module: 'disk_space', data: {
    check: 'x', severity_level: 'WARNING', mount_point: '/System/Volumes/Data', used_pct: 0.91, used_pct_str: '92%',
    free_bytes: 47767506944, most_recent_date: '2026-10-13 11:16:42', nested: { deep: { deeper: 1 } },
    duplicates: { 'Arial Unicode.ttf': ['/Library/Fonts', '/System/Library/Fonts'] }, empty: [], none: null,
    content_sha256: 'e98959b0ca1a63c6ee80503709fc7405a0f411f2d7fbd4824be9b49aec4f442a', enabled: false,
  } });
  assert.strictEqual(get(rows, 'Disk').value, '/System/Volumes/Data');
  assert.strictEqual(get(rows, 'Used').value, '92%');
  assert.strictEqual(get(rows, 'Free').value, '47.8 GB');
  assert.strictEqual(get(rows, 'Most recent').value, '13 Oct 2026');
  assert.strictEqual(get(rows, 'Arial Unicode.ttf').value, '/Library/Fonts, /System/Library/Fonts');
  assert.strictEqual(get(rows, 'Content sha256').value, 'e98959b0…f442a');
  assert.strictEqual(get(rows, 'Enabled').value, 'no');
  for (const l of ['Check', 'Severity level', 'Used pct', 'Nested', 'Empty', 'None']) {
    assert.ok(l === 'Check' ? get(rows, l).value === 'Disk space' : !get(rows, l), l);
  }
  assert.ok(!labels(rows).includes('deep'));
});

test('long lists stop at eight with "and N more"; copy has them all', () => {
  const apps = Array.from({ length: 12 }, (_, i) => `com.example.app${i}`);
  const rows = E.evidenceRows({ module: 'some_check', data: { apps } });
  assert.match(get(rows, 'Apps').value, /app7, and 4 more$/);
  assert.strictEqual(get(rows, 'Apps').copy.split(', ').length, 12);
  // A permission list is marked app by app: up to 16 apps, one row each.
  const many = Array.from({ length: 20 }, (_, i) => `com.example.app${i}`);
  const perm = E.evidenceRows({ module: 'app_permissions', data: { apps: many } }).filter((r) => r.label === 'App');
  assert.strictEqual(perm.length, 17);
  assert.strictEqual(perm[16].value, 'and 4 more');
});

test('long paths keep their start and end; the whole path is on copy', () => {
  const p = `/Users/ann/${'very-long-folder/'.repeat(8)}thing.plist`;
  const r = get(E.evidenceRows({ module: 'x', data: { path: p } }), 'Where');
  assert.ok(r.value.length <= 64, r.value);
  assert.match(r.value, /^~\/very.*….*thing\.plist$/);
  assert.strictEqual(r.copy, p.replace('/Users/ann', '~'));
});

test('helpers', () => {
  assert.strictEqual(E.plainDay('2026-10-10T18:44:55+00:00'), '10 Oct 2026');
  assert.strictEqual(E.plainDay('2026-01-02'), '2 Jan 2026');
  assert.strictEqual(E.plainDay('2026-10-13 11:16:42'), '13 Oct 2026');
  assert.strictEqual(E.plainDay('yesterday'), 'yesterday');
  assert.strictEqual(E.plainDay('2026-13-01'), '2026-13-01');
  assert.strictEqual(E.plainDay(new Date(2026, 9, 18, 23, 3)), '18 Oct 2026');
  assert.strictEqual(E.shortHash('abc'), 'abc');
  assert.strictEqual(E.homeRelative('/Users/ann/x and /home/bob/y C:\\Users\\Eve\\z /Users/Shared/q'), '~/x and ~/y ~\\z /Users/Shared/q');
  assert.strictEqual(E.bytes(512), '512 bytes');
  assert.strictEqual(E.checkLabel('code_signature_audit', { modules: [{ name: 'code_signature_audit', check_name: 'Checking app signatures' }] }), 'Checking app signatures');
  assert.strictEqual(E.checkLabel('smcreset_guide', null), 'Smcreset guide');
  assert.strictEqual(E.shortCommand(['/usr/sbin/system_profiler', 'SPUSBDataType', '-json']), 'system_profiler -json …');
  assert.strictEqual(E.shortCommand(['codesign', '--verify', '--deep', '--strict', '/Applications/Baba Is You.app']),
    'codesign --verify … /Applications/Baba Is You.app');
  assert.strictEqual(E.shortCommand(['ls']), 'ls');
  // Whole folder names: the first two and last three (P2-10).
  assert.strictEqual(E.shortPath('/tmp/claude-501/-Users-annhoward-src-multiverse-device-rescue/e5f5649d-5eac-431b-840f-8c301f2c6330/scratchpad/plan/gen4.py'),
    '/tmp/claude-501/…/scratchpad/plan/gen4.py');
});

test('odd input never throws', () => {
  for (const f of [null, undefined, 1, 'x', [], {}, { data: null }, { data: [] }, { data: { apps: 'nope' } },
    { module: 'hosts_file_check', data: { entries: 'x' } }, { module: 'keylogger_indicators', data: { apps: null }, made_by: 'x' },
    { module: 'security_baseline_diff', data: { added: 'x' } }, { made_by: [null, 1, { verified: true }] }]) {
    assert.ok(Array.isArray(E.evidenceRows(f)));
    assert.ok(Array.isArray(E.evidenceRows(f, { mode: 'city' })));
  }
  assert.strictEqual(E.renderEvidence([]), '');
  assert.strictEqual(E.renderEvidence(null), '');
});

test('renderEvidence: a grid, monospace only where marked, Copy only on monospace values, and copy all', () => {
  const rows = E.evidenceRows(F.agent);
  const html = E.renderEvidence(rows);
  assert.match(html, /^<section class="evidence" data-evidence>/);
  assert.strictEqual((html.match(/<dt>/g) || []).length, rows.length);
  assert.ok(rows.some((r) => !r.mono) && rows.some((r) => r.mono));
  assert.strictEqual((html.match(/class="evidence-copy"/g) || []).length, rows.filter((r) => r.mono).length + 1);
  assert.doesNotMatch(html, /aria-label="Copy Made by"|aria-label="Copy Check"/, 'no Copy on plain words');
  assert.strictEqual((html.match(/<code class="evidence-mono"/g) || []).length, rows.filter((r) => r.mono).length);
  assert.match(html, /data-evidence-copy="Background task: ai.hermes.gateway-deflock\nRuns: /);
  assert.match(html, /title="78eb25a05b2228/, 'the full hash on hover');
  assert.doesNotMatch(E.renderEvidence(rows, { copy: false }), /button/);
  assert.match(E.renderEvidence(rows, { title: 'Write this down' }), /Write this down/);
});

test('renderEvidence escapes everything the scan reported', () => {
  const evil = '<img src=x onerror=alert(1)>"\'&';
  const rows = E.evidenceRows({ module: 'launch_agent_audit', check_name: evil, data: { label: evil, program: `/tmp/${evil}` },
    made_by: [{ subject: evil, name: evil, verified: false, how: evil }] });
  const html = E.renderEvidence(rows, { title: evil });
  assert.doesNotMatch(html, /<img/);
  assert.doesNotMatch(html, /"'&[^a#]/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;&quot;&#39;&amp;/);
  // Attribute values can't be broken out of either.
  for (const m of html.matchAll(/data-evidence-copy="([^"]*)"/g)) assert.doesNotMatch(m[1], /[<>]/);
});

test('evidenceText: one "Label: value" line per row, full values', () => {
  const rows = E.evidenceRows(F.agent);
  const text = E.evidenceText(rows);
  assert.strictEqual(text.split('\n').length, rows.length);
  assert.match(text, /Arguments hash: 78eb25a05b222855488b6d1369beadb4a5695779698d736bc964c84d1daca7f0/);
});

test('wireCopy writes the button\'s text and says Copied', async () => {
  let handler = null;
  const root = { addEventListener: (t, h) => { handler = h; }, removeEventListener: () => { handler = null; } };
  const written = [];
  const btn = { textContent: 'Copy', getAttribute: () => 'Runs: ~/x', closest: () => btn };
  const off = E.wireCopy(root, (t) => { written.push(t); });
  handler({ target: btn });
  await new Promise((r) => setImmediate(r));
  assert.deepStrictEqual(written, ['Runs: ~/x']);
  assert.strictEqual(btn.textContent, 'Copied');
  handler({ target: { closest: () => null } });
  off();
  assert.strictEqual(handler, null);
  assert.strictEqual(typeof E.wireCopy(null, () => {}), 'function');
});

test('the monitoring checks are the same three as the rest of the app', () => {
  const Q = require('../renderer/quiet-notes.js');
  assert.deepStrictEqual([...E.MONITORING_MODULES].sort(), [...Q.MONITORING_MODULES].sort());
});

test('an adapter for every finding in the evidence table of the audit', () => {
  for (const m of ['code_signature_audit', 'launch_agent_audit', 'session_revocation_scan', 'hosts_file_check',
    'suspicious_connections', 'resource_hog_identifier', 'security_baseline_diff', 'keylogger_indicators', 'stalkerware_scan']) {
    assert.strictEqual(typeof E.ADAPTERS[m], 'function', m);
  }
});

test('no filler When row: only a real date', () => {
  assert.ok(!E.evidenceRows(F.agent).some((r) => r.label === 'When'));
  assert.ok(!E.evidenceRows(F.agent).some((r) => r.value === 'This checkup'));
  assert.strictEqual(get(E.evidenceRows(F.agent, { seen: '2026-10-18T23:03:00+00:00' }), 'When').value, '18 Oct 2026');
  assert.strictEqual(get(E.evidenceRows({ ...F.agent, collected_at: '2026-10-17' }), 'When').value, '17 Oct 2026');
});

test('city, held: no clipboard at all, drawn large, to write on paper', () => {
  const rows = E.evidenceRows(F.mspy, { mode: 'city', seen: '2026-10-18' });
  assert.strictEqual(rows.held, true);
  for (const html of [E.renderEvidence(rows), E.renderEvidence(rows, { copy: true }), E.renderEvidence([...rows], { held: true })]) {
    assert.doesNotMatch(html, /<button|data-evidence-copy|Copy/);
    assert.match(html, /class="evidence evidence--held"/);
    assert.match(html, /Write this on paper or on another device\./);
  }
  assert.match(E.CSS, /\.evidence--held\{font-size:1\.2em/);
  // Plain, or not held: the copy controls are there.
  assert.strictEqual(E.evidenceRows(F.mspy, { mode: 'standard' }).held, undefined);
  assert.match(E.renderEvidence(E.evidenceRows(F.mspy, { mode: 'standard' })), /Copy all/);
  // Flags never show up as a row's key.
  assert.deepStrictEqual(Object.keys(rows), rows.map((_, i) => String(i)));
});

test('keyboard access with every maker verified: the rows replace the "not verified" prose', () => {
  const kb = { ...F.keyboard, description: 'This tool has not verified who actually made them, because an app can pick any name.' };
  assert.strictEqual(E.replacesDescription(kb), true);
  assert.strictEqual(E.evidenceRows(kb, { mode: 'city', held: false }).replacesDescription, true);
  assert.strictEqual(E.evidenceRows(kb).replacesDescription, true);
  assert.strictEqual(E.replacesDescription({ ...kb, makers_verified: true, made_by: [] }), true, 'the engine’s own makers_verified');
  // Not every maker verified, or the engine says not: the prose stays.
  const one = { ...kb, made_by: [kb.made_by[0], { ...kb.made_by[1], verified: false }] };
  assert.strictEqual(E.replacesDescription(one), false);
  assert.strictEqual(E.evidenceRows(one).replacesDescription, undefined);
  assert.strictEqual(E.replacesDescription({ ...kb, makers_verified: false }), false);
  // Apps named by bundle id (a TCC row's client): what the app says it is,
  // never verified, even with a "verified" entry under that name.
  const named = { ...kb, data: { ...kb.data, apps: ['com.google.Chrome'] },
    made_by: [{ subject: 'com.google.Chrome', name: 'Google LLC', verified: true, what: 'Google Chrome' }] };
  assert.strictEqual(E.makersVerified(named), false);
  assert.strictEqual(E.replacesDescription(named), false, 'the engine’s “not verified” prose stays');
  assert.strictEqual(E.evidenceRows(named).replacesDescription, undefined);
  // Other findings never.
  assert.strictEqual(E.replacesDescription(F.tampered), false);
  assert.strictEqual(E.replacesDescription({ ...F.agent, made_by: [{ subject: 'x', name: 'Apple', verified: true }] }), false);
});

// ---- UX round 3 (P1-5, P2-4, P2-6) -------------------------------------------

test('several makers: the label stays "Made by", the program goes in the value', () => {
  const rows = E.evidenceRows({ module: 'launch_agent_audit', data: { label: 'ai.x' }, made_by: [
    { subject: '/Users/ann/.hermes/venv/bin/python', name: 'Unknown maker', verified: false },
    { subject: '/Users/ann/Library/LaunchAgents/ai.x.plist', name: 'Unknown maker', verified: false },
  ] });
  const made = rows.filter((r) => r.label.startsWith('Made by'));
  assert.deepStrictEqual(made.map((r) => r.label), ['Made by', 'Made by']);
  assert.strictEqual(made[0].value, 'python — Unknown maker · not verified');
  assert.strictEqual(made[1].value, 'ai.x.plist — Unknown maker · not verified');
  assert.match(made[0].copy, /^~\/\.hermes\/venv\/bin\/python — /);
});

test('no developer labels or filler: empty values, *_type, check and source keys are left out; keys read as words', () => {
  const rows = E.evidenceRows({ module: 'dns_config', data: {
    check_type: 'suspicious_dns', source: 'filesystem', servers: ['45.90.28.163'], blank: '  ', none: null,
    settings: { font_smoothing: '', mouse_tracking_speed: 1.5, keyRepeat: 2, empty: [] },
  } });
  const labels = rows.map((r) => r.label);
  assert.ok(!labels.some((l) => /type|source|blank|none/i.test(l)), labels.join(', '));
  assert.deepStrictEqual(labels.filter((l) => /check/i.test(l)), ['Check'], 'only the check’s name');
  assert.ok(!labels.includes('font_smoothing') && !labels.includes('Font smoothing'), 'an empty value is no row');
  assert.ok(labels.includes('Mouse tracking speed'));
  assert.ok(labels.includes('Key repeat'));
  assert.strictEqual(rows.find((r) => r.label === 'DNS servers').value, '45.90.28.163');
  assert.ok(!rows.some((r) => r.value === ''), 'no empty value');
});

test('app lists: names first, in the "It’s mine" panel’s order, each with the maker looked up for it', () => {
  const f = {
    module: 'app_permissions',
    data: { check: 'accessibility_access', apps: ['com.getdropbox.dropbox', 'com.apple.Terminal', 'com.example.x'] },
    made_by: [{ subject: 'com.getdropbox.dropbox', name: 'Dropbox, Inc.', verified: true }],
    markable: { items: [
      { key: 'com.apple.Terminal', label: 'Terminal', made_by: { subject: 'com.apple.Terminal', name: 'Apple', verified: true } },
      { key: 'com.getdropbox.dropbox', label: 'Dropbox' },
      { key: 'com.example.x', label: 'com.example.x' },
    ] },
  };
  const apps = E.evidenceRows(f).filter((r) => r.label === 'App').map((r) => r.value);
  assert.deepStrictEqual(apps, [
    'Terminal (com.apple.Terminal) — Apple · verified',
    'Dropbox (com.getdropbox.dropbox) — Dropbox, Inc. · verified',
    'com.example.x',
  ]);
});

test('makers verified: a {path, name} app counts only by its path, never by its own name', () => {
  const vscode = [{ subject: '/Applications/Visual Studio Code.app', verified: true }];
  assert.strictEqual(E.makersVerified({ made_by: vscode, data: { apps: [{ name: '/Applications/Visual Studio Code.app', path: '/tmp/evil' }] } }), false);
  assert.strictEqual(E.makersVerified({ made_by: vscode, data: { apps: [{ name: 'x', path: '/Applications/Visual Studio Code.app' }] } }), true);
  assert.strictEqual(E.makersVerified({ made_by: vscode, data: { apps: [{ name: 'Code' }] } }), false);
});

test('a code-signature finding says how much of the list was checked', () => {
  const rows = E.evidenceRows({ module: 'code_signature_audit', data: { name: 'A', path: '/Applications/A.app', apps_checked: 17, apps_total: 110 } });
  assert.strictEqual(rows.find((r) => r.label === 'Checked').value, '17 of 110 apps');
  assert.ok(!rows.some((r) => /apps (checked|total)/i.test(r.label)));
});

test('values wrap between names, the label column is capped, and narrow blocks stack', () => {
  const html = E.renderEvidence([{ label: 'Where', value: '~/Library/LaunchAgents/ai.hermes.gateway-deflock.plist', mono: true, copy: 'x' }]);
  assert.match(html, /~\/<wbr>Library\/<wbr>LaunchAgents\/<wbr>ai\.<wbr>hermes\.<wbr>gateway-deflock\.<wbr>plist/);
  assert.doesNotMatch(E.breakable('a <b>/c'), /<b>/, 'still escaped');
  assert.match(E.CSS, /grid-template-columns:fit-content\(11em\) minmax\(0,1fr\)/);
  assert.match(E.CSS, /\.evidence\{[^}]*container-type:inline-size/);
  assert.match(E.CSS, /@container \(max-width:28rem\)\{\.evidence-grid\{grid-template-columns:1fr/);
  assert.match(E.CSS, /@media \(max-width:800px\)\{\.evidence-grid\{grid-template-columns:1fr/);
  assert.doesNotMatch(E.CSS, /max-content/);
});
