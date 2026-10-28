const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const f = (module, code, data = {}) => ({ module, code: code && `security.${module}.${code}`, title: 'x', severity: 'warning', data });
const startup = (items) => ({ schema_version: 1, platform: 'darwin', modules: [
  { name: 'startup_optimizer', category: 'performance', status: 'ok', supported: true,
    findings: [{ title: 'N apps start automatically in the background', severity: 'info', data: { items } }] }] });
const kinds = async (finding, doc = null) => {
  const k = await game('program-kinds.js');
  return k.kindsOf(finding, k.programContext(doc)).map((x) => x.id);
};

test('each kind has one short label and one icon, defined once', async () => {
  const { PROGRAM_KINDS } = await game('program-kinds.js');
  for (const id of ['starts', 'schedule', 'running', 'listens', 'extension']) {
    const k = PROGRAM_KINDS[id];
    assert.ok(k, id);
    assert.ok(k.label.length > 0 && k.label.length <= 24, `${id}: ${k.label}`);
    assert.ok(k.icon, id);
  }
  const labels = Object.values(PROGRAM_KINDS).map((k) => k.label);
  assert.strictEqual(new Set(labels).size, labels.length, 'no two kinds share a label');
});

test('a launch agent is told apart by what its settings say, not by its title', async () => {
  const plist = '/Users/me/Library/LaunchAgents/com.example.helper.plist';
  const agent = { ...f('launch_agent_audit', 'suspicious_path', { label: 'com.example.helper', program: '/x', plist }), title: 'Background task runs from a hidden folder' };
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'com.example.helper', plist, when: ['at login'], running: true, pid: 12 }])), ['starts', 'running']);
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'com.example.helper', plist, when: ['every 5 minutes'], running: false, pid: null }])), ['schedule']);
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'com.example.helper', plist, when: ['on a schedule', 'kept running'] }])), ['starts', 'schedule']);
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'com.example.helper', plist, when: ['only when needed'] }])), ['background']);
  // No startup report in this scan: we don't know when it runs, and say so.
  assert.deepStrictEqual(await kinds(agent), ['background']);
});

test('the matching startup report entry is the one for the same settings file', async () => {
  const agent = f('launchd_persistence_audit', 'non_apple_info', { label: 'a.b', program: '/x', plist: '/L/a.b.plist' });
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'a.b', plist: '/other/a.b.plist', when: ['at login'] }])), ['background']);
  assert.deepStrictEqual(await kinds(agent, startup([{ label: 'a.b', plist: '/L/a.b.plist', when: ['at startup'] }])), ['starts']);
});

test('Windows, Linux, processes, ports and extensions', async () => {
  assert.deepStrictEqual(await kinds(f('win_autoruns_audit', 'temp_path_execution', { location: 'HKCU\\Run', command: 'x' })), ['starts']);
  assert.deepStrictEqual(await kinds(f('win_scheduled_tasks_security', 'frequent_schedule', { task_name: 't' })), ['schedule']);
  assert.deepStrictEqual(await kinds(f('win_scheduled_tasks_security', 'recent_boot_logon', { task_name: 't' })), ['starts']);
  assert.deepStrictEqual(await kinds(f('win_scheduled_tasks', 'suspicious_path', { task_name: 't' })), ['background']);
  assert.deepStrictEqual(await kinds(f('win_services_audit', 'suspicious_path', { name: 's' })), ['starts']);
  assert.deepStrictEqual(await kinds(f('cron_jobs_audit', 'every_minute', { entries: [] })), ['schedule']);
  assert.deepStrictEqual(await kinds(f('linux_persistence_audit', 'suspicious_content', { path: '/etc/systemd/system/x.timer', kind: 'systemd system unit' })), ['schedule']);
  assert.deepStrictEqual(await kinds(f('linux_persistence_audit', 'suspicious_content', { path: '/etc/systemd/system/x.service', kind: 'systemd system unit' })), ['starts']);
  assert.deepStrictEqual(await kinds(f('linux_persistence_audit', 'suspicious_content', { path: '/var/spool/cron/me', kind: 'user crontab' })), ['schedule']);
  assert.deepStrictEqual(await kinds(f('suspicious_processes', 'high_cpu', { processes: [] })), ['running']);
  assert.deepStrictEqual(await kinds(f('suspicious_connections', 'unusual_listening_port', { port: 4444 })), ['listens']);
  assert.deepStrictEqual(await kinds(f('open_ports_scan', 'listening_ports', { ports: [] })), ['listens']);
  assert.deepStrictEqual(await kinds(f('browser_extension_audit', 'excessive_permissions', { extension: 'Grammar', browser: 'Chrome' })), ['extension']);
  assert.deepStrictEqual(await kinds(f('firewall_audit', 'off', {})), []);
});

test('a marked item is told apart by its mark kind too', async () => {
  const marked = f('sharing_services', 'screen_sharing', { marked_by_user: true, marked_kind: 'sharing_service' });
  assert.deepStrictEqual(await kinds(marked), ['setting']);
  assert.deepStrictEqual(await kinds({ ...f('app_permissions', 'screen_recording', {}), markable: { kind: 'app_permissions' } }), ['access']);
});

test('the chips read as one short line, and the difference is taught in its own lesson', async () => {
  const { kindChipsHtml, PROGRAM_KINDS, KIND_LESSON } = await game('program-kinds.js');
  const html = kindChipsHtml([PROGRAM_KINDS.starts, PROGRAM_KINDS.running]);
  assert.match(html, /Starts on its own/i);
  assert.match(html, /Running now/i);
  assert.strictEqual(KIND_LESSON, 'what-kind-of-program');
  const file = path.join(__dirname, '..', 'renderer', 'game', 'lessons', `${KIND_LESSON}.js`);
  assert.ok(fs.existsSync(file));
  const lesson = (await import(pathToFileURL(file).href)).default;
  const text = JSON.stringify(lesson);
  for (const id of ['starts', 'schedule', 'running', 'listens', 'extension']) {
    assert.ok(text.toLowerCase().includes(PROGRAM_KINDS[id].label.toLowerCase()), `the lesson names "${PROGRAM_KINDS[id].label}"`);
  }
});
