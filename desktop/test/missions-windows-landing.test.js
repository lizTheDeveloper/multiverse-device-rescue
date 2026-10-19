'use strict';
// The Windows twin of missions-macos-landing.test.js: where every Windows check
// that can raise a to-do (a critical or warning finding) lands. The table is
// checked in (fixtures/missions/windows-landing.json); only checks listed on
// purpose (types.js WIN_ODD_JOBS, or ODD_JOBS for shared ones) may land in Odd
// Jobs ('simple'). Regenerate after an intended change with:
//   UPDATE_LANDING=1 node --test test/missions-windows-landing.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');

const MODULES = path.join(__dirname, '..', '..', 'modules');
const SNAPSHOT = path.join(__dirname, 'fixtures', 'missions', 'windows-landing.json');
const NO_CODE = '(no code)';
const imp = (rel) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', rel)).href);

// Every Windows engine module and the codes of its critical/warning findings,
// read from its source: each Finding( … ) block with Severity.CRITICAL or
// Severity.WARNING gives its literal code, or NO_CODE when it has none.
function windowsTodoChecks() {
  const out = {};
  for (const cat of fs.readdirSync(MODULES)) {
    const cdir = path.join(MODULES, cat);
    if (!fs.statSync(cdir).isDirectory()) continue;
    for (const dir of fs.readdirSync(cdir)) {
      const mdir = path.join(cdir, dir);
      const init = path.join(mdir, '__init__.py');
      if (!fs.existsSync(init)) continue;
      const head = fs.readFileSync(init, 'utf8');
      const name = (/^\s+name = "([a-z0-9_]+)"/m.exec(head) || [])[1];
      const platforms = (/platforms = \[([^\]]*)\]/.exec(head) || [])[1] || '';
      if (!name || !/Platform\.WIN32/.test(platforms)) continue;
      const src = fs.readdirSync(mdir).filter((f) => f.endsWith('.py')).map((f) => fs.readFileSync(path.join(mdir, f), 'utf8')).join('\n');
      const codes = new Set();
      const blocks = src.split(/\bFinding\(/).slice(1);
      for (const b of blocks) {
        if (!/Severity\.(?:CRITICAL|WARNING)/.test(b.split(/\bFinding\(|\bCheckResult\(/)[0])) continue;
        const m = /\bcode="([a-z0-9_.]+)"/.exec(b);
        codes.add(m ? m[1] : NO_CODE);
      }
      if (!codes.size && /Severity\.(?:CRITICAL|WARNING)/.test(src)) codes.add(NO_CODE);
      if (codes.size) out[name] = [...codes].sort();
    }
  }
  return out;
}

async function landing() {
  const T = await imp('types.js');
  const I = await imp('games/index.js');
  const reg = await I.loadGames();
  assert.deepStrictEqual(reg.problems, [], 'every game loads and nothing is claimed twice');
  const table = T.buildTable(I.ownGames(reg));
  const checks = windowsTodoChecks();
  const out = {};
  for (const name of Object.keys(checks).sort()) {
    out[name] = {};
    for (const code of checks[name]) {
      out[name][code] = T.typeOf({ module: name, severity: 'warning', ...(code === NO_CODE ? {} : { code }), data: {} }, table);
    }
  }
  return { out, T };
}

test('every Windows check that can raise a to-do lands in a mini-game; only intentional ones in Odd Jobs', async () => {
  const { out, T } = await landing();
  assert.ok(Object.keys(out).length > 80, 'the engine’s Windows modules were read');
  if (process.env.UPDATE_LANDING === '1') fs.writeFileSync(SNAPSHOT, `${JSON.stringify(out, null, 1)}\n`);
  const odd = new Set([...T.WIN_ODD_JOBS, ...T.ODD_JOBS]);
  const unintended = [];
  for (const [m, codes] of Object.entries(out)) for (const [c, type] of Object.entries(codes)) if (type === 'simple' && !odd.has(m)) unintended.push(`${m} ${c}`);
  assert.deepStrictEqual(unintended, [], 'these land in Odd Jobs without being listed in types.js WIN_ODD_JOBS');
  assert.deepStrictEqual(out, JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8')), 'where checks land changed: review, then regenerate the table');
});

test('the Windows gaps the review found land in their games', async () => {
  const { out } = await landing();
  const s = (c) => `security.win_suspicious_processes.${c}`;
  assert.strictEqual(out.win_suspicious_processes[s('known_malware')], 'locker');
  assert.strictEqual(out.win_suspicious_processes[s('encoded_powershell')], 'locker');
  assert.strictEqual(out.win_suspicious_processes[s('mining_software')], 'locker');
  assert.strictEqual(out.win_suspicious_processes[s('suspicious_path')], 'seal');
  assert.strictEqual(out.win_suspicious_processes[s('no_file_path')], 'seal');
  for (const c of Object.keys(out.win_autorun)) assert.strictEqual(out.win_autorun[c], 'locks', c);
  for (const c of Object.keys(out.win_local_admin_audit)) assert.strictEqual(out.win_local_admin_audit[c], 'locks', c);
  for (const c of Object.keys(out.win_credential_manager_audit)) assert.strictEqual(out.win_credential_manager_audit[c], 'locks', c);
});

test('the WIN_ODD_JOBS list is all real Windows checks that still land in Odd Jobs', async () => {
  const { out, T } = await landing();
  for (const m of T.WIN_ODD_JOBS) {
    assert.ok(out[m], `${m} is a Windows check that can warn`);
    assert.ok(Object.values(out[m]).includes('simple'), `${m} no longer lands in Odd Jobs: take it off the list`);
  }
});

test('the moved Windows items play in their games: contract checks, the right lock, the seal verdict', async () => {
  const C = await imp('contract.js');
  const I = await imp('games/index.js');
  const reg = await I.loadGames();
  const item = (module, code, data = {}, severity = 'warning') => C.makeItem({ module, code: `security.${module}.${code}`, title: `${module} ${code}`, description: 'x', severity, data });
  const moved = {
    locker: [item('win_suspicious_processes', 'known_malware', { pid: 7, name: 'evil.exe', path: 'C:\\Users\\Public\\evil.exe', type: 'known_malware' }, 'critical'),
      item('win_suspicious_processes', 'encoded_powershell', { command: 'powershell -enc AAAA', type: 'encoded_powershell' }),
      item('win_suspicious_processes', 'mining_software', { pid: 8, name: 'xmrig.exe', path: 'C:\\Temp\\xmrig.exe', type: 'mining_software' })],
    seal: [item('win_suspicious_processes', 'suspicious_path', { pid: 9, name: 'helper.exe', path: 'C:\\Temp\\helper.exe', type: 'suspicious_path' }),
      item('win_suspicious_processes', 'no_file_path', { pid: 10, name: 'ghost', type: 'no_file_path' })],
    locks: [item('win_autorun', 'autorun_enabled', { value: 0 }), item('win_autorun', 'autoplay_enabled', {}),
      item('win_local_admin_audit', 'guest_account_enabled', { check: 'guest_enabled' }, 'critical'),
      item('win_local_admin_audit', 'admin_blank_password', { check: 'blank_password', users: ['Example'] }, 'critical'),
      item('win_local_admin_audit', 'excessive_admin_accounts', { check: 'excessive_admins', users: ['A', 'B', 'C'] }),
      item('win_credential_manager_audit', 'credential_sprawl', {})],
  };
  for (const [type, items] of Object.entries(moved)) {
    assert.ok(reg.own.has(type), type);
    assert.deepStrictEqual(C.runContractChecks(reg.games[type], items), [], type);
  }
  const L = await imp('games/locks.js');
  assert.deepStrictEqual(moved.locks.map((i) => L.lockOf(i.finding)), ['autorun', 'autorun', 'guest', 'password', 'admins', 'saved-logins']);
  const S = await imp('games/seal.js');
  for (const it of moved.seal) assert.strictEqual(S.classify(it.finding).verdict, 'unknown-maker', it.finding.code);
});
