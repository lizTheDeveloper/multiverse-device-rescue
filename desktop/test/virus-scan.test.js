// The virus scan's pieces in the app: the VirusTotal channel's URL, the
// lookup panel on a lead's case, quarantine results, and how a match becomes
// a case.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { virusTotalUrlFor } = require('../virustotal-url');
const FixFlow = require('../renderer/fix-flow.js');
const pkg = require('../package.json');

const SHA = 'ab'.repeat(32);

test('the VirusTotal channel only ever opens a fingerprint page', () => {
  assert.strictEqual(virusTotalUrlFor(SHA), `https://www.virustotal.com/gui/file/${SHA}`);
  for (const bad of [SHA.toUpperCase(), SHA.slice(1), `${SHA}0`, `${SHA}/../upload`, 'https://evil.example', null, 7, {}]) {
    assert.strictEqual(virusTotalUrlFor(bad), null, String(bad));
  }
});

test('main, preload and the package all carry the channel', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  assert.match(main, /ipcMain\.handle\('open-virustotal'/);
  assert.match(main, /virusTotalUrlFor\(sha256\)/);
  assert.match(preload, /openVirusTotal: \(sha256\) => ipcRenderer\.invoke\('open-virustotal', sha256\)/);
  assert.ok(pkg.build.files.includes('virustotal-url.js'));
});

test('the lookup panel shows only for a finding with a fingerprint, and warns before any upload', async () => {
  const { lookupHtml, lookupActSha, fingerprintOf } = await import('../renderer/game/lookup.js');
  assert.strictEqual(lookupHtml({ data: {} }), '');
  assert.strictEqual(lookupHtml({ data: { sha256: 'nope' } }), '');
  assert.strictEqual(lookupHtml(null), '');
  const html = lookupHtml({ data: { sha256: SHA } });
  assert.match(html, new RegExp(`data-act="vt-open:${SHA}"`));
  assert.match(html, /isn’t sent/);
  assert.match(html, /Never upload anything private/);
  assert.match(html, /paying customers/);
  assert.match(html, /data-go="lesson:known-malware"/);
  assert.strictEqual(fingerprintOf({ data: { sha256: SHA } }), SHA);
  assert.strictEqual(lookupActSha(`vt-open:${SHA}`), SHA);
  for (const bad of ['vt-open:', `vt-open:${SHA}x`, 'open-router', null]) assert.strictEqual(lookupActSha(bad), null);
});

const QFIX = {
  action: 'quarantine_file', target: '/Users/sam/Downloads/Player.command',
  will_change: "Moves 'Player.command' into Reclaim City's quarantine folder. Nothing is deleted.",
  how_to_undo: ['Open Reclaim City and choose Undo on this item'],
};

test('a quarantine confirmation names the file; monitoring puts the safety note first', () => {
  const plain = FixFlow.fixControlsHtml({ module: 'malware_file_scan', fixable: QFIX });
  assert.match(plain, /data-fix-action="quarantine_file"/);
  assert.doesNotMatch(plain, /role="note"/);
  const note = 'Before you remove or turn anything off: removing it can alert them.';
  const watched = FixFlow.fixControlsHtml({ module: 'malware_file_scan', fixable: { ...QFIX, safety_note: note } });
  assert.ok(watched.indexOf(note) > 0 && watched.indexOf(note) < watched.indexOf('This will:'), 'note before what it will do');
  assert.ok(watched.indexOf(note) < watched.indexOf('data-fix-confirm'), 'note before Yes');
});

test('quarantine results: done with Undo, put back, already handled', () => {
  const qid = '20261028T120000Z-file-0123456789abcdef';
  const done = FixFlow.describeFixResult({ action: 'quarantine_file', applied: true, verified: true, status: 'fixed',
    quarantine_id: qid, how_to_undo: ['Undo'] });
  assert.strictEqual(done.tone, 'success');
  assert.strictEqual(done.undoId, qid);
  assert.match(done.headline, /quarantine/);
  const back = FixFlow.describeFixResult({ action: 'undo_quarantine_file', applied: true, status: 'restored', message: 'Put back.' });
  assert.strictEqual(back.restored, true);
  const again = FixFlow.describeFixResult({ action: 'quarantine_file', status: 'nothing_to_fix', error: null, message: 'm' });
  assert.strictEqual(again.tone, 'info');
  const refused = FixFlow.describeFixResult({ action: 'quarantine_file', status: 'refused', error: 'not_allowed', message: 'system file' });
  assert.strictEqual(refused.tone, 'error');
});

const sig = (over = {}) => ({ id: 'x', kind: 'real', severity: 'critical', title: 'T', districtId: 'gatehouse',
  module: 'malware_file_scan', finding: {}, tag: null, ...over });

test('a virus match is a lead, high risk if not yours; the scanners\' own status is not', async () => {
  const { caseOf } = await import('../renderer/game/case-file.js');
  const yara = caseOf(sig({ finding: { code: 'security.malware_file_scan.malware_match' } }));
  assert.deepStrictEqual([yara.type, yara.status, yara.priority], ['lead', 'unidentified', 'high']);
  const clam = caseOf(sig({ module: 'clamav_scanner', finding: { code: 'security.clamav_scanner.virus_found' } }));
  assert.strictEqual(clam.type, 'lead');
  const old = caseOf(sig({ module: 'clamav_scanner', severity: 'warning', finding: { code: 'security.clamav_scanner.clamav_outdated_definitions' } }));
  assert.notStrictEqual(old.type, 'lead');
});

test('a monitoring match is SAFETY FIRST, and MINE never closes it', async () => {
  const { caseOf } = await import('../renderer/game/case-file.js');
  for (const code of ['security.malware_file_scan.monitoring_match', 'security.clamav_scanner.monitoring_found',
    'security.win_defender_scan.monitoring_threat']) {
    const c = caseOf(sig({ tag: 'mine', finding: { code } }));
    assert.deepStrictEqual([c.status, c.open, c.priority], ['held', true, 'high'], code);
  }
});
