'use strict';
// Remote-access tools in city (stealth) mode: held in the help district with
// their evidence, never a mission; in standard mode an ordinary to-do that
// pays (spec 2026-10-21-remote-access-think-back-design.md, "Stealth (city) mode").
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const NotChecked = require('../renderer/not-checked.js');

const url = (...p) => pathToFileURL(path.join(__dirname, '..', 'renderer', ...p)).href;
const game = (f) => import(url('game', f));
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });

// Synthetic: the engine's remote_access_tools shape (plan Task 3), made-up paths only.
const RA = 'security.remote_access_tools.';
const tool = (over = {}, data = {}) => ({
  title: 'AnyDesk can let someone control this computer', description: 'Added on 3 March 2026.\n\nScammers who call or show a pop-up often ask people to install tools like this.',
  severity: 'warning', category: 'security', code: `${RA}tool_found`, removal_alert: true,
  data: { check: 'tool_found', tool: 'AnyDesk', tool_id: 'anydesk', path: '/Applications/AnyDesk.app', added_on: '2026-03-03',
    lets_in_unattended: true, unattended_via: 'com.philandro.anydesk.service', running_now: false,
    last_incoming: '2026-03-12', incoming_count: 4, one_off: false, known_item_kind: 'remote_tool', ...data },
  ...over,
});
const undated = () => tool({ title: 'TeamViewer can let someone control this computer' },
  { tool: 'TeamViewer', tool_id: 'teamviewer', path: '/Applications/TeamViewer.app', added_on: null, lets_in_unattended: null,
    unattended_via: null, running_now: null, last_incoming: null, incoming_count: null });

test('city: a remote_access_tools warning is in held, not in any mission', async () => {
  const T = await import(url('missions', 'types.js'));
  const doc = scan(mod('remote_access_tools', [tool()]));
  const list = NotChecked.displayItems(doc, { mode: 'city' });
  assert.strictEqual(list.held.length, 1);
  assert.strictEqual(list.warning.length, 0);
  const ms = T.groupMissions(doc, { mode: 'city' });
  assert.ok(!ms.some((m) => m.items.some((i) => i.finding.module === 'remote_access_tools')), 'no mission');
  const c = NotChecked.scanCounts(doc, { mode: 'city' });
  assert.strictEqual(c.todo, 0);
  assert.strictEqual(c.heldItems, 1);
  // The city's own doc (signals, districts) has none of it; the held city has it, in memory.
  const { splitHeld, heldOnly } = await game('held.js');
  const split = splitHeld(doc, { mode: 'city' });
  assert.strictEqual(split.held.length, 1);
  assert.deepStrictEqual(split.doc.modules[0].findings, []);
  assert.strictEqual(heldOnly(doc, { mode: 'city' }).modules[0].findings.length, 1);
  // Its district is never "secured" while it's there (signals.js integrity counts the held city).
  const { findingsToCity } = await game('findings-to-city.js');
  const { heldDistrictIds } = await game('signals.js');
  assert.strictEqual(heldDistrictIds(findingsToCity(heldOnly(doc, { mode: 'city' }))).size, 1);
});

test('standard: the same finding is a to-do, not held-diverted', async () => {
  const T = await import(url('missions', 'types.js'));
  const doc = scan(mod('remote_access_tools', [tool()]));
  const list = NotChecked.displayItems(doc, { mode: 'standard' });
  assert.strictEqual(list.warning.length, 1);
  assert.strictEqual(list.held.length, 0);
  const ms = T.groupMissions(doc, { mode: 'standard' });
  assert.strictEqual(ms.filter((m) => !m.notes).flatMap((m) => m.items).length, 1);
  assert.strictEqual(NotChecked.scanCounts(doc, { mode: 'standard' }).todo, 1);
  // The city map's own doc keeps it in standard mode, as before: only city mode holds it.
  const { splitHeld, heldOnly } = await game('held.js');
  assert.strictEqual(splitHeld(doc, { mode: 'standard' }).held.length, 0);
  assert.strictEqual(splitHeld(doc, { mode: 'standard' }).doc.modules[0].findings.length, 1);
  assert.strictEqual(heldOnly(doc, { mode: 'standard' }).modules.length, 0);
});

test('held evidence shows dates and "Couldn’t tell" when missing', async () => {
  const { heldEvidence } = await game('held.js');
  const e = heldEvidence(tool(), 'remote_access_tools');
  assert.strictEqual(e.name, 'AnyDesk');
  assert.strictEqual(e.where, '/Applications/AnyDesk.app');
  assert.match(e.added, /^Added on March 3(, 2026)?$/);
  assert.match(e.last_in, /^Last let someone in: March 12(, 2026)? \(4 times\)$/);
  assert.match(e.unattended, /without you clicking yes/);
  assert.match(e.running, /^Not running now$/);
  assert.strictEqual(e.running_now, false);
  const u = heldEvidence(undated(), 'remote_access_tools');
  assert.strictEqual(u.added, 'Couldn’t tell when this was added');
  assert.strictEqual(u.last_in, 'Couldn’t tell when it last let someone in');
  assert.match(u.unattended, /^Couldn’t tell/);
  assert.match(u.running, /^Couldn’t tell/);
  // A monitoring check's evidence is as before.
  const s = heldEvidence({ data: { stalkerware_name: 'X', location: '/x' } }, 'stalkerware_scan');
  assert.deepStrictEqual(Object.keys(s).sort(), ['name', 'where']);
});

test('running now: offline line comes first', async () => {
  const { splitHeld } = await game('held.js');
  const { renderSide } = await game('views/side-district.js');
  const { pickDistrict } = await game('district-names.js');
  const district = pickDistrict(7);
  // Two tools: only the running one is named, so the line never contradicts a card that says "No".
  const held = splitHeld(scan(mod('remote_access_tools', [undated(), tool({}, { running_now: true })])), { mode: 'city' }).held;
  const html = renderSide({ district, held, seen: new Date(2026, 9, 22) }).replace(/<wbr>/g, '');
  const offline = html.indexOf('AnyDesk is running now. To be safe, go offline first.');
  assert.ok(offline > 0, 'the line names the running tool');
  assert.doesNotMatch(html, /TeamViewer is running/);
  assert.ok(offline < html.indexOf('class="held-items"'), 'before the held items');
  assert.ok(offline < html.indexOf('Don’t remove it yet'), 'before anything else in the panel');
  assert.match(html, /data-act="side-offline"/, 'with the network settings (the controller opens research.js’s network pane)');
  // Each tool's facts are rows inside its own card, before the day it was found.
  const cards = html.split('<li class="held-item">').slice(1);
  assert.strictEqual(cards.length, 2);
  const [tv, ad] = cards;
  assert.match(tv, /TeamViewer/);
  assert.match(tv, /<dt>Added<\/dt><dd><span>Couldn’t tell<\/span>/);
  assert.match(tv, /<dt>Running now<\/dt><dd><span>Couldn’t tell<\/span>/);
  assert.match(ad, /<dt>Added<\/dt><dd><span>March 3(, 2026)?<\/span>/);
  assert.match(ad, /<dt>Last let someone in<\/dt><dd><span>March 12(, 2026)? \(4 times\)<\/span>/);
  assert.match(ad, /<dt>Can let someone in without a click<\/dt><dd><span>Yes<\/span>/);
  assert.match(ad, /<dt>Running now<\/dt><dd><span>Yes<\/span>/);
  assert.ok(ad.indexOf('<dt>Added</dt>') < ad.indexOf('<dt>Found on</dt>'));
  assert.match(ad, /<dt>Found on<\/dt><dd><span>22 Oct 2026<\/span>/);
  assert.doesNotMatch(html, /held-facts/, 'no facts floating outside a card');
  // Several running: all named, joined in words; city words stay safe.
  const two = splitHeld(scan(mod('remote_access_tools', [tool({}, { running_now: true }), tool({}, { tool: 'RustDesk', path: '/Applications/RustDesk.app', running_now: true })])), { mode: 'city' }).held;
  const both = renderSide({ district, held: two });
  assert.match(both, /AnyDesk and RustDesk are running now\. To be safe, go offline first\./);
  const C0 = await import(url('missions', 'contract.js'));
  const line = both.match(/<p class="intel side-offline"[\s\S]*?<\/p>/)[0];
  assert.deepStrictEqual(C0.checkCityWords(line), []);
  // Not running: no offline line.
  const quiet = renderSide({ district, held: splitHeld(scan(mod('remote_access_tools', [tool()])), { mode: 'city' }).held });
  assert.doesNotMatch(quiet, /go offline first/);
  // Hostile values stay inert.
  const C = await import(url('missions', 'contract.js'));
  for (const h of C.HOSTILE) {
    const bad = splitHeld(scan(mod('remote_access_tools', [tool({ title: h }, { tool: h, path: h, added_on: h, last_incoming: h, running_now: true })])), { mode: 'city' }).held;
    assert.deepStrictEqual(C.checkInert(renderSide({ district, held: bad })).filter((p) => !/control\/bidi/.test(p)), []);
  }
});

test('city held text outside the help district passes CITY_FORBIDDEN', async () => {
  const C = await import(url('missions', 'contract.js'));
  const { heldNoticeHtml, sideTileHtml } = await game('views/side-district.js');
  const district = { name: 'The Bakery', look: 'warm', voice: { hello: 'Fresh bread today.', bye: 'Bye.' } };
  assert.deepStrictEqual(C.checkCityWords(heldNoticeHtml(district) + sideTileHtml(district, 1)), []);
  const T = await import(url('missions', 'types.js'));
  const ms = T.groupMissions(scan(mod('remote_access_tools', [tool({}, { running_now: true })])), { mode: 'city' });
  assert.deepStrictEqual(C.checkCityWords(JSON.stringify(ms)), []);
  // app.js never names the check in city mode, as for the monitoring checks.
  const app = require('../renderer/app.js');
  assert.ok(app.CITY_HELD_MODULES.has('remote_access_tools'));
});

test('a remote tool item still pays in standard mode', async () => {
  const { isMonitoringItem } = await game('missions-city.js');
  const C = await import(url('missions', 'contract.js'));
  const T = await import(url('missions', 'types.js'));
  const item = T.groupMissions(scan(mod('remote_access_tools', [tool()])), { mode: 'standard' }).find((m) => !m.notes).items[0];
  assert.strictEqual(isMonitoringItem(item), false);
  assert.strictEqual(C.isMonitoringModule('remote_access_tools'), false);
  assert.strictEqual(item.removal_alert, true, 'it still warns');
  // The monitoring checks themselves are unchanged.
  assert.deepStrictEqual([...NotChecked.MONITORING_MODULES].sort(), ['keylogger_indicators', 'mvt_spyware_scan', 'stalkerware_scan']);
});

test('one list of what city mode holds, everywhere', async () => {
  const { CITY_HELD_MODULES, HELD_MODULES } = await game('held.js');
  const app = require('../renderer/app.js');
  const want = [...app.ALWAYS_SAFETY_MODULES, 'remote_access_tools'].sort();
  assert.deepStrictEqual([...CITY_HELD_MODULES].sort(), want);
  assert.deepStrictEqual([...NotChecked.HELD_IN_CITY].sort(), want);
  assert.deepStrictEqual([...app.CITY_HELD_MODULES].sort(), want);
  assert.deepStrictEqual([...HELD_MODULES].sort(), [...app.ALWAYS_SAFETY_MODULES].sort(), 'the monitoring checks stay three');
});
