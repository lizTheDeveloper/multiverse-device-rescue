const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (feeling) => `<i data-scout="${feeling}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/map.js')),
  ...(await import('../renderer/game/views/district.js')),
  ...(await import('../renderer/game/views/briefing.js')),
  ...(await import('../renderer/game/views/outcome.js')),
  ...(await import('../renderer/game/views/hud.js')),
  ...(await import('../renderer/game/scout-lines.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/progress.js')),
});

function evilCity(findingsToCity) {
  return findingsToCity({ modules: [
    { name: 'launch_agent_audit', category: 'security', status: 'ok', supported: true, findings: [
      { title: EVIL, description: EVIL, severity: 'critical', code: 'security.launch_agent_audit.suspicious_path',
        data: { plist: EVIL }, remediation: { title: EVIL, steps: [{ number: 1, title: EVIL, body: EVIL }] } },
      { title: EVIL, description: EVIL, severity: 'info', data: {} },
    ] },
    { name: 'wifi_security_audit', category: 'network', status: 'ok', supported: false, unsupported_reason: EVIL, findings: [] },
  ] });
}

test('no view lets engine text through as HTML', async () => {
  const v = await views();
  const city = evilCity(v.findingsToCity);
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  const mission = gate.missions[0];
  const html = [
    v.renderHud({ title: 'YOUR COMPUTER', city, progress: v.emptyProgress() }),
    v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout }),
    v.renderDistrict({ district: gate, progress: v.emptyProgress(), scout }),
    v.renderDistrict({ district: city.districts.find((d) => d.id === 'wires'), progress: v.emptyProgress(), scout }),
    v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false }),
    v.renderOutcome({ kind: 'not-yet', mission, scout, message: EVIL }),
    v.renderOutcome({ kind: 'couldnt', mission, scout, message: EVIL }),
  ].join('\n');
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('fog says it is not safe; none says no checks ran; neither says clear', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [
    { name: 'wifi_security_audit', category: 'network', status: 'ok', supported: false, unsupported_reason: 'Needs permission.', findings: [] },
  ] });
  const map = v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout });
  assert.match(map, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  assert.match(map, /No checks ran here/);
});

test('the briefing shows the controls it is given, the steps, and the three ways out', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts.find((d) => d.id === 'gatehouse').missions[0];
  const html = v.renderBriefing({ mission, status: 'open', controlsHtml: '<div data-fix-module="m">FIX</div>', scout, busy: false, wantsSafety: false });
  assert.match(html, /data-fix-module="m">FIX/);
  assert.match(html, /data-act="i-did-it"/);
  assert.match(html, /data-act="later"/);
  assert.match(html, /data-go="district:gatehouse"/);
});

test('while a re-check runs the briefing says so and offers nothing to click twice', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts.find((d) => d.id === 'gatehouse').missions[0];
  const html = v.renderBriefing({ mission, status: 'open', controlsHtml: 'X', scout, busy: true, wantsSafety: false });
  assert.match(html, /Checking again/);
  assert.doesNotMatch(html, /data-act="i-did-it"/);
});

test('the safety note shows when asked for and the mission has one', async () => {
  const v = await views();
  const mission = { ...evilCity(v.findingsToCity).districts[0].missions[0], safetyNote: 'Talk to an advocate first.' };
  assert.match(v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: true }), /Talk to an advocate first\./);
  assert.doesNotMatch(v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false }), /Talk to an advocate/);
});

test('outcomes: reclaimed has the debrief, not-yet goes back to steps, couldnt offers a retry', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts[0].missions[0];
  assert.match(v.renderOutcome({ kind: 'reclaimed', mission, scout }), /data-act="debrief:easy"/);
  assert.match(v.renderOutcome({ kind: 'reclaimed', mission, scout, undoHtml: '<div data-fix-undo-here></div>' }), /data-fix-undo-here/);
  assert.match(v.renderOutcome({ kind: 'yours', mission, scout }), /BACK TO THE DISTRICT/);
  assert.match(v.renderOutcome({ kind: 'not-yet', mission, scout }), /data-go="mission:/);
  assert.match(v.renderOutcome({ kind: 'couldnt', mission, scout }), /data-act="recheck"/);
  assert.match(v.renderOutcome({ kind: 'couldnt', mission, scout }), /doesn’t mean it’s fixed/);
});

test('a district milestone needs every mission reclaimed or yours, and lists the yours ones apart', async () => {
  const { districtComplete, renderMilestone } = await import('../renderer/game/views/milestone.js');
  const district = { id: 'gatehouse', name: 'The Gatehouse', missions: [{ id: 'a', title: 'A' }, { id: 'b', title: EVIL }], notes: [], fog: [] };
  const p = (a, b) => ({ version: 1, missions: { a: { status: a, module: 'm' }, b: { status: b, module: 'm' } } });
  assert.strictEqual(districtComplete(district, p('reclaimed', 'open')), false);
  assert.strictEqual(districtComplete(district, p('reclaimed', 'later')), false);
  assert.strictEqual(districtComplete(district, p('reclaimed', 'yours')), true);
  assert.strictEqual(districtComplete({ ...district, missions: [] }, p('open', 'open')), false);
  const html = renderMilestone({ district, progress: p('reclaimed', 'yours'), scout });
  assert.match(html, /THE GATEHOUSE/);
  assert.match(html, /marked as yours/i);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html, /share/i);
});

test('the HUD counts reclaimed from progress and never counts yours', async () => {
  const v = await views();
  const city = evilCity(v.findingsToCity);
  const progress = { version: 1, missions: { x: { status: 'reclaimed', module: 'm' }, y: { status: 'yours', module: 'm' } } };
  const hud = v.renderHud({ title: 'T', city, progress });
  assert.match(hud, />1<\/b> <small>RECLAIMED/);
  assert.match(hud, /data-act="list"/);
});

test('no Scout line promises safety', async () => {
  const { SCOUT } = await views();
  const all = JSON.stringify(SCOUT).toLowerCase();
  for (const banned of ['you’re safe', "you're safe", 'all clear', 'not hacked', 'nothing to worry']) {
    assert.ok(!all.includes(banned), banned);
  }
});

test('a district with missions and fog still shows its fog; non-string reasons and step bodies are escaped', async () => {
  const v = await views();
  const { esc } = await import('../renderer/game/escape.js');
  assert.strictEqual(esc(42), '42');
  assert.strictEqual(esc(null), '');
  assert.strictEqual(esc({ a: 1 }), '[object Object]');
  const city = evilCity(v.findingsToCity);
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  const withFog = { ...gate, fog: [{ module: 'm', reason: 7 }, { module: EVIL, reason: { x: EVIL } }] };
  const html = v.renderDistrict({ district: withFog, progress: v.emptyProgress(), scout });
  assert.match(html, /COULDN’T CHECK HERE/);
  assert.match(html, /doesn’t mean it’s safe/);
  assert.match(html, /MISSIONS/);
  const briefing = v.renderBriefing({ mission: gate.missions[0], status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false });
  assert.ok(!briefing.includes('<img src=x'));
  assert.match(briefing, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('a partial district never gets the lit skyline', async () => {
  const { skyline } = await import('../renderer/game/views/map.js');
  assert.doesNotMatch(skyline('partial'), /\blit\b/);
  assert.doesNotMatch(skyline('fog'), /\blit\b/);
  assert.match(skyline('clear'), /\blit\b/);
});

test('a reclaimed mission the scan no longer reports still completes and is listed on the milestone', async () => {
  const { districtComplete, renderMilestone } = await import('../renderer/game/views/milestone.js');
  const v = await views();
  const district = { id: 'gatehouse', name: 'The Gatehouse', status: 'clear', missions: [], notes: [], fog: [] };
  const progress = { version: 1, missions: {
    a: { status: 'reclaimed', module: 'm', districtId: 'gatehouse', title: EVIL },
    b: { status: 'reclaimed', module: 'm', districtId: 'wires', title: 'Elsewhere' },
    c: { status: 'reclaimed', module: 'm' }, // an older record without districtId still loads, and is just not placed
  } };
  assert.strictEqual(districtComplete(district, progress), true);
  assert.strictEqual(districtComplete(district, v.emptyProgress()), false, 'nothing done here: no milestone');
  const html = renderMilestone({ district, progress, scout });
  assert.match(html, /FIXED AND CHECKED[\s\S]*&lt;img src=x/);
  assert.doesNotMatch(html, /Elsewhere/);
  assert.ok(!html.includes('<img src=x'));
  const screen = v.renderDistrict({ district, progress, scout });
  assert.match(screen, /mission-row lit[\s\S]*RECLAIMED/);
  assert.ok(!screen.includes('<img src=x'));
  const map = v.renderMap({ city: { districts: [district] }, progress, cameBack: [], scout });
  assert.match(map, /1 RECLAIMED/);
  assert.doesNotMatch(map, /NOTHING FOUND/);
});

test('a district’s notes open their signal on the deck when there is one; otherwise they stay text', async () => {
  const v = await views();
  const district = { id: 'gatehouse', name: 'The Gatehouse', status: 'clear', missions: [], fog: [],
    notes: [{ title: EVIL, id: 'n1' }, { title: 'No signal', id: 'n2' }] };
  const noteGo = (n) => (n.id === 'n1' ? 'signal:n1' : null);
  const html = v.renderDistrict({ district, progress: v.emptyProgress(), scout, noteGo });
  assert.match(html, /<li><button type="button" class="note-row" data-go="signal:n1">&lt;img src=x onerror=alert\(1\)&gt; ▶<\/button><\/li>/);
  assert.match(html, /<li>No signal<\/li>/);
  assert.match(v.renderDistrict({ district, progress: v.emptyProgress(), scout }), /<li>&lt;img src=x/, 'no deck: plain text as before');
});

test('fog keeps a district from its milestone, and a milestone with fog says so', async () => {
  const { districtComplete, renderMilestone } = await import('../renderer/game/views/milestone.js');
  const district = { id: 'gatehouse', name: 'The Gatehouse', missions: [], notes: [], fog: [{ module: 'm2', reason: EVIL }] };
  const progress = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', districtId: 'gatehouse', title: 'A' } } };
  assert.strictEqual(districtComplete(district, progress), false);
  const html = renderMilestone({ district, progress, scout });
  assert.match(html, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  assert.match(html, /COULDN’T CHECK HERE[\s\S]*m2/);
  assert.doesNotMatch(html, /every mission here is done/i);
  assert.doesNotMatch(html, /DISTRICT TAKEN BACK/);
  assert.ok(!html.includes('<img src=x'));
});

test('the put-back outcome escapes engine text and promises nothing', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts[0].missions[0];
  const html = v.renderOutcome({ kind: 'put-back', mission, scout });
  assert.match(html, /Put back\. It’s showing again\./);
  assert.match(html, /data-go="mission:/);
  assert.ok(!html.includes('<img src=x'));
});

test('the HUD shows confirmed and reported apart when given counts, and stays as before without', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [] });
  const two = v.renderHud({ title: 'T', city, progress: v.emptyProgress(), counts: { confirmed: 3, reported: 5 } });
  assert.match(two, />3<\/b> <small>CONFIRMED/);
  assert.match(two, />5<\/b> <small>YOU REPORTED/);
  assert.doesNotMatch(two, /RECLAIMED/);
  assert.match(v.renderHud({ title: 'T', city, progress: v.emptyProgress() }), /RECLAIMED/);
});

test('the one-city map: two rings, focus, check again, escaped, and a notice if accounts failed to load', async () => {
  const v = await views();
  const { renderOneCityMap } = await import('../renderer/game/views/one-city-map.js');
  const city = v.findingsToCity({ modules: [] });
  const cards = [{ id: 'master-keys', name: EVIL, description: EVIL, chapter: 1, percent: 40, total: 5, completed: 2, checkAgain: true }];
  const html = renderOneCityMap({ city, accountCards: cards, focus: 'master-keys', cameBack: [], scout, accountsError: false });
  assert.match(html, /YOUR COMPUTER/);
  assert.match(html, /YOUR ACCOUNTS/);
  assert.match(html, /data-go="rc:#\/district\/master-keys"/);
  assert.match(html, /data-focus/);
  assert.match(html, /CHECK AGAIN/);
  assert.match(html, /40% REPORTED/);
  assert.ok(!html.includes('<img src=x'));
  const failed = renderOneCityMap({ city, accountCards: [], focus: 'computer', cameBack: [], scout, accountsError: true });
  assert.match(failed, /Your accounts’ districts couldn’t load\./);
});

test('the one-city map keeps Plan A’s rules: partial never lit, fog never safe, reclaimed shown', async () => {
  const v = await views();
  const { renderOneCityMap } = await import('../renderer/game/views/one-city-map.js');
  const fogCity = v.findingsToCity({ modules: [
    { name: 'wifi_security_audit', category: 'network', status: 'ok', supported: false, unsupported_reason: 'x', findings: [] },
  ] });
  const fog = renderOneCityMap({ city: fogCity, accountCards: [], focus: 'computer', cameBack: [], scout, accountsError: false });
  assert.match(fog, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  const partial = { districts: [{ id: 'gatehouse', name: 'The Gatehouse', status: 'partial', blurb: 'b', missions: [], notes: [], fog: [{ module: 'm', reason: 'r' }] }] };
  assert.doesNotMatch(renderOneCityMap({ city: partial, accountCards: [], focus: 'computer', cameBack: [], scout, accountsError: false }), /iso_liberated/);
  const clear = { districts: [{ id: 'gatehouse', name: 'The Gatehouse', status: 'clear', blurb: 'b', missions: [], notes: [], fog: [] }] };
  const progress = { version: 1, missions: { old: { status: 'reclaimed', districtId: 'gatehouse', title: 't' } } };
  assert.match(renderOneCityMap({ city: clear, progress, accountCards: [], focus: 'computer', cameBack: [], scout, accountsError: false }), /1 RECLAIMED/);
  const done = [{ id: 'vault', name: 'V', description: 'd', chapter: 2, percent: 100, total: 3, completed: 3, checkAgain: true }];
  assert.match(renderOneCityMap({ city: { districts: [] }, accountCards: [{ ...done[0], checkAgain: false }], focus: 'computer', cameBack: [], scout, accountsError: false }), /iso_liberated/);
  assert.doesNotMatch(renderOneCityMap({ city: { districts: [] }, accountCards: done, focus: 'computer', cameBack: [], scout, accountsError: false }), /iso_liberated/,
    'a district the scan disagrees with is never drawn lit');
});

test('the verification panel labels every step and links a problem to its device mission', async () => {
  const { renderVerification } = await import('../renderer/game/views/verification.js');
  const mission = { id: 'device_security-fortify-computer', steps: [{ text: 'A' }, { text: 'B' }, { text: 'C' }, { text: 'D' }, { text: 'E' }, { text: 'F' }, { text: 'G' }] };
  const verification = { allConfirmed: false, partial: true, steps: [
    { step: 0, status: 'problem', claim: 'FileVault is on', modules: ['encryption_check'], problems: [{ title: EVIL, module: 'encryption_check' }] },
    { step: 1, status: 'other-platform', claim: 'x', appliesTo: ['win32'], modules: [], problems: [] },
    { step: 4, status: 'confirmed', claim: 'A password is needed', modules: [], problems: [] },
    { step: 5, status: 'couldnt', claim: 'Find My Mac is on', modules: [], problems: [] },
  ] };
  const html = renderVerification({ mission, verification, disagreement: { reportedAt: '2026-10-09T10:00:00Z', problems: [{ title: EVIL }] }, canFinish: false, platform: 'darwin',
    deviceMissionFor: () => ({ id: 'dev-1', districtId: 'gatehouse' }) });
  assert.match(html, /PROBLEM FOUND/);
  assert.match(html, /FOR WINDOWS COMPUTERS/);
  assert.match(html, /CONFIRMED BY YOUR COMPUTER/);
  assert.match(html, /COULDN’T CHECK/);
  assert.match(html, /YOURS TO CHECK/, 'unmapped steps (index 6) are yours');
  assert.match(html, /data-go="mission:dev-1"/);
  assert.match(html, /You reported this done/);
  assert.match(html, /Your computer confirmed 1 of 6 steps\. It found a problem with 1 step\. 4 are yours to check\./,
    'the step for other computers is left out; the problem is named, not called yours');
  assert.doesNotMatch(html, /can’t check the rest/);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html, /data-act="confirm-from-scan"/);
  assert.match(renderVerification({ mission, verification: { ...verification, allConfirmed: true, partial: false }, disagreement: null, canFinish: true, platform: 'darwin', deviceMissionFor: () => null }), /data-act="confirm-from-scan"/);
  assert.doesNotMatch(renderVerification({ mission, verification, disagreement: null, canFinish: true, platform: 'darwin', deviceMissionFor: () => null }), /data-act="confirm-from-scan"/,
    'a partial mission can never be finished from the scan');
  assert.match(renderVerification({ mission, verification: { ...verification, steps: [{ ...verification.steps[1], appliesTo: ['linux'] }] }, disagreement: null, canFinish: false, platform: 'darwin', deviceMissionFor: () => null }), /FOR LINUX COMPUTERS/);
  const bad = renderVerification({ mission, verification, disagreement: { reportedAt: 'nonsense', problems: [] }, canFinish: false, platform: 'darwin', deviceMissionFor: () => null });
  assert.doesNotMatch(bad, /Invalid Date/);
  assert.doesNotMatch(html + bad, /you’re safe|you're safe|all clear/i);
});

test('the milestone split lists confirmed and reported apart', async () => {
  const { renderMilestoneSplit } = await import('../renderer/game/views/verification.js');
  const html = renderMilestoneSplit({ confirmed: ['Harden Your Computer'], reported: [EVIL] });
  assert.match(html, /CONFIRMED BY YOUR COMPUTER/);
  assert.match(html, /YOU REPORTED/);
  assert.ok(!html.includes('<img src=x'));
});

test('a partial mission on Windows leaves the Mac and Linux steps out of the count', async () => {
  const { renderVerification } = await import('../renderer/game/views/verification.js');
  const mission = { id: 'device_security-fortify-computer', steps: ['A', 'B', 'C', 'D', 'E', 'F'].map((text) => ({ text })) };
  const other = (step, p) => ({ step, status: 'other-platform', claim: 'x', appliesTo: [p], modules: [], problems: [] });
  const verification = { allConfirmed: false, partial: true, steps: [
    other(0, 'darwin'),
    { step: 1, status: 'confirmed', claim: 'BitLocker is on for your drives', appliesTo: ['win32'], modules: [], problems: [] },
    { step: 2, status: 'couldnt', claim: 'Your drive is encrypted', appliesTo: ['win32'], modules: [], problems: [] },
    other(3, 'linux'),
    { step: 4, status: 'yours', claim: 'x', appliesTo: ['darwin', 'win32', 'linux'], modules: [], problems: [] },
    { step: 5, status: 'yours', claim: 'x', appliesTo: ['darwin', 'win32'], modules: [], problems: [] },
  ] };
  const html = renderVerification({ mission, verification, disagreement: null, canFinish: true, platform: 'win32', deviceMissionFor: () => null });
  assert.match(html, /Your computer confirmed 1 of 4 steps\. 3 are yours to check\./,
    'the all-platform steps nothing checks on Windows are the person\'s');
  assert.doesNotMatch(html, /of 6/);
  assert.doesNotMatch(html, /problem with/);
  assert.match(html, /FOR MAC COMPUTERS/);
  assert.match(html, /FOR LINUX COMPUTERS/);
  assert.strictEqual((html.match(/YOURS TO CHECK/g) || []).length, 2);
  assert.doesNotMatch(html, /data-act="confirm-from-scan"/);
});

test('the badge for a step on another computer names every platform the step is for', async () => {
  const { renderVerification } = await import('../renderer/game/views/verification.js');
  const { verifyMission } = await import('../renderer/game/verified-missions.js');
  const { loadRcFromDisk } = require('./rc-from-disk.js');
  const mission = (await loadRcFromDisk()).MISSIONS.find((m) => m.id === 'device_security-fortify-computer');
  const LUKS = { name: 'linux_disk_encryption_check', status: 'ok', supported: true, findings: [{ severity: 'info', data: { check: 'encrypted', mount_points: ['/'] } }] };
  const verification = verifyMission(mission.id, { platform: 'linux', modules: [LUKS] }, mission.steps.length);
  const html = renderVerification({ mission, verification, disagreement: null, canFinish: true, platform: 'linux', deviceMissionFor: () => null });
  assert.match(html, /FOR MAC AND WINDOWS COMPUTERS/, 'Find My is for Mac and Windows');
  assert.match(html, /FOR WINDOWS COMPUTERS/);
  const items = html.split('<li class="step">').slice(1);
  assert.match(items[4], /All platforms/);
  assert.match(items[4], /YOURS TO CHECK/, 'an all-platforms step is never shown as for another computer');
  assert.doesNotMatch(items[4], /FOR MAC/);
  assert.doesNotMatch(html, /data-act="confirm-from-scan"/);
});
