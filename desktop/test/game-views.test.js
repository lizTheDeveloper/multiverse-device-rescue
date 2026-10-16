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
