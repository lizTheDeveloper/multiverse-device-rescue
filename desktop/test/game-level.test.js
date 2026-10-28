const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const load = async () => ({
  ...(await import('../renderer/game/level.js')),
  ...(await import('../renderer/game/views/level.js')),
});
const views = async () => ({
  ...(await import('../renderer/game/views/signal.js')),
  ...(await import('../renderer/game/views/district.js')),
  ...(await import('../renderer/game/views/briefing.js')),
  ...(await import('../renderer/game/views/boss.js')),
  ...(await import('../renderer/game/views/training.js')),
  ...(await import('../renderer/game/boss.js')),
  ...(await import('../renderer/game/clues.js')),
});
const memory = (init = {}) => {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), m };
};
const blocked = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };

const NODE = { module: 'suspicious_connections', code: 'security.suspicious_connections.unusual_listening_port', title: 'node listens',
  description: 'node is listening.', severity: 'warning',
  data: { check: 'unusual_listening_port', pid: 3602, ppid: 1, process: 'node', port: 8765, ports: [8765, 8766] } };
const KEXT = { module: 'kext_audit', code: 'security.kext_audit.kext_file', title: 'Old driver', severity: 'warning',
  description: 'An old driver.\n\nWhat to do: Uninstall the software that put it there.',
  data: { path: "/Library/Extensions/It's.kext" }, made_by: [{ name: 'HighPoint', verified: true, how: 'Developer ID signature' }] };

test('the level is stored as new, everyday or technical and nothing else; unset reads as everyday', async () => {
  const { LEVEL_KEY, readLevel, levelOf, writeLevel, LEVELS } = await load();
  assert.strictEqual(LEVEL_KEY, 'device-rescue.level');
  assert.deepStrictEqual(LEVELS, ['new', 'everyday', 'technical']);
  const s = memory();
  assert.strictEqual(readLevel(s), null);
  assert.strictEqual(levelOf(s), 'everyday');
  for (const lv of LEVELS) { assert.strictEqual(writeLevel(s, lv), true); assert.strictEqual(levelOf(s), lv); }
  assert.strictEqual(writeLevel(s, 'expert'), false);
  assert.strictEqual(levelOf(s), 'technical');
  assert.strictEqual(levelOf(memory({ 'device-rescue.level': 'garbage' })), 'everyday');
  assert.strictEqual(readLevel(blocked), null);
  assert.strictEqual(levelOf(null), 'everyday');
  assert.strictEqual(writeLevel(blocked, 'new'), false);
  assert.deepStrictEqual([...s.m.keys()], ['device-rescue.level'], 'nothing else is stored');
});

test('a level changes only showing: the policy has no safety switch, and everyday is the app as before', async () => {
  const { levelPolicy } = await load();
  assert.deepStrictEqual(levelPolicy('everyday'), { level: 'everyday', foldRaw: false, evidence: false, lessonsOptional: false });
  assert.deepStrictEqual(levelPolicy(undefined), levelPolicy('everyday'));
  assert.strictEqual(levelPolicy('new').foldRaw, true);
  assert.strictEqual(levelPolicy('technical').evidence, true);
  assert.strictEqual(levelPolicy('technical').lessonsOptional, true);
  for (const lv of ['new', 'everyday', 'technical']) {
    for (const k of Object.keys(levelPolicy(lv))) assert.doesNotMatch(k, /mark|fix|clear|safe|held|monitor/i, `${lv}: ${k}`);
  }
});

test('evidence rows: path, pid/ppid, process, ports, direction, signer, module and code', async () => {
  const { evidenceRows } = await load();
  const rows = Object.fromEntries(evidenceRows(NODE));
  assert.deepStrictEqual(rows, { pid: '3602', ppid: '1', process: 'node', ports: '8765, 8766', direction: 'listening (inbound)',
    module: 'suspicious_connections', code: 'security.suspicious_connections.unusual_listening_port' });
  const k = Object.fromEntries(evidenceRows(KEXT));
  assert.strictEqual(k.path, "/Library/Extensions/It's.kext");
  assert.strictEqual(k.signer, 'HighPoint (verified, Developer ID signature)');
  assert.deepStrictEqual(evidenceRows({ module: 'x', data: { pid: -4, port: 70000, path: 'relative' } }), [['module', 'x']]);
  assert.deepStrictEqual(evidenceRows(null), []);
});

test('monitoring software never gets evidence or commands, at any level', async () => {
  const { evidenceRows, checkCommands, fogCommand, evidenceHtml } = await load();
  const { HELD_MODULES } = await import('../renderer/game/held.js');
  for (const module of HELD_MODULES) {
    const f = { ...NODE, module };
    assert.deepStrictEqual(evidenceRows(f), [], module);
    assert.deepStrictEqual(checkCommands(f, 'darwin'), [], module);
    assert.strictEqual(fogCommand(module), null, module);
    assert.strictEqual(evidenceHtml(f, 'darwin'), '', module);
  }
});

test('check-it-yourself commands reuse the clues\' walkthrough commands, only look, and quote paths for the shell', async () => {
  const { checkCommands, shQuote, fogCommand } = await load();
  const { cluesFor, NET_COMMANDS } = await import('../renderer/game/clues.js');
  // No connection items: the walkthrough's listen commands, for this pid and port (clues.js NET_COMMANDS).
  const node = checkCommands(NODE, 'darwin').map((c) => c.cmd);
  assert.deepStrictEqual(node, ['lsof -i :8765', 'ps -p 3602 -o pid,ppid,command', 'rescue scan --module suspicious_connections']);
  assert.deepStrictEqual(NET_COMMANDS.listen.darwin, ['lsof -i :<port>', 'ps -p <pid> -o pid,ppid,command'], 'the same templates');
  // With items: the NEXT STEP clue's own commands, as they are, and no others for the process.
  const conn = { module: 'network_connections_monitor', title: 'c', description: 'd', severity: 'warning',
    data: { platform: 'darwin', items: [{ direction: 'out', process: 'ssh', pid: 31674, remote_addr: '87.5.113.252', remote_port: 64456, local_addr: '10.0.0.2', local_port: 50000 }] } };
  const clues = cluesFor(conn);
  const fromClue = clues.find((c) => c.kind === 'next').lines.filter((l) => l && l.code).map((l) => l.text);
  assert.deepStrictEqual(checkCommands(conn, 'darwin', clues).map((c) => c.cmd), [...fromClue, 'rescue scan --module network_connections_monitor']);
  assert.ok(fromClue.includes('ps -p 31674 -o pid,ppid,command'));
  const kext = checkCommands(KEXT, 'darwin').map((c) => c.cmd);
  assert.deepStrictEqual(kext, [`ls -la '/Library/Extensions/It'\\''s.kext'`, `codesign -dv --verbose=4 '/Library/Extensions/It'\\''s.kext'`,
    'rescue scan --module kext_audit']);
  assert.deepStrictEqual(checkCommands({ ...KEXT, data: { path: '~/Library/x $(rm -rf ~)' } }, 'linux').map((c) => c.cmd).slice(0, 1),
    [`ls -la ~/'Library/x $(rm -rf ~)'`]);
  assert.deepStrictEqual(checkCommands(NODE, 'win32').map((c) => c.cmd), ['rescue scan --module suspicious_connections'], 'no ps/lsof on Windows');
  assert.strictEqual(shQuote("a'b"), `'a'\\''b'`);
  assert.strictEqual(fogCommand('code_signature_audit'), 'rescue scan --module code_signature_audit');
  assert.strictEqual(fogCommand('bad name; rm'), null);
  for (const f of [NODE, KEXT, conn]) {
    for (const { cmd, what } of checkCommands(f, 'darwin', cluesFor(f))) {
      const verb = cmd.split(' ').slice(0, 2).join(' ');
      assert.doesNotMatch(verb, /sudo|kill|\brm\b|\bmv\b|launchctl|kextunload|--yes|rescue run/, cmd);
      assert.ok(what, cmd);
    }
  }
});

test('the picker: three plain cards, the chosen one pressed, and engine-free text', async () => {
  const { renderLevelPicker, levelButton, LEVEL_CHOICES } = await load();
  const first = renderLevelPicker({ chosen: null, first: true });
  for (const c of LEVEL_CHOICES) assert.ok(first.includes(`data-act="level:${c.id}"`), c.id);
  assert.match(first, /HOW MUCH DETAIL/);
  assert.match(first, /change it any time/);
  assert.doesNotMatch(first, /aria-pressed/);
  assert.doesNotMatch(first, /level-close/, 'the one-time ask has nothing to close: it just stays until a card is picked');
  const panel = renderLevelPicker({ chosen: 'technical' });
  assert.match(panel, /data-act="level:technical" aria-pressed="true"/);
  assert.match(panel, /data-act="level-close"/);
  assert.match(panel, /Every fix still asks first/);
  assert.match(levelButton('new'), /data-act="level-open"[^>]*>DETAIL: NEW</);
  assert.match(levelButton('nonsense'), /DETAIL: EVERYDAY/);
  for (const c of LEVEL_CHOICES) assert.doesNotMatch(`${c.title} ${c.line}`, /\b(test|quiz|score|beginner|expert)\b/i);
});

test('signal panel: "new" folds raw clue lines under DETAILS; "technical" shows evidence; everyday is unchanged', async () => {
  const v = await views();
  const sig = { id: 's', kind: 'real', severity: 'warning', title: 'Old driver', districtId: 'gatehouse', finding: KEXT, missionId: 'm', tag: null };
  const clues = v.cluesFor(KEXT);
  const base = { signal: sig, districtName: 'The Gatehouse', clues, opened: ['maker', 'where', 'what'], tagged: null, scout };
  const everyday = v.renderSignalPanel(base);
  assert.doesNotMatch(everyday, /DETAILS|clue-plain|EVIDENCE/);
  assert.match(everyday, /HighPoint, verified \(Developer ID signature\)/);
  const fresh = v.renderSignalPanel({ ...base, fold: true });
  assert.match(fresh, /clue-plain">Made by HighPoint\. The maker’s seal checked out\.[\s\S]*How to read this[\s\S]*<details class="raw"><summary>DETAILS<\/summary>[\s\S]*Developer ID signature/);
  assert.match(fresh, /clue-plain">A file on this computer\. Its exact place is under DETAILS\.[\s\S]*<details class="raw">[\s\S]*It&#39;s\.kext/);
  const { evidenceHtml } = await load();
  const tech = v.renderSignalPanel({ ...base, evidenceHtml: evidenceHtml(KEXT, 'darwin') });
  assert.match(tech, /EVIDENCE[\s\S]*CHECK IT YOURSELF[\s\S]*codesign -dv[\s\S]*CLUES/);
  // A network finding: its commands and raw addresses fold for "new"; plain sentences stay.
  const conn = { module: 'network_connections_monitor', title: 'c', description: 'd', severity: 'warning',
    data: { platform: 'darwin', items: [{ direction: 'out', process: 'ssh', pid: 31674, remote_addr: '87.5.113.252', remote_port: 64456, local_addr: '10.0.0.2', local_port: 50000 }] } };
  const cc = v.cluesFor(conn);
  const csig = { ...sig, id: 'c', finding: conn };
  const kinds = cc.map((c) => c.kind);
  const cfresh = v.renderSignalPanel({ ...base, signal: csig, clues: cc, opened: kinds, fold: true });
  assert.match(cfresh, /connecting OUT to 87\.5\.113\.252[\s\S]*<details class="raw"><summary>DETAILS<\/summary><p class="clue-line">Program: ssh \(PID 31674\)[\s\S]*<code class="clue-line code">10\.0\.0\.2:50000/);
  assert.match(cfresh, /<details class="raw"><summary>DETAILS<\/summary><code class="clue-line code">ps -p 31674/);
  const cday = v.renderSignalPanel({ ...base, signal: csig, clues: cc, opened: kinds });
  assert.doesNotMatch(cday, /<details class="raw">/);
  const drill = v.renderSignalPanel({ ...base, signal: { ...sig, kind: 'drill', drill: { setup: '' } }, evidenceHtml: '<b>EVIDENCE</b>' });
  assert.doesNotMatch(drill, /EVIDENCE/, 'a drill has no real evidence');
});

test('evidence is escaped', async () => {
  const { evidenceHtml } = await load();
  const html = evidenceHtml({ module: 'x', data: { path: `/tmp/${EVIL}`, process: EVIL }, made_by: [{ name: EVIL, how: EVIL }] }, 'darwin');
  assert.ok(!html.includes('<img'));
  assert.match(html, /&lt;img/);
});

test('district: "new" names no check; "technical" shows each mission\'s check and how to re-run a check that couldn\'t', async () => {
  const v = await views();
  const d = { id: 'gatehouse', name: 'The Gatehouse', status: 'warning', missions: [{ id: 'm1', module: 'kext_audit', severity: 'warning', title: 'Old driver' }],
    fog: [{ module: 'code_signature_audit', reason: 'timed out' }, { module: 'stalkerware_scan', reason: 'no access' }], notes: [], checksRan: 3 };
  const progress = { missions: {}, reclaimed: {} };
  const everyday = v.renderDistrict({ district: d, progress, scout });
  assert.match(everyday, /<strong>Code signature audit<\/strong>/);
  assert.doesNotMatch(everyday, /mission-module|rescue scan/);
  const fresh = v.renderDistrict({ district: d, progress, scout, level: 'new' });
  assert.doesNotMatch(fresh, /code_signature_audit|Code signature|stalkerware/i);
  const tech = v.renderDistrict({ district: d, progress, scout, level: 'technical' });
  assert.match(tech, /<code class="mission-module">kext_audit<\/code>/);
  assert.match(tech, /rescue scan --module code_signature_audit/);
  assert.match(tech, /<strong>code_signature_audit<\/strong>/);
  for (const html of [everyday, fresh, tech]) assert.doesNotMatch(html, /stalkerware/i, 'a monitoring check is never named');
});

test('briefing: "new" puts the finding\'s own What to do first and folds the walkthrough; held notes are untouched', async () => {
  const v = await views();
  const mission = { id: 'm1', districtId: 'gatehouse', severity: 'warning', title: 'Old driver', description: KEXT.description,
    steps: [{ number: 3, title: 'Remove leftover files', body: '`sudo kextunload <path>`' }], walkthroughTitle: 'Kexts', safetyNote: null, findings: [KEXT], primary: KEXT };
  const base = { mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false };
  const everyday = v.renderBriefing(base);
  assert.match(everyday, /YOUR MOVE[\s\S]*sudo kextunload/);
  const fresh = v.renderBriefing({ ...base, fold: true });
  assert.match(fresh, /WHAT IT IS<\/div><p class="intel">An old driver\.<\/p>/);
  assert.match(fresh, /WHAT TO DO<\/div><p class="intel">Uninstall the software that put it there\.<\/p>/);
  assert.match(fresh, /<details class="panel raw-steps"><summary class="label">THE DETAILED STEPS<\/summary>[\s\S]*sudo kextunload/);
  const noTodo = v.renderBriefing({ ...base, fold: true, mission: { ...mission, description: 'Just this.' } });
  assert.match(noTodo, /YOUR MOVE[\s\S]*Remove leftover files<details class="raw"><summary>DETAILS<\/summary>[\s\S]*sudo kextunload/);
  const held = v.renderBriefing({ ...base, fold: true, evidenceHtml: 'EVIDENCE-HERE', note: { kind: 'held', description: 'Held.', html: '<p>Help.</p>' } });
  assert.doesNotMatch(held, /WHAT TO DO|DETAILED STEPS|YOUR MOVE|EVIDENCE-HERE/);
  assert.deepStrictEqual(v.splitWhatToDo('A.\n\nWhat to do: B.'), { what: 'A.', todo: 'B.' });
  assert.strictEqual(v.splitWhatToDo('No steps.'), null);
});

test('quick mark: "new" always asks first, "technical" lets city mode\'s background tasks go in one click; held and watch kinds always ask', async () => {
  const { quickMarkOf } = await import('../renderer/game/yours.js');
  const MarkFlow = { markableOf: (f) => f.markable };
  const task = { module: 'launch_agents_audit', severity: 'warning', data: {}, markable: { id: 'aaaaaaaaaaaa', kind: 'background_task', code: 'security.launch_agents_audit.x' } };
  const share = { module: 'sharing_services', severity: 'warning', data: {}, markable: { id: 'bbbbbbbbbbbb', kind: 'sharing_service', code: 'security.sharing_services.x' } };
  const ask = (f, o) => quickMarkOf(f, { MarkFlow, ...o }).confirm;
  // Everyday: as before.
  assert.strictEqual(ask(task, {}), false);
  assert.strictEqual(ask(task, { watched: true }), true);
  // New: always the explain step.
  assert.strictEqual(ask(task, { level: 'new' }), true);
  // Technical: one click in city mode for a background task...
  assert.strictEqual(ask(task, { watched: true, level: 'technical' }), false);
  // ...never while something is held, never for a kind that could watch a computer.
  assert.strictEqual(ask(task, { watched: true, held: true, level: 'technical' }), true);
  assert.strictEqual(ask(share, { level: 'technical' }), true);
  // Monitoring and critical findings aren't quick-markable at any level.
  const { HELD_MODULES } = await import('../renderer/game/held.js');
  for (const level of ['new', 'everyday', 'technical']) {
    for (const module of HELD_MODULES) assert.strictEqual(quickMarkOf({ ...task, module }, { MarkFlow, level }), null, `${level} ${module}`);
    assert.strictEqual(quickMarkOf({ ...task, severity: 'critical' }, { MarkFlow, level }), null);
  }
});

test('test-out: only a lesson whose every question has an item bank; the quiz hides WHAT TO KNOW and ends on a miss', async () => {
  const { canTestOut } = await load();
  const { lessonQuizHtml } = await import('../renderer/game/views/lesson.js');
  const { lessonItems } = await import('../renderer/game/sweep.js');
  const q = (n) => ({ concept: `c${n}`, teach: `Teach ${n}`, prompt: `P${n}`, options: [{ text: 'Right', correct: true, feedback: 'Yes.' }, { text: 'Wrong', correct: false, feedback: 'No.' }],
    variants: [{ prompt: `V${n}`, options: [{ text: 'Wrong', correct: false, feedback: 'No.' }, { text: 'Right', correct: true, feedback: 'Yes.' }] }, { prompt: `W${n}`, options: [] }] });
  const banked = { id: 'b', title: 'Banked', briefing: 'Intro.', whatTheScanLooksFor: 'x', questions: [q(1), q(2)] };
  assert.strictEqual(canTestOut(banked), true);
  assert.strictEqual(canTestOut({ questions: [q(1), { prompt: 'no bank', options: [] }] }), false);
  assert.strictEqual(canTestOut({ questions: [] }), false);
  const shown = lessonItems(banked, 1);
  const first = lessonQuizHtml({ lesson: shown, qIndex: 0, picked: null, scout, testOut: true });
  assert.match(first, /TEST OUT · QUESTION 1 OF 2/);
  assert.match(first, /V1/, 'a variant, not the lesson\'s own wording');
  assert.doesNotMatch(first, /WHAT TO KNOW|Teach 1|Intro\./);
  const miss = lessonQuizHtml({ lesson: shown, qIndex: 0, picked: 0, scout, testOut: true });
  assert.match(miss, /Not this time[\s\S]*data-go="lesson:b"[^>]*>TAKE THE LESSON/);
  assert.doesNotMatch(miss, /next-question|finish-lesson/);
  const mid = lessonQuizHtml({ lesson: shown, qIndex: 0, picked: 1, scout, testOut: true });
  assert.match(mid, /data-act="next-question"/);
  const pass = lessonQuizHtml({ lesson: shown, qIndex: 1, picked: 1, scout, testOut: true });
  assert.match(pass, /Tested out\.[\s\S]*data-go="training"/);
  assert.doesNotMatch(pass, /finish-lesson/);
});

test('every lesson with item banks can be tested out of', async () => {
  const { canTestOut } = await load();
  const { loadLessons } = await import('../renderer/game/training.js');
  const lessons = await loadLessons((spec) => import(new URL(spec, require('url').pathToFileURL(require.resolve('../renderer/game/training.js'))).href));
  const banked = lessons.filter(canTestOut).map((l) => l.id);
  for (const id of ['what-a-checkup-sees', 'who-made-this', 'firewall-and-sharing', 'remote-access', 'after-a-finding']) assert.ok(banked.includes(id), id);
  assert.ok(!banked.includes('password-asker'), 'a lesson without banks has no test-out');
});

test('the Training Grounds: "technical" makes the checkup the main button; the picker and DETAIL button are drawn when given', async () => {
  const v = await views();
  const lesson = { id: 'a', title: 'A', questions: [{}] };
  const ordered = { recommended: [lesson], other: [] };
  const idle = { running: false, index: 0, total: 0, error: null };
  const everyday = v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, levelHtml: '<b>DETAIL-BTN</b>', pickerHtml: '<i>PICKER</i>' });
  assert.match(everyday, /DETAIL-BTN[\s\S]*PICKER[\s\S]*START HERE/);
  assert.match(everyday, /class="btn-s quiet" data-act="start-checkup"/);
  const tech = v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, level: 'technical' });
  assert.match(tech, /OPTIONAL REFRESHERS/);
  assert.match(tech, /class="btn-p" data-act="start-checkup"/);
  assert.doesNotMatch(tech, /lesson next/);
  assert.match(tech, /data-go="lesson:a"/, 'every lesson is still there');
  assert.doesNotMatch(tech, /testout:/, 'no test-out unless asked for');
  const offered = v.renderTraining({ ordered, progress: { lessons: {} }, scan: idle, scout, level: 'technical', testOut: () => true });
  assert.match(offered, /data-go="testout:a"[^>]*>TEST OUT</);
  const done = v.renderTraining({ ordered, progress: { lessons: { a: { doneAt: 'x' } } }, scan: idle, scout, level: 'technical', testOut: () => true });
  assert.doesNotMatch(done, /testout:/, 'a finished lesson has nothing to test out of');
});

test('no level text diagnoses this computer or names a duration', async () => {
  const { LEVEL_CHOICES, COMMANDS_NOTE } = await load();
  const { PLACE_UNKNOWN_PLAIN } = await import('../renderer/game/clues.js');
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await import('../renderer/game/training.js');
  // "I use a computer every day" names how often, not how long anything takes,
  // so card titles are checked for diagnoses only.
  for (const c of LEVEL_CHOICES) for (const p of DIAGNOSTIC_PHRASES) assert.ok(!c.title.toLowerCase().includes(p), c.title);
  for (const text of [...LEVEL_CHOICES.map((c) => c.line), COMMANDS_NOTE, PLACE_UNKNOWN_PLAIN]) {
    for (const p of DIAGNOSTIC_PHRASES) assert.ok(!text.toLowerCase().includes(p), text);
    assert.doesNotMatch(text, TIME_WORDS, text);
  }
});

test('"new" folds process ids in clue text and YOURS paths; other levels show them', async () => {
  const { foldLines } = await import('../renderer/game/views/signal.js');
  const f = foldLines({ lines: ['Your computer is connecting OUT to 1.2.3.4, port 22.', 'Program: ssh (PID 5), started by PID 1', { text: 'ps -p 5', code: true }] });
  assert.deepStrictEqual(f.shown, ['Your computer is connecting OUT to 1.2.3.4, port 22.']);
  assert.deepStrictEqual(f.folded.map((l) => (typeof l === 'string' ? l : l.text)), ['Program: ssh (PID 5), started by PID 1', 'ps -p 5']);
  const { renderYours } = await import('../renderer/game/views/yours.js');
  const inv = { count: 1, changed: [], items: [{ id: 'x' }],
    groups: [{ kind: { label: 'Background item', icon: '○' }, items: [{ id: 'x', name: 'helper', kinds: [], maker: null, evidence: '/Users/a/helper' }] }] };
  assert.match(renderYours({ inv }), /<code>\/Users\/a\/helper<\/code>/);
  assert.doesNotMatch(renderYours({ inv }), /<details class="raw">/);
  assert.match(renderYours({ inv, fold: true }), /<details class="raw"><summary>DETAILS<\/summary><code>\/Users\/a\/helper<\/code><\/details>/);
});
