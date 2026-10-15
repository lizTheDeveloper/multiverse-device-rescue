const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { createMarkPolicy, handleMark, handleUnmark, markTarget } = require('../mark-policy');
const { markArgs, unmarkArgs, runMark } = require('../engine-runner');

const MARKABLE = {
  kind: 'background_task',
  id: 'abcdef012345',
  code: 'security.launch_agent_audit.suspicious_path',
  label: 'ai.example.gateway',
  program: '/Users/me/.example/venv/bin/python',
  plist: '/Users/me/Library/LaunchAgents/ai.example.gateway.plist',
  arguments_sha256: 'a'.repeat(64),
  will_change: 'Stops warning you.',
  how_to_undo: ['Choose Stop treating this as mine'],
};
const doc = (findings) => ({ modules: [{ name: 'launch_agent_audit', findings }] });

test('markTarget keeps only a well-formed background task', () => {
  assert.deepStrictEqual(markTarget(MARKABLE), {
    kind: MARKABLE.kind, id: MARKABLE.id, code: MARKABLE.code,
    label: MARKABLE.label, program: MARKABLE.program, plist: MARKABLE.plist,
  });
  assert.strictEqual(markTarget(null), null);
  assert.strictEqual(markTarget({ ...MARKABLE, kind: 'other' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, id: undefined }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, code: '--x' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, arguments_sha256: '' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, label: '--yes' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, program: 'python' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, plist: 'relative.plist' }), null);
  assert.strictEqual(markTarget({ ...MARKABLE, plist: '/a\0b' }), null);
});

test('nothing can be marked before a scan, and only what the last scan offered', () => {
  const policy = createMarkPolicy();
  assert.strictEqual(policy.targetFor(MARKABLE.id), null);
  policy.remember(doc([{ title: 'x', markable: MARKABLE }]));
  assert.strictEqual(policy.targetFor(MARKABLE.id).program, MARKABLE.program);
  assert.strictEqual(policy.targetFor('000000000000'), null);
  policy.remember(doc([{ title: 'x' }]));
  assert.strictEqual(policy.targetFor(MARKABLE.id), null, 'a new scan replaces the allowance');
});

test('unmark is allowed only for ids the scan showed as marked', () => {
  const policy = createMarkPolicy();
  policy.remember(doc([{ title: 'x', data: { marked_by_user: true, known_item_id: 'abcdef012345' } }]));
  assert.strictEqual(policy.isUnmarkAllowed('abcdef012345'), true);
  assert.strictEqual(policy.isUnmarkAllowed('000000000000'), false);
  assert.strictEqual(policy.isUnmarkAllowed('../../x'), false);
});

test('handlers refuse before reaching the engine', async () => {
  const policy = createMarkPolicy();
  let called = false;
  const res = await handleMark(MARKABLE.id, { policy, runMark: async () => { called = true; } });
  assert.strictEqual(res.status, 'refused');
  assert.strictEqual(called, false);
  const res2 = await handleUnmark('abcdef012345', { policy, runUnmark: async () => { called = true; } });
  assert.strictEqual(res2.status, 'refused');
  assert.strictEqual(called, false);
});

test('the engine gets the target stored from the scan, whatever the renderer sends', async () => {
  const policy = createMarkPolicy();
  policy.remember(doc([{ title: 'x', markable: MARKABLE }]));
  let got;
  const runMark = async (t) => { got = t; return { status: 'marked' }; };
  // A renderer trying to smuggle its own label/path gets refused outright.
  const smuggled = await handleMark({ ...MARKABLE, program: '/evil' }, { policy, runMark });
  assert.strictEqual(smuggled.status, 'refused');
  assert.strictEqual(got, undefined);
  await handleMark(MARKABLE.id, { policy, runMark });
  assert.strictEqual(got.program, MARKABLE.program);
  assert.strictEqual(got.id, MARKABLE.id);
});

test('engine argv is a list that pins the code and the expected id', () => {
  assert.deepStrictEqual(markArgs(markTarget(MARKABLE)), [
    'known', 'add', '--code', MARKABLE.code, '--label', MARKABLE.label, '--program', MARKABLE.program,
    '--plist', MARKABLE.plist, '--expect-id', MARKABLE.id, '--json', '--i-understand',
  ]);
  assert.throws(() => markArgs({ ...MARKABLE, label: '-x' }));
  assert.throws(() => markArgs({ ...MARKABLE, kind: 'x' }));
  assert.throws(() => markArgs({ ...MARKABLE, id: 'nope' }));
  assert.throws(() => markArgs({ ...MARKABLE, code: 'a b' }));
  assert.deepStrictEqual(unmarkArgs('abcdef012345'), ['known', 'remove', 'abcdef012345', '--json']);
  assert.throws(() => unmarkArgs('--help'));
});

test('runMark parses the engine JSON whatever the exit code', async () => {
  const body = { status: 'refused', message: 'No such task.' };
  const calls = [];
  const spawn = (bin, args) => {
    calls.push(args);
    const p = new EventEmitter();
    p.stdout = new EventEmitter();
    p.stderr = new EventEmitter();
    p.kill = () => {};
    setImmediate(() => { p.stdout.emit('data', JSON.stringify(body)); p.emit('close', 2); });
    return p;
  };
  assert.deepStrictEqual(await runMark(markTarget(MARKABLE), spawn), body);
  assert.strictEqual(calls[0][0], 'known');
});
