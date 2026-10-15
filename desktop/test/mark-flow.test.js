const test = require('node:test');
const assert = require('node:assert');
const MarkFlow = require('../renderer/mark-flow.js');

const MARKABLE = {
  kind: 'background_task',
  id: 'abcdef012345',
  code: 'security.launch_agent_audit.suspicious_path',
  label: 'ai.example.gateway',
  program: '/Users/me/.example/venv/bin/python',
  plist: '/Users/me/Library/LaunchAgents/ai.example.gateway.plist',
  will_change: 'Device Rescue will stop warning you. It will still be listed as "marked as yours".',
  how_to_undo: ['Choose "Stop treating this as mine"', 'Or run: rescue known remove abc'],
};

test('no button without a well-formed markable block', () => {
  assert.strictEqual(MarkFlow.markControlsHtml({}), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, how_to_undo: [] } }), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, label: '--x' } }), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, id: '"><x' } }), '');
});

test('the button opens a hidden confirmation that says it stays listed and how to undo', () => {
  const html = MarkFlow.markControlsHtml({ markable: MARKABLE });
  assert.match(html, /This is mine — stop flagging it/);
  assert.match(html, /data-mark-id="abcdef012345"/);
  assert.ok(!html.includes('data-mark-program'), 'only the id is carried back');
  assert.match(html, /data-mark-panel hidden/);
  assert.match(html, /marked as yours/);
  assert.match(html, /To undo later:/);
  assert.match(html, /Stop treating this as mine/);
  assert.match(html, /Yes, it’s mine/);
  assert.ok(html.includes('Only do this if you set this up yourself.'));
});

test('a marked finding offers unmark instead', () => {
  const html = MarkFlow.markControlsHtml({ data: { marked_by_user: true, known_item_id: 'abcdef012345' } });
  assert.match(html, /data-unmark-id="abcdef012345"/);
  assert.match(html, /Stop treating this as mine/);
  assert.strictEqual(MarkFlow.markControlsHtml({ data: { marked_by_user: true, known_item_id: '"><x' } }), '');
});

test('everything from the engine is escaped', () => {
  const html = MarkFlow.markControlsHtml({ markable: { ...MARKABLE, label: 'a"><img src=x onerror=1>', will_change: '<b>x</b>' } });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<b>x</b>'));
});

test('results: only the engine saying so counts as saved', () => {
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'marked', how_to_undo: ['u'] }).tone, 'success');
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'removed' }).tone, 'info');
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'refused', message: 'No.' }).tone, 'error');
  assert.strictEqual(MarkFlow.describeMarkResult(null).tone, 'error');
  assert.ok(!MarkFlow.describeMarkResult({ status: 'failed' }).done);
});
