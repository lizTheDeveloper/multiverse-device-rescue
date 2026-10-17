const test = require('node:test');
const assert = require('node:assert');

// A tiny stand-in for querySelectorAll over radio/checkbox/number inputs.
function fakeForm(inputs) {
  return {
    querySelectorAll(sel) {
      const m = sel.match(/^input\[name="([^"]+)"\]:checked$/);
      if (m) return inputs.filter((i) => i.name === m[1] && i.checked);
      return [];
    },
    querySelector(sel) {
      const m = sel.match(/^input\[type="number"\]\[name="([^"]+)"\]$/);
      return m ? inputs.find((i) => i.type === 'number' && i.name === m[1]) || null : null;
    },
  };
}

test('readAnswers reads single, multi and number questions like the game does', async () => {
  const { readAnswers } = await import('../renderer/game/rc-dom.js');
  const mission = { debriefQs: [{ id: 'action' }, { id: 'flagged', multi: true }, { id: 'flagged_count', type: 'number' }, { id: 'unanswered' }] };
  const root = fakeForm([
    { name: 'q_action', value: 'completed', checked: true },
    { name: 'q_flagged', value: 'gmail', checked: true }, { name: 'q_flagged', value: 'venmo', checked: true },
    { name: 'q_flagged_count', type: 'number', value: '4', checked: false },
  ]);
  assert.deepStrictEqual(readAnswers(root, mission), { action: 'completed', flagged: ['gmail', 'venmo'], flagged_count: '4' });
});

test('a checked option beside a number wins over the typed number', async () => {
  const { readAnswers } = await import('../renderer/game/rc-dom.js');
  const mission = { debriefQs: [{ id: 'n', type: 'number' }] };
  const root = fakeForm([{ name: 'q_n', value: 'skip', checked: true }, { name: 'q_n', type: 'number', value: '3' }]);
  assert.deepStrictEqual(readAnswers(root, mission), { n: 'skip' });
});

// A form fake for refreshDebriefForm: inputs and question groups, with the
// selectors the helper uses. Nothing here touches `document`.
function fakeDebrief(missionId, inputs, groups) {
  const form = {
    dataset: { debrief: missionId },
    querySelectorAll(sel) {
      let m = sel.match(/^input\[name="([^"]+)"\]:checked$/);
      if (m) return inputs.filter((i) => i.name === m[1] && i.checked);
      m = sel.match(/^input\[name="([^"]+)"\]$/);
      if (m) return inputs.filter((i) => i.name === m[1]);
      m = sel.match(/^input\[type="checkbox"\]\[name="([^"]+)"\]$/);
      if (m) return inputs.filter((i) => i.type === 'checkbox' && i.name === m[1]);
      return sel === '[data-question]' ? groups : [];
    },
    querySelector(sel) {
      const m = sel.match(/^input\[type="number"\]\[name="([^"]+)"\]$/);
      return m ? inputs.find((i) => i.type === 'number' && i.name === m[1]) || null : null;
    },
  };
  for (const i of inputs) { i.tagName = 'INPUT'; i.closest = (s) => (s === '[data-debrief]' ? form : null); }
  return form;
}

test('picking "none" clears the other boxes, and a typed number clears the boxes beside it', async () => {
  const { refreshDebriefForm } = await import('../renderer/game/rc-dom.js');
  const rc = { MISSIONS: [], visibleQuestions: () => [] };
  const a = { name: 'q_f', type: 'checkbox', value: 'gmail', checked: true };
  const none = { name: 'q_f', type: 'checkbox', value: 'none', checked: true };
  const num = { name: 'q_f', type: 'number', value: '2' };
  fakeDebrief('m', [a, none, num], []);
  refreshDebriefForm({ target: none }, rc);
  assert.deepStrictEqual([a.checked, none.checked, num.value], [false, true, '']);
  const skip = { name: 'q_n', type: 'checkbox', value: 'skip', checked: true };
  const typed = { name: 'q_n', type: 'number', value: '5' };
  fakeDebrief('m', [skip, typed], []);
  refreshDebriefForm({ target: typed }, rc);
  assert.strictEqual(skip.checked, false);
});

test('follow-up questions show once the answer they depend on is given', async () => {
  const { refreshDebriefForm } = await import('../renderer/game/rc-dom.js');
  const { loadRcFromDisk } = require('./rc-from-disk.js');
  const rc = await loadRcFromDisk();
  const mission = { id: 'fake', debriefQs: [{ id: 'a' }, { id: 'b', showIf: { question: 'a', values: ['yes'] } }] };
  const radio = { name: 'q_a', type: 'radio', value: 'yes', checked: true };
  const groups = [{ dataset: { question: 'a' }, hidden: false }, { dataset: { question: 'b' }, hidden: true }];
  fakeDebrief('fake', [radio], groups);
  const rcWith = { ...rc, MISSIONS: [mission], visibleQuestions: rc.visibleQuestions };
  refreshDebriefForm({ target: radio }, rcWith);
  assert.deepStrictEqual(groups.map((g) => g.hidden), [false, false]);
  radio.value = 'no';
  refreshDebriefForm({ target: radio }, rcWith);
  assert.deepStrictEqual(groups.map((g) => g.hidden), [false, true]);
});

test('events that are not from a debrief answer input do nothing', async () => {
  const { refreshDebriefForm } = await import('../renderer/game/rc-dom.js');
  const rc = { get MISSIONS() { throw new Error('should not be reached'); } };
  refreshDebriefForm({ target: null }, rc);
  refreshDebriefForm({ target: { tagName: 'BUTTON', name: 'q_x' } }, rc);
  refreshDebriefForm({ target: { tagName: 'INPUT', name: 'other' } }, rc);
  refreshDebriefForm({ target: { tagName: 'INPUT', name: 'q_x', closest: () => null } }, rc);
});
