// Reclaim City's debrief form behaviour, the same as its app.js, scoped to a
// root (the shadow-root frame) instead of the game's #app element.
export function readAnswers(root, mission) {
  const answers = {};
  for (const q of mission.debriefQs) {
    const checked = [...root.querySelectorAll(`input[name="q_${q.id}"]:checked`)].map((el) => el.value);
    if (q.type === 'number') {
      const typed = root.querySelector(`input[type="number"][name="q_${q.id}"]`)?.value;
      if (checked.length) answers[q.id] = checked[0];
      else if (typed !== undefined && typed !== '') answers[q.id] = typed;
    } else if (q.multi) {
      if (checked.length) answers[q.id] = checked;
    } else if (checked.length) answers[q.id] = checked[0];
  }
  return answers;
}

// Follow-up questions appear once the answers they depend on are given; "none"
// and "couldn't check" stand alone in a pick-all list; a number and a
// "couldn't check" beside it clear each other.
export function refreshDebriefForm(e, rc) {
  const input = e.target;
  if (!input || input.tagName !== 'INPUT' || !String(input.name || '').startsWith('q_')) return;
  const form = input.closest('[data-debrief]');
  if (!form) return;
  if (input.type === 'checkbox' && input.checked) {
    const alone = input.value === 'none' || input.value === 'skip';
    for (const other of form.querySelectorAll(`input[name="${input.name}"]`)) {
      if (other === input) continue;
      if (other.type === 'number') { if (alone) other.value = ''; continue; }
      if (alone || other.value === 'none' || other.value === 'skip') other.checked = false;
    }
  }
  if (input.type === 'number' && input.value !== '') {
    for (const other of form.querySelectorAll(`input[type="checkbox"][name="${input.name}"]`)) other.checked = false;
  }
  const mission = rc.MISSIONS.find((m) => m.id === form.dataset.debrief);
  if (!mission) return;
  const shown = new Set(rc.visibleQuestions(mission, readAnswers(form, mission)).map((q) => q.id));
  for (const group of form.querySelectorAll('[data-question]')) group.hidden = !shown.has(group.dataset.question);
}

// The game's mission rows and briefings show "~5 min" beside each mission.
// The app never gives time estimates, so those labels are taken out of the
// game's HTML before it's drawn. Only a whole element holding nothing but the
// estimate is removed.
const TIME_ESTIMATE = /<div style="[^"<>]*">~\d+ ?(?:min|MIN|m)<\/div>/g;
export function withoutTimeEstimates(html) {
  return String(html).replace(TIME_ESTIMATE, '');
}
