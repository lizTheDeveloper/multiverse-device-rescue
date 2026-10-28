// The guided walkthrough: how someone new learns to sort their own signals.
// The first few real signals go one step at a time (what it is, who made it,
// what it does, then their call), the next few show every clue at once with a
// hint, and after that the ordinary Signal or Noise panel. The scaffolding
// fades with the deck's lifetime `sorts` count (ledger countSort), so it
// follows the person across sweeps and restarts. Pure; no DOM.
//
// "technical" never gets it: an expert opens the ordinary panel straight away.
// Drills and checks that couldn't run aren't walked through either.

// Below `full`: one step at a time. Below `light`: one screen with a hint.
export const FADE = Object.freeze({
  new: Object.freeze({ full: 3, light: 6 }),
  everyday: Object.freeze({ full: 2, light: 4 }),
});

// 'full' | 'light' | 'none' for a signal at this level, given the deck.
export function guideMode(level, deck, sig) {
  const fade = FADE[level];
  if (!fade || !sig || sig.kind !== 'real') return 'none';
  const sorts = Number((deck && deck.sorts) || 0);
  if (sorts < fade.full) return 'full';
  if (sorts < fade.light) return 'light';
  return 'none';
}

// The steps, from the clues the evidence supports (clues.js cluesFor): what
// it is first, then who made it, then one clue about what it does or where it
// runs, then the call. A missing clue is skipped, never invented.
const DOES = ['where', 'when', 'conn', 'listen', 'who', 'went'];
export const STEP_TITLE = { what: 'WHAT IT IS', maker: 'WHO MADE IT', does: 'WHAT IT DOES', call: 'YOUR CALL' };
export function guideSteps(clues) {
  const list = Array.isArray(clues) ? clues : [];
  const by = (k) => list.find((c) => c && c.kind === k) || null;
  const steps = [];
  const what = by('what');
  if (what) steps.push({ id: 'what', clue: what });
  const maker = by('maker');
  if (maker) steps.push({ id: 'maker', clue: maker });
  const does = DOES.map(by).find(Boolean);
  if (does) steps.push({ id: 'does', clue: does });
  steps.push({ id: 'call', clue: null });
  return steps;
}

// What each call means, in a line, so the choice is the person's own.
export const CALL_HINT = {
  mine: 'You know it: you put it there, or you use it.',
  closer: 'Not sure yet. It stays in your queue.',
  threat: 'You don’t recognise it, or it worries you.',
};

// An OPEN DOOR's calls (case-file.js): keep it on purpose, or close it.
export const DOOR_CALL = {
  mine: { label: 'KEEP IT', hint: 'It’s this way on purpose, and you want it so.' },
  closer: { label: 'LOOK CLOSER', hint: 'Not sure yet. It stays in your queue.' },
  threat: { label: 'CLOSE IT', hint: 'You want it fixed. Its steps are on the deck.' },
};

// The light mode's one hint, above every clue at once.
export const LIGHT_HINT = 'Read who made it and what it does, then make your call.';
