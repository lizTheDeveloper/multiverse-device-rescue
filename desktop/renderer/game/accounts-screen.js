// Game mode's "Take your accounts back" screens: state, clicks and drawing,
// kept apart from controller.js, which only routes to it. The safety answer
// lives here in memory; the checklist's answers go to their own store
// (account-recovery.js), never into the game's progress or the deck.
import { STEPS, loadAccounts, saveAccounts, setAnswer, setProvider, answerOf, offeredFor, devicePrereqs, SAFETY } from './account-recovery.js';
import { renderAccountList, renderAccountStep, renderAccountsTile, LESSON_ID } from './views/account-recovery.js';

export const ACCOUNT_SCREENS = new Set(['accounts', 'acct-step']);

// `ctx()` gives what the screens read from the controller: { city, progress, situation, sideName, held }.
// `openLink(url)` opens through main's allowlist. `report(id, title)` pays and logs a step
// the person marked done (YOU REPORTED); it's called once per step, ever, by the ledger's own key.
export function createAccountsScreen({ storage, now, ctx, openLink, report = () => {} }) {
  let store = loadAccounts(storage);
  let safety = null; // 'no' | 'maybe', this session only
  let stepId = null;

  // Monitoring software in this scan (held.js): the advocate note shows on
  // every account screen, whatever was answered.
  const eff = () => (ctx().held ? 'maybe' : safety);
  const prereqs = () => { const c = ctx(); return devicePrereqs(c.city, c.progress); };
  const save = (next) => { store = next; saveAccounts(storage, store); };

  function answer(id, a) {
    const before = answerOf(store, id);
    save(setAnswer(store, id, a, now()));
    if (a === 'done' && before !== 'done' && answerOf(store, id) === 'done') {
      const step = STEPS.find((s) => s.id === id);
      report(id, step ? step.title : id);
    }
  }

  return {
    offered: () => offeredFor(ctx().situation),
    reportedCount: () => STEPS.filter((s) => s.id !== 'email-provider' && answerOf(store, s.id) === 'done').length,
    tileHtml() {
      return offeredFor(ctx().situation) ? renderAccountsTile({ store, safety: eff() }) : '';
    },
    // The screen to draw for `screen`, or null when it isn't one of these.
    html(screen, scout) {
      const { sideName } = ctx();
      if (screen === 'acct-step') {
        const step = STEPS.find((s) => s.id === stepId);
        if (step) return renderAccountStep({ step, store, safety: eff(), devicePrereqs: prereqs(), scout, sideName });
      }
      if (ACCOUNT_SCREENS.has(screen)) return renderAccountList({ store, safety: eff(), devicePrereqs: prereqs(), scout, sideName });
      return null;
    },
    // A click on one of these screens. Returns the screen to show next, or
    // null when the click isn't this module's.
    click(go, act, el) {
      if (go === 'accounts') return 'accounts';
      if (go && go.startsWith('acct-step:')) {
        const id = go.slice(10);
        if (!STEPS.some((s) => s.id === id)) return 'accounts';
        stepId = id;
        return 'acct-step';
      }
      if (!act) return null;
      if (act === 'acct-link') {
        const url = el && el.getAttribute('data-url');
        if (url) openLink(url);
        return 'none';
      }
      if (act.startsWith('acct-safety:')) {
        const v = act.slice(12);
        if (SAFETY.has(v)) safety = v;
        return 'same';
      }
      if (act.startsWith('acct-provider:')) { save(setProvider(store, act.slice(14), now())); return 'same'; }
      if (act.startsWith('acct-toggle:')) {
        const id = act.slice(12);
        const a = answerOf(store, id);
        // A ticked box (done or doesn't apply) unticks; an unticked one is done.
        if (a === 'done' || a === 'na') save(setAnswer(store, id, a, now()));
        else answer(id, 'done');
        return 'same';
      }
      if (act.startsWith('acct-answer:')) {
        const [, id, a] = act.split(':');
        answer(id, a);
        return 'same';
      }
      return null;
    },
    lessonId: LESSON_ID,
  };
}
