'use strict';

/*
 * "A computer I don't want to turn on or connect": a short checklist shown
 * instead of a scan, because the computer running the app may be the clean
 * one. One step at a time, every step with its own checkbox, unticked to
 * start. The explanations live in the guide (docs/scenarios/infected-device.md);
 * this screen keeps a line or two per step. Ticks live in memory only.
 *
 * At the bottom, "Check this computer" hands back to the app, which runs the
 * infected_device checkup (offline-only checks) the usual way, plain or game.
 *
 * Pure parts (STEPS, createState, screenHtml, actionOf) are tested from Node;
 * attach() wires one card in the page. Loaded as a plain script (global `IsolateSteps`).
 */
const IsolateSteps = (function () {
  const SITE = 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/';
  const GUIDE_URL = `${SITE}infected-device/`;

  const STEPS = [
    { id: 'offline', title: 'Keep it off the internet',
      lines: [
        'Unplug its network cable before you turn it on.',
        'Turn its Wi-Fi off as soon as it starts. Mac: System Settings › Wi-Fi. Windows: Settings › Network & internet › Airplane mode.',
      ] },
    { id: 'nothing-else', title: 'Don’t connect anything you care about',
      lines: [
        'No USB drives you need: malware can copy itself onto them.',
        'Don’t sign in to anything on it, and don’t type passwords on it.',
      ] },
    { id: 'how-is-it', title: 'Work out how it’s doing',
      lines: [
        'Starts: save your files, then check it with the app from a Rescue Stick.',
        'Barely starts: start it in safe mode first.',
        'Won’t start: the app can’t check it. Try Recovery; often the honest fix is to erase and reinstall.',
      ] },
    { id: 'files', title: 'Save your files, carefully',
      lines: [
        'Documents and photos only, onto a spare drive you can erase later.',
        'Leave programs, installers and scripts behind.',
      ] },
    { id: 'accounts', title: 'Change passwords from a different device',
      lines: [
        'Not from that computer. Use this one if it’s clean, or your phone. Start with your email.',
      ],
      link: { label: 'Open the accounts guide', url: `${SITE}digital-security-reset/` } },
  ];

  // Which worries open this screen instead of a scan.
  function opensFirst(situation) {
    return !!situation && situation.steps === 'isolate';
  }

  function createState() {
    const done = new Set();
    let current = 0;
    const valid = (i) => Number.isInteger(i) && i >= 0 && i < STEPS.length;
    return {
      current: () => current,
      isDone: (i) => done.has(i),
      tick(i, on) {
        if (!valid(i)) return;
        if (on) done.add(i); else done.delete(i);
      },
      go(i) { if (valid(i)) current = i; },
      back() { if (current > 0) current -= 1; },
      // Tick this step and move to the next one not yet done (after it, then from the top).
      done() {
        done.add(current);
        const order = [...STEPS.keys()].slice(current + 1).concat([...STEPS.keys()].slice(0, current));
        const next = order.find((i) => !done.has(i));
        if (next !== undefined) current = next;
      },
      progress: () => ({ done: done.size, total: STEPS.length }),
    };
  }

  function screenHtml(state, esc) {
    const i = state.current();
    const step = STEPS[i];
    const p = state.progress();
    const status = p.done >= p.total ? `All ${p.total} done.` : `${p.done} of ${p.total} done.`;
    const lines = step.lines.map((l) => `<li>${esc(l)}</li>`).join('');
    const link = step.link
      ? `<p><button type="button" class="btn btn--secondary btn--small" data-steps-action="link">${esc(step.link.label)}</button></p>`
      : '';
    const checklist = STEPS.map((s, n) => `
        <li class="steps-item${n === i ? ' steps-item--current' : ''}">
          <input type="checkbox" data-steps-tick="${n}"${state.isDone(n) ? ' checked' : ''} id="steps-tick-${n}" aria-label="${esc(`Done: ${s.title}`)}">
          <button type="button" class="link-button" data-steps-go="${n}"${n === i ? ' aria-current="step"' : ''}>${esc(s.title)}</button>
        </li>`).join('');
    // tabindex="-1" on titles: focus moves there so a screen reader reads the step.
    return `<h1 id="steps-title" tabindex="-1">Keep that computer off your network</h1>
      <p class="muted">${esc(status)}</p>
      <section class="steps-current" aria-labelledby="steps-step-title">
        <p class="steps-count">Step ${i + 1} of ${STEPS.length}</p>
        <h2 id="steps-step-title" tabindex="-1">${esc(step.title)}</h2>
        <ul class="steps-lines">${lines}</ul>
        ${link}
        <p class="steps-nav">
          <button type="button" class="btn btn--primary" data-steps-action="done">Done</button>
          <button type="button" class="btn btn--secondary" data-steps-action="back"${i === 0 ? ' disabled' : ''}>Back</button>
        </p>
      </section>
      <ol class="steps-list" aria-label="All steps">${checklist}
      </ol>
      <p><button type="button" class="btn btn--secondary" data-steps-action="guide">Open the full guide</button></p>
      <p class="muted">No internet here? The guide is also on the Rescue Stick: guides/index.html.</p>
      <section class="steps-check">
        <h2>Is this the computer you’re worried about?</h2>
        <p class="muted">With the internet off, check it now. Only checks that work offline run.</p>
        <button type="button" class="btn btn--secondary" data-steps-action="check">Check this computer</button>
      </section>
      <p class="question-back"><button type="button" class="link-button" data-steps-action="leave">Back to the list</button></p>`;
  }

  // What a click or change asks for, from the element it landed on.
  function actionOf(el, checked) {
    if (!el || typeof el.getAttribute !== 'function') return null;
    const action = el.getAttribute('data-steps-action');
    if (action) return { action };
    const go = el.getAttribute('data-steps-go');
    if (go !== null) return { action: 'go', step: Number(go) };
    const tick = el.getAttribute('data-steps-tick');
    if (tick !== null) return { action: 'tick', step: Number(tick), on: !!checked };
    return null;
  }

  // Wire the card once. Returns { show() }, which starts the list afresh.
  // opts: { esc, openGuide(url), onCheck(), onLeave() }
  function attach(card, opts) {
    let state = createState();
    const render = (focus) => {
      card.innerHTML = screenHtml(state, opts.esc);
      if (!focus || typeof card.querySelector !== 'function') return;
      const title = card.querySelector('#steps-step-title');
      if (title && typeof title.focus === 'function') title.focus();
    };
    const run = (a) => {
      if (!a) return;
      if (a.action === 'done') { state.done(); render(true); }
      else if (a.action === 'back') { state.back(); render(true); }
      else if (a.action === 'go') { state.go(a.step); render(true); }
      else if (a.action === 'tick') { state.tick(a.step, a.on); render(false); }
      else if (a.action === 'guide') opts.openGuide(GUIDE_URL);
      else if (a.action === 'link') { const l = STEPS[state.current()].link; if (l) opts.openGuide(l.url); }
      else if (a.action === 'check') opts.onCheck();
      else if (a.action === 'leave') opts.onLeave();
    };
    card.addEventListener('click', (event) => {
      const t = event.target;
      const el = t && typeof t.closest === 'function' ? t.closest('[data-steps-action],[data-steps-go]') : null;
      if (el) run(actionOf(el));
    });
    card.addEventListener('change', (event) => {
      const t = event.target;
      if (t && typeof t.getAttribute === 'function' && t.getAttribute('data-steps-tick') !== null) run(actionOf(t, t.checked));
    });
    return {
      show() { state = createState(); render(false); },
    };
  }

  return { STEPS, GUIDE_URL, opensFirst, createState, screenHtml, actionOf, attach };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = IsolateSteps;
}
