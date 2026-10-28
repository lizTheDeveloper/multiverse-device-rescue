// "Take your accounts back": the checklist, one step's screen, and the deck's
// tile. The why lives in the lesson (taking-accounts-back), linked once from
// the list; screens keep to one line, the provider's path and its own links.
// Nothing here takes typed input: the person acts at the provider's site.
import { esc } from '../escape.js';
import { STEPS, PROVIDERS, answerOf, accountCounts, nextStep } from '../account-recovery.js';

export const LESSON_ID = 'taking-accounts-back';
const SECTIONS = [
  { id: 'first', label: 'FIRST' },
  { id: 'email', label: 'YOUR EMAIL' },
  { id: 'next', label: 'YOUR OTHER ACCOUNTS, IN THIS ORDER' },
  { id: 'after', label: 'AFTERWARDS' },
];
const BADGE = { na: '<span class="badge skip">DOESN’T APPLY</span>', help: '<span class="badge warn">NEED HELP</span>' };
// phone-account is about the phone, not the email: show the two phone accounts.
const SHOW_ALL = { 'phone-account': ['apple', 'google'] };

const providerOf = (store) => PROVIDERS.find((p) => p.id === (store && store.provider)) || null;

// The advocate note when the person said it may be someone close. Changing a
// password or signing out a device shows whoever did it that they were noticed.
export function safetyPanel({ sideName = null } = {}) {
  return `<div class="panel safety acct-safety" role="note">
    <p class="intel"><strong>${esc('Talk to an advocate before you change account settings.')}</strong>
    ${esc('Signing someone out or changing a password shows them you noticed. National Domestic Violence Hotline: 1-800-799-7233, or text START to 88788.')}</p>
    ${sideName ? `<button type="button" class="btn-s" data-go="side">${esc(`MORE HELP IN ${sideName.toUpperCase()} ▶`)}</button>` : ''}
  </div>`;
}

function linkButtons(links) {
  return (links || []).map((l) => `<button type="button" class="btn-s acct-link" data-act="acct-link" data-url="${esc(l.url)}">${esc(l.label)} ▶</button>`).join('');
}

function providerButtons(store) {
  return `<div class="acct-providers">${PROVIDERS.map((p) => `
    <button type="button" class="opt" data-act="acct-provider:${esc(p.id)}" aria-pressed="${store && store.provider === p.id}">
      <strong>${esc(p.name)}</strong> <small>${esc(p.mail)}</small></button>`).join('')}</div>`;
}

function whereBlock(at) {
  if (!at) return '';
  const where = (at.where || []).map((w) => `<li><code>${esc(w)}</code></li>`).join('');
  return `${where ? `<div class="label">WHERE IT IS</div><ul class="acct-where">${where}</ul>` : ''}
    ${at.note ? `<p class="intel">${esc(at.note)}</p>` : ''}
    <div class="acct-links">${linkButtons(at.links)}</div>`;
}

function providerPart(step, store) {
  if (!step.perProvider) return `<p class="intel">${esc(step.generic || '')}</p>${step.sources ? `<div class="acct-links">${linkButtons(step.sources)}</div>` : ''}`;
  if (SHOW_ALL[step.id]) {
    return `<p class="intel">${esc(step.generic)}</p>${SHOW_ALL[step.id].map((id) => {
      const p = PROVIDERS.find((x) => x.id === id);
      return `<div class="acct-provider-block"><div class="label">${esc(p.name.toUpperCase())}</div>${whereBlock(step.perProvider[id])}</div>`;
    }).join('')}`;
  }
  const p = providerOf(store);
  if (!p) return `<p class="intel">${esc('Pick your email first, so this shows where the setting really is.')}</p>${providerButtons(store)}`;
  if (p.id === 'other') return `<p class="intel">${esc(step.generic)}</p>`;
  return `<div class="label">${esc(p.name.toUpperCase())}</div>${whereBlock(step.perProvider[p.id])}`;
}

function devicePart(prereqs) {
  if (!prereqs.length) return `<p class="intel">${esc('This computer’s checkup has nothing open in the checks that matter most for a hack. If you’d still rather not use it, do the account steps on your phone or another device you trust.')}</p>`;
  return `<p class="intel">${esc(`This computer’s checkup has ${prereqs.length} thing${prereqs.length === 1 ? '' : 's'} open that can let someone in or read what you type. Until ${prereqs.length === 1 ? 'it’s' : 'they’re'} sorted, do the account steps on your phone or another device you trust.`)}</p>
    <ul class="missions">${prereqs.map((m) => `<li><button type="button" class="mission-row" data-go="mission:${esc(m.id)}">
      <span class="badge ${m.severity === 'critical' ? 'crit' : 'warn'}">${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</span>
      <span class="mission-text">${esc(m.title)}</span></button></li>`).join('')}</ul>`;
}

function answerRow(step, store) {
  const now = answerOf(store, step.id);
  const b = (a, label, cls) => `<button type="button" class="${cls}" data-act="acct-answer:${esc(step.id)}:${a}" aria-pressed="${now === a}">${label}</button>`;
  return `<div class="row acct-answers">${b('done', 'DONE ✓', 'btn-p')}${b('na', 'DOESN’T APPLY', 'btn-s')}${b('help', 'I NEED HELP', 'btn-t')}</div>`;
}

function helpPanel(store) {
  const p = providerOf(store);
  return `<div class="panel acct-help" role="status"><p class="intel">${esc('Open the help page above, or ask someone you trust to sit with you. You type your password and any code yourself, only on the provider’s own site: nobody helping you needs them.')}</p>
    ${p && p.hacked ? `<div class="acct-links">${linkButtons([p.hacked])}</div>` : ''}</div>`;
}

export function renderAccountStep({ step, store, safety, devicePrereqs = [], scout, sideName = null }) {
  const i = STEPS.findIndex((s) => s.id === step.id);
  const following = STEPS.slice(i + 1).find((s) => s.id !== 'safety');
  let body;
  if (step.id === 'safety') {
    body = `<p class="intel">${esc(step.short)}</p><div class="row acct-answers">
      <button type="button" class="btn-p" data-act="acct-safety:no" aria-pressed="${safety === 'no'}">NO</button>
      <button type="button" class="btn-s" data-act="acct-safety:maybe" aria-pressed="${safety === 'maybe'}">YES, OR I’M NOT SURE</button></div>
      <p class="from">${esc('Your answer isn’t saved. It’s asked again next time.')}</p>`;
  } else if (step.id === 'email-provider') {
    body = `<p class="intel">${esc(step.short)}</p>${providerButtons(store)}
      <p class="from">${esc('Only the kind of email is saved, never the address.')}</p>`;
  } else {
    // The device step's own list says it all; other steps show where the setting lives.
    body = step.id === 'device' ? devicePart(devicePrereqs) : `<p class="intel">${esc(step.short)}</p>
      <div class="panel active">${providerPart(step, store)}</div>`;
    body += `
      ${answerRow(step, store)}
      ${answerOf(store, step.id) === 'help' ? helpPanel(store) : ''}`;
  }
  const ready = step.id === 'safety' ? !!safety : answerOf(store, step.id) !== null;
  const next = ready && following
    ? `<button type="button" class="btn-p" data-go="acct-step:${esc(following.id)}">NEXT: ${esc(following.title.toUpperCase())} ▶</button>` : '';
  return `
  <section class="brief acct-step">
    <div class="brief-main">
      <div class="crumbs"><button type="button" data-go="map">City</button> / <button type="button" data-go="accounts">Your accounts</button> / <b>${esc(`STEP ${i + 1}`)}</b></div>
      <h2 class="m-title"><span>${esc(step.title)}</span></h2>
      ${safety === 'maybe' ? safetyPanel({ sideName }) : ''}
      ${body}
      <div class="row">${next}<button type="button" class="btn-t" data-go="accounts">BACK TO THE LIST</button></div>
    </div>
    <aside class="brief-side">${scout('thinkingA', 72)}<span class="scout-name">SCOUT</span>
      <p class="say">${esc('One at a time. Every step happens on the provider’s own site, and you can stop after any of them.')}</p></aside>
  </section>`;
}

export function renderAccountList({ store, safety, devicePrereqs = [], scout, sideName = null }) {
  const c = accountCounts(store);
  const next = nextStep(store, safety);
  const p = providerOf(store);
  const row = (s) => {
    if (s.id === 'safety') {
      return `<li class="acct-row"><span class="acct-box-spacer" aria-hidden="true"></span>
        <button type="button" class="mission-row" data-go="acct-step:safety"><span class="mission-text">${esc(s.title)}</span>
        <small>${esc(safety ? 'Answered for now. It’s asked again next time.' : s.short)}</small></button></li>`;
    }
    const a = answerOf(store, s.id);
    const ticked = a === 'done' || a === 'na';
    // The provider step is ticked by picking one, so its box opens the step.
    const act = s.id === 'email-provider' ? `data-go="acct-step:${esc(s.id)}"` : `data-act="acct-toggle:${esc(s.id)}"`;
    const extra = s.id === 'email-provider' && p ? p.name : s.id === 'device' && devicePrereqs.length ? `${devicePrereqs.length} open on this computer` : s.short;
    return `<li class="acct-row">
      <button type="button" class="acct-box" role="checkbox" aria-checked="${ticked}" aria-label="${esc(`Done: ${s.title}`)}" ${act}>${ticked ? '✓' : ''}</button>
      <button type="button" class="mission-row" data-go="acct-step:${esc(s.id)}"><span class="mission-text">${esc(s.title)}</span>
        <small>${esc(extra)}</small>${BADGE[a] || ''}</button></li>`;
  };
  const sections = SECTIONS.map((sec) => `
    <div class="panel"><div class="label">${esc(sec.id === 'email' && p && p.id !== 'other' ? `YOUR EMAIL · ${p.name.toUpperCase()}` : sec.label)}</div>
      <ul class="missions acct-list">${STEPS.filter((s) => s.section === sec.id).map(row).join('')}</ul></div>`).join('');
  return `
  <section class="district-screen acct-screen">
    <div class="crumbs"><button type="button" data-go="map">City</button> / <b>Your accounts</b></div>
    <h2 class="m-title">Take your accounts back</h2>
    <p class="intel">${esc(`${c.done} of ${c.total} done.`)} ${esc('Email first: the password resets for your other accounts go through it.')}
      <button type="button" class="link" data-go="lesson:${LESSON_ID}">${esc('Why this order →')}</button></p>
    ${safety === 'maybe' ? safetyPanel({ sideName }) : ''}
    ${next ? `<button type="button" class="btn-p" data-go="acct-step:${esc(next.id)}">${esc(`NEXT: ${next.title.toUpperCase()} ▶`)}</button>` : `<p class="say">${esc('Every step is done or doesn’t apply.')}</p>`}
    ${sections}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc('Reclaim City never needs your password or a code. You type those only on the provider’s own site.')}</p></div>
  </section>`;
}

// The deck's tile, above the map, so it's the first thing seen after the sweep.
export function renderAccountsTile({ store, safety }) {
  const c = accountCounts(store);
  const next = nextStep(store, safety);
  return `<button type="button" class="panel acct-tile" data-go="accounts">
    <span class="label">YOUR ACCOUNTS FIRST</span>
    <span class="acct-tile-line">${esc('Most of the fix for a hack happens in your accounts, starting with your email.')}</span>
    <span class="badge cyan">${esc(`${c.done} OF ${c.total} DONE`)}</span>
    <span class="acct-tile-next">${esc(next ? `NEXT: ${next.title.toUpperCase()} ▶` : 'ALL DONE ▶')}</span>
  </button>`;
}
