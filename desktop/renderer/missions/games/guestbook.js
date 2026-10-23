// The Guest Book: remote-access tools, "who was let in, and when" (spec
// 2026-10-21-remote-access-think-back-design.md, type "guestbook"; contract R12 and R13).
//
// A remote-access tool (TeamViewer, AnyDesk, RustDesk...) can be the person's own, a support desk's, a
// tech-support scam's, or a way someone they know watches the screen. The engine says when it arrived, whether it
// lets someone in without a click, whether it's running and when it last let someone in; this game walks the person
// back to that date with one question at a time (ask effects: the item stays on screen), then gives one outcome:
//
//   offline     running now: go offline first (the network settings), then the questions
//   q1          Think back to around <added on>. How did this get here?   installed / helped / dontknow
//   q2          Do you still use it?                                       use -> mine, nouse -> notneeded
//   q3          Who was it?                       asked -> mine, contacted -> scam, knows -> known
//   q4          Around then, did a call, pop-up, email or text say something was wrong...?  yes -> scam, else unsure
//   mine        mark it as yours (and turn off unattended access when it has it)
//   notneeded   remove it (the removal warning first), then check again
//   scam        the steps in order (bank, email, remove and recheck, report), then remove it and recheck
//   known       talk to an advocate first; no removal offered. Every effect is unpaid (R13): no points, never kept
//   unsure      the safe middle: turn off unattended access, look at its connections
//
// The engine's "several tools" finding is its own card (stage 'several'): it names them, and each tool's card names
// the others, so a recheck after removing one shows what's left.
//
// Wording never names a relationship (a running tool may be showing this screen to someone); the helpline is only
// in the known outcome's standard steps. In city mode these findings are held in the help district
// (not-checked.js HELD_IN_CITY) and the quiz never runs; render in city mode is only kept safe (CITY_FORBIDDEN).
//
// render() draws only the card; the runner draws the decision buttons, the removal warning, the evidence rows and
// the links (R1). Pure: everything comes in through ctx (esc, evidenceRows, mode, platform, answers, today).
import { makerFor } from '../contract.js';
import { dayWords } from '../day.js';
import { remoteFacts } from '../remote-facts.js';

const MODULE = 'remote_access_tools';
const MAX_VALUE = 80;
const MAX_NAMES = 6;

export const covers = [{ module: MODULE }];

const W = (standard, city) => ({ standard, city });
const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const dataOf = (item) => {
  const f = (item && item.finding) || {};
  return isObj(f.data) ? f.data : {};
};
const clip = (s) => {
  const t = String(s == null ? '' : s).trim();
  return t.length > MAX_VALUE ? `${t.slice(0, MAX_VALUE - 1)}…` : t;
};
const city = (ctx) => !!ctx && ctx.mode === 'city';
const plat = (ctx) => (ctx && ctx.platform === 'win32' ? 'win32' : 'darwin');
const say = (w, ctx) => (w ? w[city(ctx) ? 'city' : 'standard'] : '');
const answersOf = (ctx) => (ctx && Array.isArray(ctx.answers) ? ctx.answers.filter((x) => typeof x === 'string') : []);
const isSeveral = (item) => {
  const f = (item && item.finding) || {};
  return dataOf(item).check === 'several_tools' || String(f.code || '').endsWith('.several_tools');
};
const toolName = (item) => clip(dataOf(item).tool);
const hasFix = (item) => !!(item && item.finding && isObj(item.finding.fixable));
const hasMark = (item) => !!(item && item.finding && isObj(item.finding.markable));

// ---- Where the person is in the walk-through ----

export const STAGES = ['offline', 'q1', 'q2', 'q3', 'q4', 'mine', 'notneeded', 'scam', 'known', 'unsure', 'several'];
const Q2 = { use: 'mine', nouse: 'notneeded' };
const Q3 = { asked: 'mine', contacted: 'scam', knows: 'known' };
const Q4 = { yes: 'scam', no: 'unsure', notsure: 'unsure' };

// The stage the answers so far lead to. "I'm offline now" ('continue') only moves past the offline step; an answer
// this game doesn't know never jumps ahead.
export function stageOf(item, answers) {
  if (isSeveral(item)) return 'several';
  const a = Array.isArray(answers) ? answers : [];
  if (dataOf(item).running_now === true && !a.length) return 'offline';
  const [first, second] = a.filter((x) => x !== 'continue');
  if (first === 'installed') return Q2[second] || 'q2';
  if (first === 'helped') return Q3[second] || 'q3';
  if (first === 'dontknow') return Q4[second] || 'q4';
  return 'q1';
}

// ---- Words ----

const added = (item, ctx) => dayWords(dataOf(item).added_on, { today: ctx && ctx.today });

function question(stage, item, ctx) {
  const day = added(item, ctx);
  switch (stage) {
    case 'offline': return W('Running now: someone may be able to see this screen. Go offline first, then answer the questions.',
      'It’s running now: someone may be watching this post. Cut the line first, then answer.');
    case 'q1': return day ? W(`Think back to around ${day}. How did this get here?`, `Think back to around ${day}. How did this guest get in?`)
      : W('Think back. How did this get here?', 'Think back. How did this guest get in?');
    case 'q2': return W('Do you still use it?', 'Do you still use it?');
    case 'q3': return W('Who was it?', 'Who was it?');
    case 'q4': return W('Around then, did a call, pop-up, email or text say something was wrong with your computer, an account, a refund or a payment?',
      'Around then, did a call, pop-up, email or text say something was wrong with your post, an account, a refund or a payment?');
    case 'mine': return dataOf(item).lets_in_unattended === true
      ? W('It’s yours. Mark it, so the next checkup only asks again if it changes. It can let someone in without you: turn that off if you don’t need it.',
        'It’s yours. Log it, so the next sweep only asks again if it changes. It opens without a knock: lock that if you don’t need it.')
      : W('It’s yours. Mark it, so the next checkup only asks again if it changes.', 'It’s yours. Log it, so the next sweep only asks again if it changes.');
    case 'notneeded': return W('You don’t use it any more. Remove it, then check again.', 'You don’t use it any more. Clear it out, then sweep again.');
    case 'scam': return W('This looks like a tech-support scam. Do these steps now, in order.', 'This looks like a con. Do these steps now, in order.');
    case 'known': return W('Someone you know set it up. Don’t remove it yet: removing it can tell whoever set it up.',
      'Someone you know set it up. Leave it for now: clearing it out can tell them.');
    // The card already says "Found no way for it to let someone in without you": don't then ask to turn that off.
    case 'unsure': return dataOf(item).lets_in_unattended === false
      ? W('Not sure is fine. For now, look at its connection list.', 'Not sure is fine. For now, read its guest list.')
      : W('Not sure is fine. For now, turn off unattended access and look at its connection list.',
        'Not sure is fine. For now, lock its side door and read its guest list.');
    case 'several': return W('More than one remote-access tool is on this computer. Scammers often install a second one to get back in.',
      'More than one guest has a key to this post. A con often leaves a second key to get back in.');
    default: return W('', '');
  }
}

// ---- Steps (never a scan value in them: the runner shows them as text, and a name could be anything) ----

// The button opens the network pane (research.js PANE_URLS.network), so the steps say what to do on that page.
const OFFLINE_STEPS = {
  darwin: W(['In the Network settings that open, click Wi-Fi, then switch Wi-Fi off.', 'If a network cable is plugged in, unplug it.',
    'Come back here: the questions work without the internet.'],
  ['In the settings that open, click Wi-Fi and switch it off.', 'If a cable is plugged in, unplug it.', 'Come back here: the questions work offline.']),
  win32: W(['In the Network & internet settings that open, turn on Airplane mode.',
    'If a network cable is plugged in, unplug it.', 'Come back here: the questions work without the internet.'],
  ['In the settings that open, turn on Airplane mode.', 'If a cable is plugged in, unplug it.', 'Come back here: the questions work offline.']),
};

const UNATTENDED_STEPS = W(['Open the tool.', 'In its settings, find the option that lets someone connect without you accepting (often called unattended access) and turn it off.',
  'If you need to keep it, set a new password there that only you know.', 'Run the checkup again to see the change.'],
['Open the tool.', 'In its settings, switch off the option that lets someone in without you accepting.', 'If you keep it, set a new password there that only you know.', 'Sweep again to see the change.']);

const CONNECTIONS_STEPS = W(['Open the tool.', 'Look for its history or list of recent sessions.', 'Compare the dates with what you remember. A session you don’t remember is a reason to remove it.',
  'Write down any dates you don’t recognise, on paper or another device.'],
['Open the tool.', 'Look for its list of recent sessions.', 'Compare the dates with what you remember.', 'Write down any you don’t recognise, on paper or another device.']);

const REMOVE_STEPS = {
  darwin: W(['Quit it (if it has an icon at the top of the screen, quit it there too).', 'Drag it from Applications to the Trash, then empty the Trash.',
    'If it comes back, look for it in Things that start on their own.', 'Run the checkup again: scammers often leave a second tool.'],
  ['Shut it down, from the top of the screen too if it’s there.', 'Drag it from Applications to the Trash, then empty the Trash.', 'If it comes back, look for it at The Door.', 'Sweep again: a con often leaves a second key.']),
  win32: W(['Open Settings, then Apps, then Installed apps.', 'Find it, choose the three dots beside it, then Uninstall.',
    'If it comes back, look for it in Things that start on their own.', 'Run the checkup again: scammers often leave a second tool.'],
  ['Open Settings, then Apps, then Installed apps.', 'Find it, choose the three dots beside it, then Uninstall.', 'If it comes back, look for it at The Door.', 'Sweep again: a con often leaves a second key.']),
};

const SCAM_STEPS = W([
  'From another phone or computer if you can, call your bank on the number on your card.',
  'Change your email password, then your other accounts.',
  'Remove the tool, then run the check again: scammers often leave a second one.',
  'Report it: the search below finds where (the FTC in the US, Action Fraud in the UK, the Canadian Anti-Fraud Centre).',
], [
  'From another phone or computer if you can, call your bank on the number on your card.',
  'Change your email password, then your other accounts.',
  'Clear the tool out, then sweep again: a con often leaves a second key.',
  'Report it: the search below finds where.',
]);

// Standard mode only names the helpline; city mode never reaches this outcome (held), and its words stay safe.
const KNOWN_STEPS = W([
  'Removing it can tell whoever set it up. Talk to an advocate before you remove it.',
  'In the US, a free, private helpline: call 1-800-799-7233, or text START to 88788.',
  'Write down the dates on this card, on paper or on another device.',
], [
  'Clearing it out can tell whoever set it up. Talk to someone you trust first.',
  'Write down the dates on this card, on paper or on another device.',
]);

const SEVERAL_STEPS = W(['Each tool has its own card in this mission: answer the questions on each one.',
  'After you remove one, run the check again: it looks for the others too.'],
['Each guest has its own card in this mission: answer the questions on each one.', 'After you clear one out, sweep again: it looks for the others too.']);

// ---- Decisions ----

const later = (more = {}) => ({ id: 'later', label: W('Later', 'Later'), effect: { kind: 'later', ...more } });
const ask = (id, standard, cityLabel) => ({ id, label: W(standard, cityLabel), effect: { kind: 'ask' } });
const recheck = () => ({ id: 'did', label: W('I removed it', 'Cleared it out'), effect: { kind: 'recheck', module: MODULE },
  hint: W('Checks again: it’s gone once the check doesn’t see it.', 'Sweeps again: it’s gone once the sweep doesn’t see it.') });
// The removal: the engine's own fix (its confirm shows the warning), else the steps by hand behind the warning (R6).
const remove = (item, ctx) => ({ id: 'remove', label: W('Remove it', 'Clear it out'),
  effect: hasFix(item) ? { kind: 'fix' } : { kind: 'closer', warning: true, steps: REMOVE_STEPS[plat(ctx)] } });
const turnOff = () => ({ id: 'unattended', label: W('Turn off unattended', 'Lock the side door'), effect: { kind: 'closer', steps: UNATTENDED_STEPS } });

export function decisions(item, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const stage = stageOf(item, answersOf(c));
  switch (stage) {
    case 'offline': return [
      { id: 'offline', label: W('Go offline first', 'Cut the line first'), effect: { kind: 'settings', pane: 'network', steps: OFFLINE_STEPS[plat(c)] } },
      ask('continue', 'I’m offline now', 'Line’s cut'),
    ];
    case 'q1': return [ask('installed', 'I installed it', 'I let it in'), ask('helped', 'Someone helped me', 'Someone helped'), ask('dontknow', 'I don’t remember', 'Can’t recall')];
    case 'q2': return [ask('use', 'Yes, I use it', 'Still use it'), ask('nouse', 'No', 'No')];
    case 'q3': return [ask('asked', 'Help I asked for', 'Help I called'), ask('contacted', 'Someone contacted me', 'They came to me'), ask('knows', 'Someone I know', 'Someone I know')];
    case 'q4': return [ask('yes', 'Yes', 'Yes'), ask('no', 'No', 'No'), ask('notsure', 'Not sure', 'Not sure')];
    case 'mine': {
      const mine = { id: 'mine', label: W('Mark it mine', 'Log it as mine'), effect: hasMark(item) ? { kind: 'mark' } : { kind: 'keep' },
        hint: W('Marks it as yours. It comes back if it changes.', 'Logs it as yours. It comes back if it changes.') };
      return dataOf(item).lets_in_unattended === true ? [mine, turnOff(), later()] : [mine, later()];
    }
    case 'notneeded': return [later(), remove(item, c), recheck()];
    // "Do these now" is Look closer (id 'closer'): its steps stay on screen and the item stays open for the removal.
    // Once they're open (ctx.closer) it's Later, Remove it, then I removed it: the recheck confirms the removal (and
    // pays for it) and looks for a second tool. Later always comes before Remove it, so the removal never leads.
    case 'scam': return c.closer === true ? [later(), remove(item, c), recheck()]
      : [{ id: 'closer', label: W('Do these now', 'Do these now'), effect: { kind: 'closer', steps: SCAM_STEPS } }, later(), remove(item, c)];
    // R13: nothing here pays or is kept, and nothing removes it.
    case 'known': return [{ id: 'talk', label: W('Talk to someone first', 'Talk to someone first'), effect: { kind: 'closer', unpaid: true, steps: KNOWN_STEPS } },
      later({ unpaid: true })];
    case 'unsure': {
      const connections = { id: 'connections', label: W('Check its connections', 'Read its guest list'), effect: { kind: 'closer', steps: CONNECTIONS_STEPS } };
      return dataOf(item).lets_in_unattended === false ? [connections, later()] : [turnOff(), connections, later()];
    }
    case 'several': return [{ id: 'closer', label: W('Look at each', 'Check each guest'), effect: { kind: 'closer', steps: SEVERAL_STEPS } },
      { id: 'did', label: W('Check again', 'Sweep again'), effect: { kind: 'recheck', module: MODULE } }, later()];
    default: return [later(), { id: 'did', label: W('Check again', 'Sweep again'), effect: { kind: 'recheck', module: MODULE } }];
  }
}

// ---- Research ----

const WHAT = W('A remote-access tool lets another computer see and control this one. Support desks use them, and so do scammers who call or show a pop-up.',
  'This lets someone at another post see and steer yours. Help desks use them, and so do callers who make up a problem.');
// A look-up intent only (research.js turns it into a fixed search); never a URL. One search: research.js shows
// one link per label ("Search the web"), so three would collapse into the first. The scam steps name the FTC,
// Action Fraud and the Canadian Anti-Fraud Centre, and the search finds the person's own country's.
const REPORT = { kind: 'lookup', source: 'web', query: 'report a tech support scam' };

export function research(item, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const f = (item && item.finding) || {};
  const stage = stageOf(item, answersOf(c));
  let rows = [];
  try { rows = typeof c.evidenceRows === 'function' ? (c.evidenceRows(f, { mode: c.mode }) || []) : []; } catch (e) { rows = []; }
  const links = [];
  if (stage === 'offline') links.push({ kind: 'settings', pane: 'network' });
  const name = toolName(item);
  const about = { mine: 'unattended access', unsure: 'connection history', notneeded: 'uninstall' }[stage];
  // The scam outcome's one search is where to report it (its steps say how to remove it).
  if (stage === 'scam') links.push({ ...REPORT });
  else if (name && about) links.push({ kind: 'lookup', source: 'web', query: clip(`"${name}" ${about}`) });
  links.push({ kind: 'lesson', concept: 'remote-access-scams' });
  return { rows: Array.isArray(rows) ? rows : [], what: say(WHAT, c), links, unfinished: !!(item && item.unfinished === true) };
}

// ---- Render ----

function factsOf(item, ctx) {
  const d = dataOf(item);
  const facts = remoteFacts(d, { today: ctx && ctx.today });
  // Running now leads, so it's the first thing read.
  const lines = facts.running_now === true ? [facts.running, facts.added, facts.unattended, facts.last_in]
    : [facts.added, facts.unattended, facts.last_in, facts.running];
  const maker = makerFor((item && item.finding) || {});
  if (maker && maker.name) lines.push(`Made by ${clip(maker.name)} ${maker.verified ? '(checked)' : '(not checked)'}`);
  if (d.one_off === true) lines.push('A one-off download (no helper that starts on its own)');
  return lines;
}

// The other tools in this mission, so after a recheck the card left names what's still here.
function othersOf(view, item) {
  const sib = Array.isArray(view && view.siblings) ? view.siblings : [];
  const names = sib.filter((s) => s && s !== item && !isSeveral(s) && s.finding && s.finding.module === MODULE).map(toolName).filter(Boolean);
  return [...new Set(names)].slice(0, MAX_NAMES);
}

export function render(view, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const e = c.esc;
  const v = view || {};
  const item = v.item || {};
  const answers = Array.isArray(v.answers) ? v.answers : answersOf(c);
  const stage = stageOf(item, answers);
  const several = stage === 'several';
  const title = several ? say(W('More than one remote-access tool', 'More than one guest with a key'), c)
    : (toolName(item) || say(W('A remote-access tool', 'A guest with a key'), c));
  const parts = [];
  parts.push(`<article class="gb-card gb-stage-${stage}${v.practice ? ' gb-practice' : ''}">`);
  parts.push(`<header class="gb-head"><span class="gb-chip">${e(say(W('Remote access', 'Guest book'), c))}</span>`
    + `<h3 class="gb-title">${e(title)}</h3></header>`);
  if (v.step && v.step.say) parts.push(`<aside class="gb-step" role="note">${e(say(v.step.say, c))}</aside>`);
  if (several) {
    const names = (Array.isArray(dataOf(item).tools) ? dataOf(item).tools : []).map(clip).filter(Boolean).slice(0, MAX_NAMES);
    if (names.length) parts.push(`<ul class="gb-facts gb-names">${names.map((n) => `<li>${e(n)}</li>`).join('')}</ul>`);
  } else {
    const lines = factsOf(item, c);
    parts.push(`<ul class="gb-facts">${lines.map((l, i) => `<li${i === 0 && stage === 'offline' ? ' class="gb-running"' : ''}>${e(l)}</li>`).join('')}</ul>`);
    const others = othersOf(v, item);
    if (others.length) parts.push(`<p class="gb-others">${e(`${say(W('Also on this computer', 'Also at this post'), c)}: ${others.join(', ')}`)}</p>`);
  }
  const q = say(question(stage, item, c), c);
  if (q) parts.push(`<div class="gb-ask${/^q\d$|^offline$/.test(stage) ? ' gb-question' : ' gb-outcome'}"><strong>${e(q)}</strong></div>`);
  if (item.unfinished === true) parts.push(`<p class="gb-unfinished">${e(city(c) ? 'This sweep didn’t finish, so it may have missed something.' : 'This check didn’t finish, so it may have missed something.')}</p>`);
  parts.push('</article>');
  return parts.join('');
}

// ---- Summary ----

const decisionId = (r) => (r && typeof r.decision === 'string' ? r.decision : r && r.decision && typeof r.decision.id === 'string' ? r.decision.id : '');

export function summary(results, ctx) {
  const c = { mode: 'standard', ...(ctx || {}) };
  const e = c.esc || ((s) => String(s));
  const rs = Array.isArray(results) ? results : [];
  const later = rs.filter((r) => decisionId(r) === 'later').length;
  const unpaid = rs.some((r) => r && r.effect && r.effect.unpaid === true);
  const n = rs.length;
  const plural = (x, one, many) => `${x} ${x === 1 ? one : many}`;
  const head = city(c)
    ? `Guest book: ${plural(n, 'guest', 'guests')} looked at${later ? `, ${later} saved for later` : ''}.`
    : `You looked at ${plural(n, 'remote-access tool', 'remote-access tools')}${later ? `, ${later} saved for later` : ''}.`;
  const out = [`<div class="gb-summary"><p>${e(head)}</p>`];
  if (unpaid) out.push(`<p>${e(city(c) ? 'A guest someone you know let in earns no points: that’s on purpose.' : 'A tool someone you know set up earns no points: that’s on purpose.')}</p>`);
  out.push(`<p>${e(city(c) ? 'A guest you looked at is one less unknown. It doesn’t rule out guests the sweep couldn’t see.'
    : 'Each one you looked at is one less unknown. It doesn’t rule out tools a check couldn’t see.')}</p></div>`);
  return out.join('');
}

// ---- Practice (synthetic only) ----

const practiceItem = (key, data, title) => {
  const finding = { module: MODULE, code: 'security.remote_access_tools.tool_found', severity: 'warning', category: 'security', removal_alert: true,
    title, description: 'Practice: a made-up example.', data: { check: 'tool_found', running_now: false, last_incoming: null, incoming_count: 0, one_off: false,
      unattended_via: null, known_item_kind: 'remote_tool', ...data } };
  return { key: `practice:guestbook:${key}`, severity: 'warning', finding, findings: [finding], seen_in: [MODULE], marked: false, held: false, removal_alert: true };
};

const practiceRound = (pc, tvPath, rdPath) => ({
  items: [
    practiceItem('teamviewer', { tool: 'TeamViewer', tool_id: 'teamviewer', path: tvPath, added_on: '2026-03-03', lets_in_unattended: true, unattended_via: 'TeamViewer' },
      'TeamViewer can let someone control this computer'),
    practiceItem('rustdesk', { tool: 'RustDesk', tool_id: 'rustdesk', path: rdPath, added_on: '2026-05-10', lets_in_unattended: false },
      'RustDesk can let someone control this computer'),
  ],
  // Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict. `answers`: where the step stands (R12).
  script: [
    { item: 0, answers: [], expect: 'dontknow',
      say: W(`TeamViewer arrived on this ${pc} on March 3. You don’t remember installing it. How did it get here?`,
        `TeamViewer got into this ${pc} on March 3. You don’t remember letting it in. How did it get in?`),
      why: W('Not remembering is a fair answer. The next question helps you think back to that week.', 'Not remembering is a fair answer. The next question helps you think back to that week.') },
    { item: 0, answers: ['dontknow'], expect: 'yes',
      say: W('That week, a caller said you were owed a “refund” and asked you to install something. What do you answer?',
        'That week, a caller said you were owed a “refund” and asked you to let something in. What do you answer?'),
      why: W('A call about a refund, then a tool you don’t remember: that’s the scam pattern. The steps start with your bank, from another device.',
        'A call about a refund, then a guest you don’t remember: that’s the con. The steps start with your bank, from another device.') },
    { item: 1, answers: ['installed'], expect: 'use',
      say: W(`You installed RustDesk on this ${pc} to help a friend with theirs, and you still do. Do you still use it?`,
        `You let RustDesk into this ${pc} to help a friend, and you still do. Do you still use it?`),
      why: W('Then it’s yours: mark it, and the checkup asks again only if it changes.', 'Then it’s yours: log it, and the sweep asks again only if it changes.') },
  ],
});

export const practice = practiceRound('Mac', '/Applications/TeamViewer.app', '/Applications/RustDesk.app');
export const practiceByPlatform = { win32: practiceRound('PC', 'C:\\Program Files\\TeamViewer\\TeamViewer.exe', 'C:\\Program Files\\RustDesk\\rustdesk.exe') };

export default {
  type: 'guestbook',
  title: W('Remote access', 'The Guest Book'),
  concepts: ['remote-access-scams'],
  covers,
  decisions,
  research,
  practice,
  practiceByPlatform,
  render,
  summary,
};
