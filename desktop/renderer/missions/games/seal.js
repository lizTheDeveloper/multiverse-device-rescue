// Seal Check: the `seal` mini-game (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md,
// "Each mini-game" → seal; contract: ../contract.js).
//
// One item at a time, two sides: "what the maker signed" next to "what's on disk", and a plain verdict:
//   tampered       the file no longer matches its seal (codesign failure, Authenticode HashMismatch)
//   old-format     signed under the pre-2014 rules; today's macOS can't check it
//   unsigned       no seal at all (system-wide apps, unsigned drivers)
//   unknown-maker  sealed by a maker the system doesn't trust (Gatekeeper/Authenticode rejection, no bundle id,
//                  root certificates someone added)
//   expired        an expired certificate: trusted for nothing
//   checker-off    Gatekeeper or System Integrity Protection switched off
//   checker-unsure the Gatekeeper test gave no clear answer
//   no-tag         apps without the "downloaded from the internet" tag (normal)
//   other          anything else from a covered check
//
// Decisions: Reinstall from the maker (a look-up INTENT + steps) / Mine, I know why / Look closer. A tampered app
// can be a trojaned tool someone planted, so a tampered item is always treated as carrying the removal warning:
// the reinstall goes last and its effect says `removal: true` (controller ruling). Added root certificates follow
// the same rule with "Not mine".
//
// render() draws only the seal card (ruling R1): the runner draws the decisions, the removal-warning line, the
// evidence rows, `what` and the links. Effects that replace or untrust something carry `warning: true` (R6).
//
// Pure: no DOM, storage, globals, network or clipboard. Every scan value goes through ctx.esc. The engine's own
// description is never shown: it can carry help-line sentences that city mode must not show.
import { makerFor, isAlertingItem } from '../contract.js';

const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const t = (standard, city) => ({ standard, city });
const say = (text, ctx) => (ctx && ctx.mode === 'city' ? text.city : text.standard);
const str = (v) => (v == null ? '' : String(v));

const TITLE = t('App seals', 'Seal Check');

// ---- what an item is about ------------------------------------------------

function isWindows(f) {
  const d = isObj(f.data) ? f.data : {};
  return str(f.module).startsWith('win_') || /^[A-Za-z]:\\/.test(str(d.path)) || /Authenticode/i.test(str(d.detail));
}

function names(list) {
  return (Array.isArray(list) ? list : [])
    .map((x) => (isObj(x) ? str(x.name || x.path) : str(x)).replace(/\.app$/i, ''))
    .filter(Boolean);
}

function listLine(list, max = 3) {
  if (!list.length) return '';
  const shown = list.slice(0, max).join(', ');
  return list.length > max ? `${shown} and ${list.length - max} more` : shown;
}

function subjectOf(f) {
  const d = isObj(f.data) ? f.data : {};
  if (d.name) return str(d.name);
  const many = names(d.certs).length ? names(d.certs)
    : names(d.certificates).length ? names(d.certificates)
      : names(d.drivers).length ? names(d.drivers) : names(d.apps);
  if (many.length) return listLine(many);
  return str(f.title);
}

// The maker named by the engine's attribution for this item's program, and
// whether that program's own entry verified it (contract.js makerFor): never
// another program's maker on a finding that names several.
function makerOf(f) {
  const m = makerFor(f);
  return m ? { name: str(m.name), verified: m.verified, what: m.verified ? str(m.what) : '' } : null;
}

const CODE = (f) => str(f.code).replace(/^security\./, '');

// One table of words per verdict. `kind` picks the decisions and the look-ups.
const VERDICTS = {
  tampered: {
    label: t('Changed after signing', 'Broken seal'),
    maker: t('The maker signed this app when they built it.', 'The maker put a seal on this one.'),
    disk: t('Changed after signing. The file no longer matches its signature.', 'Broken seal. What’s inside was changed after sealing.'),
    means: t('Updates from the maker are always signed again, so there’s no normal reason for this. Don’t open it for now.',
      'Real updates always come with a new seal, so there’s no good reason for this. Leave it closed for now.'),
  },
  'old-format': {
    label: t('Old-style signature', 'Old seal'),
    maker: t('Signed with an older kind of signature.', 'An old-style seal.'),
    disk: t('Today’s macOS can’t check this kind, so it can’t confirm the app is unchanged.', 'The checker can’t read seals this old, so it can’t say nothing changed.'),
    means: t('Common for older apps and games. A current version from the maker comes with a current signature.',
      'Usual for older gear. A fresh copy from the maker comes with a fresh seal.'),
  },
  unsigned: {
    label: t('Unsigned', 'No seal'),
    maker: t('No signature at all, so nothing says who made it.', 'No seal at all, so nothing says who made it.'),
    disk: t('Installed where it runs for everyone on this computer.', 'Stored where everyone in the city can run it.'),
    means: t('Developer tools and apps you built yourself are often unsigned. If you didn’t install it, find out what it is.',
      'Gear you built yourself often has no seal. If you didn’t bring it in, find out what it is.'),
  },
  'unknown-maker': {
    label: t('Unknown maker', 'Unknown maker'),
    maker: t('Signed, but not by a maker this computer has checked.', 'Sealed by a maker the checker doesn’t know.'),
    disk: t('This computer won’t vouch for it.', 'The gate won’t vouch for it.'),
    means: t('Common for apps from smaller makers or old downloads. Check where you got it.',
      'Usual for gear from small workshops or old deliveries. Check where it came from.'),
  },
  expired: {
    label: t('Expired', 'Expired seal'),
    maker: t('A certificate that has run out.', 'A seal-maker’s stamp that has run out.'),
    disk: t('Trusted for nothing now.', 'The checker ignores it now.'),
    means: t('Expired certificates do nothing. You can leave them.', 'Expired stamps do nothing. You can leave them.'),
  },
  'checker-off': {
    label: t('Checker off', 'Checker off duty'),
    maker: t('The computer’s own check of app signatures.', 'The seal checker at the gate.'),
    disk: t('Switched off, so apps run without their signature being checked.', 'Off duty, so gear comes in without its seal being checked.'),
    means: t('Some specialist software asks for this. If you didn’t switch it off, switch it back on.',
      'Some special gear asks for this. If you didn’t send the checker home, call it back.'),
  },
  'checker-unsure': {
    label: t('Not sure', 'Checker unsure'),
    maker: t('The computer’s own check of app signatures.', 'The seal checker at the gate.'),
    disk: t('A test of it gave no clear answer.', 'A test of the checker came back unclear.'),
    means: t('Often a one-off glitch. Restart, then check again.', 'Often a one-off glitch. Restart, then check again.'),
  },
  'no-tag': {
    label: t('No download tag', 'No delivery tag'),
    maker: t('Apps without the “downloaded from the internet” tag.', 'Gear without a delivery tag.'),
    disk: t('Normal for apps from installers, their own updaters, Homebrew, or another Mac. Signatures are still checked.',
      'Normal for gear from installers, its own updates, or another workshop. Seals are still checked.'),
    means: t('This is shown for information. It isn’t a sign of a change.', 'Just a note. It isn’t a sign of a change.'),
  },
  other: {
    label: t('Seal note', 'Seal note'),
    maker: t('A note from the signature checks.', 'A note from the seal patrol.'),
    disk: t('Look closer to see what it found.', 'Look closer to see what it found.'),
    means: t('If it doesn’t make sense, look closer.', 'If it doesn’t make sense, look closer.'),
  },
};

// Words that replace a verdict's defaults for some kinds of item.
const OVERRIDES = {
  'win-odd-folder': {
    disk: t('Running from a temporary or personal folder, not where installed programs live.', 'Running from a back room, not where settled gear lives.'),
    means: t('Some updaters run from these folders for a moment. A program that stays there, or that you don’t know, is worth checking.',
      'Some fixers pass through back rooms. Gear that stays there, or that you don’t know, is worth a look.'),
  },
  'win-no-file': {
    maker: t('Windows gave no file for this running program, so its signature couldn’t be read.', 'No file to read a seal from.'),
    disk: t('No file on disk was found for it.', 'Nothing on the shelf to check.'),
    means: t('System programs sometimes show no file. One with a name you don’t know is worth checking.',
      'City workers sometimes show no file. A name you don’t know is worth a look.'),
  },
  driver: { disk: t('Loaded as a driver, deep inside Windows.', 'Runs deep under the streets.') },
  'win-app': {
    maker: t('Signed, but Windows can’t vouch for the signer.', 'Sealed by a maker the gate doesn’t know.'),
    disk: t('Windows doesn’t trust this signature.', 'The gate won’t vouch for it.'),
  },
  'win-tampered': { maker: t('The maker signed this program when they built it.', 'The maker put a seal on this one.') },
  'win-unsigned': { disk: t('Installed in Program Files, where it runs for everyone.', 'Stored where everyone in the city can run it.') },
  'mac-rejected': { disk: t('macOS won’t run it: it wasn’t checked (notarized) by Apple, or its signer isn’t trusted.', 'The gate won’t let it run.') },
  'no-bundle': {
    maker: t('It has no app name for itself (a bundle ID). Signed apps always have one.', 'It has no name tag, so it can’t carry a seal.'),
    disk: t('In Applications, where everyone on this computer can run it.', 'Stored where everyone in the city can run it.'),
  },
  cert: {
    maker: t('A certificate added to this computer, not from a well-known issuer.', 'A seal-maker someone added to the trust list.'),
    disk: t('Trusted to vouch for websites and apps.', 'The checker trusts every seal it stamps.'),
    means: t('Work and school tools add these. If you didn’t, it can let someone read your secure connections.',
      'Work and school gear adds these. If you didn’t, it can open your sealed letters.'),
  },
  'cert-intercept': {
    maker: t('A trusted certificate named like a tool that reads secure traffic.', 'A trusted seal-maker named like a letter-opener.'),
    disk: t('Trusted to vouch for websites and apps.', 'The checker trusts every seal it stamps.'),
    means: t('Developers use these on purpose. If you didn’t add it, it can let someone read your secure connections.',
      'Builders use these on purpose. If you didn’t add it, it can open your sealed letters.'),
  },
  gatekeeper: { maker: t('Gatekeeper: macOS’s check of app signatures.', 'The seal checker at the gate.') },
  sip: {
    maker: t('System Integrity Protection: it stops anything changing the core of macOS.', 'The guard on the city’s core.'),
    disk: t('Switched off, so the core of macOS can be changed.', 'Off duty, so the core can be changed.'),
  },
};

/**
 * classify(finding) -> { verdict, kind, win, subject, maker, label, makerText, disk, means }
 * kind: 'app' | 'driver' | 'cert' | 'checker' | 'note'
 */
export function classify(finding) {
  const f = isObj(finding) ? finding : {};
  const d = isObj(f.data) ? f.data : {};
  const c = CODE(f);
  const win = isWindows(f);
  let verdict = 'other';
  let kind = 'note';
  const extra = [];
  if (c === 'code_signature_audit.tampered_binary') { verdict = 'tampered'; kind = 'app'; if (win) extra.push('win-tampered'); }
  else if (c === 'code_signature_audit.old_signature_format') { verdict = 'old-format'; kind = 'app'; }
  else if (c === 'code_signature_audit.unsigned_system_app') { verdict = 'unsigned'; kind = 'app'; if (win) extra.push('win-unsigned'); }
  else if (c === 'code_signature_audit.gatekeeper_rejected') { verdict = 'unknown-maker'; kind = 'app'; extra.push(win ? 'win-app' : 'mac-rejected'); }
  else if (c === 'suspicious_processes.unsigned_apps') { verdict = 'unknown-maker'; kind = 'app'; extra.push('no-bundle'); }
  else if (c === 'win_suspicious_processes.suspicious_path') { verdict = 'unknown-maker'; kind = 'app'; extra.push('win-app', 'win-odd-folder'); }
  else if (c === 'win_suspicious_processes.no_file_path') { verdict = 'unknown-maker'; kind = 'app'; extra.push('win-app', 'win-no-file'); }
  else if (c === 'win_rootkit_check.unsigned_drivers' || (f.module === 'win_driver_check' && d.check === 'unsigned_drivers')) {
    verdict = 'unsigned'; kind = 'driver'; extra.push('driver');
  } else if (c === 'certificate_trust_audit.suspicious_certificates') { verdict = 'unknown-maker'; kind = 'cert'; extra.push('cert-intercept'); }
  else if (['certificate_audit.user_root_cas', 'certificate_trust_audit.self_signed_root_certs', 'certificate_trust_audit.user_added_certs'].includes(c)) {
    verdict = 'unknown-maker'; kind = 'cert'; extra.push('cert');
  } else if (/^certificate_(?:trust_)?audit\.expired_certificates$/.test(c)) { verdict = 'expired'; kind = 'cert'; }
  else if (c === 'gatekeeper_quarantine_check.gatekeeper_disabled') { verdict = 'checker-off'; kind = 'checker'; extra.push('gatekeeper'); }
  else if (c === 'gatekeeper_quarantine_check.sip_disabled') { verdict = 'checker-off'; kind = 'checker'; extra.push('sip'); }
  else if (c === 'gatekeeper_quarantine_check.gatekeeper_assessment_failed') { verdict = 'checker-unsure'; kind = 'checker'; extra.push('gatekeeper'); }
  else if (c === 'gatekeeper_quarantine_check.quarantine_removed') { verdict = 'no-tag'; kind = 'note'; }
  const base = VERDICTS[verdict];
  const words = { label: base.label, makerText: base.maker, disk: base.disk, means: base.means };
  for (const k of extra) {
    const o = OVERRIDES[k];
    if (o.maker) words.makerText = o.maker;
    if (o.disk) words.disk = o.disk;
    if (o.means) words.means = o.means;
  }
  return { verdict, kind, win, sip: extra.includes('sip'), subject: subjectOf(f), maker: makerOf(f), ...words };
}

// ---- decisions --------------------------------------------------------------

function alerting(item, v) {
  return v.verdict === 'tampered' || isAlertingItem(item);
}

const STEPS = {
  macApp: t([
    'Quit the app if it’s open.',
    'Get the current version from the maker’s own website or the App Store, not from wherever this copy came from.',
    'Install it, replacing this copy.',
  ], [
    'Close it if it’s open.',
    'Get a fresh copy straight from the maker.',
    'Swap it in for this one.',
  ]),
  winApp: t([
    'Close the program if it’s open.',
    'Open Settings, then Apps, then Installed apps, and uninstall it.',
    'Download it again from the maker’s own website or the Microsoft Store.',
  ], [
    'Close it if it’s open.',
    'Take it out from the list of installed gear.',
    'Get a fresh copy straight from the maker.',
  ]),
  driver: t([
    'Open Settings, then Windows Update, and install any driver updates offered.',
    'If the driver isn’t updated there, get a signed version from the device maker’s website.',
  ], [
    'Check the city’s updates for a sealed version.',
    'If there isn’t one, get it straight from the device maker.',
  ]),
  cert: t([
    'Open Keychain Access (in Applications, then Utilities).',
    'Find the certificate by its name and check who added it.',
    'If you don’t know why it’s there, ask someone you trust before you delete it.',
  ], [
    'Open the key cabinet (in Applications, then Utilities).',
    'Find the stamp by its name.',
    'If you don’t know why it’s there, ask someone you trust before you take it out.',
  ]),
  gatekeeper: t([
    'Open System Settings, then Privacy & Security.',
    'Under “Allow applications from”, choose “App Store and identified developers”.',
  ], [
    'Open the settings, then the privacy and security page.',
    'Set the gate to allow known makers only.',
  ]),
  sip: t([
    'Shut down the Mac. On Apple silicon, hold the power button until you see startup options, then choose Options. On an Intel Mac, hold Command-R while it starts.',
    'Choose Utilities, then Terminal, type csrutil enable, press Return, and restart.',
  ], [
    'Shut down, then start up holding the power button (or Command-R) to reach the repair room.',
    'Open Terminal there, type csrutil enable, press Return, and restart.',
  ]),
};

const CHECKLISTS = {
  tampered: t([
    'Did you change or patch this app yourself?',
    'Do you remember installing it, and where you got it?',
    'Do you know the maker it says it’s from?',
    'Search the app’s name on another device before you open it.',
  ], [
    'Did you tinker with this gear yourself?',
    'Do you remember bringing it in, and from where?',
    'Do you know the maker on the seal?',
    'Look the name up on another device before you open it.',
  ]),
  app: t([
    'Do you recognise this app?',
    'Did you install it, and where did you get it?',
    'Is there a newer version on the maker’s website?',
  ], [
    'Do you recognise this gear?',
    'Did you bring it in, and from where?',
    'Does the maker have a newer copy?',
  ]),
  driver: t([
    'Which device is it for? Search the driver’s name.',
    'Did you install hardware or software that came with it?',
    'Does Windows Update offer a newer driver?',
  ], [
    'Which machine is it for? Look up its name.',
    'Did new hardware arrive with it?',
    'Do the city’s updates have a sealed version?',
  ]),
  cert: t([
    'Does a workplace or school manage this computer?',
    'Did you install a tool that asked you to trust a certificate?',
    'Search the certificate’s name on another device.',
  ], [
    'Does a workplace or school look after this computer?',
    'Did some gear ask you to trust its stamp?',
    'Look the stamp’s name up on another device.',
  ]),
  checker: t([
    'Did you switch this off yourself, for a specific app?',
    'Did someone else set up this computer for you?',
    'Is the computer up to date?',
  ], [
    'Did you send the checker home yourself, for some gear?',
    'Did someone else set up this computer for you?',
    'Is the city up to date?',
  ]),
  note: t([
    'Do you recognise the apps it names?',
    'Did they come from an installer, an updater, or another computer?',
  ], [
    'Do you recognise the gear it names?',
    'Did it come from an installer, its own updates, or another workshop?',
  ]),
};

const D = {
  reinstall: t('Reinstall from the maker', 'Get a fresh copy'),
  update: t('Update the driver', 'Get a sealed driver'),
  mine: t('Mine, I know why', 'Mine, I know why'),
  closer: t('Look closer', 'Look closer'),
  notMine: t('Not mine', 'Not mine'),
  leave: t('Leave it', 'Leave it'),
  turnOn: t('Turn it back on', 'Call the checker back'),
  recheck: t('Check again', 'Check again'),
  normal: t('That’s normal', 'That’s normal'),
};

function mineEffect(f) {
  return f.markable && typeof f.markable === 'object' ? { kind: 'mark' } : { kind: 'keep', reason: 'mine' };
}

function closer(v, ctx) {
  const list = v.verdict === 'tampered' ? CHECKLISTS.tampered : CHECKLISTS[v.kind] || CHECKLISTS.note;
  return { id: 'closer', label: D.closer, effect: { kind: 'closer', checklist: say(list, ctx).slice() } };
}

function lookupFor(v) {
  if (v.maker && v.maker.verified) return { kind: 'lookup', source: 'maker-site', query: v.maker.name };
  return { kind: 'lookup', source: 'web', query: v.subject };
}

export function decisions(item, ctx) {
  const f = (item && item.finding) || {};
  const v = classify(f);
  const alert = alerting(item || {}, v);
  const mine = { id: 'mine', label: D.mine, effect: mineEffect(f) };
  const look = closer(v, ctx);

  if (v.kind === 'app') {
    const reinstall = {
      id: 'reinstall', label: D.reinstall,
      effect: { kind: 'link', link: lookupFor(v), steps: v.win ? STEPS.winApp : STEPS.macApp, removal: alert, warning: alert },
    };
    return alert ? [look, mine, reinstall] : [reinstall, mine, look];
  }
  if (v.kind === 'driver') {
    const update = { id: 'update', label: D.update, effect: { kind: 'link', link: { kind: 'settings', pane: 'windows-update' }, steps: STEPS.driver, removal: alert, warning: alert } };
    return alert ? [look, mine, update] : [update, mine, look];
  }
  if (v.kind === 'cert') {
    if (v.verdict === 'expired') return [{ id: 'leave', label: D.leave, effect: { kind: 'keep', reason: 'expired' } }, look];
    const notMine = {
      id: 'not-mine', label: D.notMine,
      effect: { kind: 'link', link: { kind: 'lookup', source: 'apple-support', query: 'Keychain Access delete a certificate' }, steps: STEPS.cert, removal: true, warning: true },
    };
    return [look, mine, notMine];
  }
  if (v.verdict === 'checker-off') {
    const turnOn = {
      id: 'turn-on', label: D.turnOn,
      effect: { kind: 'link', link: { kind: 'lookup', source: 'apple-support', query: v.sip ? 'System Integrity Protection' : 'Gatekeeper Privacy & Security allow applications' }, steps: v.sip ? STEPS.sip : STEPS.gatekeeper, removal: false },
    };
    return [turnOn, { id: 'mine', label: D.mine, effect: { kind: 'keep', reason: 'mine' } }, look];
  }
  if (v.verdict === 'checker-unsure') return [{ id: 'recheck', label: D.recheck, effect: { kind: 'recheck' } }, look];
  if (v.verdict === 'no-tag') return [{ id: 'normal', label: D.normal, effect: { kind: 'keep', reason: 'normal' } }, look];
  return [look, mine];
}

// ---- research ---------------------------------------------------------------

const num = (n) => (typeof n === 'number' && Number.isFinite(n) && n >= 0 ? Math.floor(n) : null);
const fmt = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');

function coverageLine(f, ctx) {
  const d = isObj(f.data) ? f.data : {};
  const a = num(d.apps_checked);
  const b = num(d.apps_total);
  if (a == null || b == null || a >= b) return '';
  return say(t(`This check looked at ${fmt(a)} of ${fmt(b)} apps. The rest weren’t checked.`,
    `The patrol reached ${fmt(a)} of ${fmt(b)} apps. The rest weren’t checked.`), ctx);
}

function unfinished(item) {
  const f = (item && item.finding) || {};
  return !!(item && (item.complete === false || item.unfinished === true || f.complete === false || f.unfinished === true
    || (isObj(f.data) && f.data.incomplete === true)));
}

export function research(item, ctx) {
  const f = (item && item.finding) || {};
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const v = classify(f);
  const rows = ctx && typeof ctx.evidenceRows === 'function' ? (ctx.evidenceRows(f, { mode }) || []) : [];
  // "Who made it" is about a program; a certificate or a system switch has no maker line.
  const program = v.kind === 'app' || v.kind === 'driver' || v.kind === 'note';
  const what = v.maker && v.maker.verified && v.maker.what ? v.maker.what
    : program ? say(t('Unknown maker', 'Maker not known'), ctx) : '';
  const coverage = coverageLine(f, ctx);
  const notDone = unfinished(item);
  const links = [];
  if (v.kind === 'app') {
    links.push(lookupFor(v));
    if (v.win) links.push({ kind: 'settings', pane: 'windows-apps' });
    if (v.win && v.verdict === 'tampered') links.push({ kind: 'settings', pane: 'windows-security' });
  } else if (v.kind === 'driver') {
    links.push({ kind: 'settings', pane: 'windows-update' });
    if (v.subject) links.push({ kind: 'lookup', source: 'web', query: v.subject });
  } else if (v.kind === 'cert') {
    links.push({ kind: 'lookup', source: 'apple-support', query: 'Keychain Access certificates' });
    if (v.subject) links.push({ kind: 'lookup', source: 'web', query: v.subject });
  } else if (v.kind === 'checker') {
    links.push({ kind: 'lookup', source: 'apple-support', query: v.sip ? 'System Integrity Protection' : 'Gatekeeper' });
  }
  links.push({ kind: 'lesson', concept: 'who-made-it' });
  if (coverage || notDone) links.push({ kind: 'lesson', concept: 'couldnt-check' });
  return { rows, what, links, verdict: v.verdict, coverage, unfinished: notDone };
}

// ---- render -----------------------------------------------------------------

const HEAD = {
  maker: t('What the maker signed', 'The maker’s seal'),
  disk: t('What’s on disk', 'What’s here now'),
  kicker: t('App seal', 'Seal Check'),
  unfinished: t('This check didn’t finish, so it may have missed things.', 'This check didn’t finish, so it may have missed things.'),
  signer: t('Says it’s from', 'Seal says'),
  verified: t('verified', 'checked'),
  notVerified: t('not verified', 'not checked'),
};

export function render(view, ctx) {
  const item = (view && view.item) || {};
  const f = item.finding || {};
  const d = isObj(f.data) ? f.data : {};
  const v = classify(f);
  const r = (view && view.research) || research(item, ctx);
  const e = ctx.esc;
  const index = num(view && view.index) || 0;
  const total = num(view && view.total) || 1;
  const signer = v.maker
    ? `<p class="seal-signer">${e(say(HEAD.signer, ctx))}: <b>${e(v.maker.name)}</b> · ${e(say(v.maker.verified ? HEAD.verified : HEAD.notVerified, ctx))}</p>`
    : '';
  const where = d.path ? `<p class="seal-path seal-mono">${e(d.path)}</p>` : '';
  const mismatch = ['tampered', 'unknown-maker', 'unsigned', 'checker-off'].includes(v.verdict);
  const parts = [
    `<article class="seal-card seal--${v.verdict}" data-verdict="${v.verdict}">`,
    '<header class="seal-head">',
    `<p class="seal-kicker">${e(say(HEAD.kicker, ctx))} · ${index + 1} / ${total}</p>`,
    `<h3 class="seal-name">${e(v.subject)}</h3>`,
    `<span class="seal-verdict">${e(say(v.label, ctx))}</span>`,
    '</header>',
    '<div class="seal-compare">',
    `<section class="seal-side seal-side--maker"><h4>${e(say(HEAD.maker, ctx))}</h4><p>${e(say(v.makerText, ctx))}</p>${signer}</section>`,
    `<div class="seal-vs" aria-hidden="true">${mismatch ? '≠' : '?'}</div>`,
    `<section class="seal-side seal-side--disk"><h4>${e(say(HEAD.disk, ctx))}</h4><p>${e(say(v.disk, ctx))}</p>${where}</section>`,
    '</div>',
    `<p class="seal-means">${e(say(v.means, ctx))}</p>`,
    r.coverage ? `<p class="seal-coverage">${e(r.coverage)}</p>` : '',
    r.unfinished ? `<p class="seal-unfinished">${e(say(HEAD.unfinished, ctx))}</p>` : '',
    view && view.step && view.step.say ? `<p class="seal-step" role="note">${e(say(view.step.say, ctx))}</p>` : '',
    '</article>',
  ];
  return parts.filter(Boolean).join('');
}

// ---- summary ----------------------------------------------------------------

const decisionId = (r) => {
  if (!r) return '';
  if (typeof r.decision === 'string') return r.decision;
  if (isObj(r.decision) && r.decision.id) return str(r.decision.id);
  return str(r.id);
};

const TALLY = [
  ['reinstall', t('to reinstall', 'to swap for a fresh copy')],
  ['update', t('drivers to update', 'drivers to swap')],
  ['turn-on', t('checks to switch back on', 'checkers to call back')],
  ['not-mine', t('certificates to look into', 'stamps to look into')],
  ['mine', t('yours', 'yours')],
  ['leave', t('left as they are', 'left as they are')],
  ['normal', t('normal', 'normal')],
  ['recheck', t('to check again', 'to check again')],
  ['closer', t('to look closer', 'to look closer')],
];

export function summary(results, ctx) {
  const list = Array.isArray(results) ? results : [];
  const e = ctx.esc;
  if (!list.length) return `<p class="seal-summary">${e(say(t('No seals decided yet.', 'No seals checked yet.'), ctx))}</p>`;
  const counts = new Map();
  for (const r of list) counts.set(decisionId(r), (counts.get(decisionId(r)) || 0) + 1);
  const bits = TALLY.filter(([id]) => counts.get(id)).map(([id, words]) => `${counts.get(id)} ${say(words, ctx)}`);
  const n = list.length;
  const head = say(t(`You went through ${n} seal${n === 1 ? '' : 's'}`, `Seal Check: ${n} seal${n === 1 ? '' : 's'} looked at`), ctx);
  const partial = list.some((r) => r && r.item && (coverageLine(r.item.finding || {}, ctx) || unfinished(r.item)));
  return [
    `<p class="seal-summary">${e(head)}${bits.length ? `: ${e(bits.join(', '))}` : ''}.</p>`,
    partial ? `<p class="seal-coverage">${e(say(t('Not every app was checked, so there may be more to find.', 'Not every app was checked by the patrol, so there may be more to find.'), ctx))}</p>` : '',
    `<p class="seal-teach">${e(say(t('A signature tells you who made an app and that it’s unchanged, not that you wanted it.', 'A seal tells you who made the gear and that nothing changed, not that you wanted it.'), ctx))}</p>`,
  ].filter(Boolean).join('');
}

// ---- practice (synthetic only) ---------------------------------------------

function practiceItem(key, finding) {
  const f = { category: 'security', synthetic: true, data: {}, ...finding };
  return { key: `practice:seal:${key}`, severity: f.severity, finding: f, findings: [f], seen_in: [f.module], marked: false, held: false, removal_alert: !!f.removal_alert, practice: true };
}

const PRACTICE_ITEMS = [
  practiceItem('old-game', {
    module: 'code_signature_audit', severity: 'warning', code: 'security.code_signature_audit.old_signature_format',
    title: 'Starfield Miners has an old-style signature',
    data: { check: 'old_signature_format', path: '/Applications/Starfield Miners.app', name: 'Starfield Miners',
      detail: 'codesign --verify: /Applications/Starfield Miners.app: resource envelope is obsolete (custom omit rules)', apps_checked: 12, apps_total: 12 },
    made_by: [{ subject: '/Applications/Starfield Miners.app', name: 'Pixel Harbor Games', verified: false, how: 'claims to be made by Pixel Harbor Games', location_note: '' }],
  }),
  practiceItem('tampered', {
    module: 'code_signature_audit', severity: 'critical', removal_alert: true, code: 'security.code_signature_audit.tampered_binary',
    title: 'App Brightframe Photo was changed after it was signed',
    data: { check: 'tampered_binary', path: '/Applications/Brightframe Photo.app', name: 'Brightframe Photo',
      detail: 'codesign --verify failed on a signed object: a sealed resource is missing or invalid', apps_checked: 12, apps_total: 12 },
    made_by: [{ subject: '/Applications/Brightframe Photo.app', name: 'Brightframe Labs', verified: false, how: 'claims to be made by Brightframe Labs', location_note: '' }],
  }),
  practiceItem('dev-build', {
    module: 'code_signature_audit', severity: 'warning', code: 'security.code_signature_audit.unsigned_system_app',
    title: 'Unsigned app MyTestBuild is installed for all users',
    data: { check: 'unsigned_system_app', path: '/Applications/MyTestBuild.app', name: 'MyTestBuild',
      detail: 'codesign: code object is not signed at all', apps_checked: 12, apps_total: 12 },
  }),
];

const PRACTICE_SCRIPT = [
  { item: 0, say: t('Two sides: what the maker signed, and what’s on disk. When they don’t match, that’s your clue.',
    'Two sides: the maker’s seal, and what’s here now. When they don’t match, that’s your clue.') },
  { item: 0, say: t('This game is signed the old way. Today’s macOS can’t check that kind, so a fresh copy from the maker is the easy fix.',
    'This game has an old seal the checker can’t read. A fresh copy from the maker sorts it out.'), expect: 'reinstall' },
  { item: 1, say: t('Changed after signing: updates are always signed again, so this has no normal reason. Don’t replace it yet. Look closer first.',
    'Broken seal: real updates always get a new seal. Don’t swap it yet. Look closer first.'), expect: 'closer' },
  { item: 2, say: t('No signature, but this is a test build you made yourself. Your own builds are often unsigned.',
    'No seal, but this is gear you built yourself. Home-built gear often has no seal.'), expect: 'mine' },
];

export default {
  type: 'seal',
  title: TITLE,
  concepts: ['who-made-it', 'couldnt-check'],
  covers: [
    { module: 'code_signature_audit' },
    { module: 'gatekeeper_quarantine_check' },
    { module: 'suspicious_processes', codes: ['security.suspicious_processes.unsigned_apps'] },
    { module: 'certificate_audit' },
    { module: 'certificate_trust_audit' },
    { module: 'win_rootkit_check', codes: ['security.win_rootkit_check.unsigned_drivers'] },
    // win_driver_check emits no codes: its unsigned-driver finding by data.check (R9).
    { module: 'win_driver_check', checks: ['unsigned_drivers'] },
    // A running program from an odd folder or with no file: whose seal is it? (Harmful ones are the Locker's.)
    { module: 'win_suspicious_processes', codes: ['security.win_suspicious_processes.suspicious_path', 'security.win_suspicious_processes.no_file_path'] },
  ],
  classify,
  decisions,
  research,
  practice: { items: PRACTICE_ITEMS, script: PRACTICE_SCRIPT },
  render,
  summary,
};
