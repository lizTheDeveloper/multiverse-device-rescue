// "Take your accounts back": the account half of "I think I've been hacked",
// as small missions in triage order. The email account comes first, because
// the password resets for almost every other account go through it.
//
// Pure, no DOM. The person always acts at the provider's own site; the app
// never asks for a password, a code or an account name, and stores none:
// only which kind of email provider (google, microsoft, apple, other) and each
// step's answer (done, not applicable, need help) with a date. The safety
// question ("could this be someone you know?") is never stored.
//
// Menu paths are copied from each provider's own help page (checked
// 2026-10-27; each link's help page is the source). Where a provider has no
// official page for a step, only its hacked-account page is linked. Never add
// a path that its linked help page doesn't spell out.
import { HELD_MODULES } from './held.js';

export const ACCOUNTS_KEY = 'device-rescue.game.accounts.v1';
export const ANSWERS = new Set(['done', 'na', 'help']);
export const SAFETY = new Set(['no', 'maybe']);

export const PROVIDERS = [
  { id: 'google', name: 'Google', mail: 'Gmail',
    hacked: { label: 'Google’s own page: Secure a hacked or compromised Google Account', url: 'https://support.google.com/accounts/answer/6294825' } },
  { id: 'microsoft', name: 'Microsoft', mail: 'Outlook.com, Hotmail or Live',
    hacked: { label: 'Microsoft’s own page: How to recover a hacked or compromised Microsoft account', url: 'https://support.microsoft.com/en-us/help/10494' } },
  { id: 'apple', name: 'Apple', mail: 'iCloud Mail',
    hacked: { label: 'Apple’s own page: If you think your Apple Account has been compromised', url: 'https://support.apple.com/en-us/102560' } },
  { id: 'other', name: 'Something else', mail: 'Yahoo, AOL, Proton, a work or school address…', hacked: null },
];

const G = {
  hacked: PROVIDERS[0].hacked,
  devices: { label: 'Google: manage the devices signed in to your account', url: 'https://support.google.com/accounts/answer/3067630' },
};
const MS = { hacked: PROVIDERS[1].hacked };
const A = { hacked: PROVIDERS[2].hacked };

// One step, one decision. `short` is the one line the checklist shows; the
// why lives in the lesson (taking-accounts-back). `generic` is for a provider
// we don't cover: what to look for, never a menu name.
export const STEPS = [
  { id: 'safety', section: 'first', title: 'Could this be someone you know?',
    short: 'A partner, ex, family member or housemate.' },
  { id: 'device', section: 'first', title: 'Use a device you trust',
    short: 'Do the account steps on a phone or computer you trust.',
    generic: 'If this computer’s checkup has things still open, use your phone or another computer you trust until they’re sorted.' },

  { id: 'email-provider', section: 'email', title: 'Which email do your accounts use?',
    short: 'The address your other accounts send password resets to.' },
  { id: 'email-signin', section: 'email', title: 'Can you still sign in to your email?',
    short: 'If not, use your provider’s own account recovery.',
    generic: 'If you can’t sign in, look on your email provider’s help site for its account recovery page. Use only the provider’s own site.',
    perProvider: {
      google: { links: [{ label: 'Google account recovery', url: 'https://accounts.google.com/signin/recovery' }, G.hacked] },
      microsoft: { links: [MS.hacked] },
      apple: { links: [{ label: 'Apple account recovery (iforgot.apple.com)', url: 'https://iforgot.apple.com' }, A.hacked] },
    } },
  { id: 'email-password', section: 'email', title: 'Change your email password',
    short: 'A new password you haven’t used anywhere else.',
    generic: 'In your email’s settings, find its security page and change the password there.',
    perProvider: {
      google: { where: ['Security & sign-in › How you sign in to Google › Password'],
        links: [{ label: 'Open Google’s security page', url: 'https://myaccount.google.com/security' },
          { label: 'Google help: change your password', url: 'https://support.google.com/accounts/answer/41078' }] },
      microsoft: { where: ['account.microsoft.com/security › Change Password'],
        links: [{ label: 'Open Microsoft’s change-password page', url: 'https://account.live.com/password/Change' },
          { label: 'Microsoft help: change your password', url: 'https://support.microsoft.com/help/4026838' }] },
      apple: { where: ['iPhone: Settings › [your name] › Sign-In & Security › Change Password', 'Web: account.apple.com › Sign-In and Security › Password'],
        links: [{ label: 'Open account.apple.com', url: 'https://account.apple.com' },
          { label: 'Apple help: change your password', url: 'https://support.apple.com/en-us/101567' }] },
    } },
  { id: 'email-signout', section: 'email', title: 'Sign out every device you don’t recognise',
    short: 'Phones, computers and browsers still signed in.',
    generic: 'In your email’s security settings, look for the list of devices or sessions signed in, and sign out the ones you don’t recognise.',
    perProvider: {
      google: { where: ['Security & sign-in › Your devices › Manage all devices › (the device) › Sign out'],
        links: [{ label: 'Open Google’s device list', url: 'https://myaccount.google.com/device-activity' }, G.devices] },
      microsoft: { where: ['Advanced security options › Sign out everywhere › Sign out'],
        links: [{ label: 'Open Microsoft’s recent activity', url: 'https://account.live.com/Activity' },
          { label: 'Microsoft help: sign out everywhere', url: 'https://support.microsoft.com/help/58da4a74-a719-43a6-9dd0-74a7e613229f' }] },
      apple: { where: ['iPhone: Settings › [your name] › (scroll down to the device) › Remove from Account', 'Web: account.apple.com › Devices › (the device) › Remove from Account'],
        links: [{ label: 'Open account.apple.com', url: 'https://account.apple.com' },
          { label: 'Apple help: remove a device', url: 'https://support.apple.com/en-us/102649' }] },
    } },
  { id: 'email-recovery', section: 'email', title: 'Check the recovery phone and email',
    short: 'Remove any number or address that isn’t yours.',
    generic: 'In your email’s security settings, look for the recovery phone number and recovery email. Remove any that aren’t yours, and add yours first.',
    perProvider: {
      google: { where: ['Security & sign-in › How you sign in to Google › Recovery phone', 'Security & sign-in › How you sign in to Google › Recovery email'],
        links: [{ label: 'Open Google’s recovery phone', url: 'https://myaccount.google.com/phone' },
          { label: 'Google help: recovery phone and email', url: 'https://support.google.com/accounts/answer/183723' }] },
      microsoft: { where: ['account.microsoft.com/security › Manage how I sign in', 'Advanced security options › (the method) › Remove'],
        note: 'Add your own phone or email before you remove one that isn’t yours.',
        links: [{ label: 'Microsoft help: add a way to sign in', url: 'https://support.microsoft.com/help/12428' },
          { label: 'Microsoft help: remove a way to sign in', url: 'https://support.microsoft.com/en-us/accounts-billing/manage/removing-a-sign-in-verification-method' }] },
      apple: { where: ['iPhone: Settings › [your name] › Sign-In & Security › Two-Factor Authentication', 'Web: account.apple.com › Sign-In and Security › Account Security', 'iPhone: Settings › [your name] › Sign-In & Security › Recovery Contacts'],
        links: [{ label: 'Apple help: trusted phone numbers', url: 'https://support.apple.com/en-us/122621' },
          { label: 'Apple help: recovery contacts', url: 'https://support.apple.com/en-us/102641' }] },
    } },
  { id: 'email-forwarding', section: 'email', title: 'Check forwarding and mail rules',
    short: 'Copies of your mail sent somewhere else, or hidden.',
    generic: 'In your email’s settings, look for forwarding and for filters or rules. Turn off forwarding you didn’t set up, and delete rules you didn’t make.',
    perProvider: {
      google: { where: ['Settings › See all settings › Forwarding and POP/IMAP', 'Settings › See all settings › Filters and Blocked Addresses', 'Settings › See all settings › Accounts and Import › Grant access to your account'],
        links: [{ label: 'Gmail help: forwarding', url: 'https://support.google.com/mail/answer/10957' },
          { label: 'Gmail help: filters', url: 'https://support.google.com/mail/answer/6579' },
          { label: 'Gmail help: who has access to your mail', url: 'https://support.google.com/mail/answer/138350' }] },
      microsoft: { where: ['Settings › Mail › Forwarding', 'Settings › Mail › Rules'],
        links: [{ label: 'Outlook.com help: forwarding', url: 'https://support.microsoft.com/en-us/outlook/turn-on-or-off-automatic-forwarding-in-outlook-com' },
          { label: 'Outlook.com help: inbox rules', url: 'https://support.microsoft.com/office/use-inbox-rules-in-outlook-com-4b094371-a5d7-49bd-8b1b-4e4896a7cc5d' }] },
      apple: { where: ['icloud.com/mail › Settings › Mail Forwarding', 'icloud.com/mail › Settings › Rules'],
        links: [{ label: 'Open iCloud Mail', url: 'https://www.icloud.com/mail' },
          { label: 'iCloud help: mail forwarding', url: 'https://support.apple.com/guide/icloud/mm6b1a3960/icloud' },
          { label: 'iCloud help: mail rules', url: 'https://support.apple.com/guide/icloud/mm6b1a3f8a/icloud' }] },
    } },
  { id: 'email-apps', section: 'email', title: 'Remove apps you don’t recognise',
    short: 'Apps and sites you once let use your account.',
    generic: 'In your email’s security settings, look for apps or sites connected to your account, and remove the ones you don’t recognise.',
    perProvider: {
      google: { where: ['Access to your Google Account › (the app) › See details › Remove access'],
        links: [{ label: 'Open Google’s connected apps', url: 'https://myaccount.google.com/linkedapps' },
          { label: 'Google help: third-party apps', url: 'https://support.google.com/accounts/answer/13533235' }] },
      // Microsoft has no help page for this list; its hacked-account page links to it.
      microsoft: { links: [MS.hacked] },
      apple: { where: ['iPhone: Settings › [your name] › Sign in with Apple › (the app) › Delete'],
        links: [{ label: 'Apple help: Sign in with Apple', url: 'https://support.apple.com/en-us/102571' }] },
    } },
  { id: 'email-app-passwords', section: 'email', title: 'Remove app passwords',
    short: 'Extra passwords that skip two-step sign-in.',
    generic: 'In your email’s security settings, look for app passwords or app-specific passwords, and remove any you don’t use.',
    perProvider: {
      google: { where: ['App passwords › Remove'], note: 'Google removes these when you change your password.',
        links: [{ label: 'Open Google’s app passwords', url: 'https://myaccount.google.com/apppasswords' },
          { label: 'Google help: app passwords', url: 'https://support.google.com/accounts/answer/185833' }] },
      microsoft: { where: ['Advanced security options › App passwords'],
        links: [{ label: 'Microsoft help: app passwords', url: 'https://support.microsoft.com/help/12409' }] },
      apple: { where: ['Web: account.apple.com › Sign-In and Security › App-Specific Passwords'], note: 'Apple removes these when you change your password.',
        links: [{ label: 'Open account.apple.com', url: 'https://account.apple.com' },
          { label: 'Apple help: app-specific passwords', url: 'https://support.apple.com/en-us/102654' }] },
    } },
  { id: 'email-2sv', section: 'email', title: 'Turn on two-step sign-in',
    short: 'And remove any phone or app on it that isn’t yours.',
    generic: 'In your email’s security settings, look for two-step verification (or two-factor authentication) and turn it on.',
    perProvider: {
      google: { where: ['Security & sign-in › How you sign in to Google › Turn on 2-Step Verification'],
        links: [{ label: 'Open Google 2-Step Verification', url: 'https://myaccount.google.com/signinoptions/two-step-verification' },
          { label: 'Google help: 2-Step Verification', url: 'https://support.google.com/accounts/answer/185839' }] },
      microsoft: { where: ['account.microsoft.com/security › Manage how I sign in › Two-step verification › Turn on'],
        links: [{ label: 'Microsoft help: two-step verification', url: 'https://support.microsoft.com/help/12408' }] },
      apple: { where: ['iPhone: Settings › [your name] › Sign-In & Security › Two-Factor Authentication'],
        links: [{ label: 'Apple help: two-factor authentication', url: 'https://support.apple.com/en-us/102660' }] },
    } },

  { id: 'password-manager', section: 'next', title: 'Your password manager',
    short: 'Change its main password, and sign out devices you don’t know.',
    generic: 'From a device you trust, change your password manager’s main password, sign out any device you don’t recognise, and check who it shares with. Its own help site has the steps. If you don’t use one, choose Doesn’t apply.' },
  { id: 'money', section: 'next', title: 'Check your bank and cards',
    short: 'Look for payments you didn’t make.',
    generic: 'Look through recent payments on each bank account and card. For anything you didn’t do, call the number on the back of your card or on your bank’s own website, not a number from an email or text.' },
  { id: 'phone-account', section: 'next', title: 'Your phone’s account',
    short: 'Apple Account or Google: the devices signed in.',
    generic: 'Your phone is signed in to an Apple Account or a Google account. Check its list of devices and remove any you don’t recognise. If that was your email above, choose Doesn’t apply.',
    perProvider: {
      google: { where: ['Security & sign-in › Your devices › Manage all devices › (the device) › Sign out'],
        links: [{ label: 'Open Google’s device list', url: 'https://myaccount.google.com/device-activity' }, G.devices] },
      microsoft: { where: ['Advanced security options › Sign out everywhere › Sign out'],
        links: [{ label: 'Microsoft help: sign out everywhere', url: 'https://support.microsoft.com/help/58da4a74-a719-43a6-9dd0-74a7e613229f' }] },
      apple: { where: ['iPhone: Settings › [your name] › (scroll down to the device) › Remove from Account'],
        links: [{ label: 'Apple help: remove a device', url: 'https://support.apple.com/en-us/102649' }] },
    } },
  { id: 'carrier', section: 'next', title: 'Ask your mobile carrier about forwarding',
    short: 'Make sure nobody set up your texts to go somewhere else.',
    generic: 'Call your mobile carrier on the number from its own website or your bill. Ask them to confirm that nobody has set up forwarding of your texts.',
    sources: [A.hacked] },
  { id: 'social', section: 'next', title: 'Social media and messaging',
    short: 'New password, sign out other devices, check what was sent as you.',
    generic: 'For each social and messaging account, one at a time: change the password, sign out the devices you don’t recognise in its security settings, and look for posts or messages you didn’t send. Tell friends if something went out in your name.' },

  { id: 'record', section: 'after', title: 'Write down what happened',
    short: 'Dates, what you saw, what you changed. On paper or another device.',
    generic: 'On paper or another device you trust, write down what you noticed and when, and each thing you changed. Reclaim City doesn’t keep any of it. If money or your identity was involved, the “Someone stole my identity” checkup is next.' },
];

export const STEP_IDS = new Set(STEPS.map((s) => s.id));
const PROVIDER_IDS = new Set(PROVIDERS.map((p) => p.id));
// The safety answer is memory only; the provider step is answered by picking one.
const STORED = new Set([...STEP_IDS].filter((id) => id !== 'safety' && id !== 'email-provider'));

// Every link the checklist can open (the main process allowlist includes these).
export function allLinks() {
  const out = new Set();
  for (const p of PROVIDERS) if (p.hacked) out.add(p.hacked.url);
  for (const s of STEPS) {
    for (const l of s.sources || []) out.add(l.url);
    for (const at of Object.values(s.perProvider || {})) for (const l of at.links || []) out.add(l.url);
  }
  return [...out].sort();
}

export function emptyAccounts() {
  return { version: 1, provider: null, steps: {} };
}

// Rebuilt from known fields only: a stray key (a name, an address) is dropped.
function clean(raw) {
  if (!raw || typeof raw !== 'object' || raw.version !== 1) return emptyAccounts();
  const steps = {};
  const src = raw.steps && typeof raw.steps === 'object' && !Array.isArray(raw.steps) ? raw.steps : {};
  for (const id of Object.keys(src)) {
    const r = src[id];
    if (STORED.has(id) && r && ANSWERS.has(r.a) && typeof r.at === 'string') steps[id] = { a: r.a, at: r.at };
  }
  return { version: 1, provider: PROVIDER_IDS.has(raw.provider) ? raw.provider : null, steps };
}

export function loadAccounts(storage) {
  try {
    const raw = storage ? storage.getItem(ACCOUNTS_KEY) : null;
    return raw ? clean(JSON.parse(raw)) : emptyAccounts();
  } catch (_) {
    return emptyAccounts();
  }
}

export function saveAccounts(storage, store) {
  try {
    storage.setItem(ACCOUNTS_KEY, JSON.stringify(clean(store)));
    return true;
  } catch (_) {
    return false;
  }
}

// The same answer again clears it, so a ticked box can be unticked.
export function setAnswer(store, id, answer, now) {
  const s = clean(store);
  if (!STORED.has(id) || !ANSWERS.has(answer)) return s;
  if (s.steps[id] && s.steps[id].a === answer) { delete s.steps[id]; return s; }
  s.steps[id] = { a: answer, at: String(now) };
  return s;
}

export function setProvider(store, provider, _now) {
  const s = clean(store);
  return PROVIDER_IDS.has(provider) ? { ...s, provider } : s;
}

export function answerOf(store, id) {
  if (id === 'email-provider') return store && store.provider ? 'done' : null;
  return (store && store.steps && store.steps[id] && store.steps[id].a) || null;
}

const settled = (store, id) => ['done', 'na'].includes(answerOf(store, id));

// The checklist's numbers: every step but the safety question.
export function accountCounts(store) {
  const steps = STEPS.filter((s) => s.id !== 'safety');
  return { done: steps.filter((s) => settled(store, s.id)).length,
    help: steps.filter((s) => answerOf(store, s.id) === 'help').length, total: steps.length };
}

// The first step not yet done or not applicable; the safety question first,
// every session, because its answer is never kept.
export function nextStep(store, safety) {
  if (!SAFETY.has(safety)) return STEPS[0];
  return STEPS.find((s) => s.id !== 'safety' && !settled(store, s.id)) || null;
}

export function offeredFor(situation) {
  return !!situation && situation.id === 'hacked';
}

// Device findings that matter for a hack: ways in from outside, things that
// start on their own, and anything that can read or redirect what's typed.
// Monitoring software is held (held.js) and never listed here.
export const HACK_MODULES = new Set([
  'remote_login_check', 'sharing_services', 'win_remote_access_audit', 'win_rdp_check',
  'browser_extension_audit', 'launch_agent_audit', 'launchd_persistence_audit', 'scheduled_tasks_audit',
  'network_proxy_check', 'win_proxy_detect', 'session_revocation_scan',
]);

export function devicePrereqs(city, progress) {
  const records = (progress && progress.missions) || {};
  const out = [];
  for (const d of (city && Array.isArray(city.districts) ? city.districts : [])) {
    for (const m of d.missions || []) {
      if (!HACK_MODULES.has(m.module) || HELD_MODULES.has(m.module)) continue;
      const st = records[m.id] && records[m.id].status;
      if (st === 'yours' || st === 'reclaimed') continue;
      out.push(m);
    }
  }
  return out;
}
