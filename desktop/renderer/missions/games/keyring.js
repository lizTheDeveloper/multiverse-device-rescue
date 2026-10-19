// The Keyring: apps with powerful access (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
//
// An item is one "key" (a privacy permission: Accessibility, Input Monitoring, Screen Recording, Camera, Microphone,
// Full Disk Access, Location, Automation, Contacts, Screen Time) and the apps holding it. Each app is a card with the
// keys it holds as chips. One decision per key: Look closer (the default on a critical or warning key) / Keep /
// Hand back (opens that exact privacy pane). On a note, Keep leads and Look closer shows when a maker isn't confirmed.
//
// Honest makers: an app named by a bundle id (or a process name) is what it says about itself, so it is never shown as
// confirmed, whatever made_by says (serialize.py _unverify_named_apps does the same; this re-checks). Only a full path
// with a verified made_by entry reads as confirmed, and only then is its "what it is" line shown.
//
// Pure: no DOM, no storage, no globals. Every scan value goes through ctx.esc. Scan titles and descriptions are never
// rendered (they carry engine words that don't belong in the city).

import { isMonitoringModule, isAlertingItem } from '../contract.js';

// key id -> words and where its switch lives. pane: macOS settings pane (null: no pane in the allowlist; Hand back
// then shows where the switch is). Windows uses its privacy page with the key as the permission hint.
export const KEYS = {
  accessibility: {
    name: { standard: 'Accessibility', city: 'Control key' },
    does: { standard: 'Can click, type and move the pointer for you.', city: 'Works every control in the building.' },
    pane: 'privacy-accessibility', where: 'System Settings > Privacy & Security > Accessibility',
  },
  keyboard: {
    name: { standard: 'Input Monitoring', city: 'Keyboard key' },
    does: { standard: 'Can see everything you type, passwords included.', city: 'Hears every key you press.' },
    pane: 'privacy-input-monitoring', where: 'System Settings > Privacy & Security > Input Monitoring',
  },
  screen: {
    name: { standard: 'Screen Recording', city: 'Window key' },
    does: { standard: 'Can see everything on your screen.', city: 'Sees through every window.' },
    pane: 'privacy-screen-recording', where: 'System Settings > Privacy & Security > Screen & System Audio Recording',
  },
  camera: {
    name: { standard: 'Camera', city: 'Lens key' },
    does: { standard: 'Can turn on the camera.', city: 'Opens the lens.' },
    pane: 'privacy-camera', where: 'System Settings > Privacy & Security > Camera',
  },
  microphone: {
    name: { standard: 'Microphone', city: 'Ear key' },
    does: { standard: 'Can listen through the microphone.', city: 'Hears the room.' },
    pane: 'privacy-microphone', where: 'System Settings > Privacy & Security > Microphone',
  },
  'full-disk': {
    name: { standard: 'Full Disk Access', city: 'Vault key' },
    does: { standard: 'Can read every file, mail and messages included.', city: 'Opens every vault.' },
    pane: 'privacy-full-disk', where: 'System Settings > Privacy & Security > Full Disk Access',
  },
  location: {
    name: { standard: 'Location', city: 'Map key' },
    does: { standard: 'Can see where this computer is.', city: 'Puts this block on the map.' },
    pane: 'privacy-location', where: 'System Settings > Privacy & Security > Location Services',
  },
  automation: {
    name: { standard: 'Automation', city: 'Puppet key' },
    does: { standard: 'Can make other apps do things.', city: 'Pulls the strings of other apps.' },
    pane: 'privacy-automation', where: 'System Settings > Privacy & Security > Automation',
  },
  contacts: {
    name: { standard: 'Contacts', city: 'Address key' },
    does: { standard: 'Can read your contacts.', city: 'Reads the address book.' },
    pane: 'privacy-contacts', where: 'System Settings > Privacy & Security > Contacts',
  },
  'screen-time': {
    name: { standard: 'Screen Time', city: 'Curfew key' },
    does: { standard: 'Sets limits on this computer, and who can change them.', city: 'Sets the curfew, and who can change it.' },
    pane: 'screen-time', where: 'System Settings > Screen Time',
  },
  other: {
    name: { standard: 'A powerful permission', city: 'A spare key' },
    does: { standard: 'Lets an app reach past its own window.', city: 'Opens a door it shouldn’t need.' },
    pane: null, where: 'System Settings > Privacy & Security',
  },
};

const SERVICES = {
  kTCCServiceAccessibility: 'accessibility', kTCCServicePostEvent: 'accessibility', kTCCServiceListenEvent: 'keyboard',
  kTCCServiceScreenCapture: 'screen', kTCCServiceCamera: 'camera', kTCCServiceMicrophone: 'microphone',
  kTCCServiceSystemPolicyAllFiles: 'full-disk', kTCCServiceAddressBook: 'contacts', kTCCServiceAppleEvents: 'automation',
  kTCCServiceLocation: 'location',
};

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const str = (v) => (typeof v === 'string' ? v : '');
const moduleOf = (f) => str(f.module) || str(f.code).split('.')[1] || '';

// The keys one finding is about, in order.
export function keysOf(finding) {
  const f = obj(finding);
  const d = obj(f.data);
  const code = str(f.code);
  const mod = moduleOf(f);
  const svc = SERVICES[str(d.service)];
  if (svc) return [{ id: svc, ...KEYS[svc] }];
  const ids = [];
  if (/camera_microphone_combo$/.test(code)) ids.push('camera', 'microphone');
  else if (/screen_accessibility_combo$/.test(code)) ids.push('screen', 'accessibility');
  else if (mod === 'keylogger_indicators' || /input_monitoring/.test(code)) ids.push('keyboard');
  else if (/accessibility/.test(code) || mod === 'accessibility_permissions') ids.push('accessibility');
  else if (/full_disk/.test(code)) ids.push('full-disk');
  else if (/screen_recording/.test(code)) ids.push('screen');
  else if (/camera/.test(code)) ids.push('camera');
  else if (/microphone/.test(code)) ids.push('microphone');
  else if (/contacts/.test(code)) ids.push('contacts');
  else if (/automation|apple_events/.test(code)) ids.push('automation');
  else if (mod === 'location_services' || /location/.test(code)) ids.push('location');
  else if (/screen_time/.test(mod) || /screen_time/.test(code)) ids.push('screen-time');
  else ids.push('other');
  return ids.map((id) => ({ id, ...KEYS[id] }));
}

const findingsOf = (item) => {
  const it = obj(item);
  const list = Array.isArray(it.findings) && it.findings.length ? it.findings : [it.finding];
  return list.filter((f) => f && typeof f === 'object');
};

// R4: groupMissions hands over one item per app: { app: { subject, name },
// keys: [{ permission, finding }], findings } — every permission finding that
// lists the app. The game then decides and draws for that app alone.
const appOfItem = (item) => {
  const a = obj(obj(item).app);
  return str(a.subject) ? { subject: str(a.subject), name: str(a.name) } : null;
};
const keyFindings = (item) => {
  const ks = Array.isArray(obj(item).keys) ? obj(item).keys : [];
  const fs = ks.map((k) => obj(k).finding).filter((f) => f && typeof f === 'object');
  return fs.length ? fs : findingsOf(item);
};

// The item's keys, without repeats. A per-key item (perKey) has just its own key.
function itemKeys(item) {
  const seen = new Map();
  for (const f of keyFindings(item)) for (const k of keysOf(f)) if (!seen.has(k.id)) seen.set(k.id, k);
  const one = str(obj(item).keyId);
  return one && seen.has(one) ? [seen.get(one)] : [...seen.values()];
}

/*
 * perKey(items) -> items: one item per key (audit P2-9). An app item holding several keys becomes one item per
 * key, each with only the findings that grant that key, so Keep / Hand back decides one key at a time and opens
 * that key's own page. The app's other keys ride along as `otherKeys` (shown, decided on their own items).
 * Warnings and holds stay as the app's (never fewer warnings than the app had). An item with one key is unchanged.
 * The grouping calls this after its per-app step (R4), as it calls the notes game's batchNotes.
 */
export function perKey(items) {
  const out = [];
  for (const item of Array.isArray(items) ? items : []) {
    const keys = itemKeys(item);
    if (keys.length <= 1 || str(obj(item).keyId)) { out.push(item); continue; }
    const all = keyFindings(item);
    for (const k of keys) {
      const fs = all.filter((f) => keysOf(f).some((x) => x.id === k.id));
      const lead = fs.find((f) => isMonitoringModule(moduleOf(f))) || fs.find((f) => f === item.finding) || fs[0];
      const seen = [...new Set(fs.map((f) => moduleOf(f)).filter(Boolean))];
      out.push({
        ...item, key: `${item.key}|key:${k.id}`, keyId: k.id, otherKeys: keys.filter((x) => x.id !== k.id).map((x) => x.id),
        finding: lead, findings: fs, seen_in: seen.length ? seen : item.seen_in,
        ...(Array.isArray(item.keys) ? { keys: item.keys.filter((x) => fs.includes(obj(x).finding)) } : {}),
      });
    }
  }
  return out;
}

// A full path ("/…", "~/…", "C:\…"): something whose file attribution checked. A bundle id or process name is not.
const isPath = (s) => typeof s === 'string' && (/^[/~]/.test(s) || /^[A-Za-z]:[\\/]/.test(s));
const baseName = (p) => {
  const parts = String(p).split(/[\\/]/).filter(Boolean);
  const last = parts.length ? parts[parts.length - 1] : String(p);
  return last.replace(/\.app$/i, '') || last;
};

// The apps (and running programs) the item names, each with the keys it holds and its maker.
// A per-app item (R4) names only its own app.
export function appsOf(item) {
  const all = appsIn(item);
  const one = appOfItem(item);
  if (!one) return all;
  const hit = all.filter((a) => a.subject === one.subject);
  if (hit.length) return hit;
  return [{ subject: one.subject, kind: isPath(one.subject) ? 'path' : 'id', name: isPath(one.subject) ? baseName(one.subject) : (one.name || one.subject),
    maker: '', confirmed: false, what: '', keys: itemKeys(item) }];
}

function appsIn(item) {
  const out = new Map();
  for (const f of keyFindings(item)) {
    const d = obj(f.data);
    const entries = [];
    for (const a of Array.isArray(d.apps) ? d.apps : []) {
      if (typeof a === 'string' && a) entries.push({ subject: a, label: '', kind: isPath(a) ? 'path' : 'id' });
      else if (a && typeof a === 'object') {
        const p = str(a.path);
        const id = str(a.bundle_id) || str(a.id);
        const subject = p || id || str(a.name);
        if (subject) entries.push({ subject, label: str(a.name), kind: p && isPath(p) ? 'path' : 'id' });
      }
    }
    for (const p of Array.isArray(d.processes) ? d.processes : []) if (typeof p === 'string' && p) entries.push({ subject: p, label: '', kind: 'process' });
    if (!entries.length && str(d.bundle_id)) entries.push({ subject: d.bundle_id, label: '', kind: 'id' });
    const keys = keysOf(f);
    const makers = Array.isArray(f.made_by) ? f.made_by.filter((m) => m && typeof m === 'object') : [];
    for (const e of entries) {
      let app = out.get(e.subject);
      if (!app) {
        const m = makers.find((x) => x.subject === e.subject);
        const confirmed = e.kind === 'path' && !!m && m.verified === true && str(m.name).trim() !== '';
        app = {
          subject: e.subject, kind: e.kind,
          name: e.kind === 'path' ? baseName(e.subject) : (e.label || e.subject),
          maker: confirmed ? str(m.name) : '', confirmed,
          what: confirmed ? str(m.what) : '',
          keys: [],
        };
        out.set(e.subject, app);
      }
      for (const k of keys) if (!app.keys.some((x) => x.id === k.id)) app.keys.push(k);
    }
  }
  return [...out.values()];
}

const isMonitoring = (item) => findingsOf(item).some((f) => isMonitoringModule(moduleOf(f)));
// The runner shows the removal warning for these itself.
const runnerWarns = (item) => isAlertingItem(item);
const unconfirmed = (apps) => apps.some((a) => !a.confirmed);
// The game's own warning line, where the runner won't show one: monitoring checks and keyboard access by an app
// whose maker isn't confirmed (keyboard access with no app named counts as unconfirmed).
function gameWarns(item) {
  if (runnerWarns(item)) return false;
  const it = obj(item);
  if (it.held || isMonitoring(item)) return true;
  const apps = appsOf(item);
  return itemKeys(item).some((k) => k.id === 'keyboard') && (!apps.length || unconfirmed(apps));
}

function unfinished(item) {
  const it = obj(item);
  if (it.unfinished === true || it.complete === false) return true;
  return findingsOf(item).some((f) => f.complete === false || obj(f.data).incomplete === true);
}

const words = (ctx) => (obj(ctx).mode === 'city' ? 'city' : 'standard');
const isWin = (ctx) => obj(ctx).platform === 'win32';

// Where a key's switch is, as a settings link intent (null when the allowlist has no pane for it).
function paneIntent(key, ctx) {
  if (isWin(ctx)) return { kind: 'settings', pane: 'windows-privacy', permission: key.id };
  return key.pane ? { kind: 'settings', pane: key.pane } : null;
}

function checklist(ctx) {
  return words(ctx) === 'city'
    ? ['Do you remember bringing this one in?', 'Does it need this key for its job?', 'Search its tag on another device.']
    : ['Do you remember installing it?', 'Does it need this access for what you use it for?', 'Search its app id to see what it is.'];
}

export function decisions(item, ctx) {
  const f = obj(obj(item).finding);
  const keys = itemKeys(item);
  const first = keys[0] || { id: 'other', ...KEYS.other };
  const apps = appsOf(item);
  // A mark covers a whole finding, so a per-app item marks only when each of
  // its findings lists this app alone; otherwise Keep is remembered by the runner.
  const one = appOfItem(item);
  const alone = !one || keyFindings(item).every((x) => appsIn({ findings: [x] }).length <= 1);
  const out = [{
    id: 'keep',
    label: { standard: 'Keep', city: 'Keep the key' },
    effect: alone && f.markable && typeof f.markable === 'object' ? { kind: 'mark' } : { kind: 'keep' },
  }];
  const pane = paneIntent(first, ctx);
  const warn = runnerWarns(item) || gameWarns(item);
  const m = words(ctx);
  const who = one ? (apps[0] && apps[0].name) || one.subject : '';
  // An app holding more than one key: the first key's page opens, and the steps name the others.
  const also = keys.slice(1).map((k) => (m === 'city' ? `Also hand back ${k.name.city}${who ? ` from ${who}` : ''} in ${isWin(ctx) ? 'Settings' : k.where}.`
    : `Also switch off ${k.name.standard}${who ? ` for ${who}` : ''} in ${isWin(ctx) ? 'Settings > Privacy' : k.where}.`));
  out.push({
    id: 'hand_back',
    label: { standard: 'Hand back', city: 'Hand it back' },
    effect: pane
      ? { ...pane, key: first.id, ...(also.length ? { steps: also } : {}), ...(warn ? { warning: true } : {}) }
      : { kind: 'closer', key: first.id, steps: [`Open ${first.where}.`, `Switch it off there${who ? ` for ${who}` : ''}.`, ...also], ...(warn ? { warning: true } : {}) },
  });
  const closer = { id: 'closer', label: { standard: 'Look closer', city: 'Look closer' }, effect: { kind: 'closer', checklist: checklist(ctx) } };
  // The first decision is the default. Keep leads only on a note (info); on a critical or warning key (or one that
  // can alert whoever set it up) Look closer leads and Keep comes after it.
  const sev = obj(item).severity || f.severity;
  if (sev === 'critical' || sev === 'warning' || warn) return [closer, out[0], out[1]];
  if ((apps.length && unconfirmed(apps)) || (isMonitoring(item) && !apps.length)) out.push(closer);
  return out;
}

export function research(item, ctx) {
  const c = obj(ctx);
  const m = words(ctx);
  // Evidence for every finding on the app's item (the lead's first), not only the lead's.
  const lead = obj(obj(item).finding);
  const rowsOf = (f) => {
    let r = [];
    try { r = typeof c.evidenceRows === 'function' ? c.evidenceRows(f, { mode: m }) || [] : []; } catch (_) { r = []; }
    return Array.isArray(r) ? r : [];
  };
  const all = [lead, ...findingsOf(item).filter((f) => f !== lead)].filter((f) => Object.keys(f).length);
  const parts = all.map(rowsOf);
  let rows = parts[0] || [];
  if (parts.length > 1) {
    const seen = new Set();
    rows = parts.flat().filter((r) => { const k = JSON.stringify([r && r.label, r && r.value]); if (seen.has(k)) return false; seen.add(k); return true; });
    if (parts.some((p) => p.held)) Object.defineProperty(rows, 'held', { value: true, enumerable: false });
  }
  const keys = itemKeys(item);
  const apps = appsOf(item);
  const links = [];
  const panes = new Set();
  for (const k of keys) {
    const p = paneIntent(k, ctx);
    const id = p ? `${p.pane}|${p.permission || ''}` : '';
    if (p && !panes.has(id)) { panes.add(id); links.push(p); }
  }
  for (const a of apps.filter((x) => !x.confirmed).slice(0, 3)) {
    if (a.kind === 'id') links.push({ kind: 'lookup', source: isWin(ctx) ? 'microsoft-support' : 'apple-support', query: a.subject });
    else links.push({ kind: 'lookup', source: 'web', query: a.name });
  }
  links.push({ kind: 'lesson', concept: 'who-made-it' });
  const known = apps.filter((a) => a.confirmed && a.what).map((a) => a.what);
  let what;
  if (known.length) what = known.join(' ');
  else if (apps.length) what = m === 'city' ? 'Maker unconfirmed.' : 'Maker not confirmed.';
  else what = (keys[0] || KEYS.other).does[m];
  return { rows, what, links, keys: keys.map((k) => k.id), unfinished: unfinished(item), checklist: checklist(ctx),
    ...(m === 'city' && isMonitoring(item) ? { copy: false } : {}) };
}

const MAX_APPS = 8;

function makerLine(app, m, esc) {
  if (app.confirmed) {
    return `<span class="kr-maker kr-ok">${m === 'city' ? 'Maker checks out: ' : 'Made by '}${esc(app.maker)}${m === 'city' ? '' : ' · confirmed'}</span>`;
  }
  const base = m === 'city' ? 'Maker unconfirmed' : 'Maker not confirmed';
  const why = app.kind === 'id' ? (m === 'city' ? ' · known only by its tag' : ' · known only by its app id')
    : app.kind === 'process' ? (m === 'city' ? ' · a running crew' : ' · a running program') : '';
  return `<span class="kr-maker kr-unk">${base}${why}</span>`;
}

function chip(key, m, esc, on) {
  return `<span class="kr-chip${on ? ' kr-chip-this' : ''}" data-key="${esc(key.id)}">${esc(key.name[m])}</span>`;
}

export function render(view, ctx) {
  const v = obj(view);
  const c = obj(ctx);
  const m = words(ctx);
  const esc = typeof c.esc === 'function' ? c.esc : (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (x) => `&#${x.charCodeAt(0)};`);
  const item = obj(v.item);
  const parts = [];
  parts.push('<article class="kr-card" data-game="keyring">');
  if (m === 'city' && item.held) {
    // Never expected: held items stay in the help district. Nothing about the item is shown here.
    parts.push('<p class="kr-held">This key is with the help district.</p></article>');
    return parts.join('');
  }
  const keys = itemKeys(item);
  const ids = new Set(keys.map((k) => k.id));
  const apps = appsOf(item);
  const lead = keys[0] || { id: 'other', ...KEYS.other };
  parts.push('<header class="kr-head">');
  parts.push(`<span class="kr-kicker">${m === 'city' ? 'A key on the ring' : 'Powerful access'}</span>`);
  parts.push(`<h3 class="kr-key-title"><span class="kr-key-icon" aria-hidden="true"></span>${keys.map((k) => esc(k.name[m])).join(' + ')}</h3>`);
  parts.push(`<p class="kr-does">${keys.map((k) => esc(k.does[m])).join(' ')}</p>`);
  parts.push('</header>');
  if (unfinished(item)) {
    parts.push(`<p class="kr-unfinished">${m === 'city' ? 'This check didn’t finish, so the ring may hold more keys.' : 'This check didn’t finish, so more apps may hold this access.'}</p>`);
  }
  if (gameWarns(item)) {
    parts.push(m === 'city'
      ? '<p class="kr-warn" role="note">Handing back this key can tip off whoever cut it. If that worries you, stop by the help district first.</p>'
      : '<p class="kr-warn" role="note">Turning this off can alert whoever set it up. If someone else may have set it up, read the safety note first.</p>');
  }
  if (apps.length) {
    parts.push(`<ul class="kr-ring" aria-label="${m === 'city' ? 'Who holds this key' : 'Apps holding this access'}">`);
    for (const a of apps.slice(0, MAX_APPS)) {
      parts.push('<li class="kr-app">');
      parts.push(`<div class="kr-app-top"><span class="kr-app-name">${esc(a.name)}</span>${makerLine(a, m, esc)}</div>`);
      if (a.kind === 'path' || a.name !== a.subject) parts.push(`<code class="kr-app-id">${esc(a.subject)}</code>`);
      if (a.what) parts.push(`<p class="kr-app-what">${esc(a.what)}</p>`);
      parts.push(`<div class="kr-chips">${a.keys.map((k) => chip(k, m, esc, ids.has(k.id))).join('')}</div>`);
      const others = (Array.isArray(item.otherKeys) ? item.otherKeys : []).filter((id) => KEYS[id] && !a.keys.some((k) => k.id === id));
      if (others.length) {
        parts.push(`<p class="kr-also">Also holds ${others.map((id) => esc(KEYS[id].name[m])).join(', ')}. ${m === 'city' ? 'Each key is its own move.' : 'You decide each one on its own.'}</p>`);
      }
      parts.push('</li>');
    }
    parts.push('</ul>');
    if (apps.length > MAX_APPS) {
      parts.push(`<p class="kr-more">and ${apps.length - MAX_APPS} more ${m === 'city' ? 'on the ring' : `in ${esc(isWin(ctx) ? 'Settings' : 'System Settings')}`}</p>`);
    }
  } else if (lead.id !== 'location' && lead.id !== 'screen-time' && lead.id !== 'other') {
    const n = findingsOf(item).map((f) => obj(f.data).count).find((x) => Number.isInteger(x) && x > 0);
    const many = n ? `${n} apps hold this key.` : 'Several apps hold this key.';
    parts.push(`<p class="kr-count">${esc(many)} ${m === 'city' ? 'The full ring is in the switch room.' : `The full list is in ${esc(isWin(ctx) ? 'Settings' : lead.where)}.`}</p>`);
  }
  const step = obj(v.step);
  if (step.say && typeof step.say[m] === 'string') parts.push(`<p class="kr-step">${esc(step.say[m])}</p>`);
  parts.push('</article>');
  return parts.join('');
}

export function summary(results, ctx) {
  const m = words(ctx);
  const n = { kept: 0, back: 0, closer: 0 };
  for (const r of Array.isArray(results) ? results : []) {
    const d = r && (typeof r.decision === 'string' ? r.decision : obj(r.decision).id);
    if (d === 'keep') n.kept += 1;
    else if (d === 'hand_back') n.back += 1;
    else if (d === 'closer') n.closer += 1;
  }
  if (!n.kept && !n.back && !n.closer) {
    return `<div class="kr-summary"><p>${m === 'city' ? 'No keys sorted on this ring yet.' : 'No keys decided in this mission yet.'}</p></div>`;
  }
  const li = m === 'city'
    ? [`Keys kept ${n.kept}`, `Keys handed back ${n.back}`, `Left to look closer at ${n.closer}`]
    : [`Kept ${n.kept}`, `Handed back ${n.back}`, `Left to look closer at ${n.closer}`];
  const tail = m === 'city'
    ? (n.back ? 'The ring is lighter. A key you hand back stays off until you switch it on again.' : 'Every key you kept is one you chose.')
    : 'A key you hand back stays off until you switch it on again. This is what the scan could see, so it can’t rule everything out.';
  return `<div class="kr-summary"><ul>${li.map((x) => `<li>${x}</li>`).join('')}</ul><p>${tail}</p></div>`;
}

// Practice: made-up apps only.
const P = (key, finding) => ({
  key, severity: 'warning', finding: { severity: 'warning', category: 'security', ...finding }, findings: [{ severity: 'warning', category: 'security', ...finding }],
  seen_in: [finding.module], marked: false, held: false, removal_alert: false, practice: true,
});

export const practice = {
  items: [
    P('practice:keyring:recorder', {
      module: 'privacy_permissions_audit', code: 'security.privacy_permissions_audit.screen_recording_access', title: 'Frame Grabber',
      data: { service: 'kTCCServiceScreenCapture', apps: ['/Applications/Frame Grabber.app'] },
      made_by: [{ subject: '/Applications/Frame Grabber.app', name: 'Example Studio Ltd', verified: true, how: 'Developer ID signature', what: 'Frame Grabber: a screen recorder you installed.' }],
    }),
    P('practice:keyring:game', {
      module: 'accessibility_permissions', code: 'security.accessibility_permissions.suspicious_accessibility', title: 'Puzzle Pop',
      data: { check: 'suspicious_accessibility', apps: [{ path: '/Applications/Puzzle Pop.app', name: 'Puzzle Pop' }] },
      made_by: [{ subject: '/Applications/Puzzle Pop.app', name: 'Example Games Ltd', verified: true, how: 'Developer ID signature', what: 'Puzzle Pop: a puzzle game.' }],
    }),
    P('practice:keyring:keyboard', {
      module: 'keylogger_indicators', code: 'security.keylogger_indicators.suspicious_input_monitoring', title: 'Key remapper',
      data: { check: 'suspicious_input_monitoring', apps: ['com.example.keyremap'] },
    }),
  ],
  // Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict and its clue. No `expect`:
  // an explanation (one GOT IT). `expect` may list several moves that all fit (the first is the best).
  script: [
    { item: 0, say: { standard: 'Each app shows the keys it holds and who made it. Ask two things: is the maker confirmed, and does the app need this key for its job?', city: 'Each holder shows its keys and its maker. Ask two things: does the maker check out, and does it need this key for its job?' } },
    { item: 0, expect: ['keep', 'closer'],
      say: { standard: 'Frame Grabber holds the Screen Recording key. What would you do?', city: 'Frame Grabber holds the Window key. What would you do?' },
      why: { standard: 'A screen recorder has to see the screen, and its maker is confirmed. Keep it.', city: 'It records windows for a living, and its maker checks out. Keep the key.' } },
    { item: 1, expect: ['hand_back', 'closer'],
      say: { standard: 'Puzzle Pop holds Accessibility, the key that clicks and types for you. What would you do?', city: 'Puzzle Pop holds the Control key, the one that works every control. What would you do?' },
      why: { standard: 'A puzzle game has no use for that key. Hand it back: the Accessibility page opens, you switch it off there, and you can switch it on again if you ever need it.', city: 'A puzzle game has no use for the Control key. Hand it back: the switch room opens, you flip it off, and you can flip it on again if you need it.' } },
    { item: 2, expect: 'closer',
      say: { standard: 'This keyboard tool can see what you type. Read its maker line. What would you do?', city: 'This tool hears every key you press. Read its maker line. What would you do?' },
      why: { standard: 'It’s known only by its app id, so its maker isn’t confirmed. Look closer before you decide.', city: 'Known only by its tag, so its maker is unconfirmed. Look closer before you choose.' } },
  ],
};

export const covers = [
  { module: 'app_permissions' },
  { module: 'privacy_permissions_audit' },
  { module: 'accessibility_permissions' },
  { module: 'keylogger_indicators' },
  { module: 'screen_time_audit' },
  { module: 'location_services' },
  { module: 'win_cortana_telemetry', codes: ['security.win_cortana_telemetry.location_services'] },
];

export default {
  type: 'keyring',
  title: { standard: 'Apps with powerful access', city: 'The Keyring' },
  concepts: ['who-made-it', 'fix-and-undo'],
  covers,
  decisions,
  research,
  practice,
  render,
  summary,
};
