// "Your progress" in plain view: the same profile as YOUR FILE, in a dialog
// opened from the results screen, with plain words. Reads the profile fresh
// each time it opens (the game may have written since); writes only through
// PlayerProfile.saveProfile, and tells the game to read it again.
//
// Standard mode only. Plain view is the standard-mode screen, and these words
// ("Your progress", "Your checkups") aren't the city's: in any other mode
// (city mode, or a host that can't say) the dialog doesn't open, and if the
// mode changes while it is open, it closes. The headline count is publish.js's
// lessonsLearned over the same bank the game measures with in standard mode,
// so it matches YOUR FILE and the rank chip.
import { loadLessons } from '../training.js';
import { loadDrills } from '../drills.js';
import { buildBank } from './item-bank.js';
import { loadProfile, saveProfile, profileSeed, summary, emptyProfile } from './player-profile.js';
import { buildPayload, publishOffered, PUBLISH_FIELDS, PUBLISH_READY } from './publish.js';
import { renderProfile, renderPublishSheet, focusProfile } from '../views/profile.js';

const FIELD_IDS = new Set(PUBLISH_FIELDS.map((f) => f.id));

// Specifiers resolve the way the game's own loaders expect: lessons against
// training.js, drills against drills.js.
async function defaultLoadBank() {
  const lessonBase = new URL('../training.js', import.meta.url).href;
  const drillBase = new URL('../drills.js', import.meta.url).href;
  const [lessons, drills] = await Promise.all([
    loadLessons((spec) => import(new URL(spec, lessonBase).href)),
    loadDrills((spec) => import(new URL(spec, drillBase).href)),
  ]);
  return buildBank(lessons, drills);
}

// `publishReady` is a TEST SEAM: the page never passes it (see the auto-attach
// below), so the publish control stays bound to PUBLISH_READY, which is false.
export function attachPlainPanel({ win, storage, loadBank = defaultLoadBank, publishReady = PUBLISH_READY }) {
  const doc = win.document;
  const button = doc.getElementById('btn-your-progress');
  const dialog = doc.getElementById('progress-dialog');
  const body = doc.getElementById('progress-dialog-body');
  if (!button || !dialog || !body) return null;
  // The button's own line on the results screen: hidden with it, so no gap is left.
  const wrap = doc.getElementById('progress-link');
  const now = () => new Date().toISOString();
  // Without the host's answer, assume 'city' (as the game does): nothing opens.
  const mode = () => (win.RescueHost && typeof win.RescueHost.mode === 'function' ? win.RescueHost.mode() : 'city');
  const standard = () => mode() === 'standard';
  const offered = () => publishOffered(mode(), publishReady);
  // A lesson-load failure is never shown as "0 of 0 learned": the dialog says
  // the lessons couldn't be read, and the next open tries again.
  let bankP = null;
  const bank = () => (bankP = bankP || Promise.resolve().then(loadBank).then((b) => ({ b, failed: false }))
    .catch(() => { bankP = null; return { b: buildBank([], []), failed: true }; }));
  const st = { profile: null, bank: null, bankFailed: false, confirming: false, publish: null };

  function draw() {
    const sum = summary(st.profile, st.bank);
    if (!offered()) st.publish = null;
    const sheet = st.publish ? renderPublishSheet({ summary: sum, ticked: st.publish.ticked, theme: 'plain',
      payload: buildPayload(sum, st.publish.ticked, { mode: mode(), now: st.publish.at }) }) : '';
    const page = renderProfile({ summary: sum, theme: 'plain', publish: offered(), confirming: st.confirming, lessonsUnread: st.bankFailed });
    // While the sheet is open, the page behind it is inert: Tab stays in the sheet.
    body.innerHTML = sheet ? `<div inert>${page}</div>${sheet}` : page;
  }
  // Focus after a draw: an element by id, or a control by selector, else the
  // Start over question (data-autofocus) or the heading.
  function focusIn(id, sel) {
    const byId = id ? doc.getElementById(id) : null;
    if (byId && typeof byId.focus === 'function') { byId.focus(); return; }
    const bySel = sel && typeof body.querySelector === 'function' ? body.querySelector(sel) : null;
    if (bySel && typeof bySel.focus === 'function') { bySel.focus(); return; }
    if (focusProfile(body)) return;
    const h = doc.getElementById('profile-title');
    if (h && typeof h.focus === 'function') h.focus();
  }
  function shut() {
    st.profile = null; st.confirming = false; st.publish = null;
    body.innerHTML = '';
    if (dialog.open) dialog.close();
  }

  async function open() {
    if (!standard()) { shut(); return; }
    const got = await bank();
    st.bank = got.b;
    st.bankFailed = got.failed;
    if (!standard()) { shut(); return; }
    st.profile = loadProfile(storage, now());
    st.confirming = false;
    st.publish = null;
    draw();
    if (!dialog.open) dialog.showModal();
    focusIn('profile-title');
  }

  function handOver(kind) {
    if (!st.publish || !offered()) return;
    const text = buildPayload(summary(st.profile, st.bank), st.publish.ticked, { mode: mode(), now: st.publish.at });
    if (!text) return;
    if (kind === 'copy') { Promise.resolve().then(() => win.navigator.clipboard.writeText(text)).catch(() => {}); return; }
    const url = win.URL.createObjectURL(new win.Blob([text], { type: 'application/json' }));
    const a = doc.createElement('a');
    a.href = url;
    a.download = 'school-profile.json';
    a.click();
    win.setTimeout(() => win.URL.revokeObjectURL(url), 0);
  }

  // The button exists only in standard mode; the host says when the mode changes.
  function syncButton() {
    button.hidden = !standard();
    if (wrap) wrap.hidden = button.hidden;
    if (!standard() && (dialog.open || st.profile)) shut();
  }
  syncButton();
  if (typeof win.addEventListener === 'function') win.addEventListener('rescue-mode-changed', syncButton);
  button.addEventListener('click', () => { open(); });
  // Escape: the sheet or the Start over question first, then the dialog.
  dialog.addEventListener('cancel', (e) => {
    if (!st.publish && !st.confirming) return;
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (st.publish) { st.publish = null; draw(); focusIn(null, '[data-act="profile-publish"]'); return; }
    st.confirming = false; draw(); focusIn(null, '[data-act="profile-start-over"]');
  });
  // Closing (the Close button, or Escape) puts focus back where it came from,
  // unless the button is gone (the mode changed): focus never lands on a hidden control.
  dialog.addEventListener('close', () => { if (!button.hidden && typeof button.focus === 'function') button.focus(); });
  body.addEventListener('click', (e) => {
    const el = e.target && typeof e.target.closest === 'function' ? e.target.closest('[data-act]') : null;
    if (!el || !st.profile) return;
    if (!standard()) { shut(); return; }
    const act = el.getAttribute('data-act');
    if (!act) return;
    if (act === 'profile-close') { dialog.close(); return; }
    if (act === 'profile-start-over') { st.confirming = true; st.publish = null; draw(); focusIn(null); return; }
    if (act === 'profile-start-over-no') { st.confirming = false; draw(); focusIn(null, '[data-act="profile-start-over"]'); return; }
    if (act === 'profile-start-over-yes') {
      if (!st.confirming) return;
      st.profile = emptyProfile(now());
      saveProfile(storage, st.profile, { seed: profileSeed(storage, win.DisplayMode), mode: mode() });
      if (win.RescueGame && typeof win.RescueGame.reloadProfile === 'function') win.RescueGame.reloadProfile();
      st.confirming = false;
      draw();
      focusIn('profile-title');
      return;
    }
    if (act === 'profile-publish') { if (offered()) { st.publish = { ticked: [], at: now() }; draw(); focusIn('pub-title'); } return; }
    if (act.startsWith('pub-toggle:')) {
      const id = act.slice(11);
      if (!st.publish || !offered() || !FIELD_IDS.has(id)) return;
      const rest = st.publish.ticked.filter((x) => x !== id);
      st.publish = { ...st.publish, ticked: el.checked ? [...rest, id] : rest };
      draw();
      return;
    }
    if (act === 'publish-close') { st.publish = null; draw(); focusIn(null, '[data-act="profile-publish"]'); return; }
    if (act === 'publish-save') { handOver('file'); return; }
    if (act === 'publish-copy') { handOver('copy'); }
  });
  return { open, syncButton };
}

function safeStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

if (typeof window !== 'undefined' && window.document && window.document.getElementById('btn-your-progress')) {
  attachPlainPanel({ win: window, storage: safeStorage() });
}
