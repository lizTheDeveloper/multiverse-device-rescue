// The only DOM code in game mode. Renders the city into a shadow root on the
// "city" screen and wires clicks, fixes, marks and re-checks. With Reclaim City
// loaded, the same map also holds the accounts' districts, and the game's own
// screens render here (its app.js is never loaded).
import { findingsToCity } from './findings-to-city.js';
import { loadProgress, saveProgress, reconcile, setStatus, ranOkModules, recheckOutcome } from './progress.js';
import { renderHud } from './views/hud.js';
import { renderMap } from './views/map.js';
import { renderDistrict } from './views/district.js';
import { renderBriefing } from './views/briefing.js';
import { renderOutcome } from './views/outcome.js';
import { districtComplete, renderMilestone } from './views/milestone.js';
import { debriefReply } from './scout-lines.js';
import { esc } from './escape.js';
import { loadRc } from './rc-load.js';
import { routeFor, applyRcAction, fileRc, afterRecorded } from './rc-actions.js';
import { readAnswers, refreshDebriefForm } from './rc-dom.js';
import { verifyMission, disagreement, loadScanConfirmed, saveScanConfirmed, markScanConfirmed, DONE } from './verified-missions.js';
import { focusFor, countConfirmedAndReported, accountDistrictCards, deviceMissionFor } from './one-city.js';
import { renderOneCityMap } from './views/one-city-map.js';
import { renderVerification, renderMilestoneSplit } from './views/verification.js';

// `loadGame` is for tests; the app always loads Reclaim City from app://rescue/rc/.
export function createController({ win, storage, scoutSprite, loadGame = loadRc }) {
  const doc0 = win.document;
  const host = doc0.getElementById('city-host');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><div class="frame" id="frame"></div>';
  const frame = shadow.getElementById('frame');
  const scout = (feeling, size) => scoutSprite(feeling, { size });
  const now = () => new Date().toISOString();

  const s = { doc: null, situation: null, city: null, progress: loadProgress(storage), cameBack: [],
    screen: 'map', districtId: null, missionId: null, outcome: null, outcomeMission: null, lastFix: null, message: '', busy: false,
    trigger: 'i-did-it', recheckModules: [], shown: 0, focusPending: false,
    rc: null, rcState: null, rcRoute: null, rcUi: {}, landing: null, accountsError: false,
    scanConfirmed: loadScanConfirmed(storage), linkNotice: '' };

  loadGame().then((rc) => {
    s.rc = rc;
    s.rcState = rc.loadState(storage);
    if (s.city) render();
  }).catch((err) => {
    console.error('Reclaim City content could not load:', err);
    s.accountsError = true;
    if (s.city) render();
  });

  // `putBack` is a mission the person just asked to have back (Undo, or "Stop
  // treating this as mine"). Its return is expected, so it isn't "came back".
  function rebuild(doc, putBack = null) {
    s.doc = doc;
    s.city = findingsToCity(doc);
    const r = reconcile(s.progress, s.city, ranOkModules(doc), now());
    s.progress = r.progress;
    s.cameBack = r.cameBack.filter((id) => id !== putBack);
    saveProgress(storage, s.progress);
  }

  // The modules whose findings a mark or unmark covered (by mark id), so each
  // gets re-checked: one task is often reported by more than one check.
  function modulesCoveredBy(ids) {
    if (!Array.isArray(ids) || !ids.length || !s.doc || !Array.isArray(s.doc.modules)) return [];
    const want = new Set(ids);
    return s.doc.modules.filter((mod) => mod && Array.isArray(mod.findings) && mod.findings.some((f) => f
      && ((f.markable && want.has(f.markable.id)) || (f.data && want.has(f.data.known_item_id)))))
      .map((mod) => mod.name);
  }
  const mission = (id) => s.city.districts.flatMap((d) => d.missions).find((m) => m.id === id) || null;
  const district = (id) => s.city.districts.find((d) => d.id === id) || null;
  const rcMission = (id) => (s.rc ? s.rc.MISSIONS.find((m) => m.id === id) : null) || null;
  const stepCount = (m) => (m && Array.isArray(m.steps) ? m.steps.length : undefined);

  // Game state changes only through the person's own clicks.
  function setRcState(next) {
    if (!next || next === s.rcState) return;
    s.rcState = next;
    s.rc.saveState(next, storage);
  }

  function rcScreenHtml() {
    const { screen, params } = s.rcRoute;
    const rc = s.rc;
    const st = s.rcState;
    if (screen === 'district') {
      const reaction = s.landing && s.landing.districtId === params.id ? s.landing.reaction : null;
      return rc.renderDistrict(st, params.id, params.tab, { reaction });
    }
    if (screen === 'briefing') {
      const mission = rcMission(params.id);
      const v = mission ? verifyMission(mission.id, s.doc, stepCount(mission)) : null;
      const record = st.missions[params.id];
      const panel = v ? renderVerification({
        mission, verification: v, disagreement: disagreement(record, v),
        canFinish: v.allConfirmed && !(record && DONE.has(record.status)),
        platform: s.doc && s.doc.platform, deviceMissionFor: (mods) => deviceMissionFor(s.city, mods),
      }) : '';
      return panel + rc.renderBriefing(st, params.id, { resetAnyway: s.rcUi.resetAnyway === params.id });
    }
    if (screen === 'debrief') return rc.renderDebrief(st, params.id);
    if (screen === 'milestone') {
      const done = rc.MISSIONS.filter((m) => rc.missionDistrict(m) === params.districtId && st.missions[m.id] && DONE.has(st.missions[m.id].status));
      const confirmedIds = new Set(done.filter((m) => s.scanConfirmed.missions[m.id]
        && (verifyMission(m.id, s.doc, stepCount(m)) || {}).allConfirmed).map((m) => m.id));
      return renderMilestoneSplit({
        confirmed: done.filter((m) => confirmedIds.has(m.id)).map((m) => m.title),
        reported: done.filter((m) => !confirmedIds.has(m.id)).map((m) => m.title),
      }) + rc.renderMilestone(st, params.districtId);
    }
    return '';
  }

  function counts() {
    if (!s.rc) return undefined;
    return countConfirmedAndReported({ rc: s.rc, progress: s.progress, rcState: s.rcState, scanConfirmed: s.scanConfirmed, doc: s.doc });
  }

  function screenHtml() {
    if (s.screen === 'rc' && s.rc && s.rcRoute) return rcScreenHtml();
    if (s.screen === 'milestone' && district(s.districtId)) {
      return renderMilestone({ district: district(s.districtId), progress: s.progress, scout });
    }
    if (s.screen === 'district' && district(s.districtId)) {
      return renderDistrict({ district: district(s.districtId), progress: s.progress, scout });
    }
    // During an Undo re-check the mission was reclaimed, so it isn't in the
    // city: show the checking briefing from the mission we last showed.
    if (s.screen === 'mission' && s.busy && !mission(s.missionId) && s.outcomeMission && s.outcomeMission.id === s.missionId) {
      const m = s.outcomeMission;
      return renderBriefing({ mission: m, status: (s.progress.missions[m.id] || {}).status || 'open', controlsHtml: '',
        scout, busy: true, wantsSafety: win.RescueHost.wantsSafety(m.primary) });
    }
    if (s.screen === 'mission' && mission(s.missionId)) {
      const m = mission(s.missionId);
      const controls = `${win.FixFlow.fixControlsHtml(m.primary, { watched: false })}${win.MarkFlow.markControlsHtml(m.primary)}`;
      return renderBriefing({ mission: m, status: (s.progress.missions[m.id] || {}).status || 'open', controlsHtml: controls,
        scout, busy: s.busy, wantsSafety: win.RescueHost.wantsSafety(m.primary) });
    }
    if (s.screen === 'outcome' && s.outcome) {
      // After a fix the engine can undo, offer Undo here too, but only on the
      // RECLAIMED screen of the mission that fix was for. FixFlow handles the
      // click, because this sits inside a [data-fix-module] card on the frame.
      const lf = s.lastFix;
      const undoHtml = s.outcome === 'reclaimed' && lf && lf.result && lf.result.quarantine_id
        && s.outcomeMission && lf.missionId === s.outcomeMission.id
        ? `<div class="fix-it" data-fix-module="${esc(lf.module)}"><div class="fix-status" data-fix-status>${win.FixFlow.resultHtml(lf.result)}</div></div>`
        : '';
      return renderOutcome({ kind: s.outcome, mission: s.outcomeMission, scout, message: s.message, undoHtml });
    }
    s.screen = 'map';
    if (s.rc || s.accountsError) {
      return renderOneCityMap({ city: s.city, progress: s.progress, scout, cameBack: s.cameBack, focus: focusFor(s.situation),
        accountCards: s.rc ? accountDistrictCards({ rc: s.rc, rcState: s.rcState, doc: s.doc }) : [],
        accountsError: s.accountsError });
    }
    return renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout });
  }

  function render() {
    try {
      frame.innerHTML = renderHud({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', city: s.city, progress: s.progress, counts: counts() })
        + s.linkNotice + screenHtml();
      // No share cards in Device Rescue: they would describe this person's progress.
      frame.querySelectorAll('[data-action="share-card"], #milestone-card-preview').forEach((el) => el.remove());
      const focused = s.screen === 'map' ? frame.querySelector('[data-focus]') : null;
      if (focused && s.focusPending) { focused.scrollIntoView({ block: 'start' }); s.focusPending = false; }
    } catch (err) {
      console.error('City view failed:', err);
      frame.innerHTML = `<p class="say">${esc('The city view hit a problem. Here’s the same thing as a list.')}</p>`;
      win.RescueHost.showList();
    }
  }

  // `trigger` is what asked for the re-check: fix | undo | mark | unmark |
  // i-did-it. `also` lists other modules to re-check (a mark that covered
  // findings in more than one check). The outcome is for this mission only.
  async function recheck(missionId, trigger = 'i-did-it', also = []) {
    const m = mission(missionId) || s.outcomeMission;
    if (!m || s.busy) return;
    const putBack = trigger === 'undo' || trigger === 'unmark';
    const shownAt = s.shown;
    const modules = [m.module, ...also.filter((x, i, a) => x !== m.module && a.indexOf(x) === i)];
    s.trigger = trigger; s.recheckModules = modules.slice(1);
    s.busy = true; s.screen = 'mission'; s.missionId = m.id; render();
    let res = null;
    for (const name of modules) {
      let r;
      try { r = await win.rescue.recheckModule(name); } catch (_) { r = null; }
      if (name === m.module) res = r;
      if (r && r.ok) {
        if (!win.RescueHost.docChanged(r.doc)) { s.busy = false; return; } // the gate closed: app.js showed the list
        rebuild(r.doc, putBack ? m.id : null);
      }
    }
    s.busy = false;
    // The city was shown afresh while this ran (LIST, then back): keep the new
    // scan's data, but don't take the person away from where they are now.
    if (s.shown !== shownAt) { render(); return; }
    const outcome = recheckOutcome(m.id, s.city, res);
    s.outcome = putBack && outcome === 'not-yet' ? 'put-back' : outcome;
    s.outcomeMission = mission(m.id) || m;
    s.message = res && !res.ok ? res.message || '' : '';
    s.screen = 'outcome';
    render();
  }

  frame.addEventListener('click', (e) => {
    const el = e.target.closest('[data-go],[data-act]');
    if (!el) return;
    const go = el.getAttribute('data-go');
    const act = el.getAttribute('data-act');
    // Always a way back to the list, even while a re-check runs.
    if (act === 'list') { win.RescueHost.showList(); return; }
    if (s.busy) return;
    if (go) s.linkNotice = '';
    if (go && go.startsWith('rc:')) { if (s.rc) goRc(go.slice(3)); return; }
    if (act === 'confirm-from-scan') { if (s.rc) confirmFromScan(); return; }
    if (go === 'map') { s.screen = 'map'; render(); return; }
    if (go && go.startsWith('district:')) { s.screen = 'district'; s.districtId = go.slice(9); render(); return; }
    if (go && go.startsWith('milestone:')) { s.screen = 'milestone'; s.districtId = go.slice(10); render(); return; }
    if (go && go.startsWith('mission:')) { s.screen = 'mission'; s.missionId = go.slice(8); render(); return; }
    if (act === 'i-did-it') { recheck(s.missionId, 'i-did-it'); return; }
    if (act === 'recheck') { recheck(s.outcomeMission && s.outcomeMission.id, s.trigger, s.recheckModules); return; }
    if (act === 'later') {
      const m = mission(s.missionId);
      if (m) {
        s.progress = setStatus(s.progress, m.id, 'later', m.module, now(), { districtId: m.districtId, title: m.title });
        saveProgress(storage, s.progress); s.screen = 'district'; s.districtId = m.districtId;
      }
      render(); return;
    }
    if (act && act.startsWith('debrief:')) {
      const choices = frame.querySelector('.choices');
      const d = district(s.outcomeMission.districtId);
      const next = d && districtComplete(d, s.progress)
        ? `<button type="button" class="btn-p" data-go="milestone:${esc(d.id)}">SEE ${esc(d.name.toUpperCase())}</button>`
        : `<button type="button" class="btn-s" data-go="district:${esc(s.outcomeMission.districtId)}">BACK TO THE DISTRICT</button>`;
      if (choices) choices.outerHTML = `<p class="say">${esc(debriefReply(act.slice(8)))}</p>${next}`;
    }
  });

  // A route the game screens can draw: one of the four screens, for a district
  // or mission that exists. Anything else is the one-city map.
  function knownRoute(r) {
    const rc = s.rc;
    if (r.screen === 'district') return rc.DISTRICTS.some((d) => d.id === r.params.id);
    if (r.screen === 'milestone') return rc.DISTRICTS.some((d) => d.id === r.params.districtId);
    if (r.screen === 'briefing' || r.screen === 'debrief') return !!rcMission(r.params.id);
    return false;
  }

  // Game navigation never touches the page's real location.hash.
  function goRc(hash, draw = true) {
    const r = routeFor(hash, s.rc.parseRoute);
    s.linkNotice = '';
    if (!knownRoute(r)) { s.screen = 'map'; s.rcRoute = null; s.landing = null; if (draw) render(); return; }
    s.rc.newScreenVisit();
    s.screen = 'rc';
    s.rcRoute = r;
    if (r.screen !== 'district') s.landing = null;
    if (draw) render();
  }

  const refusedNotice = (url) => `<p class="link-notice" role="status">${esc('This link can’t be opened from here. You can copy it:')} <code>${esc(url)}</code></p>`;

  // Links open only through main's allowlist, in the person's browser.
  async function openLink(url) {
    let ok = false;
    try { ok = await win.rescue.openMissionLink(url); } catch (_) { ok = false; }
    if (!ok) { s.linkNotice = refusedNotice(url); render(); }
  }

  // `refused` is a link the game data gave that isn't https, so nothing opens.
  function applyResult(r, refused = '') {
    if (!r || r.incomplete) return; // an unfinished form stays as the person left it
    setRcState(r.state);
    // The first-2FA hug plays on the screen they land on, so it counts as seen.
    if (r.reaction && r.reaction.reaction && r.reaction.reaction.feeling === 'hug') setRcState(s.rc.markTwoFactorHugSeen(s.rcState));
    if (r.ui) s.rcUi = { ...s.rcUi, ...r.ui };
    if (r.reaction) s.landing = r.reaction;
    if (r.route) goRc(r.route, false);
    if (refused) s.linkNotice = refusedNotice(refused);
    render();
    if (r.open) openLink(r.open);
  }

  function onRcAction(el) {
    const action = el.getAttribute('data-action') || '';
    const data = { ...el.dataset };
    if (action === 'mission-step') data.href = el.getAttribute('href');
    if (action === 'add-custom-account') data.name = (frame.querySelector('#custom-account-input') || {}).value;
    if (action.startsWith('pm-cat-')) data.raw = (frame.querySelector(`#pm-cat-num-${data.district}`) || {}).value;
    if (action === 'submit-debrief') {
      const mission = rcMission(data.mission);
      applyResult(mission ? fileRc(s.rc, s.rcState, mission.id, readAnswers(frame, mission)) : { state: s.rcState, route: '#/city' });
      return;
    }
    const r = applyRcAction(s.rc, s.rcState, action, data);
    const link = action === 'mission-step' ? data.href : action === 'go-do-it' ? data.url : '';
    applyResult(r, link && link !== '#' && !r.open ? link : '');
  }

  // "Finish from the checkup": only when the scan confirms every step, and only
  // on the person's click. Filed with the mission's own "Done" answer; the
  // scan's part is kept apart, so it counts as confirmed only while it holds.
  function confirmFromScan() {
    const id = s.screen === 'rc' && s.rcRoute && s.rcRoute.screen === 'briefing' ? s.rcRoute.params.id : null;
    const mission = rcMission(id);
    const v = mission && verifyMission(id, s.doc, stepCount(mission));
    if (!v || !v.allConfirmed) { render(); return; }
    const record = s.rcState.missions[id];
    if (record && DONE.has(record.status)) { render(); return; }
    const q = mission.debriefQs.find((x) => (x.options || []).some((o) => o.value === 'completed'));
    const filed = q ? s.rc.fileDebrief(s.rcState, mission, { [q.id]: 'completed' }) : null;
    if (!filed) {
      s.linkNotice = `<p class="link-notice" role="status">${esc('This one has a few questions only you can answer. Use I DID IT below.')}</p>`;
      render(); return;
    }
    s.scanConfirmed = markScanConfirmed(s.scanConfirmed, id, now());
    saveScanConfirmed(storage, s.scanConfirmed);
    applyResult(afterRecorded(s.rc, s.rc.ensureBurst(s.rc.streakAfterFiling(filed.state, filed.event)), mission));
  }

  // The game screens' own clicks (data-action) and links. Plan A's handler above
  // only reads data-go and data-act, so the two never act on the same click.
  frame.addEventListener('click', (e) => {
    if (!s.rc || s.busy) return;
    const actEl = e.target.closest('[data-action]');
    if (actEl && frame.contains(actEl)) { e.preventDefault(); onRcAction(actEl); return; }
    const a = e.target.closest('a[href]');
    if (!a || !frame.contains(a)) return;
    const href = a.getAttribute('href') || '';
    if (href.startsWith('#')) { e.preventDefault(); goRc(href); return; }
    if (/^[a-z][a-z0-9+.-]*:/i.test(href)) { e.preventDefault(); openLink(href); }
  });
  frame.addEventListener('keydown', (e) => {
    if (!s.rc) return;
    // Enter in a per-category number box files it, like its button.
    const id = e.target && e.target.id;
    if (e.key === 'Enter' && typeof id === 'string' && id.startsWith('pm-cat-num-')) {
      const box = e.target.closest('[data-pm-category]');
      const btn = box && box.querySelector('[data-action="pm-cat-flag"], [data-action="pm-cat-changed"]');
      if (btn) { e.preventDefault(); btn.click(); }
      return;
    }
    const el = s.rc.keyActivationTarget(e);
    if (el && frame.contains(el)) { e.preventDefault(); el.click(); }
  });
  // On the shadow root, so e.target is the real input (not retargeted to the host).
  shadow.addEventListener('change', (e) => { if (s.rc) refreshDebriefForm(e, s.rc); });
  shadow.addEventListener('input', (e) => { if (s.rc) refreshDebriefForm(e, s.rc); });

  // Device Rescue's own fix and mark flows, delegated on the frame so they survive re-renders.
  win.FixFlow.attach(frame, win.rescue, { onResult: ({ kind, module, result, described }) => {
    if (kind === 'fix') s.lastFix = { missionId: s.missionId, module, result };
    if (kind === 'undo' && described && described.restored) s.lastFix = null;
    if (described && (described.tone === 'success' || described.tone === 'info' || described.restored)) recheck(s.missionId, kind === 'undo' ? 'undo' : 'fix');
  } });
  win.MarkFlow.attach(frame, win.rescue, { onResult: ({ kind, result, described }) => {
    if (described && described.done) recheck(s.missionId, kind === 'removed' ? 'unmark' : 'mark', modulesCoveredBy(result && result.ids));
  } });

  return {
    isReady: true,
    show(doc, situation) {
      s.situation = situation;
      s.shown += 1;
      rebuild(doc);
      s.screen = 'map'; s.outcome = null; s.lastFix = null; s.linkNotice = ''; s.rcRoute = null; s.landing = null;
      s.focusPending = true;
      render();
    },
    update(doc) { rebuild(doc); render(); },
  };
}
