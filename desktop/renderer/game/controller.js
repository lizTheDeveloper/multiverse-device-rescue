// The only DOM code in game mode. Renders the city into a shadow root on the
// "city" screen and wires clicks, fixes, marks and re-checks. With Reclaim City
// loaded, the same map also holds the accounts' districts, and the game's own
// screens render here (its app.js is never loaded).
import { findingsToCity, DISTRICTS } from './findings-to-city.js';
import { splitHeld, heldOnly, briefingNote, heldPanelHtml, HELD_MODULES } from './held.js';
import { reconcile, setStatus, ranOkModules, recheckOutcome, setDeck } from './progress.js';
import { buildBank, drawLessonVisit, drawConcept } from './profile/item-bank.js';
import { loadProfile, saveProfile, profileSeed, toProgress, withProgress, recordAnswer, recordVisit, recordDrillCall, recordGap,
  callConcepts, shouldOffer, noteOffered, declineOffer, historyFor, difficultyOf, teachShown, summary, emptyProfile } from './profile/player-profile.js';
import { conceptById, isHidden } from './profile/skills.js';
import { buildPayload, publishOffered, lessonsLearned, deliver, PUBLISH_READY, PUBLISH_FIELDS } from './profile/publish.js';
import { renderProfile, renderPublishSheet, focusProfile, profileKeyAct } from './views/profile.js';
import { buildSignals, queueOf, cityIntegrity, districtHeat, sortedCount, sweepCounts, heldDistrictIds, mergeSame, severityCounts, foldPartly, notCheckedSummary, notCheckedLine } from './signals.js';
import { award, setTag, recordDrill, recordSweep, confirmFix, reconcileDeck, rankOf, sweepPercent, POINTS, MONITORING_MODULES } from './ledger.js';
import { cluesFor, drillClues, scoutRead, scoutAgrees, drillRead, COULDNT_READ } from './clues.js';
import { loadDrills, chooseDrills, drillSignal, pickDrills } from './drills.js';
import { renderDeck, preSweepCityHtml } from './views/deck.js';
import { renderInstruments } from './views/instruments.js';
import { renderSignalPanel, renderRange } from './views/signal.js';
import { renderHud } from './views/hud.js';
import { renderMap, mapLine } from './views/map.js';
import { renderDistrict, bulkLabel } from './views/district.js';
import { renderBriefing } from './views/briefing.js';
import { renderOutcome } from './views/outcome.js';
import { districtComplete, renderMilestone } from './views/milestone.js';
import { debriefReply } from './scout-lines.js';
import { esc } from './escape.js';
import { loadRc } from './rc-load.js';
import { routeFor, applyRcAction, fileRc } from './rc-actions.js';
import { readAnswers, refreshDebriefForm } from './rc-dom.js';
import { verifyMission, disagreement, loadScanConfirmed, saveScanConfirmed, markScanConfirmed, DONE } from './verified-missions.js';
import { focusFor, countDeckBars, accountDistrictCards, deviceMissionFor } from './one-city.js';
import { renderOneCityMap } from './views/one-city-map.js';
import { renderVerification, renderMilestoneSplit } from './views/verification.js';
import { loadLessons, orderLessons, lessonForModule, afterScanDone, lessonsByDistrict, districtLesson, worryIdsOf } from './training.js';
import { bossInit, bossApply, bossFinish } from './boss.js';
import { renderTraining } from './views/training.js';
import { renderLesson } from './views/lesson.js';
import { renderBoss } from './views/boss.js';
import { pickDistrict, seedFrom } from './district-names.js';
import { SIX_ROSES } from './side-district.js';
import { renderSide, sideTileHtml, heldNoticeHtml, heldText } from './views/side-district.js';

// Specifiers resolve against this file (app://rescue/game/controller.js).
const loadLessonsHere = () => loadLessons((spec) => import(spec));
const idleScan = () => ({ running: false, index: 0, total: 0, error: null });
const TRAINING_SCREENS = new Set(['training', 'lesson', 'boss']);
// Screens drawn without a city, and screens whose redraws keep keyboard focus.
// 'home': the deck before any sweep this session (city mode's landing screen).
// 'profile': YOUR FILE.
const NO_CITY_SCREENS = new Set([...TRAINING_SCREENS, 'range', 'home', 'profile']);
const KEEP_FOCUS = new Set([...TRAINING_SCREENS, 'map', 'range', 'home', 'profile']);
// A re-check whose check stopped before the end proves nothing either way.
export const UNFINISHED_RECHECK = 'That check didn’t finish, so this wasn’t checked to the end.';
const LOG_MAX = 100;
const MOMENTS_MAX = 4;
const TAG_WORD = { mine: 'MINE', threat: 'THREAT', closer: 'LOOK CLOSER', noted: 'NOTED' };
// Specifiers resolve against this file, like the lessons'.
const loadDrillsHere = () => loadDrills((spec) => import(spec));

// Lesson question families that are about someone the person knows (cutting
// off a partner, a housemate, a family member). City mode is the cover, so
// they are never asked there: not drawn, not asked as written, and their
// concept isn't counted as waiting.
export const CITY_SKIPPED_FAMILIES = new Set(['cut-off-order', 'remove-everyone']);
export const CITY_SKIPPED_CONCEPTS = new Set(['cut-off-order']);
const cityShows = (q) => !!q && !CITY_SKIPPED_FAMILIES.has(q.key) && !CITY_SKIPPED_CONCEPTS.has(q.concept);
// The lessons as city mode may show them.
export const cityLessons = (lessons) => (lessons || []).map((l) => (l && Array.isArray(l.questions)
  ? { ...l, questions: l.questions.filter(cityShows) } : l));

// What the person sees when the record couldn't be saved or read: calm, and
// in city mode only the game's own words. Codes are player-profile.js's.
const SAVE_CODES = new Set(['encode', 'too-big', 'spare', 'write']);
const READ_CODES = new Set(['salvaged', 'spare-full']);
export function saveProblemText(code, city) {
  // The whole saved file couldn't be read (a copy is kept aside).
  if (code === 'unreadable') {
    return city ? 'Your saved city couldn’t be read, so the game started from what it could find. A copy was set aside.'
      : 'Your saved progress couldn’t be read, so the game started from what it could find. A copy was set aside.';
  }
  // It couldn't be read, and no copy could be kept.
  if (code === 'unreadable-no-copy') {
    return city ? 'Your saved city couldn’t be read, and a copy couldn’t be kept. The game started from what it could find.'
      : 'Your saved progress couldn’t be read, and a copy couldn’t be kept. The game started from what it could find.';
  }
  // It couldn't be read, and was too big to keep a copy of: said plainly.
  if (code === 'unreadable-too-big') {
    return city ? 'Your saved city couldn’t be read, and it was too big to keep a copy of. The game started from what it could find.'
      : 'Your saved progress couldn’t be read, and it was too big to keep a copy of. The game started from what it could find.';
  }
  if (SAVE_CODES.has(code)) {
    return city ? 'The city couldn’t save your last move. It keeps trying.'
      : 'Your progress couldn’t be saved. It keeps trying.';
  }
  if (READ_CODES.has(code)) {
    return city ? 'Part of your saved city couldn’t be read, so the game picked up from what it could.'
      : 'Part of your saved progress couldn’t be read, so the game picked up from what it could.';
  }
  if (code === 'old-kept') {
    return city ? 'An older save couldn’t be tidied away. The city tries again when it saves.'
      : 'An older copy of your progress couldn’t be tidied away. It tries again when it saves.';
  }
  return city ? 'The city had trouble with its save. Keep playing.' : 'There was a problem with your saved progress. You can keep going.';
}

// The attribute a redraw finds a focused control by again. On the Training
// Grounds, lesson and boss screens each of these is unique on the screen.
const FOCUS_KEYS = ['data-go', 'data-act', 'id'];
export function focusKey(el) {
  if (!el || typeof el.getAttribute !== 'function') return null;
  for (const k of FOCUS_KEYS) {
    const v = el.getAttribute(k);
    if (v) return { k, v: String(v) };
  }
  return null;
}

// The element under `root` whose attribute `k` is exactly `v`, or null. Signal
// ids carry paths, which can hold quotes, backslashes or newlines: a value
// like that goes through CSS.escape when there is one, and otherwise (or if
// the selector still fails) the elements with that attribute are compared one
// by one. It never throws, so a strange path can't knock anyone out of the game.
const PLAIN_VALUE = /^[^"\\\u0000-\u001f\u007f]*$/;
export function findByAttr(root, k, v, css = globalThis.CSS) {
  if (!root || typeof root.querySelector !== 'function' || typeof v !== 'string') return null;
  try {
    if (PLAIN_VALUE.test(v)) return root.querySelector(`[${k}="${v}"]`);
    if (css && typeof css.escape === 'function') {
      const el = root.querySelector(`[${k}="${css.escape(v)}"]`);
      if (el) return el;
    }
  } catch (_) { /* fall through to the walk */ }
  try {
    for (const el of root.querySelectorAll(`[${k}]`)) if (el.getAttribute(k) === v) return el;
  } catch (_) { /* nothing to find */ }
  return null;
}
const focusEl = (el) => { if (el && typeof el.focus === 'function') el.focus(); return !!el; };
// A new screen: keyboard and screen-reader users land on its heading.
export function focusHeading(root) {
  const h = root && typeof root.querySelector === 'function' ? root.querySelector('h2') : null;
  if (!h) return false;
  if (typeof h.setAttribute === 'function' && typeof h.hasAttribute === 'function' && !h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
  return focusEl(h);
}

// `loadGame` and `loadTraining` are for tests; the app always loads Reclaim City
// from app://rescue/rc/ and the lessons from app://rescue/game/lessons/.
// `publishing` is a TEST SEAM too: the app never passes it, so the publish
// control, the consent sheet and the hand-over are all bound to PUBLISH_READY
// (views/profile.js and publish.js's deliver), which is false.
export function createController({ win, storage, scoutSprite, loadGame = loadRc, loadTraining = loadLessonsHere, loadDrillBank = loadDrillsHere,
  publishing = {} }) {
  const pub = { ready: PUBLISH_READY, renderProfile, renderPublishSheet, deliver, ...publishing };
  const doc0 = win.document;
  const host = doc0.getElementById('city-host');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><link rel="stylesheet" href="checklist.css"><link rel="stylesheet" href="game/profile.css"><div class="frame" id="frame"></div>';
  const frame = shadow.getElementById('frame');
  const scout = (feeling, size) => scoutSprite(feeling, { size });
  const now = () => new Date().toISOString();

  // The player profile (profile/player-profile.js) is the record; `progress`
  // is the v3-shaped view of it that progress.js and ledger.js work on.
  // A problem reading or writing it shows on screen once (saveProblemText).
  const noticeFor = (code) => ({ code, kind: SAVE_CODES.has(code) ? 'save' : 'other' });
  let loadNotice = null;
  const profile0 = loadProfile(storage, now(), { onProblem: (code) => { loadNotice = noticeFor(code); } });
  const bank0 = buildBank([], []);
  // Offers are once per sweep; before the first sweep, once per session.
  const sessionStart = now();
  const s = { doc: null, held: [], heldCity: null, situation: null, city: null, profile: profile0, bank: bank0, cityBank: bank0,
    progress: toProgress(profile0, bank0), saveNotice: loadNotice, cameBack: [],
    screen: 'map', districtId: null, missionId: null, outcome: null, outcomeMission: null, lastFix: null, message: '', busy: false,
    trigger: 'i-did-it', recheckModules: [], shown: 0, focusPending: false,
    rc: null, rcState: null, rcRoute: null, rcUi: {}, landing: null, accountsError: false,
    scanConfirmed: loadScanConfirmed(storage), linkNotice: '',
    lessons: [], lessonsLoaded: false, lesson: null, pendingCity: false, tips: [], tipsOpen: false, scan: idleScan(), boss: bossInit(),
    // The command center. The ops log is kept in memory only.
    signal: null, filter: null, lowOpen: false, queueOpen: false, sev: null, sideSeen: false, log: [], moments: [], opened: {}, changedTags: new Set(),
    // This sweep's evidence, memory only: real findings already counted as a
    // call gap, and drills whose first answer was recorded (a re-try after the
    // right answer was shown is practice, not evidence).
    gapped: new Set(), drillEvidence: new Set(),
    drillBank: [], drillsLoaded: false, sweepDrills: null, drillAnswers: {}, range: null, sweptDoc: null,
    // The generated district. Memory only, like the ops log; nothing about it is stored.
    sideTicket: 0, sideNotice: false, heldOpen: false,
    // Opened from city mode's home (showHome): with no sweep yet, the deck is
    // where the person lands and comes back to, never the Training Grounds.
    homeFirst: false };
  const noCity = () => (s.homeFirst ? 'home' : 'training');
  let drawnScreen = null; // the screen the last render drew

  // The generated district (city mode only): help that looks like the rest of the city.
  // The game's home when the app opens in city mode (app.js CITY_SITUATION), not a worry.
  const isCityHome = (situation) => !!situation && situation.id === 'city' && !Array.isArray(situation.ids);
  const inCity = () => !!(win.RescueHost && typeof win.RescueHost.mode === 'function' && win.RescueHost.mode() === 'city');
  // Picked once per session from the install's seed (app.js reads it once with
  // DisplayMode.ensureSeed). A missing or garbled seed gets a random one for
  // this session (seedFrom), never the same district for every such install.
  let sideDistrict = null;
  const side = () => {
    if (sideDistrict) return sideDistrict;
    let raw = null;
    try { raw = win.RescueHost && typeof win.RescueHost.citySeed === 'function' ? win.RescueHost.citySeed() : null; } catch (_) { raw = null; }
    sideDistrict = pickDistrict(seedFrom(raw));
    return sideDistrict;
  };
  // The tile is always there (the cover); the notice says something new is
  // in there, until the person has been this sweep. One pointer, not two.
  const sideTile = () => (inCity() ? sideTileHtml(side(), 0) : '');
  const heldNotice = () => (inCity() && s.held.length && !s.sideSeen ? heldNoticeHtml(side()) : '');

  // loadLessons never rejects: a lesson that fails to load is left out.
  // Until then the Training Grounds says the lessons are on their way, not that they failed.
  new Promise((r) => r(loadTraining())).catch(() => []).then((ls) => {
    s.lessons = Array.isArray(ls) ? ls : [];
    s.lessonsLoaded = true;
    refreshBank();
    if (TRAINING_SCREENS.has(s.screen) || s.screen === 'home') render();
  });

  // The drill bank, the same way: a drill file that fails to load is left out.
  new Promise((r) => r(loadDrillBank())).catch(() => []).then((ds) => {
    s.drillBank = Array.isArray(ds) ? ds : [];
    s.drillsLoaded = true;
    refreshBank();
    if (s.city && s.sweepDrills === null) s.sweepDrills = sweepDrillsNow();
    if (s.screen === 'range' || (s.screen === 'map' && s.city && !s.busy)) render();
  });

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
  // The same text as the list (QuietNotes): in standard mode no hotline paragraphs in
  // missions, notes or clues (the one line keeps any removal warning); city mode is never quieted.
  const quietDoc = (d) => (win.QuietNotes ? win.QuietNotes.quietDoc(d, hostMode()) : d);
  // City mode: the fix and "It's mine" panels carry the extra warning about whoever set something up.
  const watchedOpts = () => ({ watched: hostMode() === 'city' });
  // Without the host's answer, assume 'city': monitoring software is then held
  // (nothing to act on) rather than shown with its removal steps.
  const hostMode = () => (win.RescueHost && typeof win.RescueHost.mode === 'function' ? win.RescueHost.mode() : 'city');

  // The one place the profile is written: a recipe box in every mode. In city
  // mode the old literal store goes once the box is written (player-profile.js).
  // A problem shows on screen; a later save that works clears a save problem.
  function persist() {
    const ok = saveProfile(storage, s.profile, { seed: profileSeed(storage, win.DisplayMode), mode: hostMode(),
      onProblem: (code) => { s.saveNotice = noticeFor(code); } });
    if (ok && s.saveNotice && s.saveNotice.kind === 'save') s.saveNotice = null;
    return ok;
  }
  // The bank the game measures with, and the one city mode draws from.
  // City mode never asks the families about someone the person knows, and the
  // v3 view (which lessons are done) is read without them.
  // Anything but standard mode counts as city mode here: a host that can't
  // say, and a mode not chosen yet (null), hide the families about someone
  // the person knows until it is known they are safe to show.
  const coverMode = () => hostMode() !== 'standard';
  const drawBank = () => (coverMode() ? s.cityBank : s.bank);
  const viewOf = (p) => toProgress(p, drawBank());
  // A v3 view changed by progress.js or ledger.js: folded into the profile,
  // saved, and the view drawn again from the profile.
  function keep(nextProgress) {
    s.profile = withProgress(s.profile, nextProgress);
    persist();
    s.progress = viewOf(s.profile);
  }
  function keepProfile(next) {
    s.profile = next;
    persist();
    s.progress = viewOf(s.profile);
  }
  function refreshBank() {
    s.bank = buildBank(s.lessons, s.drillBank);
    // Every item stays measurable (the same estimates in both modes); only the
    // lesson and concept indexes, which say what is drawn and what a lesson
    // is made of, leave the skipped families out.
    const c = buildBank(cityLessons(s.lessons), s.drillBank);
    s.cityBank = { items: s.bank.items, lessons: c.lessons, concepts: c.concepts };
    s.progress = viewOf(s.profile);
  }
  // A first run moves the old store into the box straight away.
  s.progress = viewOf(s.profile);
  persist();

  function rebuild(doc, putBack = null) {
    const before = s.city ? cityIntegrity(s.city, signalsNow(), s.heldCity) : null;
    const heldBefore = heldDistrictIds(s.heldCity);
    s.doc = doc;
    // Monitoring software never becomes a mission or a signal (held.js).
    const split = splitHeld(doc);
    s.held = split.held;
    // Held findings' own districts, in memory only, so integrity and heat
    // still count them as open while they're never signals, points or stored.
    s.heldCity = findingsToCity(heldOnly(doc));
    // A note saying part of a check couldn't look is counted with the checks
    // that didn't finish, never among the notes (the same rule as the list).
    const folded = foldPartly(split.doc);
    s.city = findingsToCity(quietDoc(folded.doc));
    for (const d of s.city.districts) {
      d.unfinished = (d.unfinished || []).map((x) => (folded.partly.has(x.module) ? { ...x, titles: folded.partly.get(x.module) } : x));
    }
    const ranOk = ranOkModules(doc);
    const r = reconcile(s.progress, s.city, ranOk, now());
    s.cameBack = r.cameBack.filter((id) => id !== putBack);
    // The deck follows the scan too: a changed finding's tag is set aside, a
    // gone one's is dropped, and a confirmed fix that came back no longer counts.
    const rd = reconcileDeck(r.progress.deck, buildSignals(s.city, r.progress.deck), ranOk);
    rd.changed.forEach((id) => s.changedTags.add(id));
    // Held software seen in this sweep (a scan or a re-check) marks it, on disk
    // as a bare flag, so its going later is never paid, even after a restart.
    const carrying = heldDistrictIds(s.heldCity).size > 0;
    keep(setDeck(r.progress, carrying && rd.deck.sweep.carry !== true ? { ...rd.deck, sweep: { ...rd.deck.sweep, carry: true } } : rd.deck));
    // A district that held a monitoring finding is never "secured" by its going:
    // that would reward removing it, and the log line would say where it was.
    const heldNow = heldDistrictIds(s.heldCity);
    if (before) noteSecured(before, cityIntegrity(s.city, signalsNow(), s.heldCity), new Set([...heldBefore, ...heldNow]));
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

  // CONFIRMED is what a re-check (or the checkup, for an account mission)
  // proved; YOU REPORTED is the person's word. The deck and every HUD agree.
  function counts() {
    return countDeckBars({ rc: s.rc, deck: s.progress.deck, rcState: s.rcState, scanConfirmed: s.scanConfirmed, doc: s.doc });
  }

  // "Your checkup is done" and the way to the city: when a scan finished while
  // in a lesson, or when this worry's scan has finished and the person came back
  // to the Training Grounds (the HUD's TRAINING, or a briefing's lesson link).
  const cityWaiting = () => s.pendingCity || (!!s.city && !s.scan.running && !s.scan.error);
  const learnFor = () => {
    const by = lessonsByDistrict(s.lessons, worryIdsOf(s.situation));
    return (id) => districtLesson(by, s.progress, id);
  };

  // Review rotation: least recently reviewed first, ties in lesson order.
  // In memory only; nothing about it is saved.
  const reviewedAt = new Map();
  let reviewTick = 0;
  const nextReview = (list) => {
    let pick = list[0];
    for (const l of list) if ((reviewedAt.get(l.id) || 0) < (reviewedAt.get(pick.id) || 0)) pick = l;
    reviewTick += 1;
    reviewedAt.set(pick.id, reviewTick);
    return pick;
  };

  // Lessons show before any scan, so the platform falls back to what preload says.
  const platform = () => (s.doc && s.doc.platform) || (win.rescue && win.rescue.platform) || null;
  const settingFor = (key) => (win.SettingPanes ? win.SettingPanes.lessonSetting(key, platform()) : null);
  // "Open your router's settings": the router address from the scan, or null (no scan,
  // no private address). Blocked when the ARP check says the router may be impersonated.
  let browserName = null;
  if (win.rescue && win.rescue.defaultBrowser) {
    Promise.resolve().then(() => win.rescue.defaultBrowser()).then((n) => { browserName = n || null; }).catch(() => {});
  }
  const routerFor = () => (win.RouterLink && s.doc ? win.RouterLink.contextFrom(s.doc, browserName) : null);
  const routerHtml = (finding) => (win.RouterLink && win.RouterLink.offersRouter(finding) ? win.RouterLink.gameLinkHtml(routerFor()) : '');

  // ---------------------------------------------------------------------------
  // The command center. Everything here reads the scan and changes game state
  // (the deck) only; nothing touches the computer. Real changes go through
  // FixFlow and MarkFlow, which ask first.
  // ---------------------------------------------------------------------------
  function logEntry(kind, text) {
    s.log = [{ at: now(), kind, text: String(text == null ? '' : text) }, ...s.log].slice(0, LOG_MAX);
  }
  // Moments wait in order for the deck's next redraw. A few at most, and a
  // rank-up is never the one dropped.
  function addMoment(m) {
    const all = [...s.moments, m];
    while (all.length > MOMENTS_MAX) {
      const i = all.findIndex((x) => x.kind !== 'rank');
      all.splice(i < 0 ? 0 : i, 1);
    }
    s.moments = all;
  }
  function commitDeck(deck) {
    keep(setDeck(s.progress, deck));
  }

  // Lesson visits: a few items from the bank (profile/item-bank.js). Evidence
  // is measured on the whole bank; what is drawn comes from drawBank().
  const itemsOf = (keys) => (keys || []).map((k) => s.bank.items.get(k)).filter(Boolean);
  const teachAt = (keys, i) => (keys && keys.length && keys[i] ? teachShown(s.profile, s.bank, keys[i]) : true);
  // A lesson with no items in the bank is asked as written (city mode: without the skipped families).
  const writtenOf = (l) => (coverMode() ? cityLessons([l])[0] : l);
  const questionsOf = (lesson) => {
    const items = itemsOf(lesson && lesson.keys);
    if (items.length) return items;
    const l = lesson && s.lessons.find((x) => x.id === lesson.id);
    return l ? writtenOf(l).questions : [];
  };
  function openVisit(lessonId, keys, extra = {}) {
    s.lesson = { id: lessonId, keys, q: 0, picked: null, showTeach: teachAt(keys, 0), ...extra };
    s.screen = 'lesson';
    render();
    focusHeading(frame);
  }
  function startVisit(lessonId, extra = {}) {
    const bank = drawBank();
    openVisit(lessonId, drawLessonVisit(bank, lessonId, historyFor(s.profile, bank), { bOf: difficultyOf(s.profile, s.bank) }), extra);
  }
  // A concept the game may ask about here: never a hidden one, and in city
  // mode (or with no mode yet) only one the city bank has questions for.
  const askable = (c) => !!conceptById(c) && !isHidden(c) && !(coverMode() && CITY_SKIPPED_CONCEPTS.has(c))
    && (drawBank().concepts.get(c) || []).some((k) => (s.bank.items.get(k) || {}).kind === 'lesson');
  // "Want the 2 questions on this?": for a concept the person said they knew,
  // once per sweep (or per session before any sweep), by the profile's rules.
  function offerFor(concepts) {
    const sweepAt = s.progress.deck.sweep.at || sessionStart;
    const c = (concepts || []).find((x) => askable(x) && shouldOffer(s.profile, drawBank(), x, sweepAt));
    if (!c) return null;
    keepProfile(noteOffered(s.profile, c, now()));
    return { id: c, title: conceptById(c).title };
  }
  // A ledger result: keep its deck. A rank-up is a moment and a log entry.
  function commitAward(r) {
    if (!r) return 0;
    commitDeck(r.deck);
    if (r.rankUp) {
      const name = rankOf(r.deck).name;
      addMoment({ kind: 'rank', title: 'RANK UP', text: `You’re now ${name}.` });
      logEntry('RANK UP', name);
    }
    return r.points || 0;
  }
  const signalsNow = () => (s.city ? buildSignals(s.city, s.progress.deck, s.changedTags) : []);
  // This sweep's drills: about one per four real signals, from their districts.
  function sweepDrillsNow() {
    const real = queueOf(signalsNow(), null).urgent.filter((x) => x.kind === 'real');
    return chooseDrills(s.drillBank, real, s.progress.deck, s.progress.deck.sweeps.length);
  }
  // The queue: what the scan found (by kind and district, as filtered), and
  // this sweep's practice drills apart from it.
  function deckQueue() {
    const sigs = signalsNow();
    const q = queueOf(sigs, s.filter);
    const drills = (s.sweepDrills || []).filter((d) => !s.drillAnswers[d.id] && (!s.filter || d.district === s.filter)).map(drillSignal);
    const items = s.sev ? q.urgent.filter((x) => x.severity === s.sev) : q.urgent;
    return { sigs, q, items, drills };
  }
  function findSignal(id) {
    if (typeof id !== 'string') return null;
    if (id.startsWith('drill:')) {
      const d = s.drillBank.find((x) => x.id === id.slice(6));
      return d ? drillSignal(d) : null;
    }
    return signalsNow().find((x) => x.id === id) || null;
  }
  // Clues opened this sweep, per signal. Memory only.
  const openedFor = (id) => { if (!s.opened[id]) s.opened[id] = []; return s.opened[id]; };
  const cluesOf = (sig) => (sig.kind === 'drill' ? drillClues(sig.drill) : sig.kind === 'real' ? cluesFor(sig.finding) : []);
  const nameOf = (id) => ((s.city && district(id)) || DISTRICTS.find((d) => d.id === id) || {}).name || '';

  function signalPanelHtml() {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) { s.signal = null; return ''; }
    // The real "It's mine" step, offered only for a finding that has one. MarkFlow asks its own question.
    const mine = sig.kind === 'real' && sig.missionId && !sig.marked ? win.MarkFlow.markControlsHtml(sig.finding, { ...watchedOpts(), theme: 'game' }) : '';
    return renderSignalPanel({ signal: sig, districtName: nameOf(sig.districtId), clues: cluesOf(sig), opened: openedFor(sig.id),
      tagged: s.signal.tagged, right: s.signal.right, read: s.signal.read, points: s.signal.points, scout, mineHtml: mine,
      range: s.screen === 'range' ? { hasCity: !!s.city } : null, offer: s.signal.offer || null,
      tagNote: Object.keys(s.progress.deck.tags || {}).length === 0 });
  }

  function deckHtml() {
    const { sigs, q, items, drills } = deckQueue();
    const integ = cityIntegrity(s.city, sigs, s.heldCity);
    const deck = s.progress.deck;
    const history = deck.sweeps.map(sweepPercent);
    const c = counts();
    // A district card opens its district; the queue has its own filters.
    const goFor = (d) => `district:${d.id}`;
    const heat = districtHeat(s.city, sigs, s.heldCity);
    // Monitoring software the scan found. City mode: the generated district's
    // tile and a notice that name only the place, and the help is in there.
    // Otherwise (standard, or a host that can't say): the map's own note.
    const held = inCity() ? '' : heldPanelHtml({ held: s.held, mode: hostMode(), Q: win.QuietNotes });
    // Its district reads as checked, never NOTHING FOUND (views/map.js heldView).
    const heldIn = heldDistrictIds(s.heldCity);
    // City mode has no note above the map: a held district points to the generated one.
    const heldAt = inCity() ? side().name : null;
    const cityHtml = sideTile() + held + (s.rc || s.accountsError
      ? renderOneCityMap({ city: s.city, progress: s.progress, scout, cameBack: s.cameBack, focus: focusFor(s.situation),
        accountCards: s.rc ? accountDistrictCards({ rc: s.rc, rcState: s.rcState, doc: s.doc }) : [],
        accountsError: s.accountsError, goFor, heat, selected: s.filter, held: heldIn, heldAt, showScout: false })
      : renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout, goFor, heat, selected: s.filter, held: heldIn, heldAt, showScout: false }));
    // Scout's read sits under the queue's header, where the person starts.
    const scoutHtml = `<div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(mapLine(s.city, s.cameBack, heldIn, heldAt))}</p></div>`;
    const fd = s.filter ? district(s.filter) : null;
    const moments = s.moments;
    s.moments = []; // a moment shows once
    return renderDeck({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', rank: rankOf(deck),
      lastSweep: deck.sweeps.length ? deck.sweeps[deck.sweeps.length - 1] : null,
      items: mergeSame(items), low: q.low, lowOpen: s.lowOpen, threats: q.threats, known: [...q.known, ...q.noted],
      queueOpen: s.queueOpen, sev: s.sev, sevCounts: severityCounts(q.urgent), drills, scoutHtml,
      filter: fd ? { id: fd.id, name: fd.name } : null, cityHtml,
      instrumentsHtml: renderInstruments({ integrity: integ.percent, previous: history.length > 1 ? history[history.length - 2] : null,
        history, bars: { sorted: sortedCount(sigs), confirmed: c.confirmed, reported: c.reported }, rank: rankOf(deck) }),
      log: s.log, moments, panelHtml: s.signal ? signalPanelHtml() : '', nothingChecked: integ.percent === null, learned: learnedCount(),
      scanRunning: s.scan.running, districtName: nameOf, notice: heldNotice() + s.linkNotice,
      // With something held, an empty queue points to it instead of saying "clear".
      notChecked: notCheckedLine(notCheckedSummary(s.doc)),
      heldLine: s.held.length ? (inCity() ? `Something new in ${side().name}.` : 'There’s a note above the map.') : '' });
  }

  // The deck before any sweep: the sweep to start, the city's districts with
  // their lessons as visits, and the ops log.
  function homeHtml() {
    const deck = s.progress.deck;
    return renderDeck({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', rank: rankOf(deck),
      lastSweep: deck.sweeps.length ? deck.sweeps[deck.sweeps.length - 1] : null,
      preSweep: !s.scan.running, scanRunning: s.scan.running, scanError: s.scan.error || '',
      cityHtml: sideTile() + preSweepCityHtml(DISTRICTS, s.lessonsLoaded ? learnFor() : () => null),
      log: s.log, notice: heldNotice() + s.linkNotice, districtName: nameOf, learned: learnedCount() });
  }

  function openSignal(id) {
    const sig = findSignal(id);
    s.signal = sig ? { id: sig.id, tagged: null, right: false, read: '', points: 0 } : null;
    // A drill already answered this sweep opens with that answer: it takes one.
    const was = sig && sig.kind === 'drill' ? s.drillAnswers[sig.drill.id] : null;
    if (was) s.signal = { ...s.signal, tagged: was.tag, right: was.right, read: drillRead(sig.drill, was.right) };
    // FixFlow and MarkFlow results re-check s.missionId. An info signal has no mission.
    if (sig) s.missionId = sig.missionId || null;
    s.screen = 'map';
    render();
    const title = s.signal ? frame.querySelector('#sig-title') : null;
    if (title && typeof title.focus === 'function') title.focus();
  }

  // Opening a clue on a real finding pays once per finding per sweep (the ledger keys it).
  function scanClue(kind) {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) return;
    const opened = openedFor(sig.id);
    if (!opened.includes(kind) && cluesOf(sig).some((c) => c.kind === kind)) {
      opened.push(kind);
      if (sig.kind === 'real') s.signal.points += commitAward(award(s.progress.deck, 'clue', `${sig.id}#${kind}`));
    }
    render();
    focusAfterClue(sig, kind);
  }

  // The clue's button became its text, so focus moves on: to the next clue
  // still locked (after this one, then from the top), or else to the clue
  // just opened.
  function focusAfterClue(sig, kind) {
    const kinds = cluesOf(sig).map((c) => c.kind);
    const opened = openedFor(sig.id);
    const at = kinds.indexOf(kind);
    const locked = [...kinds.slice(at + 1), ...kinds.slice(0, at + 1)].filter((k) => !opened.includes(k));
    for (const k of locked) if (focusEl(findByAttr(frame, 'data-act', `clue:${k}`))) return;
    focusEl(findByAttr(frame, 'data-clue', kind));
  }

  // BACK TO THE DECK (or Escape): the panel and its buttons go, so focus lands
  // on the signal's row in the queue, or else INVESTIGATE NEXT.
  function closeSignal() {
    const id = s.signal && s.signal.id;
    s.signal = null; s.screen = 'map';
    render();
    if (id && focusEl(findByAttr(frame, 'data-go', `signal:${id}`))) return;
    if (focusEl(findByAttr(frame, 'data-act', 'investigate-next'))) return;
    focusEl(findByAttr(frame, 'data-go', 'range'));
  }

  // A tag is game sorting only. The bonus is for looking first (two or more
  // clues), never for which tag was picked.
  function tagSignal(tag) {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) return;
    if (sig.kind === 'drill') { answerDrill(sig, tag); return; }
    if (!(sig.kind === 'couldnt' ? ['noted'] : ['mine', 'threat', 'closer']).includes(tag)) return;
    commitDeck(setTag(s.progress.deck, sig.id, tag, sig.fp, now()));
    s.changedTags.delete(sig.id);
    if (sig.kind === 'real' && openedFor(sig.id).length >= 2) s.signal.points += commitAward(award(s.progress.deck, 'tagBonus', sig.id));
    s.signal = { ...s.signal, tagged: tag, read: sig.kind === 'couldnt' ? COULDNT_READ : scoutRead(sig, tag), offer: null };
    // Scout reading it another way is a sign a lesson might help (never "wrong").
    // Only the concepts are kept, never the finding; monitoring checks give none.
    // One gap per finding per sweep, however often it is re-tagged.
    if (sig.kind === 'real' && !scoutAgrees(sig, tag) && !s.gapped.has(sig.id)) {
      const cs = callConcepts(drawBank(), sig.module, openedFor(sig.id)).filter(askable);
      if (cs.length) { s.gapped.add(sig.id); keepProfile(recordGap(s.profile, cs, 'call', now())); s.signal.offer = offerFor(cs); }
    }
    logEntry('TAG', `${TAG_WORD[tag]}: ${sig.title}`);
    render();
    focusRead();
  }

  // After a tag, keyboard and screen-reader users land on Scout's read (an
  // answered drill's tag buttons are disabled, so focus can't stay on them).
  function focusRead() {
    const el = frame.querySelector('.sig-panel .say');
    if (!el) return;
    if (typeof el.setAttribute === 'function') el.setAttribute('tabindex', '-1');
    if (typeof el.focus === 'function') el.focus();
  }

  // A drill takes one answer: right pays (with the clue bonus), wrong pays
  // nothing and costs nothing. Drill answers never touch the deck's tags.
  // In the queue a drill takes one answer per sweep (s.drillAnswers). The DRILL
  // RANGE is practice: an answer holds while that drill is open, and it can be
  // tried again on a later turn round. Either way the ledger pays a drill once, ever.
  function answerDrill(sig, tag) {
    const d = sig.drill;
    const range = s.screen === 'range';
    if (s.signal.tagged || (!range && s.drillAnswers[d.id]) || !['mine', 'threat', 'closer'].includes(tag)) return;
    const right = tag === d.answer;
    commitDeck(recordDrill(s.progress.deck, right));
    const points = right ? commitAward(award(s.progress.deck, 'drill', d.id, openedFor(sig.id).length >= 2 ? POINTS.drillClueBonus : 0)) : 0;
    // A drill's first answer this sweep is evidence on its concept, and a cell in the calls matrix.
    const first = !s.drillEvidence.has(d.id);
    if (first) { s.drillEvidence.add(d.id); keepProfile(recordDrillCall(s.profile, s.bank, d, tag, now())); }
    const it = s.bank.items.get(`drill:${d.id}`);
    const offer = first && !right && it && it.concept ? offerFor([it.concept]) : null;
    if (!range) s.drillAnswers[d.id] = { tag, right };
    s.signal = { ...s.signal, tagged: tag, right, points, read: drillRead(d, right), offer };
    logEntry('DRILL', `${right ? 'Right' : 'Not this time'}: ${d.title}`);
    render();
    focusRead();
  }

  // "These are all fine": the visible low-priority signals go to the known pile. No points.
  function batchFine() {
    const { q } = deckQueue();
    if (q.low.length) {
      let deck = s.progress.deck;
      for (const sig of q.low) deck = setTag(deck, sig.id, 'mine', sig.fp, now());
      commitDeck(deck);
      logEntry('TAG', `${q.low.length} low-priority signal${q.low.length === 1 ? '' : 's'} sorted as fine`);
    }
    s.lowOpen = false;
    render();
  }

  // A finished scan: a date and counts in the store, a SWEEP line in the log,
  // "no longer seen" for what's gone (no points: only a re-check confirms),
  // the clean-sweep bonus when this re-sweep cleared the board, and new drills.
  // A sweep where held monitoring software is, or was in the last sweep, is
  // recorded but never scored or called clean: its going is not a win.
  // Every monitoring check in this scan that can run here ran ok (none timed
  // out or failed), and at least one did. Whether any of them holds something
  // is heldCity's to say.
  function monitoringRanClear(doc) {
    const mods = (doc && Array.isArray(doc.modules) ? doc.modules : []).filter((m) => m && HELD_MODULES.has(m.name) && m.supported !== false);
    const ok = ranOkModules(doc);
    return mods.length > 0 && mods.every((m) => ok.has(m.name));
  }

  function newSweep(doc, prev) {
    s.sweptDoc = doc;
    const sigs = signalsNow();
    const counts = sweepCounts(doc, s.city, cityIntegrity(s.city, sigs, s.heldCity), s.heldCity);
    // The mark stays until the monitoring checks ran and found nothing held:
    // a sweep where one timed out or couldn't look (fog) keeps it.
    const carry = heldDistrictIds(s.heldCity).size > 0 || (s.progress.deck.sweep.carry === true && !monitoringRanClear(doc));
    const r = recordSweep(s.progress.deck, counts, now(), { carry });
    commitAward(r);
    logEntry('SWEEP', `${counts.checks} check${counts.checks === 1 ? '' : 's'}: ${counts.critical} critical, ${counts.warning} warning, ${counts.fog} couldn’t check${counts.unfinished ? `, ${counts.unfinished} didn’t finish` : ''}.`);
    if (r.clean) {
      addMoment({ kind: 'clean', title: 'CLEAN SWEEP', text: 'No critical or warning signal is open in any district that could be checked.' });
      logEntry('CLEAN SWEEP', 'Every district that could be checked is secured.');
    }
    const here = new Set(sigs.map((x) => x.id));
    // Only a check that ran and finished can say something is no longer there.
    const looked = ranOkModules(doc);
    for (const p of prev) {
      if (p.kind === 'real' && (p.tag || p.severity !== 'info') && !here.has(p.id) && looked.has(p.module)) logEntry('NO LONGER SEEN', p.title);
    }
    s.opened = {};
    s.drillAnswers = {};
    s.gapped = new Set();
    s.drillEvidence = new Set();
    s.sweepDrills = s.drillsLoaded ? sweepDrillsNow() : null;
  }

  // A district that had something open and now has nothing open in the checks that ran.
  function noteSecured(before, after, held = new Set()) {
    for (const id of after.securedIds) {
      if (before.securedIds.has(id) || !before.checkedIds.has(id) || held.has(id)) continue;
      const name = nameOf(id) || id;
      addMoment({ kind: 'secured', title: 'DISTRICT SECURED', text: `${name}: nothing critical or warning is open in the checks that ran.` });
      logEntry('SECURED', name);
    }
  }

  // The DRILL RANGE: every district's drills, the ones not yet answered right first.
  function rangeHtml() {
    if (!s.range) s.range = { order: [], i: 0 };
    if (s.drillsLoaded && !s.range.order.length) {
      s.range.order = pickDrills(s.drillBank, DISTRICTS.map((d) => d.id), s.progress.deck, s.progress.deck.drills.tried).map((d) => d.id);
    }
    const order = s.range.order;
    const id = order.length ? order[s.range.i % order.length] : null;
    if (id && (!s.signal || s.signal.id !== `drill:${id}`)) s.signal = { id: `drill:${id}`, tagged: null, right: false, read: '', points: 0 };
    return renderRange({ loaded: s.drillsLoaded, panelHtml: id ? signalPanelHtml() : '', hasCity: !!s.city });
  }

  // Game missions the person just finished. Finished from the checkup (confirmedId)
  // is a confirmed fix; anything else is the person's report. Each pays once, ever.
  function creditReports(before, after, confirmedId) {
    const was = (before && before.missions) || {};
    for (const [id, rec] of Object.entries((after && after.missions) || {})) {
      if (!rec || !DONE.has(rec.status) || (was[id] && DONE.has(was[id].status))) continue;
      const title = (rcMission(id) || {}).title || 'A mission';
      if (id === confirmedId) {
        commitAward(award(s.progress.deck, 'fix', `rc:${id}`));
        logEntry('CONFIRMED', title);
      } else {
        if (rec.status === 'completed') commitAward(award(s.progress.deck, 'report', id));
        logEntry('YOU REPORTED', title);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // YOUR FILE (views/profile.js). City mode (or no mode yet) reads the city
  // bank and the city's lessons, so a family city mode never asks is never
  // counted as missing. The publish control and its consent sheet exist only
  // in standard mode with the school side ready (publishOffered); if the mode
  // turns to city while the sheet is open, it closes. Nothing here writes to
  // disk except Start over, which writes an empty box.
  // ---------------------------------------------------------------------------
  const canPublish = () => publishOffered(hostMode(), pub.ready);
  function profileSummary() {
    const city = coverMode();
    const o = orderLessons(city ? cityLessons(s.lessons) : s.lessons, worryIdsOf(s.situation));
    return summary(s.profile, city ? s.cityBank : s.bank, [...o.recommended, ...o.other].map((l) => l.id));
  }
  // The headline count, the rank chip's and the published one: one rule (publish.js).
  const learnedCount = () => lessonsLearned(profileSummary());
  const sheetOpen = () => !!(s.profileView && s.profileView.publish);
  function profileHtml() {
    if (sheetOpen() && !canPublish()) s.profileView = { ...s.profileView, publish: null };
    const view = s.profileView || {};
    const sum = profileSummary();
    const page = pub.renderProfile({ summary: sum, theme: 'game', publish: canPublish(), confirming: !!view.confirming });
    if (!view.publish) return page;
    const sheet = pub.renderPublishSheet({ summary: sum, ticked: view.publish.ticked,
      payload: buildPreview(sum, view.publish) });
    // While the sheet is open, YOUR FILE behind it is inert: Tab stays in the sheet.
    return sheet ? `<div inert>${page}</div>${sheet}` : page;
  }
  // The preview: exactly the text deliver would hand over (buildPayload,
  // preview only). The sheet draws it only when the school side is ready.
  const buildPreview = (sum, p) => buildPayload(sum, p.ticked, { mode: hostMode(), now: p.at });
  // Save a file or Copy: the person hands it over themselves. No network call.
  // Only through deliver, which refuses unless the school side is ready.
  function exportPayload(kind) {
    const view = s.profileView;
    if (!view || !view.publish || !canPublish() || !view.publish.ticked.length) return;
    const send = kind === 'copy' ? (text) => win.navigator.clipboard.writeText(text) : (text) => {
      const url = win.URL.createObjectURL(new win.Blob([text], { type: 'application/json' }));
      const a = doc0.createElement('a');
      a.href = url;
      a.download = 'school-profile.json';
      a.click();
      win.setTimeout(() => win.URL.revokeObjectURL(url), 0);
    };
    Promise.resolve(pub.deliver(profileSummary(), { fields: [...view.publish.ticked] }, { mode: hostMode(), now: view.publish.at, send })).catch(() => {});
  }
  // Focus after a redraw of YOUR FILE: a control by its attribute, else the
  // screen's own choice (the Start over question, or the heading).
  function focusInProfile(k, v) {
    if (k && focusEl(findByAttr(frame, k, v))) return;
    focusProfile(frame);
  }
  function openProfile() {
    const from = s.screen === 'profile' ? (s.profileView && s.profileView.from) || 'map' : s.screen;
    s.profileView = { confirming: false, publish: null, from };
    s.signal = null; s.screen = 'profile';
    render();
    focusProfile(frame);
  }
  function closeProfile() {
    const from = (s.profileView && s.profileView.from) || 'map';
    s.profileView = null;
    s.screen = from === 'lesson' && !s.lesson ? 'training' : from;
    render();
    // Back to what opened it: the rank chip, or the YOUR FILE button.
    focusEl(findByAttr(frame, 'data-go', 'profile'));
  }
  // YOUR FILE's own acts (a click, or Escape through profileKeyAct). True when handled.
  function profileAct(act, el) {
    if (s.screen !== 'profile' || !act) return false;
    const view = s.profileView || { confirming: false, publish: null, from: 'map' };
    if (act === 'profile-close') { closeProfile(); return true; }
    if (act === 'profile-start-over') {
      s.profileView = { ...view, confirming: true, publish: null }; render(); focusProfile(frame); return true;
    }
    if (act === 'profile-start-over-no') {
      s.profileView = { ...view, confirming: false }; render(); focusInProfile('data-act', 'profile-start-over'); return true;
    }
    if (act === 'profile-start-over-yes') {
      if (!view.confirming) return true;
      keepProfile(emptyProfile(now()));
      s.profileView = { ...view, confirming: false };
      render(); focusProfile(frame); return true;
    }
    if (act === 'profile-publish') {
      if (canPublish()) {
        s.profileView = { ...view, confirming: false, publish: { ticked: [], at: now() } };
        render();
        focusInProfile('id', 'pub-title');
      }
      return true;
    }
    if (act.startsWith('pub-toggle:')) {
      const id = act.slice(11);
      if (!view.publish || !canPublish() || !PUBLISH_FIELDS.some((f) => f.id === id)) { render(); return true; }
      const rest = view.publish.ticked.filter((x) => x !== id);
      s.profileView = { ...view, publish: { ...view.publish, ticked: el && el.checked ? [...rest, id] : rest } };
      render(); return true;
    }
    if (act === 'publish-close') {
      const was = !!view.publish;
      s.profileView = { ...view, publish: null }; render();
      if (was) focusInProfile('data-act', 'profile-publish');
      return true;
    }
    if (act === 'publish-save') { exportPayload('file'); return true; }
    if (act === 'publish-copy') { exportPayload('copy'); return true; }
    return false;
  }

  function screenHtml() {
    if (s.screen === 'profile') return profileHtml();
    if (s.screen === 'side') {
      if (inCity()) return renderSide({ district: side(), held: s.held, notice: s.sideNotice, scout, date: today(), copied: s.sideCopied });
      s.screen = s.city ? 'map' : noCity();
    }
    if (s.screen === 'range') return rangeHtml();
    if (s.screen === 'home') {
      if (s.city) { s.screen = 'map'; return deckHtml(); }
      return homeHtml();
    }
    if (s.screen === 'training') {
      return sideTile() + renderTraining({ ordered: orderLessons(s.lessons, worryIdsOf(s.situation)), progress: s.progress,
        // City mode is the cover: no worry's words on a game screen ("…watching
        // me"). Only the city's own home keeps its title, "Take back the city".
        worryTitle: inCity() && !isCityHome(s.situation) ? null : s.situation && s.situation.title, forYou: inCity(), scan: s.scan, scout, pendingCity: cityWaiting(),
        lessonsLoaded: s.lessonsLoaded, scanFinished: !!s.city });
    }
    if (s.screen === 'lesson') {
      const l = s.lesson && s.lessons.find((x) => x.id === s.lesson.id);
      const items = itemsOf(s.lesson.keys);
      if (l) return renderLesson({ lesson: writtenOf(l), items: items.length ? items : null, qIndex: s.lesson.q, picked: s.lesson.picked,
        showTeach: s.lesson.showTeach !== false, scan: s.scan, scout, pendingCity: cityWaiting(), scanFinished: !!s.city, settingFor,
        routerHtml: () => (win.RouterLink ? win.RouterLink.gameLinkHtml(routerFor()) : '') });
      s.screen = noCity();
      return screenHtml();
    }
    if (s.screen === 'boss') return renderBoss({ boss: s.boss, scout, tips: s.tips, tipsOpen: s.tipsOpen, learn: learnFor(),
      firstSweep: !s.progress.deck.sweeps.length,
      // Swept so far: the same path as rebuild()'s, read-only (no progress, deck or store touched).
      toCity: (d) => findingsToCity(quietDoc(splitHeld(d).doc)) });
    if (s.screen === 'rc' && s.rc && s.rcRoute) return rcScreenHtml();
    if (s.screen === 'milestone' && district(s.districtId)) {
      return renderMilestone({ district: district(s.districtId), progress: s.progress, scout });
    }
    if (s.screen === 'district' && district(s.districtId)) {
      return renderDistrict({ district: district(s.districtId), progress: s.progress, scout, message: s.districtMsg || '', busy: s.busy,
        scanRunning: !!s.scan.running });
    }
    // During an Undo re-check the mission was reclaimed, so it isn't in the
    // city: show the checking briefing from the mission we last showed.
    if (s.screen === 'mission' && s.busy && !mission(s.missionId) && s.outcomeMission && s.outcomeMission.id === s.missionId) {
      const m0 = s.outcomeMission;
      const note = briefingNote(win.QuietNotes, hostMode(), m0.primary);
      const wantsSafety = win.RescueHost.wantsSafety(m0.primary);
      const { mission: m, cityWarn } = cityBriefing(m0, note, wantsSafety);
      return renderBriefing({ mission: m, status: (s.progress.missions[m.id] || {}).status || 'open', controlsHtml: '',
        scout, busy: true, wantsSafety, note, cityWarn, modules: scanModules(), platform: s.doc && s.doc.platform });
    }
    if (s.screen === 'mission' && mission(s.missionId)) {
      const m0 = mission(s.missionId);
      // Monitoring software is held (rebuild), so it shouldn't reach here; if it
      // ever does, the briefing carries the list's own note, and in city mode
      // nothing to act on.
      const note = briefingNote(win.QuietNotes, hostMode(), m0.primary);
      const wantsSafety = win.RescueHost.wantsSafety(m0.primary);
      const { mission: m, cityWarn } = cityBriefing(m0, note, wantsSafety);
      const controls = note.kind === 'held' ? ''
        : `${win.FixFlow.fixControlsHtml(m.primary, watchedOpts())}${win.MarkFlow.markControlsHtml(m.primary, { ...watchedOpts(), theme: 'game' })}${routerHtml(m.primary)}`;
      return renderBriefing({ mission: m, status: (s.progress.missions[m.id] || {}).status || 'open', controlsHtml: controls,
        scout, busy: s.busy, scanRunning: !!s.scan.running, wantsSafety, learned: lessonForModule(s.lessons, s.progress, m.module), note,
        cityWarn, modules: scanModules(), platform: s.doc && s.doc.platform });
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
    return deckHtml();
  }

  const scanModules = () => (s.doc && Array.isArray(s.doc.modules) ? s.doc.modules.map((x) => x && x.name).filter(Boolean) : []);
  // City mode: the help lives in the help district, so a mission carries no
  // hotline or advocate wording (QuietNotes.quiet, the list's own stripping),
  // and a finding that warns about removal gets the one warning line with the
  // way there, in place of the full safety note. Its own sentence saying the
  // same is dropped from the description. Copies only; the scan is unchanged.
  function cityBriefing(m, note, wantsSafety) {
    const Q = win.QuietNotes;
    if (!inCity() || !Q || note.kind === 'held') return { mission: m, cityWarn: null };
    const warn = note.kind === 'full' || (wantsSafety && !!m.safetyNote);
    const sentences = (t) => String(t || '').split(/(?<=[.!?])\s+/);
    const desc = Q.quiet(m.description);
    const description = warn && Q.ALERTS
      ? desc.split(/\n\s*\n/).map((p) => sentences(p).filter((x) => !Q.ALERTS.test(x)).join(' ')).filter((p) => p.trim()).join('\n\n')
      : desc;
    const steps = (m.steps || []).map((x) => (x && typeof x === 'object' ? { ...x, title: Q.quiet(x.title), body: Q.quiet(x.body) } : x));
    return { mission: { ...m, description, steps, safetyNote: null }, cityWarn: warn ? { place: side().name } : null };
  }

  // A save or read problem, said once, calmly, until dismissed (or, for a
  // save problem, until a later save works).
  function saveNoticeHtml() {
    if (!s.saveNotice) return '';
    return `<p class="link-notice save-notice" role="status">${esc(saveProblemText(s.saveNotice.code, coverMode()))}
      <button type="button" class="btn-t" data-act="dismiss-save-notice">OK</button></p>`;
  }

  // false when the screen couldn't be drawn and the person was sent to the list,
  // so app.js doesn't then show the (empty) city screen.
  function render() {
    try {
      // No city yet (the scan hasn't finished): the Training Grounds.
      if (!s.city && !NO_CITY_SCREENS.has(s.screen) && s.screen !== 'side') s.screen = noCity();
      // A redraw of the same screen (a progress event, an answer, a clue, a
      // tag) mustn't lose keyboard or screen-reader focus.
      const keep = KEEP_FOCUS.has(s.screen) && s.screen === drawnScreen ? focusKey(shadow.activeElement) : null;
      // The known pile is a <details>: keep it open if the person opened it.
      const knownWasOpen = s.screen === 'map' && drawnScreen === 'map' && !!(frame.querySelector('details.known') || {}).open;
      // The held note's details (standard mode, or a host that can't say), the same way.
      if (s.screen === 'map' && drawnScreen === 'map') s.heldOpen = !!(frame.querySelector('.panel.held details') || {}).open;
      const body = screenHtml();
      // The deck has its own top bar; the training and range screens have theirs.
      const hud = NO_CITY_SCREENS.has(s.screen) || s.screen === 'map' || s.screen === 'side' ? ''
        : renderHud({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', city: s.city, progress: s.progress, counts: counts(), rank: rankOf(s.progress.deck) }) + s.linkNotice;
      frame.innerHTML = saveNoticeHtml() + hud + body;
      // No share cards in Reclaim City’s checkup: they would describe this person's progress.
      frame.querySelectorAll('[data-action="share-card"], #milestone-card-preview').forEach((el) => el.remove());
      // No "ALLIED ORGANIZATIONS" either (a district at 100%): one is a donation
      // page, and none are in mission-links.json. Then any other outside link
      // that isn't a game action, in case the markup changes upstream.
      frame.querySelectorAll('.section-label').forEach((el) => {
        if (String(el.textContent || '').trim() === 'ALLIED ORGANIZATIONS' && el.parentElement) el.parentElement.remove();
      });
      frame.querySelectorAll('a[target="_blank"]:not([data-action])').forEach((el) => el.remove());
      const known = knownWasOpen && s.screen === 'map' ? frame.querySelector('details.known') : null;
      if (known) known.open = true;
      const heldDetails = s.heldOpen && s.screen === 'map' ? frame.querySelector('.panel.held details') : null;
      if (heldDetails) heldDetails.open = true;
      // (screenHtml can move on from a lesson that's gone: then nothing to keep.)
      if (keep && s.screen === drawnScreen) focusEl(findByAttr(frame, keep.k, keep.v));
      drawnScreen = s.screen;
      const focused = s.screen === 'map' ? frame.querySelector('[data-focus]') : null;
      if (focused && s.focusPending) { focused.scrollIntoView({ block: 'start' }); s.focusPending = false; }
      return true;
    } catch (err) {
      console.error('City view failed:', err);
      drawnScreen = null;
      frame.innerHTML = `<p class="say">${esc('The city view hit a problem. Here’s the same thing as a list.')}</p>`;
      win.RescueHost.leaveGame();
      return false;
    }
  }

  // `trigger` is what asked for the re-check: fix | undo | mark | unmark |
  // i-did-it. `also` lists other modules to re-check (a mark that covered
  // findings in more than one check). The outcome is for this mission only.
  async function recheck(missionId, trigger = 'i-did-it', also = []) {
    const m = mission(missionId) || s.outcomeMission;
    // Main refuses a re-check while a sweep runs; never start one then.
    if (!m || s.busy || s.scan.running) return;
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
        if (!win.RescueHost.docChanged(r.doc)) { s.busy = false; return; } // app.js asked the follow-up instead
        rebuild(r.doc, putBack ? m.id : null);
      }
    }
    s.busy = false;
    // The city was shown afresh while this ran (LIST, then back): keep the new
    // scan's data, but don't take the person away from where they are now.
    if (s.shown !== shownAt) { render(); return; }
    const outcome = recheckOutcome(m.id, s.city, res);
    // Only a re-check proves a fix: CONFIRMED, and the fix points pay once per finding, ever.
    // Nothing about monitoring software is scored or logged (confirmFix refuses it too).
    const monitoring = MONITORING_MODULES.has(m.module);
    if (outcome === 'reclaimed' && (trigger === 'fix' || trigger === 'i-did-it') && !monitoring) {
      commitAward(confirmFix(s.progress.deck, m.id, now()));
      logEntry('CONFIRMED', m.title);
    }
    if (outcome === 'yours' && !monitoring) logEntry('MARKED', m.title);
    s.outcome = putBack && outcome === 'not-yet' ? 'put-back' : outcome;
    s.outcomeMission = mission(m.id) || m;
    s.message = res && !res.ok ? res.message || ''
      : res && res.module && res.module.complete === false ? UNFINISHED_RECHECK : '';
    s.screen = 'outcome';
    render();
  }

  const today = () => new Date().toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
  // "Copy to write down": the held item's rows, to the clipboard only (never to disk).
  function copyHeld(i) {
    const h = s.held[i];
    if (!h || s.screen !== 'side') return;
    const ticket = s.sideTicket;
    const done = (ok) => {
      if (ticket !== s.sideTicket || s.screen !== 'side') return;
      s.sideCopied = ok ? i : -(i + 1);
      render();
      focusEl(findByAttr(frame, 'data-act', `side-copy:${i}`));
    };
    Promise.resolve().then(() => win.navigator.clipboard.writeText(heldText(h, today()))).then(() => done(true), () => done(false));
  }

  // District missions ticked for a bulk move (read from the page; the
  // selection starts again on every redraw, like the list's checklists).
  const ticked = () => Array.from(frame.querySelectorAll('[data-pick]')).filter((b) => b.checked === true)
    .map((b) => b.getAttribute('data-pick')).filter((id) => mission(id));
  function updateBulk() {
    const n = ticked().length;
    frame.querySelectorAll('[data-act="bulk-did"],[data-act="bulk-later"]').forEach((b) => {
      b.disabled = n === 0 || (b.hasAttribute('data-scan-running') && b.getAttribute('data-act') === 'bulk-did');
      b.textContent = bulkLabel(b.getAttribute('data-verb'), n);
    });
    const c = frame.querySelector('[data-pick-count]');
    if (c) c.textContent = n ? `${n} ticked` : 'None ticked';
  }
  // I DID THESE MYSELF: each ticked mission's check once, then what's gone is
  // CONFIRMED (and paid, as for one), and the district says how many.
  async function recheckMany(ids) {
    if (s.busy || s.scan.running) return;
    const ms = ids.map(mission).filter(Boolean);
    const modules = ms.map((m) => m.module).filter((x, i, a) => a.indexOf(x) === i);
    const shownAt = s.shown;
    s.busy = true; s.districtMsg = ''; render();
    const res = {};
    for (const name of modules) {
      let r;
      try { r = await win.rescue.recheckModule(name); } catch (_) { r = null; }
      res[name] = r;
      if (r && r.ok) {
        if (!win.RescueHost.docChanged(r.doc)) { s.busy = false; return; }
        rebuild(r.doc);
      }
    }
    s.busy = false;
    let gone = 0; let still = 0; let couldnt = 0;
    for (const m of ms) {
      const o = recheckOutcome(m.id, s.city, res[m.module]);
      if (o === 'reclaimed') {
        gone += 1;
        if (!MONITORING_MODULES.has(m.module)) { commitAward(confirmFix(s.progress.deck, m.id, now())); logEntry('CONFIRMED', m.title); }
      } else if (o === 'couldnt') couldnt += 1; else still += 1;
    }
    const parts = [];
    if (gone) parts.push(`${gone} gone (Reclaim City checked again)`);
    if (still) parts.push(`${still} still showing`);
    if (couldnt) parts.push(`${couldnt} couldn’t be checked again, so not confirmed`);
    s.districtMsg = parts.join(', ') + '.';
    if (s.shown !== shownAt) { render(); return; }
    render();
  }

  function openSide() {
    s.sideCopied = null;
    s.signal = null; // a Signal or Noise panel left open closes
    s.sideNotice = false;
    s.sideSeen = true;
    s.screen = 'side';
    // Only where they went: nothing about what is there.
    logEntry('VISIT', `Visited ${side().name}`);
    render();
    // Keyboard and screen-reader users land on the district's name.
    const title = frame.querySelector('#side-title');
    if (title && typeof title.focus === 'function') title.focus();
  }

  // The panic key and BACK TO THE GAME: the ordinary game at once, focus on the map.
  function leaveSide() {
    s.sideTicket += 1; // a guide still opening (or a copy) says nothing afterwards
    s.sideCopied = null;
    s.sideNotice = false;
    s.screen = s.city ? 'map' : noCity();
    render();
    const first = s.city && s.city.districts.length ? s.city.districts[0] : null;
    const target = first
      ? frame.querySelector(`[data-go="district:${first.id}"]`) || frame.querySelector(`[data-go="filter:${first.id}"]`)
      : frame.querySelector('[data-act="start-checkup"]');
    if (target && typeof target.focus === 'function') target.focus();
  }

  // Only the Six Roses guide opens, through main's guide allowlist.
  function openSideGuide() {
    const ticket = s.sideTicket;
    Promise.resolve().then(() => win.rescue.openGuide(SIX_ROSES.url)).then((ok) => ok === true, () => false).then((ok) => {
      if (ok || ticket !== s.sideTicket || s.screen !== 'side') return;
      s.sideNotice = true;
      render();
    });
  }

  // Esc on the district, wherever focus is, even while something is still
  // loading. Capture phase, so nothing else sees it first. Only while the city
  // is on screen: app.js's own screens keep their Esc.
  const cityShown = () => !(host && typeof host.closest === 'function' && host.closest('[hidden]'));
  if (typeof win.addEventListener === 'function') {
    win.addEventListener('keydown', (e) => {
      if (!e || e.key !== 'Escape' || s.screen !== 'side' || !cityShown()) return;
      if (typeof e.preventDefault === 'function') e.preventDefault();
      if (typeof e.stopPropagation === 'function') e.stopPropagation();
      leaveSide();
    }, true);
  }

  frame.addEventListener('click', (e) => {
    const el = e.target.closest('[data-go],[data-act]');
    if (!el) return;
    const go = el.getAttribute('data-go');
    const act = el.getAttribute('data-act');
    // The boss screen's pop-up tips: the <details> toggles itself; remember it for redraws.
    if (act === 'toggle-tips') { s.tipsOpen = !s.tipsOpen; return; }
    // Always a way back to the list, even while a re-check runs.
    if (act === 'list') { win.RescueHost.showList(); return; }
    if (act === 'leave') { win.RescueHost.leaveGame(); return; }
    // Always works, like LIST: back to the ordinary game.
    if (act === 'side-back') { leaveSide(); return; }
    // Opens a System Settings page through main's allowlist; it changes nothing, so it's fine mid-re-check.
    if (act && act.startsWith('open-setting:')) {
      const url = win.SettingPanes ? win.SettingPanes.urlFor(act.slice(13)) : null;
      if (url) Promise.resolve().then(() => win.rescue.openSetting(url)).catch(() => {});
      return;
    }
    // The router's sign-in page: only the address goes to main, which builds the URL.
    if (act === 'open-router') {
      const ctx = routerFor();
      if (ctx && !ctx.blocked) Promise.resolve().then(() => win.rescue.openRouter(ctx.ip)).catch(() => {});
      return;
    }
    if (act === 'dismiss-save-notice') { s.saveNotice = null; render(); return; }
    if (s.busy) return;
    if (go) s.linkNotice = '';
    if (go === 'side') { if (inCity()) openSide(); return; }
    if (act === 'side-open-guide') { if (s.screen === 'side') openSideGuide(); return; }
    if (act && act.startsWith('side-copy:')) { copyHeld(Number(act.slice(10))); return; }
    // RE-SWEEP: the same read-only scan as the plain route, through app.js, whose
    // gate decides where it lands (monitoring software: the plain list).
    if (act === 'resweep') { if (!s.scan.running) win.RescueHost.startCheckup(); return; }
    // The DRILL RANGE: more drills, with or without a scan.
    if (go === 'range') { s.signal = null; s.range = { order: [], i: 0 }; s.screen = 'range'; render(); return; }
    if (act === 'next-drill' && s.range) { s.range = { ...s.range, i: s.range.i + 1 }; s.signal = null; render(); return; }
    if (act === 'leave-range') { s.range = null; s.signal = null; s.screen = s.city ? 'map' : noCity(); render(); return; }
    // The deck: the queue, the Signal or Noise panel, and the district filter.
    if (go && go.startsWith('signal:')) { openSignal(go.slice(7)); return; }
    if (go && go.startsWith('filter:')) {
      const id = go.slice(7);
      s.filter = id === 'all' || s.filter === id ? null : id;
      s.signal = null; s.screen = 'map'; render(); return;
    }
    if (act === 'investigate-next') {
      const { q, items, drills } = deckQueue();
      const next = items[0] || drills[0] || q.low[0];
      if (next) openSignal(next.id); else render();
      return;
    }
    if (act && act.startsWith('clue:')) { scanClue(act.slice(5)); return; }
    if (act && act.startsWith('tag:')) { tagSignal(act.slice(4)); return; }
    if (act === 'close-signal') { closeSignal(); return; }
    if (act === 'toggle-low') { s.lowOpen = !s.lowOpen; render(); return; }
    if (act === 'toggle-queue') { s.queueOpen = !s.queueOpen; render(); focusEl(findByAttr(frame, 'data-act', 'toggle-queue')); return; }
    if (act && act.startsWith('sev:')) {
      const k = act.slice(4);
      s.sev = k === 'all' || s.sev === k ? null : k;
      if (k === 'all') s.filter = null;
      s.queueOpen = false; s.signal = null; render(); focusEl(findByAttr(frame, 'data-act', act)); return;
    }
    if (act === 'batch-fine') { batchFine(); return; }
    // YOUR FILE, its Start over, and its publish sheet.
    if (go === 'profile') { openProfile(); return; }
    if (profileAct(act, el)) return;
    // A signal's offer: the 2 questions on that concept, or "still know it".
    // Only the offer on screen answers (a stale or made-up id does nothing).
    if (act && (act.startsWith('offer-yes:') || act.startsWith('offer-no:'))) {
      const yes = act.startsWith('offer-yes:');
      const c = act.slice(yes ? 10 : 9);
      if (!(s.signal && s.signal.offer && s.signal.offer.id === c)) return;
      if (!yes) { keepProfile(declineOffer(s.profile, c, now())); s.signal = { ...s.signal, offer: null }; render(); return; }
      const bank = drawBank();
      const keys = askable(c) ? drawConcept(bank, c, historyFor(s.profile, bank), { bOf: difficultyOf(s.profile, s.bank) }) : [];
      const first = keys.length ? s.bank.items.get(keys[0]) : null;
      if (!first) { s.signal = { ...s.signal, offer: null }; render(); return; }
      // Back to the range on the next drill (this one's answer was just shown), or to the deck.
      const back = s.screen === 'range' ? 'range' : 'map';
      if (back === 'range' && s.range) s.range = { ...s.range, i: s.range.i + 1 };
      s.signal = null;
      openVisit(first.lessonId, keys, { concept: c, back });
      return;
    }
    if (go === 'training') { s.lesson = null; s.screen = 'training'; render(); focusHeading(frame); return; }
    if (go === 'boss') { s.screen = s.scan.running ? 'boss' : noCity(); render(); return; }
    if (go === 'city') { s.pendingCity = false; s.lesson = null; s.screen = 'map'; render(); return; }
    // A lesson opened from YOUR FILE comes back to it.
    if (go && go.startsWith('lesson:')) { startVisit(go.slice(7), s.screen === 'profile' ? { back: 'profile' } : {}); return; }
    // A district on the sweep: the lesson for that area. Finishing it comes back here.
    if (go && go.startsWith('learn:')) {
      // A district whose lessons are all done opens nothing (its card isn't a
      // button any more; this guards a stale click). Reviewing is `review:`.
      const l = learnFor()(go.slice(6));
      if (l && !l.done) startVisit(l.lesson.id, { fromSweep: true });
      return;
    }
    // The optional review on a DONE district: its first lesson, coming back the same way.
    if (go && go.startsWith('review:')) {
      const l = learnFor()(go.slice(7));
      if (l) startVisit(nextReview(l.list || [l.lesson]).id, { fromSweep: true });
      return;
    }
    if (act === 'start-checkup') { if (!s.scan.running) win.RescueHost.startCheckup(); return; }
    if (act && act.startsWith('answer:')) {
      if (s.lesson && s.lesson.picked == null) {
        const list = questionsOf(s.lesson);
        const n = Number(act.slice(7));
        const q = list[s.lesson.q];
        if (!q || !Array.isArray(q.options) || !q.options[n]) return;
        s.lesson.picked = n;
        // Every answer is evidence, right or wrong (an item the bank doesn't
        // know records nothing). Answering the last item finishes the visit:
        // it counts even if the person then leaves (SEE YOUR CITY, BACK TO THE
        // CHECKUP) without FINISH. Whether anything is learned is the IRT rule's
        // to say (player-profile.js), never this count.
        let next = q.key ? recordAnswer(s.profile, s.bank, q.key, q.options[n].correct === true, now()) : s.profile;
        if (s.lesson.q >= list.length - 1 && !s.lesson.concept) next = recordVisit(next, s.lesson.id, now());
        if (next !== s.profile) keepProfile(next);
        render();
      }
      return;
    }
    if (act === 'next-question' && s.lesson) {
      if (s.lesson.q >= questionsOf(s.lesson).length - 1) return;
      s.lesson = { ...s.lesson, q: s.lesson.q + 1, picked: null, showTeach: teachAt(s.lesson.keys, s.lesson.q + 1) };
      render();
      return;
    }
    // Each answer was saved as it was given; leaving part-way keeps those but
    // makes nothing done. FINISH (after the last answer) is the visit.
    if (act === 'finish-lesson' && s.lesson) {
      const rec = s.profile.lessons[s.lesson.id];
      // "Learn this" questions on one concept (s.lesson.concept) are no visit to a lesson.
      if (!s.lesson.concept && !(rec && rec.visited)) keepProfile(recordVisit(s.profile, s.lesson.id, now()));
      // A lesson opened from the sweep goes back to the sweep, or, once the
      // checkup has finished, to the city: never the Training Grounds' list.
      const fromSweep = s.lesson.fromSweep;
      // One opened from elsewhere (s.lesson.back) goes back there.
      s.screen = s.lesson.back ? s.lesson.back : !fromSweep ? 'training' : s.scan.running ? 'boss' : s.city ? 'map' : noCity();
      if (s.screen === 'range' && !s.range) s.screen = s.city ? 'map' : noCity();
      if (s.screen === 'map') s.pendingCity = false;
      s.lesson = null;
      render();
      return;
    }
    if (go && go.startsWith('rc:')) { if (s.rc) goRc(go.slice(3)); return; }
    if (act === 'confirm-from-scan') { if (s.rc) confirmFromScan(); return; }
    if (go === 'map') { s.screen = 'map'; s.signal = null; render(); return; }
    if (go && go.startsWith('district:')) { s.screen = 'district'; s.districtId = go.slice(9); s.districtMsg = ''; render(); focusHeading(frame); return; }
    if (act === 'bulk-did' || act === 'bulk-later') {
      const ids = ticked();
      if (!ids.length || s.screen !== 'district') return;
      if (act === 'bulk-did') { recheckMany(ids); return; }
      let p = s.progress;
      for (const id of ids) {
        const m = mission(id);
        if (m) p = setStatus(p, m.id, 'later', m.module, now(), { districtId: m.districtId, title: m.title });
      }
      keep(p);
      s.districtMsg = `${ids.length} saved for later.`;
      render();
      return;
    }
    if (go && go.startsWith('milestone:')) { s.screen = 'milestone'; s.districtId = go.slice(10); render(); focusHeading(frame); return; }
    if (go && go.startsWith('mission:')) { s.screen = 'mission'; s.missionId = go.slice(8); render(); focusHeading(frame); return; }
    if (act === 'i-did-it') { recheck(s.missionId, 'i-did-it'); return; }
    if (act === 'recheck') { recheck(s.outcomeMission && s.outcomeMission.id, s.trigger, s.recheckModules); return; }
    if (act === 'later') {
      const m = mission(s.missionId);
      if (m) {
        keep(setStatus(s.progress, m.id, 'later', m.module, now(), { districtId: m.districtId, title: m.title }));
        s.screen = 'district'; s.districtId = m.districtId;
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
  // `confirmedId`: the mission "Finish from the checkup" just filed.
  function applyResult(r, refused = '', confirmedId = null) {
    if (!r || r.incomplete) return; // an unfinished form stays as the person left it
    const before = s.rcState;
    setRcState(r.state);
    creditReports(before, s.rcState, confirmedId);
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
    // Filed the same way as the person's own debrief (fileRc), so nothing the
    // game does on filing is skipped.
    const r = q ? fileRc(s.rc, s.rcState, id, { [q.id]: 'completed' }) : { incomplete: true };
    if (r.incomplete) {
      s.linkNotice = `<p class="link-notice" role="status">${esc('This one has a few questions only you can answer. Use I DID IT below.')}</p>`;
      render(); return;
    }
    s.scanConfirmed = markScanConfirmed(s.scanConfirmed, id, now());
    saveScanConfirmed(storage, s.scanConfirmed);
    applyResult(r, '', id);
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
  // Escape on YOUR FILE closes what is on top: the publish sheet, the Start
  // over question, then the screen itself.
  frame.addEventListener('keydown', (e) => {
    if (!e || s.screen !== 'profile' || s.busy) return;
    const view = s.profileView || {};
    const act = profileKeyAct(e.key, { confirming: !!view.confirming, sheet: !!view.publish });
    if (!act) return;
    if (typeof e.preventDefault === 'function') e.preventDefault();
    profileAct(act, null);
  });
  // Escape closes the Signal or Noise panel, like BACK TO THE DECK. Inside a
  // fix or mark card, Escape belongs to that card (it closes its question).
  frame.addEventListener('keydown', (e) => {
    if (!e || e.key !== 'Escape' || s.screen !== 'map' || !s.signal || s.busy) return;
    const t = e.target;
    if (t && typeof t.closest === 'function' && t.closest('[data-mark-card],[data-fix-module]')) return;
    if (typeof e.preventDefault === 'function') e.preventDefault();
    closeSignal();
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
  shadow.addEventListener('change', (e) => {
    if (e && e.target && typeof e.target.hasAttribute === 'function' && e.target.hasAttribute('data-pick')) { updateBulk(); return; }
    if (s.rc) refreshDebriefForm(e, s.rc);
  });
  shadow.addEventListener('input', (e) => { if (s.rc) refreshDebriefForm(e, s.rc); });

  // The app's own fix and mark flows (FixFlow, MarkFlow), delegated on the frame so they survive re-renders.
  // A change refused because a sweep is running (main's scan gate) tried
  // nothing: no re-check, no outcome screen, and it isn't the last fix.
  const refusedMidScan = (result) => !!(result && result.error === 'scan_running');
  win.FixFlow.attach(frame, win.rescue, { onResult: ({ kind, module, result, described }) => {
    if (refusedMidScan(result)) return;
    if (kind === 'fix') s.lastFix = { missionId: s.missionId, module, result };
    if (kind === 'undo' && described && described.restored) s.lastFix = null;
    if (described && (described.tone === 'success' || described.tone === 'info' || described.restored)) recheck(s.missionId, kind === 'undo' ? 'undo' : 'fix');
  } });
  win.MarkFlow.attach(frame, win.rescue, { onResult: ({ kind, result, described }) => {
    if (refusedMidScan(result)) return;
    if (described && described.done) recheck(s.missionId, kind === 'removed' ? 'unmark' : 'mark', modulesCoveredBy(result && result.ids));
  } });

  // A fresh city from a finished scan: back to the map, forgetting the last screen's state.
  function showCityFrom(doc) {
    // A sweep that finishes while the person is in the generated district leaves them there.
    const stay = s.screen === 'side' && inCity();
    s.shown += 1;
    const prev = signalsNow();
    rebuild(doc);
    // A new scan, not the same one shown again, is a sweep.
    if (doc !== s.sweptDoc) newSweep(doc, prev);
    s.screen = stay ? 'side' : 'map'; s.outcome = null; s.lastFix = null; s.linkNotice = ''; s.rcRoute = null; s.landing = null;
    s.lesson = null; s.pendingCity = false;
    s.signal = null; s.filter = null; s.lowOpen = false; s.range = null; s.queueOpen = false; s.sev = null;
    // A new sweep that holds something says NEW on the tile again.
    if (doc !== s.sweptDocSeen) { s.sideSeen = false; s.sweptDocSeen = doc; }
    s.focusPending = !stay;
  }

  // A new worry: no city until its scan finishes.
  function newWorry(situation) {
    s.situation = situation;
    // Only city mode's own home lands on the deck before a sweep (showHome).
    if (!isCityHome(situation)) s.homeFirst = false;
    s.city = null; s.doc = null;
    s.scan = idleScan();
    s.pendingCity = false;
    s.lesson = null;
  }

  // show, showTraining, showBoss, scanDone and scanFailed return render()'s
  // answer: false means the person is already back on Plain view's screens.
  return {
    isReady: true,
    // The display mode changed: save once now, so city mode retires the old
    // store at once, and the lessons are read for the new mode.
    profileModeChanged() {
      persist();
      s.progress = viewOf(s.profile);
      // A visit drawn for the other mode isn't carried on (city mode skips some items).
      if (s.screen === 'lesson') { s.lesson = null; s.screen = s.city ? 'map' : noCity(); }
      // Only while the city is on screen: otherwise the next show draws it.
      if (drawnScreen !== null && cityShown()) render();
    },
    // Plain view changed the profile (Start over in "Your progress"): read it
    // again, so the game's next save doesn't put the old one back.
    reloadProfile() {
      s.profile = loadProfile(storage, now(), { onProblem: (code) => { s.saveNotice = noticeFor(code); } });
      s.progress = viewOf(s.profile);
      if (s.screen === 'profile') s.profileView = { ...(s.profileView || { from: 'map' }), confirming: false, publish: null };
      if (drawnScreen !== null && cityShown()) render();
    },
    show(doc, situation) {
      s.situation = situation;
      // A city shown from a finished scan: no game scan is running any more
      // (the person may have left the boss screen with "Plain view").
      if (s.scan.running) { s.boss = bossFinish(s.boss); s.scan = idleScan(); }
      showCityFrom(doc);
      return render();
    },
    update(doc) { rebuild(doc); render(); },
    // A new worry in game mode: its scan starts at once (showBoss), no Training Grounds first.
    newWorry,
    // A new worry's Training Grounds.
    showTraining(situation) {
      newWorry(situation);
      s.homeFirst = false;
      s.screen = 'training';
      return render();
    },
    // City mode's home: the command deck, before any sweep this session. The
    // sweep is its main action; lessons are visits from its districts, and
    // the Training Grounds is a button on its top bar, never the landing.
    showHome(situation) {
      newWorry(situation);
      s.homeFirst = true;
      s.screen = 'home';
      return render();
    },
    showBoss() {
      s.boss = bossInit();
      s.tipsOpen = false; // one line; the details only when asked for
      s.scan = { running: true, index: 0, total: 0, error: null };
      s.pendingCity = false;
      s.screen = 'boss';
      const ok = render();
      Promise.resolve().then(() => win.RescueHost.scanTips()).then((t) => {
        s.tips = Array.isArray(t) ? t : [];
        if (s.screen === 'boss') render();
      }, () => {});
      return ok;
    },
    // The skip bar's "N of M checks" is the boss meter's finished-check count.
    scanEvent(ev) {
      if (!s.scan.running) return;
      s.boss = bossApply(s.boss, ev);
      s.scan = { ...s.scan, index: s.boss.index, total: s.boss.total };
      if (s.screen === 'boss' || s.screen === 'training' || s.screen === 'home') render();
    },
    // Mid-lesson, the person stays in the lesson with a banner; otherwise the city.
    scanDone(doc, situation) {
      s.boss = bossFinish(s.boss);
      s.scan = { running: false, index: s.boss.total, total: s.boss.total, error: null };
      if (situation) s.situation = situation;
      const inLesson = afterScanDone(s.screen) === 'banner';
      const lesson = s.lesson;
      showCityFrom(doc);
      if (inLesson) { s.lesson = lesson; s.screen = 'lesson'; s.pendingCity = true; s.focusPending = false; }
      return render();
    },
    // Never a frozen boss screen: back to the Training Grounds with the error.
    scanFailed(message) {
      s.boss = bossFinish(s.boss);
      s.scan = { running: false, index: 0, total: 0, error: String(message || 'The checkup stopped.') };
      if (s.screen !== 'lesson') s.screen = noCity();
      return render();
    },
  };
}
