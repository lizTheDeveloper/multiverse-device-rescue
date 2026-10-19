// Little missions in the city: the controller's part that groups the scan
// into missions, runs one at a time (missions/runner.js), and carries each
// act out through the paths the city already has (MarkFlow, FixFlow, the
// re-check, open-setting). The controller owns the DOM, the profile and the
// deck; it hands this desk what it needs as `deps`.
import { groupMissions, buildTable, missionCounts } from '../missions/types.js';
import { loadGames, gameFor, ownGames } from '../missions/games/index.js';
import { assemble, resolveLink, unfinishedModules } from '../missions/research.js';
import * as Run from '../missions/runner.js';
import { renderMissionRows, renderMissionScreen, nextMissionLine } from './views/mission-run.js';
import { roundOf, markRound, recordRound, keepAnswer, recallAnswer, decisionHash, conceptState } from './profile/player-profile.js';
import { conceptById } from './profile/skills.js';
import { award, confirmItem, missionKey, MONITORING_MODULES } from './ledger.js';
import { esc } from './escape.js';

const visible = (s) => String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
const SETTING_SCHEME = /^(?:x-apple\.systempreferences:|ms-settings:)/;

/*
 * deps: {
 *   win, mode() -> 'standard'|'city', platform(), districtName(id), place() -> help district name (city) or '',
 *   getProfile(), keepProfile(p), bank(), commitAward(result) -> points, logEntry(kind, text), now(),
 *   evidenceRows(finding, mode), renderEvidence(rows, module, gameCopy) (the controller's clipboard rule),
 *   rebuild(doc), docChanged(doc), sweeping(), stopped(), render(), focusHeading(), watchedOpts(),
 *   openConcept(concept) -> boolean, deck() -> the ledger's deck, setScreen(name), modulesCoveredBy(markIds),
 *   onGames(registry)?, loadMissionGames?
 * }
 */
export function createMissionDesk(deps) {
  const d = { reg: null, missions: [], run: null, runs: new Map(), answered: new Map(), odd: new Set(), notice: '', act: null,
    busy: false, doc: null, unfinished: new Set(), paidSummary: new Set() };
  const mode = () => (deps.mode() === 'standard' ? 'standard' : 'city');
  const table = () => buildTable(ownGames(d.reg));
  const notesModule = () => (d.reg && d.reg.modules && d.reg.modules.notes) || null;

  new Promise((r) => r((deps.loadMissionGames || loadGames)())).catch(() => null).then((reg) => {
    d.reg = reg;
    if (d.doc) regroup();
    deps.onGames && deps.onGames(reg);
  });

  function regroup() {
    const nm = notesModule();
    d.missions = groupMissions(d.doc, { mode: mode(), table: table(), odd: d.odd, batchNotes: nm && typeof nm.batchNotes === 'function' ? nm.batchNotes : null });
    d.unfinished = unfinishedModules(d.doc);
    // A run under way follows the new scan: answers kept for items still there.
    if (d.run) {
      const m = mission(d.run.missionId);
      if (m) {
        const keys = new Set(m.items.map((i) => i.key));
        const kept = d.run.results.filter((r) => keys.has(r.key));
        const gone = d.run.results.filter((r) => !keys.has(r.key));
        d.run = { ...d.run, items: m.items, results: [...gone, ...kept], index: Math.min(d.run.index, Math.max(0, m.items.length - 1)) };
        // On the first unanswered item from where the person was (or the summary).
        if (d.run.phase === 'item' && !d.run.pending) d.run = Run.skip({ ...d.run, index: d.run.index - 1 });
      }
    }
  }

  const mission = (id) => d.missions.find((m) => m.id === id) || null;
  const gameOf = (type) => gameFor(d.reg, type);

  function ctxFor(m, extra = {}) {
    const md = mode();
    return { mode: md, practice: false, platform: deps.platform(), districtName: deps.districtName(m ? m.district : null),
      esc: (s) => esc(visible(s)), visible, evidenceRows: (f, o = {}) => deps.evidenceRows(f, (o && o.mode) || md),
      resolve: (l) => resolveLink(l, { mode: md, platform: deps.platform() }), notes: m && m.notes ? notesProgress(m) : undefined, ...extra };
  }

  // Remembered answers: the decision kept for this item while its evidence holds.
  function recalledFor(m) {
    const p = deps.getProfile();
    const game = gameOf(m.type);
    const out = {};
    for (const item of m.items) {
      if (d.answered.has(item.key)) { out[item.key] = d.answered.get(item.key); continue; }
      const h = recallAnswer(p, item.key, Run.fingerprint(item));
      if (!h) continue;
      let id = 'kept';
      try { const hit = (game.decisions(item, ctxFor(m)) || []).find((x) => x && decisionHash(x.id) === h); if (hit) id = hit.id; } catch (_) { /* kept */ }
      out[item.key] = id;
    }
    return out;
  }
  function statusOf(m) {
    const rec = recalledFor(m);
    const decided = m.items.filter((i) => rec[i.key]).length;
    return { decided, done: decided === m.items.length };
  }
  const unfinishedMissions = () => d.missions.filter((m) => !m.notes && !statusOf(m).done);

  function notesProgress(m) {
    const all = d.missions.filter((x) => x.notes);
    const area = all.filter((x) => x.district === m.district);
    const sorted = (list) => list.reduce((n, x) => n + statusOf(x).decided, 0);
    const total = (list) => list.reduce((n, x) => n + x.items.length, 0);
    const cleared = area.every((x) => statusOf(x).done);
    return { sorted: sorted(all), total: total(all), areaSorted: sorted(area), areaTotal: total(area),
      batchPoints: 0, cleared, bonus: 0 };
  }

  // --- opening a mission ---
  function open(id) {
    const m = mission(id);
    if (!m) return false;
    const game = gameOf(m.type);
    const p = deps.getProfile();
    const was = d.runs.get(id);
    if (was && was.phase !== 'summary') d.run = was;
    else {
      const concepts = (game.concepts || []).filter((c) => conceptById(c));
      const due = !!(game.practice && game.practice.script && game.practice.script.length)
        && Run.practiceDue(roundOf(p, m.type), concepts.map((c) => conceptState(p, deps.bank(), c)));
      d.run = Run.startRun(m, { practiceDue: due, recalled: recalledFor(m) });
    }
    d.notice = ''; d.act = null;
    if (d.run.phase === 'summary') enterSummary();
    return true;
  }
  const keepRun = () => { if (d.run) d.runs.set(d.run.missionId, d.run); };

  // --- points, remembering ---
  function afterResults(before) {
    const m = mission(d.run.missionId);
    const fresh = d.run.results.filter((r) => !before.some((b) => b.key === r.key && b.decision === r.decision) && r.outcome === 'done');
    for (const r of fresh) {
      if (!r.effect || r.effect.kind === 'later') continue;
      d.answered.set(r.key, r.decision);
      if (Run.remembers(r)) deps.keepProfile(keepAnswer(deps.getProfile(), r.key, Run.fingerprint(r.item), r.decision, deps.now()));
      // Notes pay per batch; every other decided item pays once, ever. A
      // monitoring check's item pays nothing, whatever was decided.
      if (m && !m.notes) {
        const pts = deps.commitAward(award(deps.deck(), 'decide', missionKey(r.item.finding.module, r.key)));
        if (pts) d.run = Run.addPoints(d.run, r.key, pts);
      }
    }
    if (d.run.phase === 'summary') enterSummary();
    keepRun();
  }
  function enterSummary() {
    const m = mission(d.run.missionId);
    if (!m || d.paidSummary.has(m.id + d.run.results.map((r) => r.key).join('|'))) return;
    d.paidSummary.add(m.id + d.run.results.map((r) => r.key).join('|'));
    const allDecided = m.items.every((i) => d.run.results.some((r) => r.key === i.key && r.decision !== 'later'));
    if (!allDecided) return;
    // The lead module is a monitoring check's whenever one is in the mission: then no bonus.
    const lead = (m.items.find((i) => MONITORING_MODULES.has(i.finding.module)) || m.items[0]).finding.module;
    const keys = m.items.map((i) => i.key).sort();
    if (m.notes) {
      const pts = deps.commitAward(award(deps.deck(), 'notesBatch', missionKey(lead, ...keys)));
      d.batchPoints = pts;
      if (notesProgress(m).cleared) {
        const bonus = deps.commitAward(award(deps.deck(), 'notesArea', missionKey(lead, 'area', m.district)));
        d.areaBonus = bonus;
      }
    } else {
      deps.commitAward(award(deps.deck(), 'mission', missionKey(lead, ...keys)));
    }
    // Notes the person called odd become items of their own type now.
    const odd = d.run.results.filter((r) => r.effect && r.effect.kind === 'odd').map((r) => r.key);
    if (odd.length) { odd.forEach((k) => d.odd.add(k)); regroup(); }
  }

  // --- the acts ---
  async function carryOut(act) {
    d.act = null;
    if (!act) return;
    const w = deps.win;
    if (act.kind === 'steps') { d.notice = ''; return; }
    if (act.kind === 'odd') return;
    if (act.kind === 'settings' || act.kind === 'link') {
      const url = act.url;
      if (url && SETTING_SCHEME.test(url)) { Promise.resolve().then(() => w.rescue.openSetting(url)).catch(() => {}); d.notice = mode() === 'city' ? 'Opened the settings. Make the change there, then come back.' : 'Opened in Settings. You make the change there, then come back here.'; return; }
      // Standard mode: a look-up opens in the browser (main re-checks it against
      // research.js's templates). City mode never opens one: a watched computer
      // keeps browser history, so it is words to search somewhere else.
      if (url && mode() !== 'city' && w.rescue && typeof w.rescue.openLookup === 'function') {
        d.notice = 'Opened in your browser.';
        Promise.resolve().then(() => w.rescue.openLookup(url)).then((ok) => {
          if (ok === false) { d.notice = `Search in your browser: ${url}`; deps.render(); }
        }).catch(() => {});
        return;
      }
      if (url && mode() === 'city') { d.notice = act.text || 'Search for it on another device.'; return; }
      // The runner already put the decision's steps on screen (run.guide).
      d.notice = act.text || (url ? `Search in your browser: ${url}` : (act.steps && act.steps.length ? '' : 'There is no page to open for this one.'));
      return;
    }
    if (act.kind === 'lesson') { deps.openConcept(act.concept); return; }
    if (deps.stopped() && (act.kind === 'mark' || act.kind === 'fix')) {
      d.notice = 'Fixes and marks open after a sweep that finishes.';
      d.run = Run.cancelPending(d.run); keepRun(); return;
    }
    if (act.kind === 'mark') {
      const html = w.MarkFlow.markControlsHtml({ ...act.item.finding }, { ...deps.watchedOpts(), theme: 'game' });
      if (!html) { d.notice = mode() === 'city' ? 'This one can’t be marked from here.' : 'This one can’t be marked as yours from here.'; d.run = Run.cancelPending(d.run); return; }
      d.act = { kind: 'mark', html, item: act.item };
      return;
    }
    if (act.kind === 'fix') {
      const html = w.FixFlow.fixControlsHtml({ ...act.item.finding }, { ...act.options, ...(act.options && act.options.watched ? { place: deps.place() } : {}) });
      if (!html) { d.notice = mode() === 'city' ? 'No patch the city can make for this one.' : 'There’s no fix the app can make for this one.'; d.run = Run.cancelPending(d.run); return; }
      d.act = { kind: 'fix', html, item: act.item };
      return;
    }
    if (act.kind === 'recheck') await recheckItem(act.item, act.modules, 'recheck');
  }

  // Re-check an item's checks. 'gone' only when every check ran to the end.
  async function recheckItem(item, modules, why) {
    if (d.busy || deps.sweeping()) { d.notice = 'A sweep is running. Try again when it’s done.'; d.run = Run.cancelPending(d.run); return; }
    d.busy = true; deps.render();
    let ok = true;
    for (const name of modules) {
      let r = null;
      try { r = await deps.win.rescue.recheckModule(name); } catch (_) { r = null; }
      if (!r || !r.ok || (r.module && r.module.complete === false)) ok = false;
      if (r && r.ok) {
        if (!deps.docChanged(r.doc)) { d.busy = false; return; }
        deps.rebuild(r.doc);
      }
    }
    d.busy = false;
    const still = d.missions.some((m) => m.items.some((i) => i.key === item.key || (i.sourceKeys || []).includes(item.key)));
    const before = d.run ? d.run.results.slice() : [];
    if (!ok) {
      d.notice = mode() === 'city' ? 'That check couldn’t run to the end, so this wasn’t confirmed.' : 'That check couldn’t run to the end, so this isn’t confirmed.';
      if (why === 'mark') d.run = Run.settle(d.run, 'done', item); else d.run = Run.settle(d.run, 'cancelled', item);
    } else if (!still) {
      if (why !== 'mark') {
        const pts = deps.commitAward(confirmItem(deps.deck(), missionKey(item.finding.module, item.key), deps.now()));
        if (!MONITORING_MODULES.has(item.finding.module)) deps.logEntry('CONFIRMED', item.finding.title || '');
        d.notice = mode() === 'city' ? `Confirmed: the sweep doesn’t see it any more.${pts ? ` +${pts}` : ''}` : `Checked again: it’s gone.${pts ? ` +${pts} points` : ''}`;
      } else d.notice = '';
      d.run = Run.settle(d.run, 'done', item);
    } else if (why === 'mark') {
      d.run = Run.settle(d.run, 'done', item);
    } else {
      d.notice = mode() === 'city' ? 'Still showing after the check. It stays on the board.' : 'Checked again: it’s still there, so it stays open.';
      d.run = Run.settle(d.run, 'cancelled', item);
    }
    afterResults(before);
    deps.render();
  }

  // FixFlow / MarkFlow results while a mission's act is open. True when handled here.
  function onFlowResult(kind, payload) {
    if (!d.run || !d.act || !d.run.pending) return false;
    const { described, result } = payload || {};
    if (kind === 'fix' && d.act.kind === 'fix') {
      if (described && (described.tone === 'success' || described.tone === 'info')) {
        const item = d.act.item; d.act = null;
        recheckItem(item, item.seen_in && item.seen_in.length ? item.seen_in : [item.finding.module], 'fix');
      }
      return true;
    }
    if (kind === 'mark' && d.act.kind === 'mark') {
      if (described && described.done) {
        const item = d.act.item; d.act = null;
        const also = deps.modulesCoveredBy(result && result.ids);
        recheckItem(item, [...new Set([...(item.seen_in || [item.finding.module]), ...also])], 'mark');
      }
      return true;
    }
    return false;
  }

  // --- drawing ---
  function screenHtml() {
    const run = d.run;
    const m = run && (mission(run.missionId) || { id: run.missionId, type: run.type, district: '', items: run.items, title: gameOf(run.type).title, part: 1, of: 1 });
    if (!run || !m) return null;
    const game = gameOf(run.type);
    const practice = run.phase === 'practice';
    const ctx = ctxFor(m, { practice });
    const pv = Run.viewFor(run, game, ctx, {});
    const item = pv.item;
    let research = { rows: [], what: '', links: [], unfinished: '' };
    let card = '';
    let evidence = '';
    if (item && (run.phase === 'item' || run.phase === 'confirm' || practice)) {
      let raw = null;
      try { raw = game.research(item, ctx); } catch (_) { raw = null; }
      research = assemble(game, item, ctx, { unfinished: practice ? new Set() : d.unfinished });
      if (item.unfinished && !research.unfinished) research.unfinished = 'This check didn’t finish, so it may have missed something here.';
      const view = { ...pv, research, item };
      try { card = String(game.render(view, ctx) || ''); } catch (_) { card = `<div class="mg-card"><h3>${ctx.esc(item.finding && item.finding.title)}</h3></div>`; }
      evidence = practice ? '' : deps.renderEvidence(research.rows, item.finding && item.finding.module, !(raw && raw.copy === false));
    }
    let summary = '';
    if (run.phase === 'summary') {
      const sctx = ctxFor(m);
      if (m.notes && sctx.notes) sctx.notes = { ...sctx.notes, batchPoints: d.batchPoints || 0, bonus: d.areaBonus || 0 };
      try { summary = String(game.summary(Run.summaryResults(run), sctx) || ''); } catch (_) { summary = ''; }
    }
    const points = run.results.reduce((n, r) => n + (r.points || 0), 0);
    const next = unfinishedMissions().find((x) => x.id !== m.id) || null;
    return renderMissionScreen({ mission: m, run, view: pv, mode: mode(), districtName: deps.districtName(m.district), cardHtml: card,
      evidenceHtml: evidence, research, actHtml: d.act ? d.act.html : '', notice: d.notice, summaryHtml: summary, points,
      nextMission: next, place: deps.place(), busy: d.busy, canPractice: !!(game.practice && game.practice.script && game.practice.script.length) });
  }

  function districtMissionsHtml(districtId) {
    const list = d.missions.filter((m) => m.district === districtId);
    if (!list.length) return '';
    return renderMissionRows(list, { mode: mode(), status: statusOf });
  }

  // --- clicks; true when handled ---
  function click(act, go) {
    if (go && go.startsWith('mx:')) { if (open(go.slice(3))) { deps.setScreen('mx'); deps.render(); deps.focusHeading(); } return true; }
    if (!act || !act.startsWith('mx-') || !d.run) return false;
    const game = gameOf(d.run.type);
    const m = mission(d.run.missionId);
    const ctx = ctxFor(m);
    if (d.busy) return true;
    d.notice = '';
    const before = d.run.results.slice();
    if (act.startsWith('mx-decide:')) {
      const r = Run.choose(d.run, act.slice(10), game, ctx);
      d.run = r.run;
      afterResults(before);
      const mid = d.run.results.slice();
      Promise.resolve(carryOut(r.act)).then(() => { afterResults(mid); deps.render(); });
    } else if (act === 'mx-confirm') {
      const r = Run.confirmPending(d.run, game, ctx);
      d.run = r.run;
      afterResults(before);
      const mid = d.run.results.slice();
      Promise.resolve(carryOut(r.act)).then(() => { afterResults(mid); deps.render(); });
    } else if (act === 'mx-continue') {
      d.run = Run.proceed(d.run);
      afterResults(before);
    } else if (act === 'mx-cancel') {
      d.act = null; d.run = Run.cancelPending(d.run);
    } else if (act === 'mx-skip') {
      d.run = Run.skip(d.run);
    } else if (act === 'mx-practice') {
      d.run = Run.startPractice(d.run, game);
    } else if (act === 'mx-know') {
      deps.keepProfile(markRound(deps.getProfile(), d.run.type, 'skipped', deps.now()));
      d.run = Run.skipPractice(d.run);
    } else if (act === 'mx-practice-leave') {
      d.run = Run.skipPractice(d.run);
    } else if (act.startsWith('mx-practice-move:')) {
      const r = Run.choosePractice(d.run, game, act.slice(17));
      d.run = r.run;
      if (r.answer && r.answer.right !== null) {
        const concepts = (game.concepts || []).filter((c) => conceptById(c));
        deps.keepProfile(recordRound(deps.getProfile(), deps.bank(), d.run.type, r.answer.step, concepts, r.answer.right, deps.now()));
      }
    } else if (act === 'mx-practice-next') {
      d.run = Run.nextPracticeStep(d.run, game);
      if (d.run.phase !== 'practice' && d.run.practiced) deps.keepProfile(markRound(deps.getProfile(), d.run.type, 'played', deps.now()));
    } else if (act.startsWith('mx-link:')) {
      const item = Run.currentItem(d.run);
      const links = item ? assemble(game, item, ctx, { unfinished: d.unfinished }).links : [];
      const l = links[Number(act.slice(8))];
      if (l) carryOut({ kind: l.kind === 'settings' ? 'settings' : 'link', url: l.url, text: l.text, item, steps: [] });
    } else if (act.startsWith('mx-lesson:')) {
      keepRun();
      deps.openConcept(act.slice(10));
      return true;
    } else if (act === 'mx-next') {
      const next = unfinishedMissions().find((x) => x.id !== d.run.missionId);
      keepRun();
      if (next && open(next.id)) { deps.render(); deps.focusHeading(); return true; }
      deps.setScreen('map');
    } else return false;
    keepRun();
    deps.render();
    return true;
  }

  return {
    rebuild(doc) { d.doc = doc; regroup(); },
    // A fresh sweep: answers made this session stay remembered in the profile; runs start again.
    newSweep() { d.runs.clear(); d.run = null; d.paidSummary.clear(); d.odd.clear(); if (d.doc) regroup(); },
    missions: () => d.missions,
    counts: () => missionCounts(d.missions),
    nextMission: () => unfinishedMissions()[0] || null,
    nextLine: () => nextMissionLine(unfinishedMissions()[0] || null, mode()),
    hud: () => { const todo = d.missions.filter((m) => !m.notes); return { done: todo.filter((m) => statusOf(m).done).length, total: todo.length }; },
    open, click, screenHtml, districtMissionsHtml, onFlowResult,
    active: () => !!d.run,
    rounds: () => ownGames(d.reg).filter((g) => g.practice && g.practice.script).map((g) => ({ type: g.type, concepts: g.concepts || [], steps: g.practice.script.length })),
    ownTypes: () => (d.reg ? [...d.reg.own] : []),
    state: d,
  };
}
