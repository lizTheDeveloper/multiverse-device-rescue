// Little missions in the city: the controller's part that groups the scan
// into missions, runs one at a time (missions/runner.js), and carries each
// act out through the paths the city already has (MarkFlow, FixFlow, the
// re-check, open-setting). The controller owns the DOM, the profile and the
// deck; it hands this desk what it needs as `deps`.
import { groupMissions, buildTable, missionCounts, missionRows } from '../missions/types.js';
import { loadGames, gameFor, ownGames } from '../missions/games/index.js';
import { assemble, resolveLink, unfinishedModules } from '../missions/research.js';
import * as Run from '../missions/runner.js';
import { renderMissionScreen, nextMissionLine } from './views/mission-run.js';
import { renderMissionList } from './views/district.js';
import { roundOf, markRound, recordRound, keepAnswer, recallAnswer, forgetAnswer, decisionHash, conceptState } from './profile/player-profile.js';
import { conceptById } from './profile/skills.js';
import { award, confirmItem, missionKey } from './ledger.js';
import { isMonitoringModule } from '../missions/contract.js';

// Points and remembering (the controller's ruling after the security round):
// only an item from a monitoring check (any of its findings) pays nothing and
// is remembered for this session only. Other warned items (a remote-access
// tool, an unknown background task, removal_alert) still warn, and pay and are
// remembered like any other. contract.js isMonitoringFinding also counts
// removal_alert and safety notes, so it is the warning rule, not this one.
// `monitoringApp`: one key of an app a monitoring check flagged (types.js keysOf).
export const isMonitoringItem = (item) => !!item && typeof item === 'object' && (item.monitoringApp === true
  || [item.finding, ...(Array.isArray(item.findings) ? item.findings : [])].some((f) => f && isMonitoringModule(f.module)));
// Contract R13: an answer whose effect says `unpaid` (the Guest Book's "Someone I know") is treated the same:
// no points, never kept in the profile, and no mission bonus.
export const isUnpaidResult = (r) => !!(r && r.effect && r.effect.unpaid === true);
import { esc } from './escape.js';

const visible = (s) => String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
const SETTING_SCHEME = /^(?:x-apple\.systempreferences:|ms-settings:)/;

/*
 * deps: {
 *   win, mode() -> 'standard'|'city', platform(), districtName(id), place() -> help district name (city) or '',
 *   getProfile(), keepProfile(p), bank(), commitAward(result) -> points, logEntry(kind, text), now(),
 *   evidenceRows(finding, mode), renderEvidence(rows, module, gameCopy) (the controller's clipboard rule),
 *   safetyNote(finding, { answers }) -> HTML (standard mode: the list's safety note for it, or ''; `answers`: the item's so far),
 *   helpPlace() -> the help district's name in standard mode ('' otherwise),
 *   rebuild(doc), docChanged(doc), sweeping(), stopped(), render(), focusHeading(), watchedOpts(),
 *   openConcept(concept) -> boolean, deck() -> the ledger's deck, setScreen(name), modulesCoveredBy(markIds),
 *   onGames(registry)?, loadMissionGames?
 * }
 */
export function createMissionDesk(deps) {
  // `done`: fixes and marks made from a mission this session, each with its
  // Undo (UX audit P1-5). `undoing`: the one whose Undo is running.
  const d = { reveal: false, reg: null, missions: [], run: null, runs: new Map(), answered: new Map(), odd: new Set(), notice: '', act: null,
    busy: false, doc: null, unfinished: new Set(), paidSummary: new Set(), done: [], doneSeq: 0, undoing: null, laterKeys: new Set() };
  const mode = () => (deps.mode() === 'standard' ? 'standard' : 'city');
  const table = () => buildTable(ownGames(d.reg));
  const notesModule = () => (d.reg && d.reg.modules && d.reg.modules.notes) || null;
  const keyringModule = () => (d.reg && d.reg.modules && d.reg.modules.keyring) || null;

  new Promise((r) => r((deps.loadMissionGames || loadGames)())).catch(() => null).then((reg) => {
    d.reg = reg;
    if (d.doc) regroup();
    deps.onGames && deps.onGames(reg);
  });

  function regroup() {
    const nm = notesModule();
    const km = keyringModule();
    d.missions = groupMissions(d.doc, { mode: mode(), table: table(), odd: d.odd, batchNotes: nm && typeof nm.batchNotes === 'function' ? nm.batchNotes : null,
      perKey: km && typeof km.perKey === 'function' ? km.perKey : null });
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
  const gameOf = (type) => gameFor(d.reg, type, deps.platform());

  function ctxFor(m, extra = {}) {
    const md = mode();
    // helpPlace (standard mode): the help district's name, for a game's own steps that would name the helpline.
    const helpPlace = md === 'standard' && typeof deps.helpPlace === 'function' ? String(deps.helpPlace() || '') : '';
    return { mode: md, practice: false, platform: deps.platform(), districtName: deps.districtName(m ? m.district : null), helpPlace,
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
      // A monitoring item's answer is the session's only.
      if (isMonitoringItem(item)) continue;
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

  // --- progress (UX audit P1-1, P2-8) ---
  // What the person has decided, counted on TO DO's own unit: the list's items
  // (an item's sourceKeys, as types.js missionCounts counts them), so DECIDED
  // can sit beside TO DO and never pass it. Decided is not fixed: TO DO stays
  // the scan's count, and only a re-check takes something off it.
  // `district`: one district's, or every district's. Rows are the district
  // list's (types.js missionRows), so "3 of 9 missions" counts what it shows.
  function progress(district = null) {
    // A list item is decided when every mission item standing for it is (one
    // app's keys are one item each in the Keyring, but one item on the list).
    const all = new Map();
    let notes = 0; let notesSorted = 0;
    const here = d.missions.filter((m) => !district || m.district === district);
    for (const m of here) {
      const rec = recalledFor(m);
      for (const i of m.items) {
        const todo = m.notes ? i.asNote === true : !i.fromNote;
        if (!todo) { notes += 1; if (rec[i.key]) notesSorted += 1; continue; }
        for (const k of i.sourceKeys || [i.key]) all.set(k, (all.has(k) ? all.get(k) : true) && !!rec[i.key]);
      }
    }
    const decided = [...all.values()].filter(Boolean);
    const rows = missionRows(here.filter((m) => !m.notes));
    const rowsDone = rows.filter((r) => r.missions.every((m) => statusOf(m).done)).length;
    return { decided: decided.length, total: all.size, rows: rows.length, rowsDone, notes, notesSorted };
  }

  // A notice about one item names it, so it can't be read as being about the
  // next one on screen (UX audit P2-5).
  const nameOf = (item) => {
    const t = visible((item && item.finding && item.finding.title) || '').trim();
    return t.length > 70 ? `${t.slice(0, 69)}…` : t;
  };
  const about = (item, text) => (nameOf(item) ? `${nameOf(item)}: ${text}` : text);

  // The deck's next missions (UX audit P2-1): the district list's rows not
  // done yet, the one INVESTIGATE NEXT opens first, then by where their next
  // part is in the mission order. Each with its district, size and first
  // undecided item's name.
  function nextRows(limit = 5) {
    const at = new Map(d.missions.map((m, i) => [m.id, i]));
    const rows = missionRows(d.missions.filter((m) => !m.notes)).map((r) => {
      const open = r.missions.find((m) => !statusOf(m).done);
      return open ? { r, open, at: at.get(open.id) } : null;
    }).filter(Boolean).sort((a, b) => a.at - b.at);
    return { rows: rows.slice(0, limit), more: Math.max(0, rows.length - limit) };
  }
  const titleOf = (t, md) => (t && typeof t === 'object' ? t[md === 'city' ? 'city' : 'standard'] : String(t == null ? '' : t));
  function deckMissionsHtml(limit = 5) {
    const { rows, more } = nextRows(limit);
    if (!rows.length) return '';
    const md = mode();
    const SEV = { critical: '<span class="badge crit">CRITICAL</span>', warning: '<span class="badge warn">WARNING</span>' };
    const li = ({ r, open }) => {
      const rec = recalledFor(open);
      const first = open.items.find((i) => !rec[i.key]) || open.items[0];
      const left = r.missions.reduce((k, m) => k + m.items.length - statusOf(m).decided, 0);
      const detail = [deps.districtName(r.district), `${left} ${left === 1 ? 'item' : 'items'} left`, nameOf(first)].filter(Boolean).join(' · ');
      return `<li><button type="button" class="sig mx-deck-row sev-${esc(r.severity)}" data-go="mx:${esc(open.id)}"><span class="sig-badges">${SEV[r.severity] || ''}</span>
        <span class="sig-title">${esc(titleOf(r.title, md))}</span><small>${esc(detail)}</small></button></li>`;
    };
    return `<div class="label mx-deck-label">${esc(md === 'city' ? 'NEXT MISSIONS' : 'NEXT MISSIONS')}</div><ul class="queue mx-deck-missions">${rows.map(li).join('')}</ul>${more
      ? `<p class="intel faint">${esc(`And ${more} more mission${more === 1 ? '' : 's'} in the districts.`)}</p>` : ''}`;
  }

  // --- one-step decisions (UX audit P2-4) ---
  // The decision already chose to fix or to mark, so its flow opens at its own
  // confirm: the flow's open button is hidden and pressed for the person
  // after each draw (afterRender), so FixFlow's or MarkFlow's own confirm is
  // the one click left. Cancel there cancels the decision too.
  function undoWhere() {
    return mode() === 'city' ? 'Once it’s patched, Undo is right here, and on the district’s list under DONE THIS SWEEP.'
      : 'Once it’s done, Undo is right here in this mission, and on the district’s list under DONE THIS SESSION.';
  }
  function oneStep(html, kind) {
    let h = String(html || '');
    if (kind === 'fix') {
      h = h.replace(/(<button\b[^>]*\bdata-fix-open)>/, '$1 hidden>').replace(/(\bdata-fix-cancel)>/, '$1 data-act="mx-cancel">');
      // FixFlow's "Undo is on this item." points at the outcome screen's Undo; in a mission it is the done list.
      const here = deps.win.FixFlow && deps.win.FixFlow.UNDO_HERE;
      if (here) h = h.split(esc(here)).join(esc(undoWhere()));
    } else {
      h = h.replace(/(<button\b[^>]*\bdata-mark-open)>/, '$1 hidden>').replace(/(\bdata-mark-cancel)>/g, '$1 data-act="mx-cancel">');
    }
    return h;
  }
  // After the screen is drawn: open the act's confirm and move focus to it.
  function afterRender(root) {
    if (!root || typeof root.querySelector !== 'function') return;
    // Steps a decision just opened sit below the card, where the sticky decision bar covers them: bring them into
    // view once (an instant jump, no animation; the guide's scroll-margin keeps it clear of the bar).
    if (d.reveal) {
      const guide = root.querySelector('.mx-guide');
      if (guide) { d.reveal = false; if (typeof guide.scrollIntoView === 'function') guide.scrollIntoView({ block: 'nearest' }); }
    }
    if (!d.act || !d.act.open) return;
    const fix = d.act.kind === 'fix';
    const btn = root.querySelector(fix ? '.mx-act [data-fix-open]' : '.mx-act [data-mark-open]');
    if (btn && typeof btn.click === 'function') btn.click();
    // FixFlow moves focus to its confirm itself; MarkFlow doesn't.
    if (fix) return;
    const panel = root.querySelector('.mx-act [data-mark-panel]') || root.querySelector('.mx-act');
    if (panel && typeof panel.focus === 'function') {
      if (typeof panel.setAttribute === 'function') panel.setAttribute('tabindex', '-1');
      panel.focus();
    }
  }

  // --- done, with Undo (UX audit P1-5) ---
  // A fix or a mark made from a mission is listed as done in its mission and
  // on its district's list, with the existing Undo: FixFlow's (an engine fix
  // with a quarantine id) or MarkFlow's "Stop treating this as mine". A fix the
  // engine can't undo shows its own undo steps instead.
  function addDone(kind, item, result) {
    const W = deps.win;
    const m = d.run ? mission(d.run.missionId) : null;
    let undo = '';
    if (kind === 'fix') {
      const said = W.FixFlow && typeof W.FixFlow.describeFixResult === 'function' ? W.FixFlow.describeFixResult(result) : null;
      const qid = said && said.undoId;
      const steps = (result && Array.isArray(result.how_to_undo) && result.how_to_undo.length ? result.how_to_undo
        : (item.finding.fixable && item.finding.fixable.how_to_undo) || []).filter((x) => typeof x === 'string');
      if (qid) {
        undo = `<div class="fix-it mx-undo" data-fix-module="${esc(item.finding.module)}"><button type="button" class="btn-s" data-fix-undo data-quarantine-id="${esc(qid)}">UNDO</button><div class="fix-status" data-fix-status role="status" aria-live="polite"></div></div>`;
      } else if (steps.length && W.FixFlow && typeof W.FixFlow.undoListHtml === 'function') {
        undo = `<details class="mx-undo-steps"><summary>${esc(mode() === 'city' ? 'How to undo it' : 'To undo it')}</summary>${W.FixFlow.undoListHtml(steps)}</details>`;
      }
    } else {
      const id = item.finding.markable && typeof item.finding.markable.id === 'string' ? item.finding.markable.id : '';
      const html = id && W.MarkFlow ? W.MarkFlow.markControlsHtml({ module: item.finding.module, data: { marked_by_user: true, known_item_id: id } }, { ...deps.watchedOpts(), theme: 'game' }) : '';
      undo = String(html || '').replace(/(\bdata-unmark)>Stop treating this as mine</, '$1 aria-label="Undo: stop treating this as mine">UNDO<');
    }
    d.done = d.done.filter((x) => x.key !== item.key);
    d.done.push({ id: `u${d.doneSeq += 1}`, key: item.key, kind, item, state: kind === 'fix' ? 'checking' : 'marked',
      missionId: m ? m.id : (d.run && d.run.missionId) || '', district: m ? m.district : '', modules: item.seen_in && item.seen_in.length ? item.seen_in : [item.finding.module], undo });
  }
  const DONE_WORDS = {
    gone: { badge: 'DONE', standard: 'Fixed, and checked again: it’s gone.', city: 'Patched, and the sweep doesn’t see it any more.' },
    still: { badge: 'CHANGED', standard: 'The change was made, but the re-check still shows it.', city: 'Changed, but the sweep still shows it.' },
    checking: { badge: 'CHANGED', standard: 'The change was made. It isn’t confirmed yet.', city: 'Changed. Not confirmed yet.' },
    marked: { badge: 'DONE', standard: 'Marked as yours. Nothing on your computer changed.', city: 'Marked as yours. Nothing changed on the computer.' },
  };
  function doneHtml(list) {
    if (!list.length) return '';
    const md = mode();
    const row = (e) => {
      const w = DONE_WORDS[e.state] || DONE_WORDS.checking;
      return `<li class="mx-row mx-done mx-undo-row"><span class="badge safe">${esc(w.badge)}</span>
        <span class="mission-text">${esc(nameOf(e.item))}<small class="mission-detail">${esc(w[md])}</small></span>
        ${e.undo ? `<span class="mx-undo-wrap" data-act="mx-undo:${esc(e.id)}">${e.undo}</span>` : ''}</li>`;
    };
    return `<div class="label mx-done-label">${esc(md === 'city' ? 'DONE THIS SWEEP' : 'DONE THIS SESSION')}</div><ul class="missions mx-list mx-done-list">${list.map(row).join('')}</ul>`;
  }
  // Undo went through: the item is open again (its answer forgotten, its
  // mission no longer counts it), and its checks run again to show it.
  // Points are never taken back (ledger.js).
  async function afterUndo(e) {
    d.undoing = null;
    d.done = d.done.filter((x) => x.id !== e.id);
    d.answered.delete(e.key);
    deps.keepProfile(forgetAnswer(deps.getProfile(), e.key));
    const drop = (run) => (run && run.results.some((r) => r.key === e.key) ? { ...run, results: run.results.filter((r) => r.key !== e.key) } : run);
    for (const [id, run] of d.runs) d.runs.set(id, drop(run));
    d.run = drop(d.run);
    d.notice = about(e.item, mode() === 'city' ? 'Put back. Checking again…' : 'Put back the way it was. Checking again…');
    d.listNotice = d.notice;
    deps.render();
    const ok = await recheckModules(e.modules);
    // The current run picks the item up again (from the summary too).
    if (d.run && d.run.phase === 'summary' && mission(d.run.missionId)) {
      const m = mission(d.run.missionId);
      d.run = { ...d.run, items: m.items };
      if (m.items.some((i) => !d.run.results.some((r) => r.key === i.key))) d.run = Run.skip({ ...d.run, index: -1 });
      keepRun();
    }
    // Said only as the scan shows it: back on the list, or not seen by the check right now.
    const back = d.missions.some((m) => m.items.some((i) => i.key === e.key || (i.sourceKeys || []).includes(e.key)));
    d.notice = about(e.item, !ok ? 'Put back, but the check couldn’t run to the end.'
      : back ? (mode() === 'city' ? 'Put back. It’s on the board again.' : 'Put back. It’s on the list again.')
        : (mode() === 'city' ? 'Put back, but the sweep doesn’t see it right now.' : 'Put back, but the check doesn’t show it right now.'));
    // Said on the district's list too, where its Undo may have been.
    d.listNotice = d.notice;
    deps.render();
  }

  // --- opening a mission ---
  function open(id) {
    const m = mission(id);
    if (!m) return false;
    const game = gameOf(m.type);
    const p = deps.getProfile();
    const was = d.runs.get(id);
    if (was && was.phase !== 'summary') {
      // A run kept from before a re-check or an Undo follows the mission as it is now.
      d.run = { ...was, items: m.items, index: Math.min(was.index, Math.max(0, m.items.length - 1)) };
      const cur = Run.currentItem(d.run);
      if (d.run.phase === 'item' && !d.run.pending && (!cur || d.run.results.some((r) => r.key === cur.key))) d.run = Run.skip({ ...d.run, index: d.run.index - 1 });
    } else {
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
      const watched = isMonitoringItem(r.item) || isUnpaidResult(r);
      if (Run.remembers(r) && !watched) deps.keepProfile(keepAnswer(deps.getProfile(), r.key, Run.fingerprint(r.item), r.decision, deps.now()));
      // Notes pay per batch; every other decided item pays once, ever. A
      // monitoring item pays nothing, whatever was decided.
      if (m && !m.notes && !watched) {
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
    // A mission with a monitoring item in it, or an unpaid answer (R13), pays no bonus.
    if (m.items.some(isMonitoringItem) || d.run.results.some(isUnpaidResult)) return regroupOdd();
    const lead = m.items[0].finding.module;
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
    regroupOdd();
  }
  // Notes the person called odd become items of their own type now.
  function regroupOdd() {
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
      if (url && SETTING_SCHEME.test(url)) {
        // Said only once main has opened it (false: refused or failed).
        let ok = false;
        try { ok = (await w.rescue.openSetting(url)) !== false; } catch (_) { ok = false; }
        if (ok) d.notice = mode() === 'city' ? 'Opened the settings. Make the change there, then come back.' : 'Opened in Settings. You make the change there, then come back here.';
        if (ok) openedLock(act.item);
        else d.notice = mode() === 'city' ? 'The settings didn’t open. Open them yourself, then come back.' : 'Settings didn’t open. Open them yourself, then come back here.';
        return;
      }
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
      // The checkup can't record this mark (MarkFlow offers none): the answer
      // is kept here instead (remembered while the evidence holds), so the
      // item is never a dead end. Nothing on the computer changes.
      if (!html) {
        d.notice = about(act.item, mode() === 'city' ? 'Noted as yours here. The sweep will still show it.' : 'Noted as yours in this app. The checkup will still list it.');
        d.run = Run.settle(d.run, 'done', act.item);
        return;
      }
      d.act = { kind: 'mark', html: oneStep(html, 'mark'), item: act.item, open: /\bdata-mark-open\b/.test(html) };
      return;
    }
    if (act.kind === 'fix') {
      const html = w.FixFlow.fixControlsHtml({ ...act.item.finding }, { ...act.options, ...(act.options && act.options.watched ? { place: deps.place() } : {}) });
      if (!html) { d.notice = about(act.item, mode() === 'city' ? 'No patch the city can make for this one.' : 'There’s no fix the app can make for this one.'); d.run = Run.cancelPending(d.run); return; }
      d.act = { kind: 'fix', html: oneStep(html, 'fix'), item: act.item, open: /\bdata-fix-open\b/.test(html) };
      return;
    }
    if (act.kind === 'recheck') await recheckItem(act.item, act.modules, 'recheck');
  }

  // Run checks again; true when every one ran to the end.
  async function recheckModules(modules) {
    d.busy = true; deps.render();
    let ok = true;
    for (const name of modules) {
      let r = null;
      try { r = await deps.win.rescue.recheckModule(name); } catch (_) { r = null; }
      if (!r || !r.ok || (r.module && r.module.complete === false)) ok = false;
      // An unchanged scan means the item is still there: carry on to the answer
      // below rather than leaving the confirm waiting for nothing.
      if (r && r.ok && deps.docChanged(r.doc)) deps.rebuild(r.doc);
    }
    d.busy = false;
    return ok;
  }
  // Lock Run: a settings page that opened is the lock's decision (Turn it on).
  // It is recorded (and pays as a decided item, once) while the item stays on
  // screen, so Done can still check the change; Done's answer replaces it.
  function openedLock(item) {
    const cur = d.run && d.run.type === 'locks' ? Run.currentItem(d.run) : null;
    if (!cur || !item || cur.key !== item.key) return;
    const was = d.run.results.find((r) => r.key === item.key);
    if (was) return;
    const dec = { id: 'on', effect: { kind: 'settings' } };
    d.run = { ...d.run, results: [...d.run.results, { key: item.key, item, decision: dec.id, effect: dec.effect, outcome: 'done', points: 0 }] };
  }

  // Re-check an item's checks. 'gone' only when every check ran to the end.
  async function recheckItem(item, modules, why) {
    if (d.busy || deps.sweeping()) { d.notice = 'A sweep is running. Try again when it’s done.'; d.run = Run.cancelPending(d.run); return; }
    const ok = await recheckModules(modules);
    const still = d.missions.some((m) => m.items.some((i) => i.key === item.key || (i.sourceKeys || []).includes(item.key)));
    const before = d.run ? d.run.results.slice() : [];
    const p = d.run && d.run.pending;
    const unpaid = !!(p && p.key === item.key && isUnpaidResult({ effect: p.decision && p.decision.effect }));
    const entry = why === 'fix' ? d.done.find((x) => x.key === item.key && x.kind === 'fix') : null;
    if (entry) entry.state = !ok ? 'checking' : still ? 'still' : 'gone';
    if (!ok) {
      d.notice = about(item, mode() === 'city' ? 'That check couldn’t run to the end, so this wasn’t confirmed.' : 'That check couldn’t run to the end, so this isn’t confirmed.');
      if (why === 'mark') d.run = Run.settle(d.run, 'done', item); else d.run = Run.settle(d.run, 'cancelled', item);
    } else if (!still) {
      if (why !== 'mark') {
        const watched = isMonitoringItem(item) || unpaid;
        const pts = watched ? 0 : deps.commitAward(confirmItem(deps.deck(), missionKey(item.finding.module, item.key), deps.now()));
        if (!watched) deps.logEntry('CONFIRMED', item.finding.title || '');
        d.notice = about(item, mode() === 'city' ? `Confirmed: the sweep doesn’t see it any more.${pts ? ` +${pts}` : ''}` : `Checked again: it’s gone.${pts ? ` +${pts} points` : ''}`);
      } else d.notice = '';
      d.run = Run.settle(d.run, 'done', item);
    } else if (why === 'mark') {
      d.run = Run.settle(d.run, 'done', item);
    } else if (d.run && d.run.type === 'locks') {
      // Lock Run: Done is the person's decision even when the lock still reads
      // off. It is answered and pays like any decided item; it stays on TO DO,
      // and only a re-check that sees the change pays CONFIRMED.
      d.notice = about(item, mode() === 'city' ? 'Still showing after the check. Your move is noted; it stays on the board until a sweep sees the change.'
        : 'Checked again: it’s still there. Your decision is noted; it stays on the list until a re-check sees the change.');
      d.run = Run.settle(d.run, 'done', item);
    } else {
      d.notice = about(item, mode() === 'city' ? 'Still showing after the check. It stays on the board.' : 'Checked again: it’s still there, so it stays open.');
      d.run = Run.settle(d.run, 'cancelled', item);
    }
    afterResults(before);
    deps.render();
  }

  // FixFlow / MarkFlow results while a mission's act is open. True when handled here.
  function onFlowResult(kind, payload) {
    const { described, result } = payload || {};
    // An Undo from the done list (its own FixFlow or MarkFlow card).
    if (d.undoing && d.undoing.kind === kind) {
      const e = d.undoing;
      const back = kind === 'fix' ? !!(described && described.restored) : !!(described && described.done && result && result.status === 'removed');
      if (back) afterUndo(e); else d.undoing = null;
      return true;
    }
    if (!d.run || !d.act || !d.run.pending) return false;
    if (kind === 'fix' && d.act.kind === 'fix') {
      if (described && (described.tone === 'success' || described.tone === 'info')) {
        const item = d.act.item; d.act = null;
        if (described.tone === 'success') addDone('fix', item, result);
        recheckItem(item, item.seen_in && item.seen_in.length ? item.seen_in : [item.finding.module], 'fix');
      }
      return true;
    }
    if (kind === 'mark' && d.act.kind === 'mark') {
      if (described && described.done) {
        const item = d.act.item; d.act = null;
        addDone('mark', item, result);
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
    const ctx0 = ctxFor(m, { practice });
    const pv = Run.viewFor(run, game, ctx0, {});
    const item = pv.item;
    // R12: research and the card see the item's answers so far (a practice step's own).
    const ctx = practice ? { ...ctx0, answers: pv.answers || [] } : Run.contextFor(run, ctx0, item);
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
    // Standard mode: the list's own safety note for the item (the first of its findings that has one).
    let safetyHtml = '';
    const answers = Array.isArray(ctx.answers) ? ctx.answers : [];
    if (item && !practice && typeof deps.safetyNote === 'function') {
      for (const f of [item.finding, ...(item.findings || [])]) { try { safetyHtml = deps.safetyNote(f, { answers }) || ''; } catch (_) { safetyHtml = ''; } if (safetyHtml) break; }
    }
    // A remote-access tool that may be running now: no way to the help district on its screen until "I'm offline
    // now" (QuietNotes.goThereWaits). Unknown, or no QuietNotes: it waits.
    const Q = deps.win && deps.win.QuietNotes;
    const goThere = !(item && [item.finding, ...(item.findings || [])].some((f) => f && (!Q || typeof Q.goThereWaits !== 'function'
      ? (f.module === 'remote_access_tools') : Q.goThereWaits(f, { answers }))));
    // This mission's fixes and marks, each with its Undo.
    const doneHere = doneHtml(d.done.filter((e) => e.missionId === m.id || run.results.some((r) => r.key === e.key)));
    return renderMissionScreen({ mission: m, run, view: pv, mode: mode(), districtName: deps.districtName(m.district), cardHtml: card, safetyHtml, goThere, doneHtml: doneHere,
      evidenceHtml: evidence, research, actHtml: d.act ? d.act.html : '', notice: d.notice, summaryHtml: summary, points,
      nextMission: next, place: deps.place(), busy: d.busy, canPractice: !!(game.practice && game.practice.script && game.practice.script.length) });
  }

  // A district's list: how far along it is, its rows, then what was done here with Undo.
  function districtMissionsHtml(districtId) {
    const list = d.missions.filter((m) => m.district === districtId);
    const done = doneHtml(d.done.filter((e) => e.district === districtId));
    const said = d.listNotice ? `<p class="intel mx-notice" role="status">${esc(d.listNotice)}</p>` : '';
    if (!list.length) return said + done;
    return `${said}${progressLine(progress(districtId))}${renderMissionList(list, { mode: mode(), status: statusOf })}${done}`;
  }
  // "2 of 5 missions done · 7 of 18 decided": a bar that moves as items are
  // decided, with the honest line that decided isn't fixed.
  function progressLine(p) {
    if (!p.total && !p.rows) return '';
    const pct = p.total ? Math.round((p.decided / p.total) * 100) : 0;
    const city = mode() === 'city';
    const parts = [p.rows ? `${p.rowsDone} of ${p.rows} mission${p.rows === 1 ? '' : 's'} done` : '', p.total ? `${p.decided} of ${p.total} decided` : ''].filter(Boolean);
    return `<div class="mx-progress-line"><p class="intel"><b>${esc(parts.join(' · '))}</b></p>
      <div class="bar" role="progressbar" aria-label="${esc(city ? 'Moves made' : 'Decided')}" aria-valuemin="0" aria-valuemax="${esc(p.total)}" aria-valuenow="${esc(p.decided)}"><i style="--pct: ${pct}%"></i></div>
      ${p.decided ? `<p class="intel faint">${esc(city ? 'A move made isn’t a patch: only a sweep that checks again confirms one.' : 'Decided isn’t fixed: only a re-check confirms a fix.')}</p>` : ''}</div>`;
  }

  // --- clicks; true when handled ---
  function click(act, go) {
    if (!(act && act.startsWith('mx-undo:'))) d.listNotice = '';
    if (go && go.startsWith('mx:')) { if (open(go.slice(3))) { deps.setScreen('mx'); deps.render(); deps.focusHeading(); } return true; }
    // An Undo on the done list: FixFlow or MarkFlow carries it out on this
    // click; the desk only notes which one, and doesn't redraw under it.
    if (act && act.startsWith('mx-undo:')) {
      const e = d.done.find((x) => x.id === act.slice(8));
      if (e && !d.busy && !deps.sweeping()) d.undoing = e;
      return true;
    }
    if (!act || !act.startsWith('mx-') || !d.run) return false;
    const game = gameOf(d.run.type);
    const m = mission(d.run.missionId);
    const ctx = ctxFor(m);
    if (d.busy) return true;
    d.notice = '';
    const before = d.run.results.slice();
    const guideBefore = d.run.guide;
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
    } else if (act === 'mx-unask') {
      // BACK on a question (R12): the question before, nothing recorded.
      d.act = null; d.run = Run.unask(d.run);
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
      const links = item ? assemble(game, item, Run.contextFor(d.run, ctx, item), { unfinished: d.unfinished }).links : [];
      const l = links[Number(act.slice(8))];
      if (l) {
        // R6 for links too: a warned item's page opens only after the warning was read.
        const r = Run.openLink(d.run, game, ctx, { kind: l.kind === 'settings' ? 'settings' : 'link', url: l.url, text: l.text, item, steps: [],
          ...(l.warning === true ? { warning: true } : {}) });
        d.run = r.run;
        if (r.act) Promise.resolve(carryOut(r.act)).then(() => deps.render());
      }
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
    const g = d.run && d.run.guide;
    d.reveal = !!(g && g !== guideBefore && ((g.steps && g.steps.length) || (g.checklist && g.checklist.length)));
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
    // The HUD's MISSIONS counts the district list's rows (types.js missionRows), not parts.
    hud: () => { const p = progress(); return { done: p.rowsDone, total: p.rows, decided: p.decided }; },
    progress, progressLine: (district = null) => progressLine(progress(district)),
    // YOUR FILE's missions panel: this session's answers by kind, and what was done.
    tally: () => {
      const kinds = { later: 0, keep: 0, mark: 0, fix: 0, steps: 0 };
      const runs = new Map(d.runs);
      if (d.run) runs.set(d.run.missionId, d.run);
      for (const run of runs.values()) {
        for (const r of run.results) {
          const k = r.effect && r.effect.kind;
          if (k === 'later') kinds.later += 1; else if (k === 'mark') kinds.mark += 1; else if (k === 'fix') kinds.fix += 1;
          else if (k === 'keep' || k === 'note' || k === 'odd') kinds.keep += 1; else if (r.outcome === 'done') kinds.steps += 1;
        }
      }
      return { ...progress(), ...kinds, fixedGone: d.done.filter((e) => e.kind === 'fix' && e.state === 'gone').length };
    },
    deckMissionsHtml,
    open, click, screenHtml, districtMissionsHtml, onFlowResult, afterRender,
    active: () => !!d.run,
    rounds: () => ownGames(d.reg).filter((g) => g.practice && g.practice.script).map((g) => ({ type: g.type, concepts: g.concepts || [], steps: g.practice.script.length })),
    ownTypes: () => (d.reg ? [...d.reg.own] : []),
    state: d,
  };
}
