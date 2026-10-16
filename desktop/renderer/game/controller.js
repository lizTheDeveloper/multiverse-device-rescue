// The only DOM code in game mode. Renders the city into a shadow root on the
// "city" screen and wires clicks, fixes, marks and re-checks.
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

export function createController({ win, storage, scoutSprite }) {
  const doc0 = win.document;
  const host = doc0.getElementById('city-host');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><div class="frame" id="frame"></div>';
  const frame = shadow.getElementById('frame');
  const scout = (feeling, size) => scoutSprite(feeling, { size });
  const now = () => new Date().toISOString();

  const s = { doc: null, situation: null, city: null, progress: loadProgress(storage), cameBack: [],
    screen: 'map', districtId: null, missionId: null, outcome: null, outcomeMission: null, lastFix: null, message: '', busy: false,
    trigger: 'i-did-it', recheckModules: [] };

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

  function screenHtml() {
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
    return renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout });
  }

  function render() {
    try {
      frame.innerHTML = renderHud({ title: 'YOUR COMPUTER', city: s.city, progress: s.progress }) + screenHtml();
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
      rebuild(doc);
      s.screen = 'map'; s.outcome = null; s.lastFix = null;
      render();
    },
    update(doc) { rebuild(doc); render(); },
  };
}
