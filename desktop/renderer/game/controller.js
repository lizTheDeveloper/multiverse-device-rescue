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
    screen: 'map', districtId: null, missionId: null, outcome: null, outcomeMission: null, lastFix: null, message: '', busy: false };

  function rebuild(doc) {
    s.doc = doc;
    s.city = findingsToCity(doc);
    const r = reconcile(s.progress, s.city, ranOkModules(doc), now());
    s.progress = r.progress;
    s.cameBack = r.cameBack;
    saveProgress(storage, s.progress);
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

  async function recheck(missionId) {
    const m = mission(missionId) || s.outcomeMission;
    if (!m || s.busy) return;
    s.busy = true; s.screen = 'mission'; s.missionId = m.id; render();
    let res;
    try { res = await win.rescue.recheckModule(m.module); } catch (_) { res = null; }
    s.busy = false;
    if (res && res.ok) {
      if (!win.RescueHost.docChanged(res.doc)) return; // the gate closed: app.js showed the list
      rebuild(res.doc);
    }
    s.outcome = recheckOutcome(m.id, s.city, res);
    s.outcomeMission = mission(m.id) || m;
    s.message = res && !res.ok ? res.message || '' : '';
    s.screen = 'outcome';
    render();
  }

  frame.addEventListener('click', (e) => {
    const el = e.target.closest('[data-go],[data-act]');
    if (!el || s.busy) return;
    const go = el.getAttribute('data-go');
    const act = el.getAttribute('data-act');
    if (go === 'map') { s.screen = 'map'; render(); return; }
    if (go && go.startsWith('district:')) { s.screen = 'district'; s.districtId = go.slice(9); render(); return; }
    if (go && go.startsWith('milestone:')) { s.screen = 'milestone'; s.districtId = go.slice(10); render(); return; }
    if (go && go.startsWith('mission:')) { s.screen = 'mission'; s.missionId = go.slice(8); render(); return; }
    if (act === 'list') { win.RescueHost.showList(); return; }
    if (act === 'i-did-it') { recheck(s.missionId); return; }
    if (act === 'recheck') { recheck(s.outcomeMission && s.outcomeMission.id); return; }
    if (act === 'later') {
      const m = mission(s.missionId);
      if (m) { s.progress = setStatus(s.progress, m.id, 'later', m.module, now()); saveProgress(storage, s.progress); s.screen = 'district'; s.districtId = m.districtId; }
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
    if (described && (described.tone === 'success' || described.tone === 'info' || described.restored)) recheck(s.missionId);
  } });
  win.MarkFlow.attach(frame, win.rescue, { onResult: ({ described }) => {
    if (described && described.done) recheck(s.missionId);
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
