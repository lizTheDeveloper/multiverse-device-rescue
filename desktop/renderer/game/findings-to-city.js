// Turns an engine scan (rescue scan --json) into a city: one district per
// kind of problem, one mission per warning or critical finding, notes for info
// findings, fog where a check couldn't run, and `unfinished` where a check ran
// but stopped before the end (the engine's "complete": false). Pure; no DOM.
// One mission per item of NotChecked.displayItems (the engine's same_key,
// then the thing a finding names, then its title), the list Plain renders
// too, so the city counts what the list counts (scanCounts.todo).
// Sets globalThis.NotChecked (a plain script the list loads too).
import '../not-checked.js';

const NC = globalThis.NotChecked;

export const DISTRICTS = [
  { id: 'gatehouse', category: 'security', name: 'The Gatehouse', blurb: 'Security: things that start on their own, permissions, protection.' },
  { id: 'wires', category: 'network', name: 'The Wires', blurb: 'Network: your Wi-Fi, router and connections.' },
  { id: 'foundations', category: 'integrity', name: 'The Foundations', blurb: 'Integrity: updates, disk health, system files.' },
  { id: 'engine-room', category: 'performance', name: 'The Engine Room', blurb: 'Performance: speed, memory and storage.' },
  { id: 'junkyard', category: 'bloatware', name: 'The Junkyard', blurb: 'Clutter: preinstalled extras and leftovers.' },
];
export const OUTSKIRTS = { id: 'outskirts', category: null, name: 'The Outskirts', blurb: 'Everything else the checkup noticed.' };
const SEVERITY_RANK = { critical: 2, warning: 1 };
// Data fields that name the thing a finding is about, most specific first.
const STABLE_KEYS = ['plist', 'path', 'program', 'label', 'bundle_id', 'extension_id', 'name', 'target', 'id'];

// A finding's level in the city's totals: the list's (NotChecked.listSeverity),
// so a finding marked as yours counts at its old severity.
function cityLevel(finding, category) {
  return NC.listSeverity(finding, category);
}
// Each finding's place in the scan, while the missions are built (never kept).
const ORDER = Symbol('order');

function districtFor(category) {
  return DISTRICTS.find((d) => d.category === category) || OUTSKIRTS;
}

export function districtIdFor(category) {
  return districtFor(category).id;
}

// Not the mark id (markable.id / data.known_item_id): rescue/known_items.py
// hashes the program's content into it, so it changes when the program does.
// The engine keeps code and data.plist on a marked finding, so this identity
// holds across mark, unmark and a changed program.
export function findingIdentity(finding) {
  const fd = finding || {};
  const data = fd.data && typeof fd.data === 'object' ? fd.data : {};
  const what = fd.code || fd.title || '';
  for (const key of STABLE_KEYS) {
    if (typeof data[key] === 'string' && data[key] !== '') return `${fd.module}|${what}|${key}=${data[key]}`;
  }
  return `${fd.module}|${what}`;
}

export function missionSteps(finding) {
  const rem = finding && finding.remediation;
  if (rem && Array.isArray(rem.steps) && rem.steps.length) return rem.steps;
  const text = String((finding && finding.description) || '');
  const m = text.split(/what to do:?/i);
  if (m.length > 1) {
    const lines = m.slice(1).join(' ').split('\n').map((l) => l.trim())
      .filter(Boolean).map((l) => l.replace(/^(\d+[.)]|[-*•])\s*/, ''));
    if (lines.length) return lines.map((title, i) => ({ number: i + 1, title, body: '' }));
  }
  return [{ number: 1, title: text.trim() || 'Follow the steps in the list view.', body: '' }];
}

function emptyDistrict(d) {
  return { id: d.id, name: d.name, blurb: d.blurb, category: d.category, missions: [], notes: [], fog: [], unfinished: [], checksRan: 0, status: 'none' };
}

function statusOf(d) {
  if (d.missions.length) return d.missions.some((m) => m.severity === 'critical') ? 'hot' : 'warn';
  if (d.fog.length && d.checksRan === 0) return 'fog';
  // A check that didn't finish may have missed something: never clear.
  if (d.fog.length || d.unfinished.length) return 'partial';
  return d.checksRan > 0 || d.notes.length ? 'clear' : 'none';
}

export function findingsToCity(doc) {
  const byId = new Map([...DISTRICTS, OUTSKIRTS].map((d) => [d.id, emptyDistrict(d)]));
  const missions = new Map();
  const categoryOf = new Map();
  const totals = { critical: 0, warning: 0, info: 0, fog: 0 };
  const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];

  for (const mod of modules) {
    if (!mod || typeof mod.name !== 'string') continue;
    const district = byId.get(districtFor(mod.category).id);
    categoryOf.set(mod.name, mod.category);
    const named = typeof mod.check_name === 'string' && mod.check_name.trim() ? { checkName: mod.check_name.trim() } : {};
    if (mod.status === 'error' || mod.supported === false) {
      // `notStarted`: an opt-in check that can run here but waits for a
      // go-ahead (held.js marks it): fog, never clear, and never "couldn't run".
      district.fog.push({ module: mod.name, ...named, reason: mod.unsupported_reason || mod.error || 'This check couldn’t run.',
        ...(mod.not_started === true ? { notStarted: true } : {}) });
      totals.fog += 1;
    } else {
      district.checksRan += 1;
      if (mod.complete === false) {
        district.unfinished.push({ module: mod.name, ...named });
      }
    }
    for (const raw of Array.isArray(mod.findings) ? mod.findings : []) {
      if (!raw || typeof raw !== 'object') continue;
      const finding = { ...raw, module: mod.name };
      const sev = cityLevel(finding, mod.category);
      totals[sev] += 1;
      if (sev === 'info') district.notes.push(finding);
    }
  }

  // The missions: one per to-do or marked item of NotChecked.displayItems,
  // the list both views render (todo + markedItems), so different things
  // with one code (four Chrome extensions) stay four missions. Held items
  // stay missions here; the city leaves them out of its numbers (held.js).
  // A mission's id is its first finding's identity (doc order), as before;
  // two items that would share one keep apart by their merge key.
  const ordered = { ...(doc || {}), modules: modules.map((mod, i) => (mod && Array.isArray(mod.findings)
    ? { ...mod, findings: mod.findings.map((f, j) => (f && typeof f === 'object' ? { ...f, [ORDER]: i * 1e6 + j } : f)) } : mod)) };
  const list = NC.displayItems(ordered, { mode: 'standard' });
  for (const item of [...list.critical, ...list.warning, ...list.marked]) {
    const first = item.findings.reduce((x, f) => (f[ORDER] < x[ORDER] ? f : x), item.findings[0]);
    const findings = item.findings.map(({ [ORDER]: _o, ...f }) => f);
    const primary = findings[0];
    let id = findingIdentity(first);
    if (missions.has(id)) id = `${id}|${item.key}`;
    const district = byId.get(districtFor(categoryOf.get(primary.module)).id);
    const mission = {
      id, module: primary.module, code: primary.code || null, severity: item.severity, districtId: district.id,
      title: primary.title || 'Something worth a look',
      description: primary.description || '',
      steps: missionSteps(primary),
      walkthroughTitle: (primary.remediation && primary.remediation.title) || null,
      safetyNote: (primary.remediation && primary.remediation.safety_note) || null,
      findings, primary,
      fixable: findings.some((f) => !!f.fixable), markable: findings.some((f) => !!f.markable),
      marked: item.marked,
    };
    missions.set(id, mission);
    district.missions.push(mission);
  }

  for (const m of missions.values()) {
    m.title = m.primary.title || m.title;
    m.description = m.primary.description || m.description;
    m.steps = missionSteps(m.primary);
  }
  const districts = [...byId.values()]
    .filter((d) => d.id !== 'outskirts' || d.missions.length || d.notes.length || d.fog.length)
    .map((d) => {
      // Worst first; then, as on the list, what can be fixed, then what can be marked as yours.
      const act = (m) => (m.fixable ? 2 : m.markable ? 1 : 0);
      d.missions.sort((a, b) => (SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]) || (act(b) - act(a)));
      return { ...d, status: statusOf(d) };
    });
  return { districts, totals };
}
