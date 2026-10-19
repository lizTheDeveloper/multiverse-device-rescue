// Turns an engine scan (rescue scan --json) into a city: one district per
// kind of problem, one mission per warning or critical finding, notes for info
// findings, fog where a check couldn't run, and `unfinished` where a check ran
// but stopped before the end (the engine's "complete": false). Pure; no DOM.

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
  const totals = { critical: 0, warning: 0, info: 0, fog: 0 };
  const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];

  for (const mod of modules) {
    if (!mod || typeof mod.name !== 'string') continue;
    const district = byId.get(districtFor(mod.category).id);
    if (mod.status === 'error' || mod.supported === false) {
      district.fog.push({ module: mod.name, reason: mod.unsupported_reason || mod.error || 'This check couldn’t run.' });
      totals.fog += 1;
    } else {
      district.checksRan += 1;
      if (mod.complete === false) {
        district.unfinished.push({ module: mod.name });
      }
    }
    for (const raw of Array.isArray(mod.findings) ? mod.findings : []) {
      if (!raw || typeof raw !== 'object') continue;
      const finding = { ...raw, module: mod.name };
      // A finding the person marked as theirs comes back as info (known_items.py),
      // with its old severity kept. It stays a mission, shown as "yours".
      const markedByUser = !!(finding.data && finding.data.marked_by_user === true);
      const original = markedByUser && finding.data.original_severity;
      const sev = markedByUser
        ? (SEVERITY_RANK[original] ? original : 'warning')
        : (SEVERITY_RANK[finding.severity] ? finding.severity : 'info');
      totals[sev] += 1;
      if (sev === 'info') { district.notes.push(finding); continue; }
      const id = findingIdentity(finding);
      const existing = missions.get(id);
      if (existing) {
        existing.findings.push(finding);
        if (SEVERITY_RANK[sev] > SEVERITY_RANK[existing.severity]) { existing.severity = sev; existing.primary = finding; }
        existing.fixable = existing.fixable || !!finding.fixable;
        existing.markable = existing.markable || !!finding.markable;
        existing.marked = existing.marked && !!(finding.data && finding.data.marked_by_user === true);
        continue;
      }
      const mission = {
        id, module: mod.name, code: finding.code || null, severity: sev, districtId: district.id,
        title: finding.title || 'Something worth a look',
        description: finding.description || '',
        steps: missionSteps(finding),
        walkthroughTitle: (finding.remediation && finding.remediation.title) || null,
        safetyNote: (finding.remediation && finding.remediation.safety_note) || null,
        findings: [finding], primary: finding,
        fixable: !!finding.fixable, markable: !!finding.markable,
        marked: !!(finding.data && finding.data.marked_by_user === true),
      };
      missions.set(id, mission);
      district.missions.push(mission);
    }
  }

  for (const m of missions.values()) {
    m.title = m.primary.title || m.title;
    m.description = m.primary.description || m.description;
    m.steps = missionSteps(m.primary);
  }
  const districts = [...byId.values()]
    .filter((d) => d.id !== 'outskirts' || d.missions.length || d.notes.length || d.fog.length)
    .map((d) => {
      d.missions.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
      return { ...d, status: statusOf(d) };
    });
  return { districts, totals };
}
