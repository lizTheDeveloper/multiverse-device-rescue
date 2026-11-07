// The command center as an incident report. A signal (signals.js) becomes a
// case: what kind of case it is, where the investigation stands, and how much
// it matters. Pure; no DOM.
//
// The engine's severity says how bad a finding would be at its worst. For a
// program, a script or a connection, that depends on whose it is, which the
// scan can't know: such a case is a LEAD, UNIDENTIFIED until the person says,
// never "critical" on its own. A setting that leaves the computer open is an
// OPEN DOOR: there's no "whose" to ask, only close it or keep it on purpose.
// Disk space, sleep settings and the like are UPKEEP, kept out of the
// incident queue. A check that couldn't run is a BLIND SPOT.
//
// Held findings (held.js: monitoring) are cases too, but only ever SAFETY
// FIRST: no tag moves them, and "yours" never applies.

export const CASE_TYPES = Object.freeze({
  lead: Object.freeze({ id: 'lead', label: 'LEAD', question: 'Is this yours?' }),
  door: Object.freeze({ id: 'door', label: 'OPEN DOOR', question: 'Close it, or keep it on purpose?' }),
  upkeep: Object.freeze({ id: 'upkeep', label: 'UPKEEP', question: 'Worth a tidy-up?' }),
  blind: Object.freeze({ id: 'blind', label: 'BLIND SPOT', question: 'This check couldn’t look here.' }),
  note: Object.freeze({ id: 'note', label: 'NOTE', question: '' }),
});

export const CASE_STATUSES = Object.freeze({
  unidentified: Object.freeze({ id: 'unidentified', label: 'UNIDENTIFIED', open: true }),
  investigating: Object.freeze({ id: 'investigating', label: 'INVESTIGATING', open: true }),
  open: Object.freeze({ id: 'open', label: 'OPEN', open: true }),
  held: Object.freeze({ id: 'held', label: 'SAFETY FIRST', open: true }),
  threat: Object.freeze({ id: 'threat', label: 'CONFIRMED THREAT', open: true }),
  yours: Object.freeze({ id: 'yours', label: 'IDENTIFIED: YOURS', open: false }),
  kept: Object.freeze({ id: 'kept', label: 'KEPT ON PURPOSE', open: false }),
  closed: Object.freeze({ id: 'closed', label: 'CLOSED', open: false }),
  noted: Object.freeze({ id: 'noted', label: 'NOTED', open: false }),
});

// What a lead is about when the finding itself names one thing: a program,
// a script, a driver, a connection, a permission list, a redirect.
const LEAD_MODULES = new Set([
  'ai_worm_filesystem', 'kext_audit', 'suspicious_connections', 'network_connections_monitor', 'open_ports_scan',
  'accessibility_permissions', 'app_permissions', 'privacy_permissions_audit', 'hosts_file_check', 'dns_config',
  'launch_agents_audit', 'launch_agent_audit', 'launchd_persistence_audit', 'login_items_cleanup', 'cron_jobs_audit',
  'scheduled_tasks_audit', 'browser_extension_audit', 'chrome_extensions', 'safari_extensions', 'suspicious_processes',
  'win_suspicious_processes', 'win_autoruns_audit', 'win_startup', 'win_services_audit', 'network_proxy_check',
  'win_proxy_detect', 'win_remote_access_audit', 'ssh_config_audit', 'sharing_services_audit',
]);
// Outside the Gatehouse and the Wires, these still leave a door open.
const DOOR_MODULES = new Set([
  'backup_status', 'time_machine_check', 'time_machine_health', 'update_checker', 'automatic_updates',
  'filevault_check', 'appleid_security_check', 'find_my_mac_check', 'lock_screen_check', 'screen_lock_check',
  'login_password_policy',
]);
const DOOR_DISTRICTS = new Set(['gatehouse', 'wires']);
// Marks that are the person's answer about a setting, not a claim on a thing
// whose owner is unknown: "I back up another way" keeps a door open on purpose.
const ANSWER_MARKS = new Set(['backup_elsewhere']);

function typeOf(sig, kinds, held) {
  if (held) return 'lead';
  if (sig.kind === 'couldnt') return 'blind';
  if (sig.severity === 'info') return 'note';
  const f = sig.finding || {};
  const leadMark = f.markable && !ANSWER_MARKS.has(f.markable.kind);
  if ((kinds && kinds.length) || leadMark || LEAD_MODULES.has(sig.module)) return 'lead';
  if (DOOR_MODULES.has(sig.module) || DOOR_DISTRICTS.has(sig.districtId)) return 'door';
  return 'upkeep';
}

// Every program the finding names was signed by a maker the system verified.
export function verifiedMaker(finding) {
  const mb = finding && Array.isArray(finding.made_by) ? finding.made_by : [];
  return mb.length > 0 && mb.every((m) => m && m.verified === true);
}

function statusOf(type, sig, { held, closed }) {
  if (held) return 'held';
  if (type === 'blind' || type === 'note') return sig.tag === 'noted' ? 'noted' : 'open';
  if (closed) return 'closed';
  if (sig.tag === 'threat') return 'threat';
  if (sig.tag === 'mine') return type === 'lead' ? 'yours' : 'kept';
  if (sig.tag === 'closer') return 'investigating';
  return type === 'lead' ? 'unidentified' : 'open';
}

// How much a case matters: 'high' | 'medium' | 'low'. For a lead it's what it
// would mean if it isn't theirs, which a verified maker lowers by one step.
function priorityOf(type, sig, held) {
  if (held) return 'high';
  if (type === 'upkeep' || type === 'note' || type === 'blind') return 'low';
  const base = sig.severity === 'critical' ? 'high' : 'medium';
  if (type === 'lead' && verifiedMaker(sig.finding)) return base === 'high' ? 'medium' : 'low';
  return base;
}

// `kinds`: program-kinds.js kindsOf for this finding. `held`: held.js holds it.
// `closed`: its mission is fixed and confirmed (progress.js).
export function caseOf(sig, { kinds = null, held = false, closed = false } = {}) {
  const s = sig || {};
  const type = typeOf(s, kinds, !!held);
  const status = statusOf(type, s, { held: !!held, closed: !!closed });
  return { type, status, priority: priorityOf(type, s, !!held), open: CASE_STATUSES[status].open };
}

// A lead's line under its title, e.g. "UNIDENTIFIED · HIGH RISK IF NOT YOURS".
export function caseLine(c) {
  const st = CASE_STATUSES[c.status].label;
  if (c.type === 'lead' && c.status === 'unidentified') return `${st} · ${c.priority.toUpperCase()} RISK IF NOT YOURS`;
  if (c.type === 'door' && c.status === 'open') return `${CASE_TYPES.door.label} · ${c.priority.toUpperCase()}`;
  return c.type === 'lead' || c.status !== 'open' ? st : CASE_TYPES[c.type].label;
}

const PRIORITY = { high: 0, medium: 1, low: 2 };
const TYPE_ORDER = { lead: 0, door: 1, upkeep: 2, blind: 3, note: 4 };
const STATUS_ORDER = { held: 0, threat: 1, unidentified: 2, investigating: 3, open: 4 };

// Open cases first: held, then confirmed threats, then by priority and type.
export function compareCases(a, b) {
  return (Number(!a.case.open) - Number(!b.case.open))
    || ((STATUS_ORDER[a.case.status] ?? 9) - (STATUS_ORDER[b.case.status] ?? 9))
    || (PRIORITY[a.case.priority] - PRIORITY[b.case.priority])
    || (TYPE_ORDER[a.case.type] - TYPE_ORDER[b.case.type])
    || String(a.title).localeCompare(String(b.title));
}

const norm = (t) => String(t == null ? '' : t).toLowerCase().replace(/\s+/g, ' ').trim();

// Several checks often report the same door or upkeep in the same words
// ("Your Mac is set to never sleep" three times). Those become one case with
// `also` listing the others. Leads never merge: each names its own thing.
export function mergeEchoes(items) {
  const out = [];
  const seen = new Map();
  for (const it of items || []) {
    if (it.case.type === 'lead' || it.case.status === 'held') { out.push(it); continue; }
    const key = `${it.case.type}|${norm(it.title)}`;
    const first = seen.get(key);
    if (first) { first.also.push(it); continue; }
    const copy = { ...it, also: [] };
    seen.set(key, copy);
    out.push(copy);
  }
  return out;
}

// The incident report's numbers. `items`: signals with their `case`.
export function caseReport(items) {
  const r = { leads: 0, unidentified: 0, investigating: 0, threats: 0, held: 0, identified: 0,
    doors: 0, doorsOpen: 0, upkeep: 0, blind: 0, open: 0, closed: 0 };
  for (const { case: c } of items || []) {
    if (c.type === 'note') continue;
    if (c.type === 'lead') r.leads += 1;
    if (c.type === 'door') { r.doors += 1; if (c.open) r.doorsOpen += 1; }
    if (c.type === 'upkeep') r.upkeep += 1;
    if (c.type === 'blind') r.blind += 1;
    if (c.status === 'unidentified') r.unidentified += 1;
    if (c.status === 'investigating') r.investigating += 1;
    if (c.status === 'threat') r.threats += 1;
    if (c.status === 'held') r.held += 1;
    if (c.status === 'yours') r.identified += 1;
    if (c.type !== 'blind') { if (c.open) r.open += 1; else r.closed += 1; }
  }
  return r;
}
