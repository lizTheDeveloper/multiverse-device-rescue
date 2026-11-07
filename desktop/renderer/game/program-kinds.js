// What kind of thing a finding is about: something that starts on its own,
// runs on a schedule, is running now, listens on the network, or is a browser
// extension (plus a setting or an access list, for the other things a person
// can mark as theirs). Pure.
//
// The kind comes from the evidence, never from the title: engine titles often
// call a login item a "background task" whatever starts it. On a Mac a launch
// agent's own finding doesn't say when it runs, so its kinds come from the
// same scan's startup report (startup_optimizer's items[].when / running), matched by
// settings file. Without that report the honest answer is "background item":
// set up to run in the background, when isn't known.
//
// One short label per kind, defined here and nowhere else. The difference
// between them is taught once, in the lesson KIND_LESSON, not on every card.
import { esc } from './escape.js';

export const KIND_LESSON = 'what-kind-of-program';

export const PROGRAM_KINDS = Object.freeze({
  starts: Object.freeze({ id: 'starts', icon: '⏻', label: 'Starts on its own' }),
  schedule: Object.freeze({ id: 'schedule', icon: '◷', label: 'Runs on a schedule' }),
  background: Object.freeze({ id: 'background', icon: '◌', label: 'Background item' }),
  running: Object.freeze({ id: 'running', icon: '●', label: 'Running now' }),
  listens: Object.freeze({ id: 'listens', icon: '⇄', label: 'Listens on the network' }),
  extension: Object.freeze({ id: 'extension', icon: '⧉', label: 'Browser extension' }),
  setting: Object.freeze({ id: 'setting', icon: '⚙', label: 'A setting' }),
  access: Object.freeze({ id: 'access', icon: '⚿', label: 'Access list' }),
});
// The order chips are shown in, and the order the inventory groups by.
export const KIND_ORDER = ['starts', 'schedule', 'background', 'running', 'listens', 'extension', 'setting', 'access'];

const LAUNCHD = new Set(['launch_agent_audit', 'launchd_persistence_audit', 'scheduled_tasks_audit']);
const STARTS_MODULES = new Set(['win_autoruns_audit', 'win_startup', 'win_services_audit', 'login_items_cleanup']);
const SCHEDULE_MODULES = new Set(['cron_jobs_audit']);
const RUNNING_MODULES = new Set(['suspicious_processes', 'win_suspicious_processes', 'resource_hog_identifier']);
const EXTENSION_MODULES = new Set(['browser_extension_audit', 'chrome_extensions', 'safari_extensions']);
const LISTEN_CODES = new Set(['unusual_listening_port', 'listening_ports', 'exposed_risky_ports', 'backdoor_ports']);
const NETWORK_MODULES = new Set(['open_ports_scan', 'suspicious_connections', 'network_connections_monitor']);
// Mark kinds (rescue/known_items.py) that are a setting or a list, not a program.
const MARK_KIND = { sharing_service: 'setting', network_proxy: 'setting', app_permissions: 'access', ssh_authorized_keys: 'access',
  browser_extension: 'extension', system_extension: 'background', ai_tooling: 'setting' };

const dataOf = (x) => (x && x.data && typeof x.data === 'object' ? x.data : {});
const str = (v) => (typeof v === 'string' ? v : '');
const codeTail = (code) => str(code).split('.').slice(2).join('.');

// What the scan's startup report says about each launchd job, by settings file.
// `doc` is the whole scan; anything malformed is skipped.
export function programContext(doc) {
  const byPlist = new Map();
  for (const mod of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    if (!mod || mod.name !== 'startup_optimizer' || !Array.isArray(mod.findings)) continue;
    for (const fd of mod.findings) {
      const items = dataOf(fd).items;
      for (const it of Array.isArray(items) ? items : []) {
        if (it && typeof it.plist === 'string' && it.plist && !byPlist.has(it.plist)) byPlist.set(it.plist, it);
      }
    }
  }
  return { byPlist };
}

function launchdKinds(d, ctx) {
  const it = ctx && ctx.byPlist && str(d.plist) ? ctx.byPlist.get(d.plist) : null;
  const when = it && Array.isArray(it.when) ? it.when.map(str) : [];
  const out = [];
  if (when.some((w) => w === 'at login' || w === 'at startup' || w === 'kept running')) out.push('starts');
  if (when.some((w) => w === 'on a schedule' || /^every /.test(w))) out.push('schedule');
  if (!out.length) out.push('background');
  if (it && (it.running === true || Number.isInteger(it.pid))) out.push('running');
  return out;
}

function linuxKind(d) {
  const kind = str(d.kind).toLowerCase();
  const mech = str(d.mechanism).toLowerCase();
  const p = str(d.path || d.location);
  if (/cron/.test(kind) || /cron/.test(mech) || /\.timer$/.test(p)) return 'schedule';
  if (/systemd|autostart|startup|launchd|run key/.test(kind + mech)) return 'starts';
  if (/scheduled task/.test(mech)) return 'background';
  return null;
}

// The kind ids for one finding, in KIND_ORDER, as PROGRAM_KINDS entries.
export function kindsOf(finding, ctx = null) {
  if (!finding || typeof finding !== 'object') return [];
  const d = dataOf(finding);
  const mod = str(finding.module);
  const tail = codeTail(finding.code);
  const ids = new Set();
  const markKind = str(d.marked_kind) || str(finding.markable && finding.markable.kind);
  if (LAUNCHD.has(mod) || markKind === 'background_task') launchdKinds(d, ctx).forEach((k) => ids.add(k));
  else if (MARK_KIND[markKind]) ids.add(MARK_KIND[markKind]);
  else if (EXTENSION_MODULES.has(mod)) ids.add('extension');
  else if (RUNNING_MODULES.has(mod)) ids.add('running');
  else if (SCHEDULE_MODULES.has(mod)) ids.add('schedule');
  else if (STARTS_MODULES.has(mod)) ids.add('starts');
  else if (mod === 'win_scheduled_tasks_security') ids.add(tail === 'frequent_schedule' ? 'schedule' : tail === 'recent_boot_logon' ? 'starts' : 'background');
  else if (mod === 'win_scheduled_tasks') ids.add('background');
  else if (mod === 'win_startup_programs_audit') ids.add('starts');
  else if (NETWORK_MODULES.has(mod)) { if (LISTEN_CODES.has(tail) || /listen/.test(str(d.check))) ids.add('listens'); }
  else if (mod === 'linux_persistence_audit' || mod === 'crypto_miner_persistence' || mod === 'ai_worm_persistence') {
    const k = linuxKind(d);
    if (k) ids.add(k);
  }
  return KIND_ORDER.filter((k) => ids.has(k)).map((k) => PROGRAM_KINDS[k]);
}

// "⏻ Starts on its own · ● Running now": one short line of chips.
export function kindChipsHtml(kinds) {
  const list = Array.isArray(kinds) ? kinds.filter(Boolean) : [];
  if (!list.length) return '';
  return `<span class="kinds">${list.map((k) => `<span class="kind kind-${esc(k.id)}"><span aria-hidden="true">${esc(k.icon)}</span> ${esc(k.label)}</span>`).join('<span class="kind-sep" aria-hidden="true"> · </span>')}</span>`;
}
