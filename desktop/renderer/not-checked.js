'use strict';

/*
 * What a scan didn't fully check, by one rule for the Plain list and the city,
 * so the two can never count it differently:
 *
 *   couldntRun  checks that couldn't run (status "error", "supported": false),
 *               and monitoring checks that couldn't look (no iPhone backup, no
 *               scanner, a scan that wasn't run) and found nothing;
 *   unfinished  checks that ran but stopped before the end ("complete": false);
 *   partly      notes that say part of a check couldn't look ("We couldn't
 *               list your USB devices", "Checked 16 of 110 app signatures").
 *
 *   notStarted  opt-in checks that can run here but weren't started (an iPhone
 *               backup is on this computer; its long spyware scan asks first):
 *               neither "couldn't run" nor clean. The engine says
 *               "not_started": true; older scans are read by the
 *               mvt_scan_available note. (The city still shows it as fog:
 *               couldntLook stays true for it.)
 *
 *   NotChecked.isPartlyChecked(finding) -> boolean
 *   NotChecked.couldntLook(module) -> boolean
 *   NotChecked.notStarted(module) -> boolean
 *   notReached  checks a stopped checkup never got to (engine-runner's
 *               error_kind "stopped"): not "couldn't run", they weren't tried.
 *
 *   NotChecked.notCheckedParts(doc) -> { couldntRun: [{name, error}], notReached: [{name}],
 *       unfinished: [{name}], notStarted: [{name}], partly: [{name, title}] }
 *   NotChecked.notCheckedSummary(doc) -> { checks, couldntRun, notReached, unfinished, notStarted, partly, count }
 *   NotChecked.namesLine(names, { max = 5 }) -> { inline, count, all, folded }:
 *       names inline up to `max`, else none inline and `all` under a fold.
 *   NotChecked.fmt(n) -> '4,837'
 *
 * THE NUMBERS BOTH VIEWS SHOW (UX round 5; render only these, never count locally):
 *   todo          "N things on your list" / "N TO DO": critical + warning
 *                 items, duplicates merged (displayItems). Never checks.
 *   notes         "N good-to-know notes" / "LOW PRIORITY (N)": info items, merged.
 *   markedItems   items marked as yours (not in todo or notes).
 *   heldItems     held monitoring items. In 'city' they are in no other
 *                 number; in 'standard' they stay in todo/notes (Plain shows
 *                 them). That is the only difference between the two modes.
 *   couldntCheck  "COULDN'T CHECK N": checks that checked nothing:
 *                 couldntRun + notReached + notStarted.
 *   unfinished    "DIDN'T FINISH N": ran but didn't finish (their findings
 *                 are listed; what's missing may not have been looked at).
 *   notChecked    couldntCheck + unfinished: every check not fully done.
 *   partly        notes saying part of a check couldn't look.
 *   (didntFinish = couldntRun + notReached + unfinished and items, the older
 *   itemKey count, stay for older callers.)
 *
 *   NotChecked.displayItems(doc, { mode }) -> { critical, warning, info, marked, held }:
 *       the merged list both views render; see the rule above the function.
 *   NotChecked.mergeKey(finding, module) -> the merge key displayItems uses.
 *   NotChecked.listSeverity(finding, category) -> severity an item is listed at.
 *   NotChecked.asCard(item) -> Plain's card ({...lead, seen_in, also}).
 *   NotChecked.notCheckedLine(summary) -> the top line, '' when everything was checked
 *
 * One count for both views (so LAST SWEEP, the chips, the district badges,
 * the Plain list and its progress can never disagree):
 *
 *   NotChecked.shownSeverity(finding) -> 'critical' | 'warning' | 'info'
 *       (critical only for security and network; the Plain list's rule)
 *   NotChecked.isHeld(finding, module) -> boolean   (game/held.js's rule; HELD_IN_CITY's checks)
 *   NotChecked.itemKey(finding, module) -> string   one key per item: the
 *       engine's same_key (one thing seen by several checks), else the check,
 *       the finding's code (or title) and the thing it names. Monitoring
 *       findings never share a key.
 *   NotChecked.scanCounts(doc, { mode, districtOf }) -> {
 *       checks,        every check in the scan (each counted once)
 *       ran,           checks that ran (checks - couldntRun - notStarted)
 *       couldntRun, unfinished, notStarted, partly,   as notCheckedSummary
 *       didntFinish,   couldntRun + unfinished: "N COULDN'T RUN OR DIDN'T FINISH"
 *       notFully,      checks not fully checked, each once (any of the four)
 *       critical, warning, info,   findings by shownSeverity
 *       items,         distinct critical + warning items (itemKey)
 *       marked,        findings the person marked as theirs
 *       held,          held monitoring findings; in mode 'city' they are left
 *                      out of critical/warning/info/items (never shown there)
 *       byDistrict: { [districtOf(category)]: { couldntRun, unfinished,
 *                      notStarted, partly, notFully, critical, warning, items } }
 *     }
 *     `districtOf(category)` maps a check's category to a district id (the
 *     city passes findings-to-city's districtIdFor); default: the category.
 *
 * Loaded as a plain script (global `NotChecked`, also on window/globalThis);
 * the game's ES modules `import '../not-checked.js'` and read globalThis.NotChecked;
 * tested from Node.
 */
const NotChecked = (function () {
  // The same three checks as app.js's ALWAYS_SAFETY_MODULES and game/held.js.
  const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  // What city (stealth) mode holds in the help district: the monitoring checks, and remote-access tools (a remote
  // tool can be how someone watches a screen; a person who chose stealth has told us their situation). Only the
  // hold differs: remote tools are not monitoring checks, so in standard mode they are ordinary to-dos that pay.
  // app.js CITY_HELD_MODULES and game/held.js CITY_HELD_MODULES are the same set (a test keeps them equal).
  const HELD_IN_CITY = new Set([...MONITORING_MODULES, 'remote_access_tools']);

  // What those checks say when they found nothing or couldn't look
  // (QuietNotes' NOT_DETECTIONS; a test keeps them equal).
  const NOT_DETECTIONS = new Set([
    'security.mvt_spyware_scan.mvt_requires_wsl',
    'security.mvt_spyware_scan.no_backups_found',
    'security.mvt_spyware_scan.mvt_not_installed',
    'security.mvt_spyware_scan.mvt_scan_available',
    'security.mvt_spyware_scan.mvt_backup_too_large',
    'security.mvt_spyware_scan.mvt_clean_scan',
    'security.keylogger_indicators.input_monitoring_access',
  ]);
  // Of those, the lines that mean the check couldn't look at all.
  const COULDNT_LOOK = new Set([
    'security.mvt_spyware_scan.mvt_requires_wsl',
    'security.mvt_spyware_scan.no_backups_found',
    'security.mvt_spyware_scan.mvt_not_installed',
    'security.mvt_spyware_scan.mvt_scan_available',
    'security.mvt_spyware_scan.mvt_backup_too_large',
  ]);
  const COULDNT_LOOK_REASON = 'This check couldn’t look here.';

  const COULDNT_TITLE = /^(?:we\s+)?(?:couldn[’']t|could\s+not)\s+(?:check|list|read|see|tell|find\s+out)\b/i;

  function isPartlyChecked(finding) {
    if (!finding || finding.severity !== 'info') return false;
    const title = String(finding.title || '');
    if (COULDNT_TITLE.test(title)) return true;
    return !!(finding.data && finding.data.incomplete) && /^checked\s+\d+\s+of\s+\d+/i.test(title);
  }

  // A monitoring finding that says software is there (QuietNotes.isDetection).
  function isDetection(f) {
    if (!f) return false;
    if (f.code) return !NOT_DETECTIONS.has(f.code);
    return f.severity !== 'info';
  }

  // A monitoring check that ran but couldn't look, and found nothing: never clear.
  function couldntLook(mod) {
    if (!mod || !MONITORING_MODULES.has(mod.name) || mod.status === 'error' || mod.supported === false) return false;
    const fs = Array.isArray(mod.findings) ? mod.findings.filter(Boolean) : [];
    return fs.some((f) => COULDNT_LOOK.has(f.code)) && !fs.some(isDetection);
  }

  const NOT_STARTED_CODE = 'security.mvt_spyware_scan.mvt_scan_available';

  // An opt-in check that can run here but wasn't started, and found nothing.
  function notStarted(mod) {
    if (!mod || mod.status === 'error' || mod.supported === false) return false;
    const fs = Array.isArray(mod.findings) ? mod.findings.filter(Boolean) : [];
    if (MONITORING_MODULES.has(mod.name) && fs.some(isDetection)) return false;
    if (mod.not_started === true) return true;
    return mod.name === 'mvt_spyware_scan' && fs.some((f) => f.code === NOT_STARTED_CODE);
  }

  // A check a stopped checkup never got to (engine-runner stoppedDocOf).
  const notReachedMod = (mod) => !!mod && mod.status === 'error' && mod.error_kind === 'stopped';

  function notCheckedParts(doc) {
    const couldntRun = [];
    const notReached = [];
    const unfinished = [];
    const started = [];
    const partly = [];
    const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
    for (const mod of modules) {
      if (!mod) continue;
      if (notReachedMod(mod)) notReached.push({ name: mod.name });
      else if (mod.status === 'error') couldntRun.push({ name: mod.name, error: mod.error || null });
      else if (mod.supported === false) couldntRun.push({ name: mod.name, error: mod.unsupported_reason || null });
      else if (notStarted(mod)) started.push({ name: mod.name });
      else if (couldntLook(mod)) couldntRun.push({ name: mod.name, error: COULDNT_LOOK_REASON });
      else if (mod.complete === false) unfinished.push({ name: mod.name });
      for (const f of Array.isArray(mod.findings) ? mod.findings : []) {
        if (isPartlyChecked(f)) partly.push({ name: mod.name, title: String(f.title || '') });
      }
    }
    return { couldntRun, notReached, unfinished, notStarted: started, partly };
  }

  function notCheckedSummary(doc) {
    const p = notCheckedParts(doc);
    const checks = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean).length : 0;
    return {
      checks,
      couldntRun: p.couldntRun.length,
      notReached: p.notReached.length,
      unfinished: p.unfinished.length,
      notStarted: p.notStarted.length,
      partly: p.partly.length,
      count: p.couldntRun.length + p.notReached.length + p.unfinished.length + p.notStarted.length + p.partly.length,
    };
  }

  // A number as people read it: 4,837.
  const fmt = (n) => Number(n || 0).toLocaleString('en-US');

  // Names in a sentence: up to `max` inline; past that, none inline (the
  // views put `all` under a fold) so a stopped checkup never reads as a wall.
  //   namesLine(names, { max = 5 }) -> { inline: 'A, B and C' | '', count, all: [...], folded: boolean }
  function namesLine(names, { max = 5 } = {}) {
    const all = [...new Set((names || []).map((x) => String(x)).filter(Boolean))];
    if (!all.length || all.length > max) return { inline: '', count: all.length, all, folded: all.length > max };
    const inline = all.length === 1 ? all[0] : `${all.slice(0, -1).join(', ')} and ${all[all.length - 1]}`;
    return { inline, count: all.length, all, folded: false };
  }

  // The top line when something wasn't fully checked. Never an all-clear.
  function notCheckedLine(sum) {
    const s = sum || {};
    const ran = (s.couldntRun || 0) + (s.unfinished || 0);
    const how = s.couldntRun && s.unfinished ? 'couldn’t run or didn’t finish' : s.couldntRun ? 'couldn’t run' : 'didn’t finish';
    const parts = [];
    if (s.notReached) parts.push(`${fmt(s.notReached)} ${s.notReached === 1 ? 'check' : 'checks'} didn’t get to run because the checkup stopped`);
    if (ran) parts.push(`${fmt(ran)} ${ran === 1 ? 'check' : 'checks'} ${how}`);
    if (s.notStarted) parts.push(`${s.notStarted} ${s.notStarted === 1 ? 'check waits' : 'checks wait'} for your go-ahead`);
    if (s.partly) parts.push(`${s.partly} ${s.partly === 1 ? 'thing was' : 'things were'} only partly checked`);
    if (!parts.length) return '';
    return `${parts.join(', and ')}, so this isn’t a clean bill of health.`;
  }

  // The Plain list's severity rule: critical only where it is an alarm.
  const ALARM_CATEGORIES = new Set(['security', 'network']);
  const SEVERITIES = new Set(['critical', 'warning', 'info']);
  function shownSeverity(f) {
    const sev = f && SEVERITIES.has(f.severity) ? f.severity : 'info';
    return sev === 'critical' && !ALARM_CATEGORIES.has(f.category) ? 'warning' : sev;
  }

  // game/held.js's rule, here so the counts can leave held findings out.
  const FAMILIAR_CODE = 'security.keylogger_indicators.suspicious_input_monitoring';
  const FAMILIAR_CHECK = 'claimed_vendor_input_monitoring';
  // A full path: the file attribution checked. A bundle id is not one: it is
  // the name a TCC row's client reports about itself, and the signature of
  // whichever app declares that id says nothing about the program holding the
  // access (rescue/serialize.py _app_subject says the same).
  const isPathSubject = (a) => typeof a === 'string' && (/^[/~]/.test(a) || /^[A-Za-z]:[\\/]/.test(a));
  // The one exception, and only on the engine's own proof: macOS's permission
  // record for the grant holds a code requirement (what macOS itself enforces)
  // that pinned the expected company's Team ID for that bundle id. The engine
  // says so twice: a data.verified_apps entry (verified_by
  // 'macos_code_requirement', a Team ID or 'apple', a maker from its table)
  // and a verified made_by entry with REQUIREMENT_HOW (rescue/serialize.py
  // _requirement_entries). A name, or a made_by entry alone, never counts.
  const REQUIREMENT_HOW = 'macOS permission record (code requirement)';
  const SIGNER = /^(?:[A-Z0-9]{10}|apple)$/;
  const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';
  function requirementProven(a, d, mb) {
    if (typeof a !== 'string' || isPathSubject(a) || !Array.isArray(d.verified_apps)) return false;
    const v = d.verified_apps.find((x) => x && typeof x === 'object' && x.bundle_id === a);
    if (!v || v.verified_by !== 'macos_code_requirement' || typeof v.team_id !== 'string'
      || !SIGNER.test(v.team_id) || !nonEmpty(v.maker)) return false;
    return mb.some((m) => m.subject === a && m.verified === true && m.how === REQUIREMENT_HOW && nonEmpty(m.name));
  }
  function familiarVerified(f, module = f && f.module) {
    if (!f || f.severity !== 'info' || f.code !== FAMILIAR_CODE || module !== 'keylogger_indicators') return false;
    if (f.makers_verified === false) return false;
    const d = f.data && typeof f.data === 'object' ? f.data : {};
    const apps = Array.isArray(d.apps) ? d.apps : [];
    const mb = Array.isArray(f.made_by) ? f.made_by.filter(Boolean) : [];
    if (!apps.every((a) => isPathSubject(a) || requirementProven(a, d, mb))) return false;
    // A path app needs a known program (`what`); a requirement-proven one a
    // known maker, which the engine only names from its own table.
    const known = (m) => m.verified === true && nonEmpty(m.name)
      && (nonEmpty(m.what) || (m.how === REQUIREMENT_HOW && requirementProven(m.subject, d, mb)));
    return d.check === FAMILIAR_CHECK && apps.length > 0 && mb.length > 0 && mb.every(known)
      && apps.every((a) => mb.some((m) => m.subject === a));
  }
  function isHeld(f, module = f && f.module) {
    return !!f && HELD_IN_CITY.has(module) && isDetection(f) && !familiarVerified(f, module);
  }

  const SUBJECT_KEYS = ['label', 'plist', 'path', 'program', 'bundle_id', 'extension_id', 'name', 'target', 'id'];
  // A count in brackets ("(11)", "(16 of 110)") doesn't make it another item.
  const norm = (t) => String(t || '').toLowerCase().replace(/\(\d[\d,]*(?: of \d[\d,]*)?\)/g, ' ')
    .replace(/[^a-z0-9]+/g, ' ').trim();
  function itemKey(f, module = f && f.module) {
    const fd = f || {};
    const data = fd.data && typeof fd.data === 'object' ? fd.data : {};
    let subject = '';
    for (const k of SUBJECT_KEYS) if (typeof data[k] === 'string' && data[k] !== '') { subject = `${k}=${data[k]}`; break; }
    const what = fd.code || norm(fd.title);
    if (MONITORING_MODULES.has(module)) return `m|${module}|${what}|${norm(fd.title)}|${subject}`;
    if (typeof fd.same_key === 'string' && fd.same_key) return `same|${fd.same_key}`;
    return `${module}|${what}|${subject}`;
  }

  // ---- The one list both views render (UX round 5) ----
  //
  // mergeKey(finding, module): when two findings are one item. The engine's
  // same_key (one thing seen by several checks); else the check, the code (or
  // title) and the thing it names (a label, path, extension...), and when it
  // names nothing, its title: "Extension with broad permissions: OneTab" and
  // "...: LastPass" are two items with one code. Counts in brackets ("(11)")
  // don't make another item. Monitoring findings never merge (displayItems).
  const MERGE_SUBJECT_KEYS = ['label', 'plist', 'path', 'program', 'bundle_id', 'extension_id', 'extension', 'name', 'target', 'id'];
  function mergeKey(f, module = f && f.module) {
    const fd = f || {};
    if (typeof fd.same_key === 'string' && fd.same_key && !MONITORING_MODULES.has(module)) return `same|${fd.same_key}`;
    const data = fd.data && typeof fd.data === 'object' ? fd.data : {};
    let subject = '';
    for (const k of MERGE_SUBJECT_KEYS) if (typeof data[k] === 'string' && data[k] !== '') { subject = `${k}=${data[k]}`; break; }
    if (!subject) subject = `title=${norm(fd.title)}`;
    return `${module}|${fd.code || norm(fd.title)}|${subject}`;
  }

  const isMarked = (f) => !!(f && f.data && f.data.marked_by_user === true);
  // The severity an item is listed at: the list's rule (shownSeverity); a
  // finding marked as yours comes back from the engine as info with its old
  // severity kept, and is listed at that (it is still the same item).
  function listSeverity(f, category) {
    const withCat = f && !f.category && category ? { ...f, category } : f;
    if (isMarked(f)) {
      const o = f.data.original_severity;
      return shownSeverity({ ...withCat, severity: o === 'critical' || o === 'warning' ? o : 'warning' });
    }
    return shownSeverity(withCat);
  }
  const RANK = { critical: 2, warning: 1, info: 0 };
  const acts = (f) => !!(f && ((f.fixable && typeof f.fixable === 'object') || (f.markable && typeof f.markable === 'object')));

  /*
   * displayItems(doc, { mode }) -> {
   *   critical: [item], warning: [item],   the to-do list (todo = their total)
   *   info: [item],                        good-to-know notes (notes)
   *   marked: [item],                      every finding in it marked as yours
   *   held: [item],                        city only: held monitoring software
   * }
   * Each item is in exactly one list:
   *   { key, severity, finding, findings, seen_in, marked, held }
   *   finding: the lead finding (a copy, with .module); findings: all of the
   *   item's findings, lead first; seen_in: their checks, lead's first.
   * The rule: partly-checked notes are not items (they count as not fully
   * checked). Findings with the same mergeKey are one item when both are
   * to-dos (critical or warning, by listSeverity) or both are notes; a to-do
   * never merges with a note. Monitoring findings never merge. The lead is
   * the worst; at the same severity the one that can be fixed or marked;
   * else the first. An item is marked only when all of its findings are. In
   * 'standard' held findings stay in critical/warning (Plain shows them with
   * the one line); in 'city' they go to `held` only. Doc order is kept: each
   * view sorts its own lists.
   */
  function displayItems(doc, { mode = 'standard' } = {}) {
    const city = mode === 'city';
    const out = { critical: [], warning: [], info: [], marked: [], held: [] };
    const all = [];
    const byKey = new Map();
    let n = 0;
    const modules = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean) : [];
    for (const mod of modules) {
      for (const raw of Array.isArray(mod.findings) ? mod.findings : []) {
        if (!raw || typeof raw !== 'object' || isPartlyChecked(raw)) continue;
        const f = { ...raw, module: mod.name };
        const sev = listSeverity(f, mod.category);
        const held = isHeld(raw, mod.name);
        const cls = sev === 'info' ? 'note' : 'todo';
        const key = MONITORING_MODULES.has(mod.name) ? `m|${(n += 1)}|${itemKey(f, mod.name)}` : `${cls}|${mergeKey(f, mod.name)}`;
        const have = byKey.get(key);
        if (!have) {
          const item = { key, severity: sev, finding: f, findings: [f], seen_in: [mod.name], marked: isMarked(f), held };
          byKey.set(key, item);
          all.push(item);
          continue;
        }
        const leads = RANK[sev] > RANK[have.severity] || (RANK[sev] === RANK[have.severity] && acts(f) && !acts(have.finding));
        if (leads) {
          have.findings.unshift(f);
          have.finding = f;
          have.severity = sev;
          have.seen_in = [mod.name, ...have.seen_in.filter((m) => m !== mod.name)];
        } else {
          have.findings.push(f);
          if (!have.seen_in.includes(mod.name)) have.seen_in.push(mod.name);
        }
        have.marked = have.marked && isMarked(f);
      }
    }
    for (const item of all) {
      if (item.held && city) out.held.push(item);
      else if (item.marked) out.marked.push(item);
      else out[item.severity].push(item);
    }
    return out;
  }

  // The LIST's card shape for an item (app.js plainCards, named for the retired Plain view): the lead
  // finding with `seen_in` and `also` (the other findings).
  function asCard(item) {
    return Object.assign({}, item.finding, { seen_in: item.seen_in.slice(), also: item.findings.slice(1) });
  }

  function scanCounts(doc, { mode = 'standard', districtOf = (c) => c || 'other' } = {}) {
    const city = mode === 'city';
    const modules = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean) : [];
    const p = notCheckedParts(doc);
    const cats = new Map(modules.map((m) => [m.name, m.category]));
    const out = {
      checks: modules.length, ran: 0,
      couldntRun: p.couldntRun.length, notReached: p.notReached.length, unfinished: p.unfinished.length,
      notStarted: p.notStarted.length, partly: p.partly.length,
      couldntCheck: p.couldntRun.length + p.notReached.length + p.notStarted.length,
      notChecked: p.couldntRun.length + p.notReached.length + p.notStarted.length + p.unfinished.length,
      didntFinish: p.couldntRun.length + p.notReached.length + p.unfinished.length, notFully: 0,
      todo: 0, notes: 0, markedItems: 0, heldItems: 0,
      critical: 0, warning: 0, info: 0, items: 0, marked: 0, held: 0, byDistrict: {},
    };
    out.ran = out.checks - out.couldntRun - out.notReached - out.notStarted;
    const district = (name) => {
      const id = districtOf(cats.get(name) || null);
      if (!out.byDistrict[id]) {
        out.byDistrict[id] = { couldntRun: 0, notReached: 0, unfinished: 0, notStarted: 0, partly: 0, notFully: 0,
          couldntCheck: 0, notChecked: 0, critical: 0, warning: 0, items: 0, todo: 0, notes: 0 };
      }
      return out.byDistrict[id];
    };
    const notFully = new Set();
    for (const [part, list] of [['couldntRun', p.couldntRun], ['notReached', p.notReached], ['unfinished', p.unfinished], ['notStarted', p.notStarted]]) {
      for (const x of list) {
        const d = district(x.name);
        d[part] += 1;
        d.notChecked += 1;
        if (part !== 'unfinished') d.couldntCheck += 1;
        notFully.add(x.name);
      }
    }
    const partlyMods = new Set(p.partly.map((x) => x.name));
    for (const name of partlyMods) { district(name).partly += 1; notFully.add(name); }
    for (const name of notFully) district(name).notFully += 1;
    out.notFully = notFully.size;

    const keys = new Map(); // itemKey -> district id (the older `items`)
    for (const mod of modules) {
      for (const f of Array.isArray(mod.findings) ? mod.findings : []) {
        if (!f || typeof f !== 'object' || isPartlyChecked(f)) continue;
        if (isHeld(f, mod.name)) {
          out.held += 1;
          if (city) continue;
        }
        if (f.data && f.data.marked_by_user === true) out.marked += 1;
        const sev = shownSeverity(f);
        out[sev] += 1;
        if (sev === 'info') continue;
        district(mod.name)[sev] += 1;
        const key = itemKey(f, mod.name);
        if (!keys.has(key)) keys.set(key, mod.name);
      }
    }
    out.items = keys.size;
    for (const name of keys.values()) district(name).items += 1;

    const list = displayItems(doc, { mode });
    out.todo = list.critical.length + list.warning.length;
    out.notes = list.info.length;
    out.markedItems = list.marked.length;
    out.heldItems = city ? list.held.length
      : [...list.critical, ...list.warning, ...list.info, ...list.marked].filter((x) => x.held).length;
    for (const item of [...list.critical, ...list.warning]) district(item.finding.module).todo += 1;
    for (const item of list.info) district(item.finding.module).notes += 1;
    return out;
  }

  return {
    MONITORING_MODULES, HELD_IN_CITY, NOT_DETECTIONS, COULDNT_LOOK, COULDNT_LOOK_REASON, NOT_STARTED_CODE,
    isPartlyChecked, isDetection, couldntLook, notStarted, notCheckedParts, notCheckedSummary, notCheckedLine,
    shownSeverity, familiarVerified, isPathSubject, isHeld, itemKey, scanCounts,
    mergeKey, listSeverity, displayItems, asCard, namesLine, fmt,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = NotChecked;
}
// A top-level const isn't a window property. The game's ES modules import this
// file for its side effect and read it from globalThis (window in the app).
if (typeof globalThis !== 'undefined') {
  globalThis.NotChecked = NotChecked;
}
