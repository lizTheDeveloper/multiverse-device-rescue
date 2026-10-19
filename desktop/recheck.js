// Re-checking one module after a fix.
//
// The engine scans just that module. Its result replaces that module's entry in
// the last full scan, and both gatekeeping policies are re-armed from the merged
// scan. Merging whole scans (rather than patching one module's entries) keeps
// mark-policy's cross-module grouping correct. A re-check that fails, or that
// comes back without the module (it could not run here), changes nothing and
// is never treated as "fixed".
const MODULE_NAME = /^[a-z0-9_]+$/;
const NOT_RECHECKED = 'That check couldn’t run just now.';

function mergeModuleResult(lastDoc, partialDoc, name) {
  const mods = partialDoc && Array.isArray(partialDoc.modules) ? partialDoc.modules : [];
  const fresh = mods.find((m) => m && m.name === name) || null;
  if (!fresh || !lastDoc || !Array.isArray(lastDoc.modules)) return { doc: lastDoc, module: null };
  const has = lastDoc.modules.some((m) => m && m.name === name);
  const modules = has
    ? lastDoc.modules.map((m) => (m && m.name === name ? fresh : m))
    : [...lastDoc.modules, fresh];
  return { doc: { ...lastDoc, modules }, module: fresh };
}

function fail(error, message) {
  return { ok: false, error, message };
}

// A module that errored or could not run here checked nothing.
function didCheck(m) {
  return m.status !== 'error' && m.supported !== false;
}

// Pure handler behind ipcMain.handle('recheck-module'). Never throws.
async function handleRecheck(name, { getLastDoc, setLastDoc, runRecheck, policies }) {
  const last = getLastDoc();
  if (typeof name !== 'string' || !MODULE_NAME.test(name)) return fail('not_allowed', 'That check can’t be re-run from here.');
  if (!last || !Array.isArray(last.modules)) return fail('no_scan', 'Run the checkup first.');
  // A checkup that stopped before the end is shown, never acted on.
  if (last.stopped && typeof last.stopped === 'object') return fail('no_scan', 'Run the checkup again first.');
  if (!last.modules.some((m) => m && m.name === name)) return fail('not_allowed', 'That check wasn’t part of this checkup.');
  let partial;
  try {
    partial = await runRecheck(name);
  } catch (err) {
    return fail('engine_error', `We couldn’t re-check this: ${err && err.message ? err.message : err}`);
  }
  if (!partial || partial.engine_error) {
    return fail('engine_error', (partial && partial.message) || 'We couldn’t re-check this.');
  }
  // A full scan can land while the re-check runs (the person can go back to
  // the list and start one). That scan is newer: never overwrite it with a
  // merge into the old one.
  if (getLastDoc() !== last) return fail('not_rechecked', NOT_RECHECKED);
  const { doc, module } = mergeModuleResult(last, partial, name);
  if (!module || !didCheck(module)) return fail('not_rechecked', NOT_RECHECKED);
  setLastDoc(doc);
  for (const p of policies) p.remember(doc);
  return { ok: true, doc, module };
}

// An optional one-check sweep (the iPhone backup) is not a new checkup: when
// it comes back, its entry replaces that module's entry in the last full scan
// and everything else stays. null when it must not merge (no full last scan, a
// stopped or partial result on either side, or more than one module), so the
// caller keeps its old behaviour.
function isActionable(doc) {
  return !!doc && Array.isArray(doc.modules) && !(doc.stopped && typeof doc.stopped === 'object') && !(doc.partial && typeof doc.partial === 'object');
}
function mergeSingleModuleScan(lastDoc, doc) {
  if (!isActionable(lastDoc) || !isActionable(doc)) return null;
  const mods = doc.modules.filter(Boolean);
  if (mods.length !== 1 || typeof mods[0].name !== 'string' || !MODULE_NAME.test(mods[0].name)) return null;
  return mergeModuleResult(lastDoc, doc, mods[0].name).doc;
}

// Optional one-check sweeps that join the last full scan instead of replacing it.
const OPTIONAL_SWEEPS = new Set(['iphone_spyware_check']);
const joinsLastScan = (profile, lastDoc) => OPTIONAL_SWEEPS.has(profile) && isActionable(lastDoc);

// What run-scan does with a finished scan: returns the new "last scan" and
// re-arms the policies from it. A stopped or partial document never arms
// them (the policies' own filter stays), and a stopped one-check sweep leaves
// the last full scan alone.
function applyScanResult({ profile, lastDoc, doc, policies }) {
  if (joinsLastScan(profile, lastDoc)) {
    if (!isActionable(doc)) return lastDoc;
    const merged = mergeSingleModuleScan(lastDoc, doc);
    if (merged) {
      for (const p of policies) p.remember(merged);
      return merged;
    }
  }
  for (const p of policies) p.remember(doc);
  return doc;
}

module.exports = { mergeModuleResult, mergeSingleModuleScan, applyScanResult, joinsLastScan, handleRecheck };
