// Words that must never be written to disk by the app. A stored key or value
// containing one could tell whoever looks at this computer what the person
// was worried about. Used by the storage tests.
const FORBIDDEN_ON_DISK = /partner|safety|\bsafe\b|stalk|watch|abuse|violence|advocate|hotline|799-7233|88788|monitor|spy/i;

// A storage that records every write, for the tests.
function recordingStore(initial = {}) {
  const data = { ...initial };
  const writes = [];
  const removed = [];
  return {
    data, writes, removed,
    getItem: (k) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null),
    setItem: (k, v) => { writes.push([String(k), String(v)]); data[k] = String(v); },
    removeItem: (k) => { removed.push(String(k)); delete data[k]; },
    clear: () => { removed.push('*'); for (const k of Object.keys(data)) delete data[k]; },
  };
}

// The writes that broke the rule, as "key=value".
function forbiddenWrites(store) {
  return store.writes.filter(([k, v]) => FORBIDDEN_ON_DISK.test(k) || FORBIDDEN_ON_DISK.test(v)).map(([k, v]) => `${k}=${v}`);
}

module.exports = { FORBIDDEN_ON_DISK, recordingStore, forbiddenWrites };
