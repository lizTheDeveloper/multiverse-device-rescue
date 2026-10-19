'use strict';

/*
 * The worry screen is a checklist: the person ticks everything that sounds
 * close, and the checkup runs every check any of those worries would run.
 * This turns the ticked worries into one situation object, shaped like a
 * SITUATIONS entry, so the rest of the app and the game read it as before.
 * "Check everything" and the iPhone check run on their own: the first
 * already covers every worry, and the second reads a large phone backup.
 *
 * Nothing here is stored. Loaded as a plain script (global `Worries`) and
 * required from Node by the tests.
 */
const Worries = (function () {
  const CHECKLIST_IDS = Object.freeze(['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping']);
  const ON_THEIR_OWN = Object.freeze(['unsure', 'phone']);

  function idsOf(situation) {
    if (!situation) return [];
    if (Array.isArray(situation.ids)) return situation.ids.filter((x) => typeof x === 'string');
    return typeof situation.id === 'string' ? [situation.id] : [];
  }

  function has(situation, id) {
    return idsOf(situation).includes(id);
  }

  // The same worries in any order are the same checkup.
  function key(situation) {
    return [...idsOf(situation)].sort().join('+');
  }

  // The value for the first worry (in the list's order) that has one in `table`.
  function firstWith(situation, table) {
    for (const id of idsOf(situation)) {
      if (table && Object.prototype.hasOwnProperty.call(table, id)) return table[id];
    }
    return undefined;
  }

  function joinTitles(titles) {
    if (titles.length < 2) return titles[0] || '';
    return `${titles.slice(0, -1).join(', ')} and ${titles[titles.length - 1]}`;
  }

  function combine(ids, situations) {
    const list = Array.isArray(situations) ? situations : [];
    const wanted = new Set(Array.isArray(ids) ? ids : []);
    const picked = list.filter((s) => s && wanted.has(s.id));
    if (!picked.length) return null;
    if (picked.length === 1) {
      const s = picked[0];
      return Object.freeze({ ...s, ids: [s.id], profiles: s.profile ? [s.profile] : [] });
    }
    if (picked.some((s) => ON_THEIR_OWN.includes(s.id))) return null;
    const profiles = [...new Set(picked.map((s) => s.profile).filter((p) => typeof p === 'string' && p))];
    return Object.freeze({
      id: 'several',
      ids: picked.map((s) => s.id),
      icon: '',
      sub: '',
      title: joinTitles(picked.map((s) => s.title)),
      profiles,
      profile: profiles[0] || null,
      guide: picked[0].guide,
      guides: [...new Set(picked.map((s) => s.guide))],
      safety: picked.some((s) => !!s.safety),
    });
  }

  // What runScan takes: null (every check), one profile name, or several.
  function scanProfile(situation) {
    if (!situation) return null;
    const profiles = Array.isArray(situation.profiles)
      ? situation.profiles
      : (situation.profile ? [situation.profile] : []);
    if (!profiles.length) return null;
    return profiles.length === 1 ? profiles[0] : [...profiles];
  }

  return { CHECKLIST_IDS, ON_THEIR_OWN, idsOf, has, key, firstWith, combine, scanProfile };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Worries;
}
