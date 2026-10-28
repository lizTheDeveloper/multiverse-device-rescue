// What a thing the person marked as theirs is FOR, in their own words picked
// from a short list. Saying what it is shows they know it, and the YOURS radar
// draws their computer's habits from it. Pure.
//
// The list is fixed so nothing free-typed is stored. A suggestion comes from
// the evidence (who made it, what kind of program it is), never from a guess
// about the person; it is only ever a pre-selected choice they confirm.

export const OWN_CATEGORIES = Object.freeze([
  Object.freeze({ id: 'work', icon: '▤', label: 'Work and office' }),
  Object.freeze({ id: 'dev', icon: '⌘', label: 'Developer tools' }),
  Object.freeze({ id: 'browser', icon: '◎', label: 'Browser and add-ons' }),
  Object.freeze({ id: 'chat', icon: '✉', label: 'Chat and calls' }),
  Object.freeze({ id: 'cloud', icon: '☁', label: 'Cloud and sync' }),
  Object.freeze({ id: 'security', icon: '⛨', label: 'Security and privacy' }),
  Object.freeze({ id: 'hardware', icon: '⚙', label: 'Hardware and drivers' }),
  Object.freeze({ id: 'media', icon: '♫', label: 'Media and games' }),
  Object.freeze({ id: 'other', icon: '…', label: 'Something else' }),
]);
export const OWN_CATEGORY_IDS = new Set(OWN_CATEGORIES.map((c) => c.id));
// The radar's spokes: every category but "something else".
export const RADAR_AXES = OWN_CATEGORIES.filter((c) => c.id !== 'other');

const MAKER_HINTS = [
  [/zoom|slack|discord|signal messenger|whatsapp|skype|telegram|webex/i, 'chat'],
  [/dropbox|google drive|onedrive|box, inc|icloud|backblaze|sync/i, 'cloud'],
  [/microsoft office|adobe|notion|atlassian|zoom video|1password|bitwarden/i, 'work'],
  [/docker|jetbrains|github|homebrew|node|python|visual studio|xcode|anaconda|vagrant|hashicorp/i, 'dev'],
  [/spotify|valve|steam|epic games|blizzard|apple music|vlc|netflix/i, 'media'],
  [/logitech|razer|elgato|wacom|highpoint|fujitsu|epson|canon|hp inc|brother|nvidia|amd|intel/i, 'hardware'],
  [/malwarebytes|objective-see|little snitch|nordvpn|proton|mullvad|norton|avast|sophos|crowdstrike/i, 'security'],
];
const DEV_PROGRAMS = /\b(ssh|node|python\d?|ruby|java|docker|git|code|npm|uvicorn|postgres|redis|mongod)\b/i;

// A pre-selected choice for the "what is it?" question, or null.
// `kinds`: program-kinds.js kindsOf ids.
export function suggestCategory(finding, kinds = []) {
  const f = finding || {};
  if ((kinds || []).includes('extension')) return 'browser';
  const makers = Array.isArray(f.made_by) ? f.made_by.map((m) => String((m && m.name) || '')).join(' ') : '';
  for (const [re, id] of MAKER_HINTS) if (re.test(makers)) return id;
  const d = f.data && typeof f.data === 'object' ? f.data : {};
  if (DEV_PROGRAMS.test(String(d.program || d.process || ''))) return 'dev';
  if (/kext|driver/i.test(String(f.module || ''))) return 'hardware';
  return null;
}

// How many things marked as theirs fall in each category, for the radar.
// `deck`: progress.js deck; only MINE tags with a category count.
export function radarOf(deck) {
  const counts = Object.fromEntries(OWN_CATEGORIES.map((c) => [c.id, 0]));
  const tags = (deck && deck.tags) || {};
  for (const t of Object.values(tags)) {
    if (t && t.tag === 'mine' && OWN_CATEGORY_IDS.has(t.cat)) counts[t.cat] += 1;
  }
  return counts;
}
