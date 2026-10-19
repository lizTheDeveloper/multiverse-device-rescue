// One district of the city is generated per install: its name, its look and
// the voice it greets you in are picked from these pools with the install's
// own number (DisplayMode's seed). The same install always gets the same
// district; different installs get different ones, so there is no fixed name
// to search for or recognise. Pure; no DOM.

export const NAMES = [
  'The Night Market', 'Pier 9', 'Clocktower Commons', 'The Observatory', 'Lantern Row', 'Copper Alley',
  'The Old Mill', 'Gearwheel Row', 'Ferry Landing', 'The Arcade', 'Tin Roof Lane', 'The Boardwalk',
  'The Depot', 'The Foundry', 'Canal Street', 'The Tramyard', 'Velvet Quarter', 'Tollbooth Corner',
  'The Waterworks', 'Moonlight Diner', 'Neon Strip', 'Harbor Quay', 'The Atrium', 'Saltmarsh Row',
  'Rivet Street', 'The Bandstand', 'Cobalt Yard', 'Bell Foundry Lane', 'The Cannery', 'Driftwood Quay',
  'Paper Lantern Plaza', 'Signal Hill', 'The Roundhouse', 'Kite Hill', 'Ember Lane', 'Silverfish Wharf',
  'Quarry Steps', 'The Planetarium', 'Crow’s Nest', 'The Print Shop', 'Starlight Rink', 'The Junction',
  'Brass Button Lane', 'Lamplighter Way', 'Ninth Street Garage', 'The Bakery Steps', 'Rooftop Terrace', 'Gaslight Row',
];

// Each look is a `.look-<id>` rule in game.css.
export const LOOKS = ['dusk', 'harbor', 'brass', 'moss', 'ember', 'neon'];

// Each voice fits the places it is given to (VOICE_OF): no dome in a print shop.
export const VOICES = [
  { id: 'market', hello: 'Lanterns are up. Pull up a crate and stay a while.', bye: 'The stalls will be here when you come back.' },
  { id: 'dock', hello: 'Tide’s in. Find a spot on the bench.', bye: 'The boats come in every night.' },
  { id: 'clock', hello: 'The gears are turning. Have a seat by the big wheel.', bye: 'The clock keeps going for you.' },
  { id: 'stars', hello: 'The sky’s clear tonight. Plenty of room up here.', bye: 'The sky will still be here.' },
  { id: 'workshop', hello: 'The kettle’s on in the back room. Grab a stool by the bench.', bye: 'Your stool will be here when you want it.' },
  { id: 'diner', hello: 'The booth by the window is free. Coffee’s on.', bye: 'Your booth stays open.' },
  { id: 'street', hello: 'The lamps are on. Find a spot and stay a while.', bye: 'This corner will be here when you come back.' },
  { id: 'arcade', hello: 'The machines are humming. Grab the stool by the window.', bye: 'Your stool stays free.' },
  { id: 'rail', hello: 'The last tram’s in. Have a seat on the platform bench.', bye: 'The trams keep running.' },
  { id: 'bakery', hello: 'Something’s just out of the oven. Have a seat on the steps.', bye: 'There’ll be more in the morning.' },
];

// The voice each place greets you in.
export const VOICE_OF = {
  'The Night Market': 'market', 'Pier 9': 'dock', 'Clocktower Commons': 'clock', 'The Observatory': 'stars',
  'Lantern Row': 'market', 'Copper Alley': 'workshop', 'The Old Mill': 'workshop', 'Gearwheel Row': 'clock',
  'Ferry Landing': 'dock', 'The Arcade': 'arcade', 'Tin Roof Lane': 'street', 'The Boardwalk': 'dock',
  'The Depot': 'rail', 'The Foundry': 'workshop', 'Canal Street': 'dock', 'The Tramyard': 'rail',
  'Velvet Quarter': 'street', 'Tollbooth Corner': 'street', 'The Waterworks': 'workshop', 'Moonlight Diner': 'diner',
  'Neon Strip': 'arcade', 'Harbor Quay': 'dock', 'The Atrium': 'street', 'Saltmarsh Row': 'dock',
  'Rivet Street': 'workshop', 'The Bandstand': 'street', 'Cobalt Yard': 'workshop', 'Bell Foundry Lane': 'workshop',
  'The Cannery': 'workshop', 'Driftwood Quay': 'dock', 'Paper Lantern Plaza': 'market', 'Signal Hill': 'stars',
  'The Roundhouse': 'rail', 'Kite Hill': 'stars', 'Ember Lane': 'street', 'Silverfish Wharf': 'dock',
  'Quarry Steps': 'street', 'The Planetarium': 'stars', 'Crow’s Nest': 'dock', 'The Print Shop': 'workshop',
  'Starlight Rink': 'arcade', 'The Junction': 'rail', 'Brass Button Lane': 'street', 'Lamplighter Way': 'street',
  'Ninth Street Garage': 'workshop', 'The Bakery Steps': 'bakery', 'Rooftop Terrace': 'stars', 'Gaslight Row': 'street',
};
const voiceFor = (name) => VOICES.find((v) => v.id === VOICE_OF[name]) || VOICES.find((v) => v.id === 'street');

// No name or voice may hint at what the district holds.
export const GIVEAWAY = /safe|help|hotline|advoca|abuse|partner|watch|stalk|shelter|refuge|haven|sanctuar|escape|rescue|secret|hidden|danger|violen|protect|support|crisis|hope|recover|garden|rose|flower|bloom|petal|briar|thistle|vine/i;

// mulberry32: a small, well-mixed generator; the same seed gives the same picks.
function generator(seed) {
  let a = seed | 0;
  return function next() {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pickDistrict(seed) {
  const n = Number.isInteger(seed) && seed > 0 ? seed : 1;
  const next = generator(n);
  const at = (list) => list[Math.floor(next() * list.length)];
  // Name, then look: the same picks as before for every install. The voice follows the name.
  const name = at(NAMES);
  return { name, look: at(LOOKS), voice: voiceFor(name) };
}

// The install's seed as the game gets it (RescueHost.citySeed, which app.js
// reads once per session with DisplayMode.ensureSeed): a positive integer, or
// the digits of one. Anything else (missing, blocked, garbled) gets a random
// seed for this session, never a constant that every such install would share.
const MAX_SEED = 0x7fffffff;
export function seedFrom(raw, random = Math.random) {
  const n = typeof raw === 'string' && /^\s*\d+\s*$/.test(raw) ? Number(raw.trim()) : raw;
  if (Number.isInteger(n) && n >= 1 && n <= MAX_SEED) return n;
  return 1 + Math.floor(random() * (MAX_SEED - 1));
}
