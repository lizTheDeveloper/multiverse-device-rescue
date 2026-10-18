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

export const VOICES = [
  { id: 'market', hello: 'Lanterns are up. Pull up a crate and stay a while.', bye: 'The stalls will be here when you come back.' },
  { id: 'dock', hello: 'Tide’s in. Find a spot on the bench.', bye: 'The boats come in every night.' },
  { id: 'clock', hello: 'The gears are turning. Have a seat by the big wheel.', bye: 'The clock keeps going for you.' },
  { id: 'stars', hello: 'The dome is open. Plenty of room under the sky.', bye: 'The sky will still be here.' },
  { id: 'workshop', hello: 'The soldering iron is warm. Grab a stool by the bench.', bye: 'Your stool will be here when you want it.' },
  { id: 'diner', hello: 'The booth by the window is free. Coffee’s on.', bye: 'Your booth stays open.' },
];

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
  return { name: at(NAMES), look: at(LOOKS), voice: at(VOICES) };
}
