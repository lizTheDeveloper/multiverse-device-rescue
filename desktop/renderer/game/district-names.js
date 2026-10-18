// One district of the city is generated per install: its name, its look and
// the voice it greets you in are picked from these pools with the install's
// own number (DisplayMode's seed). The same install always gets the same
// district; different installs get different ones, so there is no fixed name
// to search for or recognise. Pure; no DOM.

export const NAMES = [
  'The Night Market', 'Pier 9', 'Clocktower Commons', 'The Observatory', 'Lantern Row', 'Copper Alley',
  'The Old Mill', 'Glasshouse Gardens', 'Ferry Landing', 'The Arcade', 'Tin Roof Lane', 'The Boardwalk',
  'Juniper Court', 'The Foundry', 'Canal Street', 'The Tramyard', 'Velvet Quarter', 'Pinecone Square',
  'The Waterworks', 'Moonlight Diner', 'Neon Strip', 'Harbor Lights', 'The Atrium', 'Saltmarsh Row',
  'Briar Lane', 'The Bandstand', 'Cobalt Yard', 'Orchard Street', 'The Greenhouse', 'Driftwood Quay',
  'Paper Lantern Plaza', 'Marigold Mews', 'The Roundhouse', 'Kite Hill', 'Ember Lane', 'Silverfish Wharf',
  'Thistle Court', 'The Planetarium', 'Crow’s Nest', 'Fig Tree Square', 'Starlight Rink', 'The Junction',
  'Brass Button Lane', 'Willow Steps', 'Ninth Street Garage', 'The Bakery Steps', 'Rooftop Terrace', 'Gaslight Row',
];

// Each look is a `.look-<id>` rule in game.css.
export const LOOKS = ['dusk', 'harbor', 'brass', 'moss', 'ember', 'neon'];

export const VOICES = [
  { id: 'market', hello: 'Lanterns are up. Pull up a crate and stay a while.', bye: 'The stalls will be here when you come back.' },
  { id: 'dock', hello: 'Tide’s in. Find a spot on the bench.', bye: 'The boats come in every night.' },
  { id: 'clock', hello: 'The gears are turning. Have a seat by the big wheel.', bye: 'The clock keeps going for you.' },
  { id: 'stars', hello: 'The dome is open. Plenty of room under the sky.', bye: 'The sky will still be here.' },
  { id: 'garden', hello: 'Mind the vines. There’s a bench in the shade.', bye: 'Come back when the flowers open.' },
  { id: 'diner', hello: 'The booth by the window is free. Coffee’s on.', bye: 'Your booth stays open.' },
];

// No name or voice may hint at what the district holds.
export const GIVEAWAY = /safe|help|hotline|advoca|abuse|partner|watch|stalk|shelter|refuge|haven|sanctuar|escape|rescue|secret|hidden|danger|violen|protect|support|crisis|hope|recover/i;

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
