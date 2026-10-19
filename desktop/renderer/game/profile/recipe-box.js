// The player profile on disk, disguised as a box of recipe cards. Every byte
// of the profile's JSON becomes one ingredient word, through a word order
// shuffled by a number made once per install, so two installs write the same
// profile differently and nothing literal ever reaches disk. Only this code
// maps the cards back. It hides; it doesn't lock: anyone with this file could
// decode it, which is fine, because the goal is that a glance at the disk (or
// a search for a word) finds recipes, not progress.
//
// Pure. No storage, no DOM. TextEncoder/TextDecoder exist in Electron and Node.
export const WORDS = Object.freeze([
  'basil', 'thyme', 'sage', 'rosemary', 'parsley', 'dill', 'oregano', 'tarragon', 'chive',
  'cilantro', 'fennel', 'cumin', 'coriander', 'paprika', 'saffron', 'turmeric', 'cardamom',
  'clove', 'nutmeg', 'cinnamon', 'ginger', 'garlic', 'shallot', 'vanilla', 'anise', 'caraway',
  'marjoram', 'sorrel', 'lovage', 'chervil', 'allspice', 'sumac', 'fenugreek', 'juniper', 'pepper',
  'mustard', 'horseradish', 'wasabi', 'leek', 'onion', 'carrot', 'celery', 'potato', 'tomato',
  'squash', 'pumpkin', 'zucchini', 'courgette', 'aubergine', 'eggplant', 'spinach', 'kale',
  'chard', 'cabbage', 'lettuce', 'arugula', 'radish', 'turnip', 'parsnip', 'beetroot', 'artichoke',
  'asparagus', 'broccoli', 'cauliflower', 'okra', 'pea', 'bean', 'lentil', 'chickpea', 'corn',
  'mushroom', 'truffle', 'olive', 'caper', 'cucumber', 'gherkin', 'endive', 'kohlrabi', 'yam',
  'cassava', 'taro', 'rhubarb', 'watercress', 'scallion', 'celeriac', 'apple', 'pear', 'plum',
  'peach', 'apricot', 'cherry', 'grape', 'fig', 'lemon', 'lime', 'orange', 'tangerine', 'mandarin',
  'grapefruit', 'melon', 'mango', 'papaya', 'guava', 'kiwi', 'banana', 'pineapple', 'coconut',
  'raspberry', 'strawberry', 'blueberry', 'blackberry', 'cranberry', 'gooseberry', 'currant',
  'raisin', 'sultana', 'prune', 'quince', 'lychee', 'pomegranate', 'persimmon', 'kumquat',
  'elderberry', 'mulberry', 'nectarine', 'flour', 'bread', 'toast', 'bagel', 'brioche', 'biscuit',
  'scone', 'muffin', 'crumpet', 'pancake', 'waffle', 'crepe', 'noodle', 'pasta', 'rice', 'barley',
  'oats', 'rye', 'wheat', 'millet', 'quinoa', 'polenta', 'couscous', 'bulgur', 'semolina',
  'dumpling', 'pretzel', 'cracker', 'oatcake', 'galette', 'tart', 'pie', 'crumble', 'cobbler',
  'pudding', 'custard', 'trifle', 'souffle', 'risotto', 'paella', 'pilaf', 'curry', 'stew', 'soup',
  'broth', 'chowder', 'gumbo', 'goulash', 'ragout', 'casserole', 'frittata', 'omelette', 'quiche',
  'tagine', 'korma', 'biryani', 'ramen', 'udon', 'soba', 'gnocchi', 'lasagne', 'ravioli',
  'tortilla', 'taco', 'burrito', 'empanada', 'pierogi', 'samosa', 'falafel', 'hummus', 'pesto',
  'salsa', 'chutney', 'relish', 'compote', 'jam', 'marmalade', 'jelly', 'syrup', 'honey',
  'caramel', 'toffee', 'fudge', 'praline', 'meringue', 'macaron', 'sorbet', 'gelato', 'granita',
  'parfait', 'fondue', 'gratin', 'terrine', 'butter', 'cream', 'cheese', 'yogurt', 'ricotta',
  'feta', 'brie', 'cheddar', 'gouda', 'parmesan', 'mozzarella', 'halloumi', 'paneer', 'ghee',
  'kefir', 'buttermilk', 'milk', 'egg', 'almond', 'walnut', 'pecan', 'hazelnut', 'cashew',
  'pistachio', 'peanut', 'chestnut', 'macadamia', 'sesame', 'poppy', 'flax', 'sugar', 'salt',
  'vinegar', 'molasses', 'treacle', 'cocoa', 'chocolate', 'coffee',
]);
export const CARD_SIZE = 24;
// The decoded text starts with this, so a wrong seed or a damaged card fails
// to decode instead of producing nonsense.
const MAGIC = 'rb1:';
const MAX_SEED = 0x7fffffff;

// A small, well-known 32-bit generator (mulberry32). Deterministic per seed.
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function validSeed(seed) {
  return Number.isInteger(seed) && seed >= 1 && seed <= MAX_SEED;
}

// byte -> word index, shuffled per seed (Fisher-Yates).
export function wordOrder(seed) {
  const order = Array.from({ length: 256 }, (_, i) => i);
  const rnd = mulberry32(seed);
  for (let i = 255; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

// The keystream that scrambles the bytes before they become words, so a run
// of the same character doesn't become a run of the same ingredient.
function keystream(seed) {
  const rnd = mulberry32((seed ^ 0x5bd1e995) >>> 0);
  return () => Math.floor(rnd() * 256);
}

// The seed itself, as four words in the unshuffled order, so a card box can
// always be read back even if the install's seed key is lost.
function seedWords(seed) {
  return [24, 16, 8, 0].map((s) => WORDS[(seed >>> s) & 0xff]).join(' ');
}

function seedFrom(kitchen) {
  const parts = typeof kitchen === 'string' ? kitchen.split(' ') : [];
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const i = WORDS.indexOf(p);
    if (i < 0) return null;
    n = (n * 256) + i;
  }
  return validSeed(n) ? n : null;
}

const dish = (order, i) => `${WORDS[order[(i * 7) % 256]]} ${WORDS[order[(i * 13 + 5) % 256]]}`;

// Any JSON value -> the stored text. Throws on a bad seed or a value that
// JSON can't hold (the caller then keeps what's on disk).
export function encode(value, seed) {
  if (!validSeed(seed)) throw new Error('recipe box: bad seed');
  const json = JSON.stringify(value);
  if (typeof json !== 'string') throw new Error('recipe box: nothing to store');
  const bytes = new TextEncoder().encode(MAGIC + json);
  const order = wordOrder(seed);
  const ks = keystream(seed);
  const words = Array.from(bytes, (b) => WORDS[order[b ^ ks()]]);
  const cards = [];
  for (let i = 0; i * CARD_SIZE < words.length; i += 1) {
    cards.push({ dish: dish(order, i), serves: 2 + (i % 5), ingredients: words.slice(i * CARD_SIZE, (i + 1) * CARD_SIZE) });
  }
  return JSON.stringify({ kitchen: seedWords(seed), cards });
}

// The stored text -> the value, or null when it isn't a card box this code wrote.
export function decode(text) {
  try {
    const box = JSON.parse(text);
    const seed = seedFrom(box && box.kitchen);
    if (seed === null || !Array.isArray(box.cards)) return null;
    const order = wordOrder(seed);
    const back = new Map(order.map((w, b) => [WORDS[w], b]));
    const ks = keystream(seed);
    const bytes = [];
    for (const card of box.cards) {
      if (!card || !Array.isArray(card.ingredients)) return null;
      for (const word of card.ingredients) {
        if (!back.has(word)) return null;
        bytes.push(back.get(word) ^ ks());
      }
    }
    const textOut = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    if (!textOut.startsWith(MAGIC)) return null;
    return JSON.parse(textOut.slice(MAGIC.length));
  } catch (_) {
    return null;
  }
}

// The seed a stored box was written with, or null.
export function seedOf(text) {
  try { return seedFrom(JSON.parse(text).kitchen); } catch (_) { return null; }
}
