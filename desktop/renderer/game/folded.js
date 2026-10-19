// One-way, compact records of keys the game no longer stores in full, so a
// long-lived profile stays small without paying anything twice. Pure.
//
// - A Bloom filter of lifetime award keys ("fix:…", "report:…") folded out of
//   deck.once. A key in it has paid. A false positive (about 0.1% of new keys
//   at 2,000 folded, about 5% at 5,000) means a new key doesn't pay: points
//   are lost in that rare case, never paid twice.
// - Short hashes of ids (7 characters, 32 bits) for "was this folded?".
//
// Both are written in an alphabet with no vowels, no "y" and no 8, so
// no word that must stay off disk can appear in it.
export const BLOOM_BITS = 1 << 15;
export const BLOOM_HASHES = 6;
const ALPHABET = '012345679bcdfghjklmnpqrstvwxz-_.';
const BITS_PER_CHAR = 5;
export const BLOOM_CHARS = Math.ceil(BLOOM_BITS / BITS_PER_CHAR);
const VALUE = new Map([...ALPHABET].map((c, i) => [c, i]));

// FNV-1a over UTF-16 code units, with a final mix.
export function hash32(s, seed = 0x811c9dc5) {
  let h = seed >>> 0;
  const t = String(s);
  for (let i = 0; i < t.length; i += 1) h = Math.imul(h ^ t.charCodeAt(i), 0x01000193);
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h >>> 0;
}

export const SHORT_HASH_CHARS = 7;
export function shortHash(s) {
  let h = hash32(s);
  let out = '';
  for (let i = 0; i < SHORT_HASH_CHARS; i += 1) { out += ALPHABET[h & 31]; h >>>= 5; }
  return out;
}

function positions(key) {
  const h1 = hash32(key);
  const h2 = hash32(key, 0x9747b28c) | 1;
  return Array.from({ length: BLOOM_HASHES }, (_, i) => ((h1 + Math.imul(i, h2)) >>> 0) % BLOOM_BITS);
}

const BLOOM_RE = /^[012345679bcdfghjklmnpqrstvwxz_.-]*$/;
export const validBloom = (s) => typeof s === 'string' && s.length === BLOOM_CHARS && BLOOM_RE.test(s);

function bitsOf(s) {
  const bits = new Uint8Array(BLOOM_CHARS * BITS_PER_CHAR);
  if (!validBloom(s)) return bits;
  for (let i = 0; i < BLOOM_CHARS; i += 1) {
    const v = VALUE.get(s[i]);
    for (let b = 0; b < BITS_PER_CHAR; b += 1) bits[i * BITS_PER_CHAR + b] = (v >> b) & 1;
  }
  return bits;
}

function textOf(bits) {
  let out = '';
  for (let i = 0; i < BLOOM_CHARS; i += 1) {
    let v = 0;
    for (let b = 0; b < BITS_PER_CHAR; b += 1) v |= bits[i * BITS_PER_CHAR + b] << b;
    out += ALPHABET[v];
  }
  return out;
}

// Whether `key` was added. False for a missing or malformed filter.
export function bloomHas(s, key) {
  if (!validBloom(s)) return false;
  return positions(key).every((p) => (VALUE.get(s[Math.floor(p / BITS_PER_CHAR)]) >> (p % BITS_PER_CHAR)) & 1);
}

// A new filter with `keys` added to `s` (or to an empty one).
export function bloomAdd(s, keys) {
  const bits = bitsOf(s);
  for (const k of keys) for (const p of positions(k)) bits[p] = 1;
  return textOf(bits);
}

// A filter with every bit set: every key in it. What a damaged filter is
// replaced with, so a folded key can never pay again (fail safe).
export const FULL_BLOOM = ALPHABET[31].repeat(BLOOM_CHARS);

// A list of short hashes, as one string, newest last, at most MAX_HASHES.
export const MAX_HASHES = 500;
const HASHES_RE = new RegExp(`^(?:[012345679bcdfghjklmnpqrstvwxz_.-]{${SHORT_HASH_CHARS}})*$`);
export const validHashes = (s) => typeof s === 'string' && s.length <= MAX_HASHES * SHORT_HASH_CHARS && HASHES_RE.test(s);
export const addHashes = (s, ids) => ((validHashes(s) ? s : '') + ids.map(shortHash).join('')).slice(-MAX_HASHES * SHORT_HASH_CHARS);
// `s` without the hash of `id`, or null when it isn't there.
export function takeHash(s, id) {
  if (!validHashes(s) || !s) return null;
  const h = shortHash(id);
  for (let i = 0; i < s.length; i += SHORT_HASH_CHARS) if (s.slice(i, i + SHORT_HASH_CHARS) === h) return s.slice(0, i) + s.slice(i + SHORT_HASH_CHARS);
  return null;
}
