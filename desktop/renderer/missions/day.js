// A day the engine gives as an ISO date ("2026-03-03", or the date part of a
// longer ISO time), in words: "March 3", with the year when it isn't this
// year's. The string is split, never handed to new Date(iso): that reads a bare
// date as UTC midnight, which is the day before west of Greenwich. Pure; the
// Guest Book and the help district both use it.
//
//   isoDay(v) -> { y, m, d } | null       null for anything that isn't a real calendar day
//   dayWords(v, { today, year, locale }) -> string  '' when isoDay(v) is null; `today`: a Date or ISO day (default now);
//                                           `year: true` always says the year (a record copied onto paper);
//                                           `locale`: default the computer's ('en-US' for the photo record, whose words are hashed)
//   localIso(date) -> 'YYYY-MM-DD'          a Date's own local day, for dayWords (no UTC shift)

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})(?:$|[T ])/;

export function isoDay(v) {
  if (typeof v !== 'string') return null;
  const m = ISO_DAY.exec(v.trim());
  if (!m) return null;
  const y = Number(m[1]); const mo = Number(m[2]); const d = Number(m[3]);
  // A local date from its parts: no timezone shift. It must come back the same (no 31 February).
  const local = new Date(y, mo - 1, d);
  if (local.getFullYear() !== y || local.getMonth() !== mo - 1 || local.getDate() !== d) return null;
  return { y, m: mo, d };
}

function yearOf(today) {
  if (today instanceof Date && !Number.isNaN(today.getTime())) return today.getFullYear();
  const t = isoDay(today);
  return t ? t.y : new Date().getFullYear();
}

export function localIso(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  const two = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}`;
}

export function dayWords(v, { today, year = false, locale } = {}) {
  const p = isoDay(v);
  if (!p) return '';
  const opts = !year && p.y === yearOf(today) ? { month: 'long', day: 'numeric' } : { month: 'long', day: 'numeric', year: 'numeric' };
  return new Date(p.y, p.m - 1, p.d).toLocaleDateString(locale, opts);
}
