// Keyboard and screen-reader help for the city. The words a screen reader
// hears (polite and few: a sweep's quarters, its end, new signals), and the
// clean-up Reclaim City's own screens need after each draw.

// The sweep's progress, said at most once per quarter: '' when nothing new.
// `said` is the last quarter already said (0 to 3), so a redraw says nothing.
export function sweepLine(boss, said = 0) {
  if (!boss || !boss.total) return { text: '', said };
  const quarter = Math.min(3, Math.floor((4 * boss.index) / boss.total));
  if (quarter <= said) return { text: '', said };
  return { text: `Checkup ${quarter * 25}% done.`, said: quarter };
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// When a checkup finishes: how many real signals wait to be sorted, and how many
// weren't there last time. Counts only: no titles, nothing held, no drills.
export function sweepDoneLine(sigs, prev = []) {
  const real = (Array.isArray(sigs) ? sigs : []).filter((x) => x && x.kind === 'real');
  const critical = real.filter((x) => x.severity === 'critical').length;
  const warning = real.filter((x) => x.severity === 'warning').length;
  const parts = [];
  if (critical) parts.push(plural(critical, 'critical signal', 'critical signals'));
  if (warning) parts.push(plural(warning, 'warning', 'warnings'));
  let text = parts.length ? `Checkup finished. ${parts.join(' and ')} to sort.` : 'Checkup finished. Nothing critical or warning to sort.';
  const before = new Set((Array.isArray(prev) ? prev : []).filter((x) => x && x.kind === 'real').map((x) => x.id));
  if (before.size) {
    const fresh = real.filter((x) => x.severity !== 'info' && !before.has(x.id)).length;
    if (fresh) text += ` ${plural(fresh, 'new one', 'new ones')} since the last checkup.`;
  }
  return text;
}

// Reclaim City's screens draw some controls as spans with data-action (Enter and
// Space already work on role="button", rc keyboard.js). Each gets a role and a
// Tab stop; an account's ON/OFF says which account and whether it's on. Its
// pictures are decoration beside their own names, so they get an empty alt.
const NATIVE = new Set(['A', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'SUMMARY']);
export function fixRcControls(root) {
  if (!root || typeof root.querySelectorAll !== 'function') return 0;
  let fixed = 0;
  for (const el of root.querySelectorAll('[data-action]')) {
    if (NATIVE.has(String(el.tagName).toUpperCase())) continue;
    if (!el.hasAttribute('role')) el.setAttribute('role', 'button');
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    if (el.getAttribute('data-action') === 'toggle-account') {
      const on = String(el.textContent || '').trim().toUpperCase() === 'ON';
      el.setAttribute('aria-pressed', on ? 'true' : 'false');
      const row = el.parentElement;
      const label = row ? String(row.textContent || '').replace(/\s+/g, ' ').replace(/\s*\b(ON|OFF)\s*$/, '').trim() : '';
      if (label) el.setAttribute('aria-label', label);
    }
    fixed += 1;
  }
  for (const img of root.querySelectorAll('img')) if (!img.hasAttribute('alt')) img.setAttribute('alt', '');
  return fixed;
}

// A new screen: focus its heading, so a screen reader starts there and Tab goes
// on from there (the caller scrolls the screen to its top). A screen's own title is
// marked data-landing (a district, a briefing, an outcome); otherwise its h1.
// The heading takes focus without joining the Tab order.
export function focusScreenHeading(root) {
  if (!root || typeof root.querySelector !== 'function') return false;
  const h = root.querySelector('[data-landing]') || root.querySelector('h1') || root.querySelector('h2');
  if (!h || typeof h.focus !== 'function') return false;
  if (!h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
  h.focus({ preventScroll: true });
  return true;
}
