// Odd Jobs: the fallback game, and the reference implementation of the
// mini-game contract (../contract.js). One item at a time with the finding's
// own actions: mark it as yours, fix it, or say you did it (a re-check). Later
// is always first, the safe default. Pure: it returns decisions, research
// intents and HTML; the runner carries every effect out.

const label = (standard, city) => ({ standard, city });

// The thing a finding names, for a look-up: a label, an extension id, a
// program or file name (its last path part), else nothing.
const SUBJECT = ['label', 'bundle_id', 'extension_id', 'name', 'program', 'path', 'plist', 'target', 'app'];
function subjectOf(finding) {
  const d = finding && finding.data && typeof finding.data === 'object' ? finding.data : {};
  for (const k of SUBJECT) {
    const v = d[k];
    if (typeof v !== 'string' || !v.trim()) continue;
    if (/[\\/]/.test(v)) return v.split(/[\\/]/).filter(Boolean).pop() || '';
    return v;
  }
  return '';
}

const hasMark = (f) => !!(f && f.markable && typeof f.markable === 'object');
const hasFix = (f) => !!(f && f.fixable && typeof f.fixable === 'object');

// The paragraphs a standard-mode card shows: the finding's first one only (teach once).
const firstParagraph = (s) => String(s == null ? '' : s).split(/\n\s*\n/)[0].trim();

export default {
  type: 'simple',
  title: label('Other', 'Odd Jobs'),
  concepts: [],
  // The fallback claims nothing: anything no other game claims lands here.
  covers: [],

  decisions(item) {
    const f = (item && item.finding) || {};
    const out = [{ id: 'later', label: label('Later', 'Later'), effect: { kind: 'later' } }];
    if (hasMark(f)) out.push({ id: 'mine', label: label('It’s mine', 'Mine'), effect: { kind: 'mark' } });
    if (hasFix(f)) out.push({ id: 'fix', label: label('Fix it', 'Patch it'), effect: { kind: 'fix' } });
    if (out.length < 3) out.push({ id: 'did', label: label('I did this', 'Done it'), effect: { kind: 'recheck' } });
    return out.slice(0, 3);
  },

  research(item, ctx) {
    const f = (item && item.finding) || {};
    const subject = subjectOf(f);
    const links = subject ? [{ kind: 'lookup', source: ctx.platform === 'win32' ? 'microsoft-support' : 'web', query: subject }] : [];
    return { rows: ctx.evidenceRows(f, { mode: ctx.mode }) || [], what: '', links };
  },

  practice: {
    items: [
      { key: 'practice:simple:1', severity: 'warning', seen_in: ['practice'], marked: false, held: false, removal_alert: false,
        finding: { module: 'practice', title: 'A setting is switched off', description: 'A made-up example: a setting that is usually on is off.',
          severity: 'warning', category: 'integrity', data: { name: 'Example setting' } },
        findings: [] },
      { key: 'practice:simple:2', severity: 'warning', seen_in: ['practice'], marked: false, held: false, removal_alert: false,
        finding: { module: 'practice', title: 'A helper you may know', description: 'A made-up example: a small helper from an app.',
          severity: 'warning', category: 'security', data: { label: 'com.example.helper' } },
        findings: [] },
    ],
    // Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict. No `expect`: an
    // explanation (one GOT IT). `expect` may list several moves that all fit (the first is the best).
    script: [
      { item: 0, expect: 'later',
        say: label('A setting that is usually on is off, and you’re not sure why yet. What would you do?', 'A switch that is usually on is off, and you’re not sure why yet. What would you do?'),
        why: label('Not sure yet? Later is always safe: the job stays on your list.', 'Not sure yet? Later is always safe: the job stays on the board.') },
      { item: 1, expect: 'did',
        say: label('In this practice, you already removed this helper yourself. What would you do?', 'In this drill, you already cleared this helper out yourself. What would you do?'),
        why: label('“I did this” checks again, and the job counts once the check sees it gone.', '“Done it” sends the city to check again, and the job counts once it sees it gone.') },
    ],
  },

  render(view, ctx) {
    const f = (view && view.item && view.item.finding) || {};
    const r = (view && view.research) || {};
    const rows = (Array.isArray(r.rows) ? r.rows : []).slice(0, 8)
      .map((x) => `<div class="mg-row"><span class="mg-k">${ctx.esc(x && x.label)}</span> <span class="mg-v">${ctx.esc(x && x.value)}</span></div>`).join('');
    const about = ctx.mode === 'city' ? '' : `<p class="mg-about">${ctx.esc(firstParagraph(f.description))}</p>`;
    const what = r.what ? `<p class="mg-what">${ctx.esc(r.what)}</p>` : '';
    return `<div class="mg-card mg-simple"><h3 class="mg-title">${ctx.esc(f.title || '')}</h3>${about}${what}${rows ? `<div class="mg-rows">${rows}</div>` : ''}</div>`;
  },

  summary(results, ctx) {
    const list = Array.isArray(results) ? results : [];
    const later = list.filter((x) => x && x.decision === 'later').length;
    const done = list.length - later;
    const city = ctx && ctx.mode === 'city';
    const head = city ? `Odd jobs: ${done} done` : `${done} decided`;
    return `<p class="mg-summary">${head}${later ? `, ${later} saved for later` : ''}.</p>`;
  },
};
