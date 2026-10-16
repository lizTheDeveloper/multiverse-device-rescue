// Who vouches for each step of a game mission: the computer (confirmed, or a
// problem it found), nobody (couldn't check), or the person (yours to check).
import { esc } from '../escape.js';

const PLATFORM_NAME = { darwin: 'MAC', win32: 'WINDOWS', linux: 'LINUX' };
const OTHER = { darwin: 'win32', win32: 'darwin', linux: 'darwin' };

function badge(status, row, platform) {
  if (status === 'confirmed') return '<span class="badge safe">CONFIRMED BY YOUR COMPUTER</span>';
  if (status === 'problem') return '<span class="badge crit">PROBLEM FOUND</span>';
  if (status === 'couldnt') return '<span class="badge fog">COULDN’T CHECK</span>';
  if (status === 'other-platform') {
    const p = (row && Array.isArray(row.platforms) && row.platforms[0]) || OTHER[platform] || 'win32';
    return `<span class="badge skip">FOR ${PLATFORM_NAME[p] || 'OTHER'} COMPUTERS</span>`;
  }
  return '<span class="badge skip">YOURS TO CHECK</span>';
}

function shortDate(iso) {
  const d = iso ? new Date(iso) : null;
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString() : '';
}

const titles = (problems) => (problems || []).map((p) => p && p.title).filter(Boolean).join('; ');

export function renderVerification({ mission, verification, disagreement, canFinish, platform, deviceMissionFor }) {
  const byStep = new Map(verification.steps.map((s) => [s.step, s]));
  const rows = mission.steps.map((st, i) => {
    const v = byStep.get(i);
    const status = v ? v.status : 'yours';
    let detail = '';
    if (status === 'confirmed') detail = `<small>${esc(v.claim)}.</small>`;
    if (status === 'couldnt') detail = '<small>Couldn’t check this one. That doesn’t mean it’s done.</small>';
    if (status === 'problem') {
      const dm = deviceMissionFor(v.modules);
      detail = `<small>Your computer says: ${esc(titles(v.problems))}</small>${dm
        ? `<button type="button" class="btn-t" data-go="mission:${esc(dm.id)}">Fix it on your computer →</button>` : ''}`;
    }
    return `<li class="step"><span class="step-n">${i + 1}</span><span class="step-t">${esc(String(st.text).slice(0, 140))}${detail}</span>${badge(status, v, platform)}</li>`;
  }).join('');
  // Some steps confirmed, but not enough to finish. Steps for other computers
  // are left out; a problem is named as a problem; only steps nobody could
  // check (or no check covers) are the person's.
  const statuses = mission.steps.map((_, i) => (byStep.get(i) || { status: 'yours' }).status);
  const count = (st) => statuses.filter((x) => x === st).length;
  const here = statuses.length - count('other-platform');
  const problems = count('problem');
  const theirs = count('couldnt') + count('yours');
  const plural = (n) => (n === 1 ? 'step' : 'steps');
  const partial = verification.partial && !verification.allConfirmed ? `
    <p class="intel">Your computer confirmed ${count('confirmed')} of ${here} ${plural(here)}.${problems
      ? ` It found a problem with ${problems} ${plural(problems)}.` : ''}${theirs
      ? ` ${theirs} ${theirs === 1 ? 'is' : 'are'} yours to check.` : ''}</p>` : '';
  const date = disagreement ? shortDate(disagreement.reportedAt) : '';
  const reported = disagreement ? `
    <div class="panel disagree" role="note">
      <p class="intel"><strong>You reported this done${date ? ` on ${esc(date)}` : ''}.</strong>
      Your computer still shows: ${esc(titles(disagreement.problems))}. Your answer is kept.</p>
    </div>` : '';
  // Finishing from the scan needs every step settled by the computer.
  const finish = canFinish && verification.allConfirmed;
  return `
  <section class="verify" aria-label="What your computer can confirm">
    ${reported}
    <div class="panel active"><div class="label">WHO VOUCHES FOR EACH STEP</div>${partial}<ol class="steps">${rows}</ol></div>
    ${finish ? '<button type="button" class="btn-p" data-act="confirm-from-scan">FINISH FROM THE CHECKUP ✓</button>' : ''}
  </section>`;
}

export function renderMilestoneSplit({ confirmed, reported }) {
  const list = (xs) => ((xs || []).length ? `<ul class="notes">${xs.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="intel">None yet.</p>');
  return `
  <section class="panel milestone-split">
    <div class="label">CONFIRMED BY YOUR COMPUTER</div>${list(confirmed)}
    <div class="label">YOU REPORTED</div>${list(reported)}
  </section>`;
}
