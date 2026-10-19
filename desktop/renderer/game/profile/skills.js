// What the profile measures: concepts (one skill each, for item response
// theory), and skills (a few concepts read together, MVProfile-style depth).
// `ref` is the concept's number in the teach-once proposal
// (docs/superpowers/specs/2026-10-18-teach-once-and-checklists-proposal.md,
// section 1.3); null where that list has no entry.
//
// Ids are stored (inside the recipe box), so each must pass FORBIDDEN_ON_DISK.
// `hidden`: measured, and counts toward its lesson, but never listed on the
// profile screen, in a skill, or in anything published.
export const CONCEPTS = Object.freeze([
  { id: 'who-made-it', ref: 'C1', title: 'Who made it' },
  { id: 'where-it-lives', ref: 'C2', title: 'Where it lives' },
  { id: 'fix-and-undo', ref: 'C8', title: 'Switching things off so you can undo it' },
  { id: 'couldnt-check', ref: 'C9', title: 'What “couldn’t check” means' },
  { id: 'clean-isnt-certain', ref: 'C10', title: 'What a clean result means' },
  { id: 'disk-encryption', ref: 'C12', title: 'Disk encryption and the recovery key' },
  { id: 'auto-updates', ref: 'C13', title: 'Automatic updates' },
  { id: 'lock-screen', ref: 'C14', title: 'The lock screen' },
  { id: 'browser-add-ons', ref: 'C15', title: 'Browser add-ons' },
  { id: 'remote-access-scams', ref: 'C17', title: 'Remote-access scams' },
  { id: 'password-prompts', ref: 'C19', title: 'Who asks for your password' },
  { id: 'wifi-and-mining', ref: 'C22', title: 'Your Wi-Fi and a hot, slow computer' },
  { id: 'cut-off-order', ref: 'C4', title: 'The order to do things in', hidden: true },
  { id: 'poisoned-packages', ref: 'C23', title: 'Poisoned packages' },
  { id: 'fake-messages', ref: null, title: 'Spotting a fake message' },
]);

export const SKILLS = Object.freeze([
  { id: 'reading-makers', title: 'Reading who made it and where it lives', concepts: ['who-made-it', 'where-it-lives'] },
  { id: 'starting-on-its-own', title: 'Things that start on their own', concepts: ['fix-and-undo'] },
  { id: 'locks-and-updates', title: 'Locks and updates', concepts: ['auto-updates', 'disk-encryption', 'lock-screen'] },
  { id: 'add-ons', title: 'Browser add-ons', concepts: ['browser-add-ons'] },
  { id: 'your-network', title: 'Your network', concepts: ['wifi-and-mining'] },
  { id: 'spotting-scams', title: 'Spotting a scam', concepts: ['remote-access-scams', 'password-prompts', 'fake-messages'] },
  { id: 'developer-packages', title: 'Developer packages', concepts: ['poisoned-packages'] },
  { id: 'honest-results', title: 'Honest results', concepts: ['couldnt-check', 'clean-isnt-certain'] },
]);

// Which concept a practice drill measures, by drill id. A drill not listed
// here (or listed as null) still counts toward drill accuracy, but toward no
// concept: its skill has no lesson to measure against yet.
export const DRILL_CONCEPTS = Object.freeze({
  'upd8r-hidden-cache': 'where-it-lives',
  'zoom-helper-signed': 'who-made-it',
  'tmp-script-agent': 'where-it-lives',
  'sync-keepalive': 'who-made-it',
  'small-app-helper': 'who-made-it',
  'own-backup-script': 'who-made-it',
  'hosts-bank-redirect': null,
  'dev-cert-app': 'who-made-it',
  'proxy-unknown': null,
  'proxy-work': null,
  'busy-miner': 'wifi-and-mining',
  'busy-video-export': 'wifi-and-mining',
  'preinstalled-trial': 'who-made-it',
  'signed-optimizer': 'who-made-it',
  'downloads-login-item': 'where-it-lives',
});

// A Signal or Noise call on a real finding has no right answer, so it is
// never graded. When Scout reads a call differently, it is a gap signal for
// the concepts behind the clues the person opened (or, with none opened, the
// concepts of the lessons that teach the finding's module).
export const CLUE_CONCEPTS = Object.freeze({ maker: 'who-made-it', where: 'where-it-lives' });

const BY_ID = new Map(CONCEPTS.map((c) => [c.id, c]));
export const conceptById = (id) => BY_ID.get(id) || null;
export const isHidden = (id) => !!(BY_ID.get(id) || {}).hidden;
export const shownConcepts = () => CONCEPTS.filter((c) => !c.hidden);
