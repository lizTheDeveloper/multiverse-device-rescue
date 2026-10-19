// "Spot the fake message", built from Reclaim City's own scam-defense quiz data
// (vendor/reclaim-city/src/data/phishing.js). The messages and their "tells" are
// Reclaim City's content; only the wrapper text here is Reclaim City's.
//
// Each of PICKS is a question (a family); FAMILY_VARIANTS lists the other
// messages of the same kind, so item response theory has several of each.
export const PICKS = [1, 4, 5];
export const FAMILY_VARIANTS = { 1: [8, 10, 6], 4: [3, 11, 12], 5: [2, 7, 9] };

function sentence(tells) {
  return `${tells.map((t) => String(t).replace(/[.\s]+$/, '')).join('. ')}.`;
}

const usable = (m) => m && (m.answer === 'pretext' || m.answer === 'genuine') && Array.isArray(m.tells) && m.tells.length;

function message(m) {
  return { type: m.type, from: m.from, subject: m.subject || null, body: m.body };
}

function item(m) {
  const fake = m.answer === 'pretext';
  const why = sentence(m.tells);
  return {
    key: `msg-${m.id}`,
    prompt: 'Real or fake?',
    message: message(m),
    options: [
      { text: 'Fake', correct: fake, feedback: fake ? `Right, it’s fake. ${why}` : `This one is real. ${why}` },
      { text: 'Real', correct: !fake, feedback: fake ? `This one is fake. ${why}` : `Right, it’s real. ${why}` },
    ],
  };
}

// A variant offers three options (two carry too little information for item
// response theory): the same real-or-fake call, with an advert as a third kind.
function variant(m) {
  const fake = m.answer === 'pretext';
  const why = sentence(m.tells);
  const right = fake ? 'Right, it’s fake.' : 'Right, it’s real.';
  const wrong = fake ? 'This one is fake.' : 'This one is real.';
  return {
    key: `msg-${m.id}`,
    prompt: 'What kind of message is this?',
    message: message(m),
    options: [
      { text: 'A fake pretending to be a company', correct: fake, feedback: fake ? `${right} ${why}` : `${wrong} ${why}` },
      { text: 'A real notice from the company', correct: !fake, feedback: fake ? `${wrong} ${why}` : `${right} ${why}` },
      { text: 'An advert from the company', correct: false, feedback: `${wrong} ${why}` },
    ],
  };
}

export function buildSpotTheFake(messages) {
  const byId = new Map((Array.isArray(messages) ? messages : []).map((m) => [m && m.id, m]));
  const questions = PICKS.map((id) => byId.get(id)).filter(usable).map((m) => ({
    ...item(m),
    concept: 'fake-messages',
    variants: (FAMILY_VARIANTS[m.id] || []).map((v) => byId.get(v)).filter(usable).map(variant),
  }));
  if (questions.length) questions[0].teach = 'Look at who sent it, whether it rushes you, and what it asks you to do. Even when a message looks real, type the company’s address into the address bar yourself, and don’t call a number from the message.';
  if (!questions.length) throw new Error('Spot the fake message: no usable messages');
  return {
    id: 'spot-the-fake',
    type: 'phishing',
    title: 'Spot the fake message',
    recommendedFor: ['hacked', 'identity', 'helping'],
    modules: [],
    districts: [],
    sources: ['desktop/vendor/reclaim-city/src/data/phishing.js', 'guides/identity_theft_recovery/phase_6.md'],
    briefing: 'Scammers copy the messages real companies send. These come from Reclaim City’s scam-defense quiz. For each one, decide whether it’s real or fake.',
    whatTheScanLooksFor: 'The checkup can’t see your messages. It looks for what a scam can leave behind on the computer, like remote-access tools.',
    questions,
  };
}
