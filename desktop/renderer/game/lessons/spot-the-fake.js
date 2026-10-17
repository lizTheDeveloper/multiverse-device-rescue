// "Spot the fake message", built from Reclaim City's own scam-defense quiz data
// (vendor/reclaim-city/src/data/phishing.js). The messages and their "tells" are
// Reclaim City's content; only the wrapper text here is Device Rescue's.
export const PICKS = [1, 4, 5];

function sentence(tells) {
  return `${tells.map((t) => String(t).replace(/[.\s]+$/, '')).join('. ')}.`;
}

export function buildSpotTheFake(messages) {
  const byId = new Map((Array.isArray(messages) ? messages : []).map((m) => [m && m.id, m]));
  const questions = PICKS.map((id) => byId.get(id))
    .filter((m) => m && (m.answer === 'pretext' || m.answer === 'genuine') && Array.isArray(m.tells) && m.tells.length)
    .map((m) => {
      const fake = m.answer === 'pretext';
      const why = sentence(m.tells);
      return {
        prompt: 'Real or fake?',
        message: { type: m.type, from: m.from, subject: m.subject || null, body: m.body },
        options: [
          { text: 'Fake', correct: fake, feedback: fake ? `Right, it’s fake. ${why}` : `This one is real. ${why}` },
          { text: 'Real', correct: !fake, feedback: fake ? `This one is fake. ${why}` : `Right, it’s real. ${why}` },
        ],
      };
    });
  if (!questions.length) throw new Error('Spot the fake message: no usable messages');
  return {
    id: 'spot-the-fake',
    type: 'phishing',
    title: 'Spot the fake message',
    recommendedFor: ['hacked', 'identity', 'helping'],
    modules: [],
    sources: ['desktop/vendor/reclaim-city/src/data/phishing.js', 'guides/identity_theft_recovery/phase_6.md'],
    briefing: 'Scammers copy the messages real companies send. These come from Reclaim City’s scam-defense quiz. For each one, decide whether it’s real or fake. Look at who sent it, whether it rushes you, and what it asks you to do. Even when a message looks real, type the company’s address into the address bar yourself, and don’t call a number from the message.',
    whatTheScanLooksFor: 'The checkup can’t see your messages. It looks for what a scam can leave behind on the computer, like remote-access tools.',
    questions,
  };
}
