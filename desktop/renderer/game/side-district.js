// What the generated district holds. Every line is traceable, word for word,
// to the Six Roses guide (https://themultiverse.school/x/six-roses, checked in
// as desktop/test/fixtures/six-roses-excerpt.txt) or to one of this project's
// guides; desktop/test/game-side-district.test.js enforces it. `quotes` are
// the source's own words inside `text`; the rest of `text` is joining words.
const SIX = 'six-roses';
const RESPOND = 'guides/remediation/respond_to_monitoring_software.md';
// The checkup's own words on a monitoring finding, which the list shows.
const ENGINE = 'modules/security/stalkerware_scan/__init__.py';

export const FIRST_STEPS = [
  { id: 'record', title: 'Keep a hidden record.', source: SIX,
    text: 'Use a new notebook that stays hidden. Write down all accounts you think they might access. List all devices you’ve shared or they’ve touched. Track strange occurrences with dates/times.',
    quotes: ['Use a NEW notebook that stays hidden', 'Write down all accounts you think they might access', "List all devices you've shared or they've touched", 'Track strange occurrences with dates/times'] },
  { id: 'phone', title: 'A safety phone.', source: SIX,
    text: 'Get a burner phone. This is your “safety phone” - guard it carefully. Don’t activate at home. Don’t save contacts with real names. Keep it OFF and battery out when not using.',
    quotes: ['Get a burner phone', 'This is your "safety phone" - guard it carefully', "Don't activate at home", "Don't save contacts with real names", 'Keep it OFF and battery out when not using'] },
  { id: 'code-words', title: 'Code words with a trusted friend.', source: SIX,
    text: 'Create a code system with trusted friend: “Thinking of you” = I’m okay. “Let’s get coffee” = I need help but not emergency. “Can you pick up milk?” = Call 911 for me. You can change these phrases to match your normal patterns.',
    quotes: ['Create a code system with trusted friend', '"Thinking of you" = I\'m okay', '"Let\'s get coffee" = I need help but not emergency', '"Can you pick up milk?" = Call 911 for me', 'You can change these phrases to match your normal patterns'] },
  { id: 'freedom-email', title: 'A separate “freedom email”.', source: SIX,
    text: 'Create email on friend’s device or library computer. NEVER access from your current devices. Don’t use identifying info in address. This becomes your “freedom email”.',
    quotes: ["Create email on friend's device or library computer", 'NEVER access from your current devices', "Don't use identifying info in address", 'This becomes your "freedom email"'] },
  { id: 'evidence-first', title: 'Keep the evidence before you change anything.', source: SIX,
    text: 'Document it first - screenshots/photos taken with a DIFFERENT device. Keep receipts/screenshots of harassment.',
    quotes: ['Document it first - screenshots/photos taken with a DIFFERENT device', 'Keep receipts/screenshots of harassment'] },
];

export const HELP = [
  { id: '911', name: '911', source: SIX, text: 'If you are in immediate danger, call 911.', quotes: ['If you are in immediate danger, call 911'] },
  { id: 'hotline', name: 'National Domestic Violence Hotline', source: SIX,
    text: 'National Domestic Violence Hotline: 1-800-799-7233. Text “START” to 88788.',
    quotes: ['National Domestic Violence Hotline: 1-800-799-7233', 'Text "START" to 88788'] },
  { id: 'techsafety', name: 'TechSafety.org', source: SIX, url: 'https://techsafety.org',
    text: 'TechSafety.org - Tech abuse resources', quotes: ['TechSafety.org - Tech abuse resources'] },
  { id: 'safety-net', name: 'NNEDV Safety Net', source: SIX, url: 'https://nnedv.org/safetynet',
    text: 'NNEDV Safety Net - Technology safety', quotes: ['NNEDV Safety Net - Technology safety'] },
  { id: 'womenslaw', name: 'WomensLaw.org', source: SIX, url: 'https://womenslaw.org',
    text: 'WomensLaw.org - Legal information', quotes: ['WomensLaw.org - Legal information'] },
  { id: 'ceta', name: 'Clinic to End Tech Abuse', source: SIX, url: 'https://ceta.tech.cornell.edu/',
    text: 'Clinic to End Tech Abuse', quotes: ['Clinic to End Tech Abuse'] },
];

// Shown as text: opening them from here would leave their names in the browser's history.
export const OPEN_NOTE = { source: SIX, text: 'Consider using a library or friend’s computer to look these up.',
  quotes: ["Consider using a library or friend's computer"] };

export const SIX_ROSES = {
  name: 'The Story of Six Roses', url: 'https://themultiverse.school/x/six-roses', source: SIX,
  text: 'How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life',
  quotes: ['How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life'],
  note: { source: SIX, text: 'It opens in your web browser. The title looks like a recipe, but the page is a safety guide, so open it when you’re alone or on a device that’s yours. Delete this from your browser history after reading.',
    quotes: ['Delete this from your browser history after reading'] },
};

export const LEAVING = { source: SIX, text: 'Leaving is the most dangerous time. Plan carefully with DV advocates.',
  quotes: ['Leaving is the most dangerous time. Plan carefully with DV advocates.'] };

// For monitoring software the checkup found: never "remove", and how to keep a quiet record of it.
export const HELD = {
  heading: { source: ENGINE, text: 'Don’t remove it yet. Talk to an advocate first.', quotes: ["Don't remove it yet", 'talk to an advocate'] },
  steps: [
    { source: SIX, text: 'Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it.',
      quotes: ['Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it'] },
    { source: RESPOND, text: 'On paper or on another device, write down the name the scan found, where it was found, and today’s date. Take a photo of the scan result with your phone.',
      quotes: ["On paper or on another device, write down the name the scan found, where it was found, and today's date", 'Take a photo of the scan result with your phone'] },
    { source: SIX, text: 'Plan the timing with a DV advocate (Hotline: 1-800-799-7233, or text “START” to 88788).',
      quotes: ['Plan the timing with a DV advocate (Hotline: 1-800-799-7233, or text "START" to 88788)'] },
    { source: SIX, text: 'Sometimes it’s safer to leave it in place for now and use a separate, safe device for anything private.',
      quotes: ["Sometimes it's safer to leave it in place for now and use a separate, safe device for anything private"] },
  ],
};
