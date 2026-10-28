// The why behind "Take your accounts back" (account-recovery.js). The
// checklist keeps to one line per step; this is where each step is explained.
export default {
  id: 'taking-accounts-back',
  title: 'Taking your accounts back',
  recommendedFor: ['hacked', 'identity'],
  // The device half of account recovery: what stays signed in on this computer.
  modules: ['session_revocation_scan'],
  districts: ['gatehouse'],
  sources: [
    'docs/scenarios/digital-security-reset.md',
    'guides/digital_security_reset/phase_2.md',
    'docs/trust-and-safety.md',
  ],
  briefing: 'When someone gets into an account, most of the fix happens in your accounts, on each provider’s own website. The checkup on this computer is the smaller half.',
  whatTheScanLooksFor: 'The checkup counts the browser profiles and accounts on this computer that stay signed in after a password change. It can’t see where your accounts are signed in elsewhere: that list is on each provider’s security page, which is what “Take your accounts back” walks you through.',
  questions: [
    {
      teach: 'Most accounts send their password reset links to your email. Whoever controls your email can reset the passwords of your other accounts, so the email account comes first.',
      prompt: 'Which account should you take back first?',
      options: [
        { text: 'Your social media', correct: false, feedback: 'Social media matters, but its password reset goes to your email. Take the email back first, or a new social password can be reset again.' },
        { text: 'The email your other accounts use', correct: true, feedback: 'Right. The email account is the recovery path for almost every other account.' },
        { text: 'A shopping site', correct: false, feedback: 'Shopping accounts come later. Their resets go through your email too.' },
      ],
    },
    {
      teach: 'If the computer you use has something that can read what you type, like a browser add-on that reads sign-in pages, a new password typed there can be read too. Until the checkup’s items are sorted, change passwords on a phone or another device you trust.',
      prompt: 'The checkup found a browser extension that can read everything you type on websites. Where should you change your email password?',
      options: [
        { text: 'Right here, now, on this computer', correct: false, feedback: 'The extension could read the new password as you type it. Use a device you trust, or sort out the extension first.' },
        { text: 'On your phone, or another device you trust', correct: true, feedback: 'Right. A device you trust keeps the new password to yourself.' },
      ],
    },
    {
      teach: 'Someone who got in can leave ways back in: a device still signed in, a forwarding rule that sends copies of your mail to them, their phone number as your recovery phone, or an app password. A new password doesn’t always remove these, so each one is its own step.',
      prompt: 'You changed your email password. Is the account yours again?',
      options: [
        { text: 'Yes, the new password locks them out', correct: false, feedback: 'Not always. A signed-in device, a forwarding rule or their recovery phone can still let them back in or read your mail.' },
        { text: 'Not yet: check the signed-in devices, forwarding, recovery details and apps too', correct: true, feedback: 'Right. Each of those is a door a new password may leave open.' },
      ],
    },
    {
      teach: 'You type your password and any code yourself, only on the provider’s own website. Nobody helping you needs them, and Reclaim City never asks for an account password, a one-time code or a recovery code.',
      prompt: 'Someone calls, says they’re from your email provider, and asks you to read out the code that was just texted to you, to “secure the account”. What do you do?',
      options: [
        { text: 'Read it out so they can help', correct: false, feedback: 'That code is how they get in. Never read a code to someone who contacted you.' },
        { text: 'Hang up, and go to the provider’s website yourself', correct: true, feedback: 'Right. Start from the provider’s own site, never from a call, text or email you didn’t expect.' },
      ],
    },
    {
      teach: 'If it may be a partner, an ex or someone you live with, signing them out or changing a password shows them you noticed. Talk to an advocate before you change account settings, so you can plan when to do it.',
      prompt: 'You think an ex is reading your email. What comes before signing them out?',
      options: [
        { text: 'Nothing. Sign them out right away.', correct: false, feedback: 'They may notice at once. An advocate can help you plan the timing and keep a record first (US National DV Hotline: 1-800-799-7233).' },
        { text: 'Talking to an advocate, so you can plan the timing', correct: true, feedback: 'Right. In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text START to 88788.' },
      ],
    },
  ],
};
