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
      concept: 'email-first',
      teach: 'Most accounts send their password reset links to your email. Whoever controls your email can reset the passwords of your other accounts, so the email account comes first.',
      prompt: 'Which account should you take back first?',
      options: [
        { text: 'Your social media', correct: false, feedback: 'Social media matters, but its password reset goes to your email. Take the email back first, or a new social password can be reset again.' },
        { text: 'The email your other accounts use', correct: true, feedback: 'Right. The email account is the recovery path for almost every other account.' },
        { text: 'A shopping site', correct: false, feedback: 'Shopping accounts come later. Their resets go through your email too.' },
      ],
      variants: [
        {
          prompt: 'Your bank, your social media and your email were all signed in to by someone else. Which do you change first?',
          options: [
            { text: 'The bank, because it has the money', correct: false, feedback: 'The bank matters a lot, and call it soon. But its password reset goes to your email, so take the email back first.' },
            { text: 'The email, because the others reset through it', correct: true, feedback: 'Right. Then the bank, then the rest.' },
          ],
        },
        {
          prompt: 'Why does the email account come before the others?',
          options: [
            { text: 'It has the most private messages', correct: false, feedback: 'It may, but the reason is different: password resets for your other accounts arrive there.' },
            { text: 'Whoever controls it can reset the passwords of your other accounts', correct: true, feedback: 'Right. It’s the key that opens the other locks.' },
            { text: 'Email providers are hacked most often', correct: false, feedback: 'That’s not the reason. It comes first because the other accounts’ resets go through it.' },
          ],
        },
      ],
    },
    {
      concept: 'trusted-device',
      teach: 'If the computer you use has something that can read what you type, like a browser add-on that reads sign-in pages, a new password typed there can be read too. Until the checkup’s items are sorted, change passwords on a phone or another device you trust.',
      prompt: 'The checkup found a browser extension that can read everything you type on websites. Where should you change your email password?',
      options: [
        { text: 'Right here, now, on this computer', correct: false, feedback: 'The extension could read the new password as you type it. Use a device you trust, or sort out the extension first.' },
        { text: 'On your phone, or another device you trust', correct: true, feedback: 'Right. A device you trust keeps the new password to yourself.' },
      ],
      variants: [
        {
          prompt: 'The checkup found Screen Sharing turned on, and you don’t know who set it up. You need to change your bank password. Where?',
          options: [
            { text: 'On this computer, quickly, before anyone notices', correct: false, feedback: 'If someone can see this screen, they could watch you type it. Use a device you trust.' },
            { text: 'On a phone or another device you trust', correct: true, feedback: 'Right. Sort out this computer’s items when you can; the new password stays yours meanwhile.' },
          ],
        },
        {
          prompt: 'What makes a device one you can trust for changing passwords?',
          options: [
            { text: 'It’s the newest one you own', correct: false, feedback: 'New doesn’t mean nobody else can reach it. What matters is that only you use it and nothing on it was set up by someone else.' },
            { text: 'Only you use it, and nothing on it was set up by someone else', correct: true, feedback: 'Right. For many people that’s their own phone, with a screen lock only they know.' },
          ],
        },
      ],
    },
    {
      concept: 'doors-left-open',
      teach: 'Someone who got in can leave ways back in: a device still signed in, a forwarding rule that sends copies of your mail to them, their phone number as your recovery phone, or an app password. A new password doesn’t always remove these, so each one is its own step.',
      prompt: 'You changed your email password. Is the account yours again?',
      options: [
        { text: 'Yes, the new password locks them out', correct: false, feedback: 'Not always. A signed-in device, a forwarding rule or their recovery phone can still let them back in or read your mail.' },
        { text: 'Not yet: check the signed-in devices, forwarding, recovery details and apps too', correct: true, feedback: 'Right. Each of those is a door a new password may leave open.' },
      ],
      variants: [
        {
          prompt: 'You find a forwarding rule in your email that sends copies to an address you don’t know. What is it?',
          options: [
            { text: 'Probably a setting the provider added', correct: false, feedback: 'Providers don’t add forwarding to strangers. Treat it as a way someone kept reading your mail.' },
            { text: 'A way for someone to keep reading your mail, even after a password change', correct: true, feedback: 'Right. Remove it. Keep a note or screenshot first if you may need a record.' },
          ],
        },
        {
          prompt: 'Your account’s recovery phone number isn’t yours. Why does that matter?',
          options: [
            { text: 'It doesn’t, as long as the password is new', correct: false, feedback: 'The recovery number can be used to reset the password again. Whoever has that phone can get back in.' },
            { text: 'Whoever has that phone can reset your password again', correct: true, feedback: 'Right. Put your own number and recovery email back.' },
          ],
        },
      ],
    },
    {
      concept: 'never-share-codes',
      teach: 'You type your password and any code yourself, only on the provider’s own website. Nobody helping you needs them, and Reclaim City never asks for an account password, a one-time code or a recovery code.',
      prompt: 'Someone calls, says they’re from your email provider, and asks you to read out the code that was just texted to you, to “secure the account”. What do you do?',
      options: [
        { text: 'Read it out so they can help', correct: false, feedback: 'That code is how they get in. Never read a code to someone who contacted you.' },
        { text: 'Hang up, and go to the provider’s website yourself', correct: true, feedback: 'Right. Start from the provider’s own site, never from a call, text or email you didn’t expect.' },
      ],
      variants: [
        {
          prompt: 'A text says “Your account is locked. Reply with your password to unlock it.” What do you do?',
          options: [
            { text: 'Reply, since it says it’s urgent', correct: false, feedback: 'No real provider asks for your password by text. Urgency is how these messages push you.' },
            { text: 'Don’t reply. Go to the provider’s website yourself.', correct: true, feedback: 'Right. Type the address yourself or use the app you already have.' },
          ],
        },
        {
          prompt: 'Someone helping you with your accounts asks for your recovery code “to save time”. What do you say?',
          options: [
            { text: 'Give it, since they’re helping', correct: false, feedback: 'A recovery code lets whoever has it into the account. Nobody helping you needs it; you type it yourself.' },
            { text: 'No: you type codes yourself, on the provider’s site', correct: true, feedback: 'Right. Real help never needs your password or a code.' },
          ],
        },
      ],
    },
    {
      concept: 'plan-before-signing-out',
      teach: 'If it may be a partner, an ex or someone you live with, signing them out or changing a password shows them you noticed. Talk to an advocate before you change account settings, so you can plan when to do it.',
      prompt: 'You think an ex is reading your email. What comes before signing them out?',
      options: [
        { text: 'Nothing. Sign them out right away.', correct: false, feedback: 'They may notice at once. An advocate can help you plan the timing and keep a record first (US National DV Hotline: 1-800-799-7233).' },
        { text: 'Talking to an advocate, so you can plan the timing', correct: true, feedback: 'Right. In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text START to 88788.' },
      ],
      variants: [
        {
          prompt: 'You think someone you live with has your phone’s account password. Why might changing it right away be risky?',
          options: [
            { text: 'It isn’t risky; it’s always safest to change it now', correct: false, feedback: 'They may notice the change at once. An advocate can help you plan when, and keep a record first (US National DV Hotline: 1-800-799-7233).' },
            { text: 'They may notice, so it helps to plan the timing first', correct: true, feedback: 'Right. In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text START to 88788.' },
          ],
        },
        {
          prompt: 'Before signing out an ex who may be in your accounts, what is worth keeping?',
          options: [
            { text: 'Nothing; delete everything they touched', correct: false, feedback: 'A record can matter later. Screenshots of signed-in devices, rules and dates are worth keeping first.' },
            { text: 'A record: screenshots of signed-in devices, rules and dates', correct: true, feedback: 'Right. An advocate can help you decide what to keep and when to act.' },
          ],
        },
      ],
    },
  ],
};
