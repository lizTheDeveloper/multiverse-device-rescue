export default {
  id: 'password-asker',
  title: 'The tool that asks for your password',
  recommendedFor: ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'],
  modules: ['win_remote_access_audit'],
  sources: [
    'docs/trust-and-safety.md',
    'desktop/renderer/permissions-content.json',
    'guides/remediation/review_windows_remote_access.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'Device Rescue never asks for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password. There is no prompt for any of them anywhere in the tool. Your computer itself may ask for your administrator password, but only if you choose to apply a fix that changes a system setting. Read-only checks never ask for your password. Anything else that asks, whether it’s a pop-up, a phone call or a chat message, is a red flag. A common scam is an unexpected call or pop-up telling you to install remote-access software, which hands someone your screen.',
  whatTheScanLooksFor: 'The checkup looks for remote-access tools like TeamViewer, AnyDesk and VNC, which are common leftovers from “tech support” phone scams.',
  questions: [
    {
      prompt: 'A pop-up claims a virus was found and gives you a number to call for help. What should you do?',
      options: [
        { text: 'Call the number so they can fix it', correct: false,
          feedback: 'That’s how the scam starts. The caller usually asks you to install remote-access software, which hands them your screen.' },
        { text: 'Don’t call. Close it, and run a checkup you started yourself.', correct: true,
          feedback: 'Right. A checkup you opened yourself is one you can trust, and Device Rescue never asks for your passwords or codes.' },
        { text: 'Read them the code your phone just got, to prove it’s you', correct: false,
          feedback: 'Never read a code to anyone who contacted you. Device Rescue never asks for a one-time code.' },
      ],
    },
    {
      prompt: 'A box that says it’s from Device Rescue asks for your email password to “finish the scan”. What is it?',
      options: [
        { text: 'A normal part of the checkup', correct: false,
          feedback: 'Device Rescue has no prompt like that anywhere. Its checks never need your email password.' },
        { text: 'Something pretending to be Device Rescue. Don’t type anything, and close it.', correct: true,
          feedback: 'Right. The only password your computer may ask for is its own administrator password, and only when you choose a fix that changes a system setting.' },
      ],
    },
  ],
};
