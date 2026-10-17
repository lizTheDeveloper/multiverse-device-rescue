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
  briefing: 'Device Rescue never asks for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password. There is no prompt for any of them anywhere in the tool. Your computer may ask for its own administrator password, in its own window. Device Rescue never sees what you type there, and it never asks you to type a password into it. If something claiming to be Device Rescue asks you to type a password into it, it is not Device Rescue. Be wary of an unexpected call or pop-up telling you to install remote-access software. Scammers use that to take over your screen.',
  whatTheScanLooksFor: 'On Windows, the checkup looks for remote-access tools like TeamViewer, AnyDesk and VNC, which are common leftovers from “tech support” phone scams.',
  questions: [
    {
      prompt: 'A pop-up claims a virus was found and gives you a number to call for help. What should you do?',
      options: [
        { text: 'Call the number so they can fix it', correct: false,
          feedback: 'That’s how the scam starts. The caller may walk you through installing remote-access software, which gives them access to your computer.' },
        { text: 'Don’t call. Close it, and run a checkup you started yourself.', correct: true,
          feedback: 'Right. A checkup you started yourself doesn’t come from a stranger, and Device Rescue never asks for your passwords or codes.' },
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
          feedback: 'Right. Your computer may ask for its own administrator password in its own window, but Device Rescue never asks you to type a password into it.' },
      ],
    },
  ],
};
