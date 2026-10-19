export default {
  id: 'password-asker',
  title: 'The tool that asks for your password',
  recommendedFor: ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'],
  modules: ['win_remote_access_audit'],
  districts: ['gatehouse'],
  sources: [
    'docs/trust-and-safety.md',
    'desktop/renderer/permissions-content.json',
    'guides/remediation/review_windows_remote_access.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'Reclaim City never asks for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password. There is no prompt for any of them anywhere in the tool.',
  whatTheScanLooksFor: 'On Windows, the checkup looks for remote-access tools like TeamViewer, AnyDesk and VNC, which are common leftovers from “tech support” phone scams.',
  questions: [
    {
      teach: 'Be wary of an unexpected call or pop-up telling you to install remote-access software (a tool that lets someone else control your computer). Scammers use that to take over your screen.',
      prompt: 'A pop-up claims a virus was found and gives you a number to call for help. What should you do?',
      options: [
        { text: 'Call the number so they can fix it', correct: false,
          feedback: 'That’s how the scam starts. The caller may walk you through installing remote-access software, which gives them access to your computer.' },
        { text: 'Don’t call. Close it, and run a checkup you started yourself.', correct: true,
          feedback: 'Right. A checkup you started yourself doesn’t come from a stranger, and Reclaim City never asks for your passwords or codes.' },
        { text: 'Read them the code your phone just got, to prove it’s you', correct: false,
          feedback: 'Never read a code to anyone who contacted you. Reclaim City never asks for a one-time code.' },
      ],
    },
    {
      teach: 'Your computer may ask for its own administrator password, in its own window. Reclaim City never sees what you type there, and it never asks you to type a password into it. If something claiming to be Reclaim City asks you to type a password into it, it is not Reclaim City.',
      prompt: 'A box that says it’s from Reclaim City asks for your email password to “finish the scan”. What is it?',
      options: [
        { text: 'A normal part of the checkup', correct: false,
          feedback: 'Reclaim City has no prompt like that anywhere. Its checks never need your email password.' },
        { text: 'Something pretending to be Reclaim City. Don’t type anything, and close it.', correct: true,
          feedback: 'Right. Your computer may ask for its own administrator password in its own window, but Reclaim City never asks you to type a password into it.' },
      ],
    },
  ],
};
