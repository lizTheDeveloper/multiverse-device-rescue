export default {
  id: 'firewall-and-sharing',
  title: 'Firewall and sharing settings',
  recommendedFor: ['wifi', 'hacked', 'watched', 'unsure'],
  modules: ['firewall_audit', 'win_firewall', 'sharing_preferences_audit', 'sharing_services', 'win_network_shares_audit'],
  districts: ['gatehouse'],
  sources: [
    'guides/remediation/enable_and_tighten_firewall.md',
    'guides/remediation/enable_windows_firewall.md',
    'guides/remediation/review_sharing_services.md',
    'guides/remediation/review_windows_network_shares.md',
    'docs/REMEDIATION_CATALOG.md',
    'modules/security/firewall_audit/__init__.py',
    'modules/security/win_firewall/__init__.py',
    'modules/security/sharing_preferences_audit/__init__.py',
  ],
  briefing: 'A firewall decides which connections from other devices get in. Sharing settings open doors on purpose. This lesson looks at both.',
  whatTheScanLooksFor: 'On a Mac, the checkup checks whether the firewall and its stealth mode are on, and which sharing settings are switched on: Screen Sharing, File Sharing, Remote Login, Remote Management, Printer Sharing, and AirDrop set to Everyone. On Windows, it checks the firewall for each kind of network (Domain, Private and Public), and looks at shared folders and the old SMBv1 file-sharing protocol.',
  questions: [
    {
      concept: 'firewall-blocks-incoming',
      teach: 'A firewall blocks connection attempts from other devices that you didn’t ask for. It doesn’t affect your own outgoing connections or normal browsing, so it won’t stop you visiting a bad website.',
      prompt: 'What does a firewall do?',
      options: [
        { text: 'Blocks connections from other devices that you didn’t ask for', correct: true,
          feedback: 'Right. It filters what comes in uninvited. Your own browsing goes out as normal.' },
        { text: 'Stops you opening dangerous websites', correct: false,
          feedback: 'It doesn’t affect your browsing. It blocks uninvited connections coming in from other devices.' },
        { text: 'Scans your files for harmful software', correct: false,
          feedback: 'That’s a different kind of tool. A firewall blocks uninvited connections coming in.' },
      ],
      variants: [
        {
          prompt: 'Your firewall is on. Does that protect you from a fake website linked in an email?',
          options: [
            { text: 'No. The firewall handles connections coming in, not the sites you visit', correct: true,
              feedback: 'Right. It doesn’t affect normal browsing, so be careful with links whether it’s on or off.' },
            { text: 'Yes. The firewall blocks bad websites', correct: false,
              feedback: 'It doesn’t. A firewall blocks uninvited connections coming in. Visiting a website is a connection you started.' },
          ],
        },
        {
          prompt: 'On a Mac, where do you turn the firewall on?',
          options: [
            { text: 'System Settings > Network > Firewall', correct: true,
              feedback: 'Right. Once it’s on, if an app you use needs other devices to reach it, macOS asks you to allow that app.' },
            { text: 'System Settings > General > Sharing', correct: false,
              feedback: 'That’s where the sharing settings live. The firewall is under Network.' },
          ],
        },
        {
          prompt: 'You turn the firewall on, and later a program you use asks to accept connections. What’s the better move?',
          options: [
            { text: 'Allow that one program, if you recognise it', correct: true,
              feedback: 'Right. Allow the programs you recognise one at a time, and leave the firewall on.' },
            { text: 'Turn the firewall off again', correct: false,
              feedback: 'That opens everything back up. Allowing just the one program you recognise keeps the rest blocked.' },
          ],
        },
      ],
    },
    {
      concept: 'sharing-opens-doors',
      teach: 'Sharing settings let other devices reach this computer on purpose. File Sharing shows your folders, Screen Sharing lets someone see and control your screen, and Remote Login lets someone run commands from another computer. Each is useful to someone, but if nobody uses one, switch it off.',
      prompt: 'File Sharing is on, and nobody in your home uses it. What’s the best move?',
      options: [
        { text: 'Switch it off, in System Settings > General > Sharing', correct: true,
          feedback: 'Right. Check first that nobody else relies on it, then turn off the File Sharing switch.' },
        { text: 'Leave it. It only matters if you use it', correct: false,
          feedback: 'While it’s on, other devices on your network can see the shared folders, whether you use it or not.' },
      ],
      variants: [
        {
          prompt: 'Which setting lets someone see and control your screen from another device?',
          options: [
            { text: 'Screen Sharing', correct: true,
              feedback: 'Right. Someone using it can see your screen and use your mouse and keyboard.' },
            { text: 'Printer Sharing', correct: false,
              feedback: 'That lets other devices print to your printer. Screen Sharing is the one that shows your screen.' },
            { text: 'File Sharing', correct: false,
              feedback: 'That lets other devices see shared folders. Screen Sharing is the one that shows your screen.' },
          ],
        },
        {
          prompt: 'On Windows, the checkup finds a shared folder that exposes your personal files. What should you check before changing it?',
          options: [
            { text: 'Whether another of your devices, or someone at home, actually uses it', correct: true,
              feedback: 'Right. A smart TV, a backup box or a family member’s computer might connect to it. If nothing does, restrict or remove the share.' },
            { text: 'Nothing. Shared folders are only visible to you', correct: false,
              feedback: 'A shared folder can be reached by other devices on the network. That’s what sharing means.' },
          ],
        },
      ],
    },
    {
      concept: 'public-wifi-matters-most',
      teach: 'On public Wi-Fi, like a café or an airport, you don’t know the other devices on the network. That’s where a firewall that’s off, or sharing that’s left on, matters most.',
      prompt: 'Where does leaving File Sharing on matter most?',
      options: [
        { text: 'On café or airport Wi-Fi', correct: true,
          feedback: 'Right. Strangers’ devices share that network, and you don’t know any of them.' },
        { text: 'At home, with only your own devices on the Wi-Fi', correct: false,
          feedback: 'At home you know the devices. On public Wi-Fi you don’t, so that’s where it matters most.' },
        { text: 'It makes no difference where you are', correct: false,
          feedback: 'It does. File Sharing lets devices on the same Wi-Fi see your folders, and on public Wi-Fi those are strangers’ devices.' },
      ],
      variants: [
        {
          prompt: 'Windows has separate firewall settings for Domain, Private and Public networks. Which one being off is most serious?',
          options: [
            { text: 'Public', correct: true,
              feedback: 'Right. Public covers networks like café Wi-Fi, where anyone there could try to connect to your computer.' },
            { text: 'Private', correct: false,
              feedback: 'Private is for networks you trust, like home. It’s still worth having on, but Public matters most.' },
          ],
        },
        {
          prompt: 'You’re at a busy café, and AirDrop is set to Everyone. What does that allow?',
          options: [
            { text: 'Strangers nearby can send you files', correct: true,
              feedback: 'Right. Change it to “Contacts Only” in System Settings > General > AirDrop & Handoff.' },
            { text: 'Only you can send files to others', correct: false,
              feedback: '“Everyone” means anyone nearby can send files to you. “Contacts Only” is the safer choice.' },
          ],
        },
      ],
    },
    {
      concept: 'who-can-connect',
      teach: 'Screen Sharing, Remote Login and Remote Management let someone reach this computer from elsewhere. Knowing who switched one on doesn’t settle it, even if it was you or a relative helping out. The question is who can connect now.',
      prompt: 'Remote Management is on, on your personal laptop. A relative set it up to help you. Is that settled?',
      options: [
        { text: 'No. What matters is who can connect now, and whether you want that', correct: true,
          feedback: 'Right. If you don’t need it any more, switch it off. If a partner, ex or housemate may be involved, get help planning the safest order first.' },
        { text: 'Yes. Family set it up, so it’s fine', correct: false,
          feedback: 'A good reason for switching it on doesn’t tell you who can connect now. That’s the question to answer.' },
      ],
      variants: [
        {
          prompt: 'Screen Sharing is on, and you think an ex set it up. What comes first?',
          options: [
            { text: 'Get help planning the safest order before you switch it off', correct: true,
              feedback: 'Right. Switching it off can alert the person who set it up. An advocate can help you plan.' },
            { text: 'Switch it off straight away', correct: false,
              feedback: 'That can alert the person who set it up. When it may be an ex, get help planning the safest order first.' },
            { text: 'Leave it. It’s only screen sharing', correct: false,
              feedback: 'Screen Sharing lets someone see and control your screen. Get help planning what to do about it.' },
          ],
        },
        {
          prompt: 'Remote Login is on. You switched it on once so a friend could fix something. Nobody needs it now. What’s sensible?',
          options: [
            { text: 'Switch it off, because it still lets people connect', correct: true,
              feedback: 'Right. Switching it on yourself doesn’t close the door afterwards. You’ll find the switch in System Settings > General > Sharing.' },
            { text: 'Leave it. You turned it on yourself, so it’s fine', correct: false,
              feedback: 'Who turned it on doesn’t matter now. While it’s on, people can still try to connect and run commands.' },
          ],
        },
      ],
    },
  ],
};
