export default {
  id: 'remote-access',
  title: 'When someone else can reach your screen',
  recommendedFor: ['watched', 'hacked', 'helping', 'unsure'],
  modules: ['remote_login_check', 'sharing_services', 'win_remote_access_audit'],
  districts: ['gatehouse'],
  sources: [
    'modules/security/remote_login_check/__init__.py',
    'modules/security/sharing_services/__init__.py',
    'modules/security/win_remote_access_audit/__init__.py',
    'guides/remediation/disable_unwanted_remote_access.md',
    'guides/remediation/review_sharing_services.md',
    'guides/remediation/review_windows_remote_access.md',
    'guides/remediation/respond_to_monitoring_software.md',
    'README.md',
  ],
  briefing: 'Remote access means someone on another computer can see your screen, control it, or log in to it. Lots of people use it on purpose, for IT support or to help family. The same door can be used by someone you didn’t mean to let in.',
  whatTheScanLooksFor: 'On a Mac, the checkup looks at the switches for Screen Sharing, Remote Management, Remote Login (SSH) and Remote Apple Events. On Windows, it looks for TeamViewer, AnyDesk, a VNC server, LogMeIn and Chrome Remote Desktop, and whether Remote Desktop (RDP) is turned on. On Windows, several remote tools found together are flagged more strongly.',
  questions: [
    {
      concept: 'remote-access-is-a-door',
      teach: 'A remote-access finding means a door is there: a setting is on, or a tool is installed. It does not say who, if anyone, has used it. Many of these are ordinary tools that IT support or family use on purpose.',
      prompt: 'The checkup says Screen Sharing is turned on. What does that tell you?',
      options: [
        { text: 'Someone is watching the screen right now', correct: false,
          feedback: 'The checkup reads the setting. It can’t tell who, if anyone, has connected.' },
        { text: 'The Mac is set up so another person could see and control the screen', correct: true,
          feedback: 'Right. It’s a door that’s open. The next question is who is able to come through it.' },
        { text: 'Nothing. Screen Sharing is a built-in part of every Mac.', correct: false,
          feedback: 'It’s built in, but it’s a switch, and most people don’t need it on. The checkup flags it so you can decide.' },
      ],
      variants: [
        {
          prompt: 'On Windows, the checkup finds AnyDesk. Which is true?',
          options: [
            { text: 'AnyDesk is only ever used by scammers', correct: false,
              feedback: 'AnyDesk is often used for tech support. The checkup flags it being installed, not misuse.' },
            { text: 'It’s a tool that lets someone control the computer from elsewhere. It can be fine or not, depending on who uses it.', correct: true,
              feedback: 'Right. The tool itself is ordinary. What matters is who can connect with it.' },
          ],
        },
        {
          prompt: 'The checkup says it “couldn’t check some remote access settings”. What does that mean?',
          options: [
            { text: 'Those settings are off', correct: false,
              feedback: 'A check that couldn’t run checked nothing. It isn’t the same as “off”.' },
            { text: 'It doesn’t know if they’re on or off. You can look for yourself.', correct: true,
              feedback: 'Right. It isn’t a sign that anything is wrong, and it isn’t a clean result either. On a Mac, you can see the switches in System Settings > General > Sharing.' },
            { text: 'Someone has hidden them', correct: false,
              feedback: 'Usually it just means the check couldn’t read the setting without more permission. It doesn’t point to anyone.' },
          ],
        },
      ],
    },
    {
      concept: 'who-can-connect',
      teach: 'The deciding question is who can connect, not who set it up. “I turned it on so my partner could help” or “it’s for work” doesn’t settle it on your own computer. If anyone other than you can connect, and you’re not sure you want that, treat it as worth a closer look.',
      prompt: 'A partner set up TeamViewer on your laptop “so I can fix things for you”. What question matters most?',
      options: [
        { text: 'Whether they meant well when they set it up', correct: false,
          feedback: 'Good intentions don’t change what the tool can do. It lets them reach your screen whenever it’s running.' },
        { text: 'Who can connect to your laptop with it, and whether you want that', correct: true,
          feedback: 'Right. Who installed it doesn’t clear it. Who can connect is what counts.' },
        { text: 'Whether TeamViewer is a well-known company', correct: false,
          feedback: 'It is a legitimate tool. That tells you who made it, not who can use it to reach you.' },
      ],
      variants: [
        {
          prompt: 'You turned on Screen Sharing yourself so your adult son could help with your Mac. Does that make the finding nothing to think about?',
          options: [
            { text: 'Yes. You set it up, so it’s fine.', correct: false,
              feedback: 'Setting it up yourself doesn’t answer who can connect now. Ask that question, and whether you still want it on.' },
            { text: 'Not by itself. Think about who can connect, and whether it still needs to be on.', correct: true,
              feedback: 'Right. If only people you trust can use it and you still need it, you can leave it on. If not, it can be switched off.' },
          ],
        },
        {
          prompt: 'Someone says remote-access software on your own home computer is “just for work”. What settles whether it’s okay?',
          options: [
            { text: 'Knowing who can connect with it, and being fine with that', correct: true,
              feedback: 'Right. “It’s for work” doesn’t clear it on a personal computer. Who can connect is the question.' },
            { text: 'That it’s for work', correct: false,
              feedback: 'A reason, even a reasonable one, doesn’t change who can reach your screen.' },
            { text: 'That it was installed a long time ago', correct: false,
              feedback: 'How old it is doesn’t tell you who can connect with it today.' },
          ],
        },
      ],
    },
    {
      concept: 'switching-off-can-alert',
      teach: 'If a partner, ex or someone you live with might be the one connecting, switching it off can alert them. Before you change anything, talk to an advocate who can help plan the safest order. Use a device they’ve never had access to for that.',
      prompt: 'You think an ex may be connecting to your computer. What’s the safest first move?',
      options: [
        { text: 'Switch the remote tool off straight away', correct: false,
          feedback: 'Removing it can alert the person who installed it. Plan first, with someone who knows this kind of situation.' },
        { text: 'Get help planning first, from a device they can’t reach', correct: true,
          feedback: 'Right. In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text START to 88788. They help with tech safety as well.' },
        { text: 'Message the ex to ask if they installed it', correct: false,
          feedback: 'That tells them you’ve noticed. Talk to an advocate first, so you can plan what happens next.' },
      ],
      variants: [
        {
          prompt: 'Why might switching off Remote Management not be the first step, if a partner may be using it?',
          options: [
            { text: 'Because it might alert them that you’ve noticed', correct: true,
              feedback: 'Right. They may notice it stopped working. An advocate can help you decide when and how to switch it off.' },
            { text: 'Because it can’t be switched off', correct: false,
              feedback: 'It can be switched off. The question is when it’s safe to do that.' },
          ],
        },
        {
          prompt: 'You’re worried a housemate set up remote access to watch you. What’s worth doing before you remove anything?',
          options: [
            { text: 'Delete it, then tell the housemate', correct: false,
              feedback: 'Removing it can alert them, and deleting erases most of the record. Plan first.' },
            { text: 'Keep a record of what the scan found, on paper or another device, and talk to an advocate', correct: true,
              feedback: 'Right. Write down the name the scan found and take a photo of the result. That record can matter later, and removing the software erases most of it.' },
            { text: 'Nothing. Remote access can’t be used to watch someone.', correct: false,
              feedback: 'It can. Screen-sharing tools let someone see and control the screen from elsewhere.' },
          ],
        },
      ],
    },
    {
      concept: 'switch-off-unknown-tool',
      teach: 'If you don’t use a remote tool, no one you trust needs it, and nobody close to you may be involved, you can switch it off yourself. On a Mac, turn off its switch in System Settings > General > Sharing. On Windows, uninstall the tool in Windows Settings > Apps > Installed apps. For Remote Desktop, the switch is in Windows Settings > System > Remote Desktop.',
      prompt: 'Remote Login is turned on, and you don’t use it. Nobody else needs it. What can you do?',
      options: [
        { text: 'Switch it off: in System Settings > General > Sharing, turn off the switch next to Remote Login', correct: true,
          feedback: 'Right. You can turn it back on there later if you ever need it.' },
        { text: 'Leave it. Every Mac has it on.', correct: false,
          feedback: 'Not every Mac has it on, and most people don’t need it. If no one uses it, switching it off closes the door.' },
        { text: 'Erase the Mac', correct: false,
          feedback: 'That’s far more than needed. A switch in System Settings turns it off, and you can undo it.' },
      ],
      variants: [
        {
          prompt: 'On Windows, the checkup finds TeamViewer, AnyDesk and a VNC server together. Nobody you know uses them, and no one close to you may be involved. Which is right?',
          options: [
            { text: 'Several remote tools together is a stronger warning sign. Uninstall the ones you don’t use.', correct: true,
              feedback: 'Right. Several tools found together is a common sign of a tech-support scam. To remove one: in Windows Settings > Apps > Installed apps, find it and select Uninstall.' },
            { text: 'Three tools are no more worrying than one', correct: false,
              feedback: 'The checkup flags several remote tools together more strongly. Scammers often add more tools to keep access.' },
          ],
        },
        {
          prompt: 'The checkup says Remote Desktop (RDP) is turned on. You never use it. What’s a sensible fix?',
          options: [
            { text: 'Switch it off: in Windows Settings > System > Remote Desktop, toggle it to Off.', correct: true,
              feedback: 'Right. It’s often left on after a tech support session. If you don’t use it, it’s safer off, and you can turn it on again later.' },
            { text: 'Give Reclaim City your Windows password so it can turn it off', correct: false,
              feedback: 'Reclaim City never asks for your password. You switch this off yourself in Windows Settings.' },
            { text: 'Unplug the computer from the internet for good', correct: false,
              feedback: 'Not needed. Turning off the Remote Desktop switch closes this door.' },
          ],
        },
      ],
    },
  ],
};
