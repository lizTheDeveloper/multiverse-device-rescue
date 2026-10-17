export default {
  id: 'whos-on-wifi',
  title: 'Who’s on your Wi-Fi',
  recommendedFor: ['wifi'],
  modules: ['lan_device_inventory', 'arp_spoof_check', 'router_security_audit', 'wifi_security_audit', 'crypto_miner_detect', 'win_crypto_miner_detect'],
  sources: [
    'guides/home_network_intrusion/phase_0.md',
    'guides/home_network_intrusion/phase_1.md',
    'guides/home_network_intrusion/phase_2.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'A slow computer, fans running all the time, a hot laptop doing nothing: these are some of the things that make people worry about their Wi-Fi. The checkup can list devices that have recently talked to this computer, but that list can be incomplete. The router’s own admin page is the full list. If the person you’re worried about is someone you know, stop before you cut them off. Cutting off someone’s access tells them they’ve been found out. If they have ever frightened you, it’s worth getting help to plan the safest order.',
  whatTheScanLooksFor: 'The checkup lists devices that have recently talked to this computer, looks for signs that something is intercepting your traffic, and checks which admin services your router offers to the network. On a Mac or a Windows computer, it also looks for cryptocurrency mining running right now.',
  questions: [
    {
      prompt: 'Your computer is hot and slow. What does the checkup do about that?',
      options: [
        { text: 'It looks for cryptocurrency mining running right now, and checks your network separately', correct: true,
          feedback: 'Right. On a Mac or a Windows computer, it looks for miner programs, mining commands and live connections to mining pools. The devices on your network and your router’s settings are separate checks.' },
        { text: 'It counts the devices on your Wi-Fi to find what’s slowing the computer down', correct: false,
          feedback: 'The device list shows what has recently talked to this computer. For a hot, slow computer, a separate check looks for mining running on the computer itself, on a Mac or a Windows computer.' },
        { text: 'It checks your router’s settings for the cause', correct: false,
          feedback: 'The router check looks at which admin services your router offers to the network, and whether UPnP is on. For a hot, slow computer, a separate check looks for mining running on the computer itself, on a Mac or a Windows computer.' },
      ],
    },
    {
      prompt: 'The list shows more devices than you expected. What’s most likely?',
      options: [
        { text: 'Strangers have joined', correct: false,
          feedback: 'Maybe, but check first. Phones, laptops, TVs, printers, doorbells and smart plugs all count. Most households are surprised by the count, and twenty is normal now.' },
        { text: 'They’re your own things: phones, TV, printer, smart plugs', correct: true,
          feedback: 'Usually, yes. Name each one. For anything you can’t name, unplug it or switch it off and look again. The one that disappears is that device.' },
      ],
    },
    {
      prompt: 'What actually removes everyone you haven’t allowed onto your Wi-Fi?',
      options: [
        { text: 'A new Wi-Fi passphrase', correct: true,
          feedback: 'Right. The passphrase is what devices use to join. Update the router’s firmware first, because if the router has a known weakness, a new passphrase doesn’t help. Turn off WPS too, or its PIN gets around the new passphrase. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
        { text: 'Blocking devices by hardware address', correct: false,
          feedback: 'A hardware address is easy to change, so blocking one only tells an intruder which address to stop using. A new Wi-Fi passphrase is what works. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
        { text: 'Restarting the laptop', correct: false,
          feedback: 'That doesn’t change who can join. A new Wi-Fi passphrase does. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
      ],
    },
  ],
};
