// Practice signals for The Wires. Invented: none of this is on the person's computer.
export default [
  {
    id: 'proxy-unknown',
    district: 'wires',
    severity: 'warning',
    modules: ['network_proxy_check'],
    title: 'A web proxy is set that you don’t remember',
    setup: 'Practice setup: this is your own laptop at home. No workplace or school manages it, and you can’t think of an app that would set a proxy.',
    clues: {
      maker: null,
      path: null,
      what: 'Your network settings send web traffic through a proxy server.',
      when: '2026-10-12',
    },
    answer: 'closer',
    why: 'A proxy can read and change your web traffic, so an unexplained one deserves a look. But a VPN client, an ad-blocking or filtering tool, or a developer tool can set one too. To tell them apart, check which app you installed that does this, and open the proxy settings to see where it points. If you can’t match it to anything you installed, remove it.',
    sources: ['guides/remediation/remove_unwanted_proxy.md'],
  },
  {
    id: 'proxy-work',
    district: 'wires',
    severity: 'info',
    modules: ['network_proxy_check'],
    title: 'A proxy is set on a work laptop',
    setup: 'Practice setup: this is a work laptop, and your IT team set up its network.',
    clues: {
      maker: null,
      path: null,
      what: 'Your network settings send web traffic through your workplace’s proxy server.',
      when: '2025-03-04',
    },
    answer: 'mine',
    why: 'Workplaces often route traffic through their own proxy, so this is expected. If you’re ever unsure, check with your IT department before changing anything.',
    sources: ['guides/remediation/remove_unwanted_proxy.md'],
  },
];
