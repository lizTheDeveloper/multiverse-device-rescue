// The Switchboard: network lines (spec 2026-10-19-little-missions-and-minigames-design.md, type "switchboard").
//
// Every network finding is traced as a line: this computer -> the port, program or service it goes through ->
// where it goes (who can reach it, the server that answers, the address a name is sent to). The person decides
// one thing per item:
//
//   Expected       mark it as theirs when the engine offers a mark (sharing services, proxies, the DNS profile),
//                  else keep it as it is
//   Odd — close it the engine's fix when it offers one, else the settings pane that switches it off, else the
//                  steps to remove it by hand (hosts file, router, a program's connection)
//   Look closer    what to check, as a checklist
//
// The DNS filtering profile asks whose profile it is. Firewall on/off belongs to Lock Run; this game takes the
// firewall's rules (which apps are let in) and open ports.
//
// render() draws only the line diagram card; the runner draws the decision buttons, the removal warning, the
// evidence rows and the links (controller ruling R1).
//
// Pure module: everything comes in through ctx (esc, visible, evidenceRows, mode, platform). City mode never prints
// a finding's own title or description; it uses game words around the traced values.

const MAX_LINES = 4;
const MAX_VALUE = 120;
const MARK_ID = /^[0-9a-f]{12}$/;
// rescue/known_items.py ITEM_KINDS this game's findings can carry (mark-policy.js keeps the full list).
const MARK_KINDS = new Set(['sharing_service', 'network_proxy', 'dns_profile']);

const PROFILE_CODE = 'security.dns_poisoning_check.dns_filtering_profile';

// ---- Which kind of line a finding is ----

const MODULE_KIND = {
  open_ports_scan: 'port',
  suspicious_connections: 'conn',
  network_connections_monitor: 'conn',
  firewall_rules_audit: 'firewall',
  win_firewall_rules_audit: 'firewall',
  dns_config: 'dns',
  win_dns_config: 'dns',
  dns_poisoning_check: 'dns',
  dns_over_https_check: 'dns',
  hosts_file_check: 'hosts',
  win_hosts_file: 'hosts',
  win_hosts_file_check: 'hosts',
  network_proxy: 'proxy',
  network_proxy_check: 'proxy',
  network_proxy_detect: 'proxy',
  win_proxy_detect: 'proxy',
  remote_login_check: 'sharing',
  sharing_preferences_audit: 'sharing',
  sharing_services: 'sharing',
  airdrop_config: 'sharing',
  airdrop_security_check: 'sharing',
  win_rdp_check: 'sharing',
  win_remote_access_audit: 'sharing',
  win_network_shares_audit: 'sharing',
  wifi_security_audit: 'wifi',
  router_security_audit: 'router',
  arp_spoof_check: 'router',
  lan_device_inventory: 'router',
  vpn_leak_check: 'vpn',
};

const CODE_KIND = {
  'security.suspicious_connections.unusual_listening_port': 'port',
  [PROFILE_CODE]: 'profile',
  'network.vpn_leak_check.dns_leak': 'dns',
};

// What this game claims (the foundation's types.js lets a registered game's covers replace the table's entry).
// firewall_audit and win_firewall (the firewall switch) and firewall_rules_audit's on/off/stealth codes are
// Lock Run's.
export const covers = [
  { module: 'firewall_rules_audit', codes: [
    'security.firewall_rules_audit.allow_signed_enabled',
    'security.firewall_rules_audit.too_many_apps',
    'security.firewall_rules_audit.firewall_summary',
  ] },
  ...Object.keys(MODULE_KIND).filter((m) => m !== 'firewall_rules_audit').map((module) => ({ module })),
];

function moduleOf(finding) {
  const f = finding || {};
  if (typeof f.module === 'string' && f.module) return f.module;
  const parts = String(f.code || '').split('.');
  return parts.length === 3 ? parts[1] : '';
}

export function lineKind(finding) {
  const code = finding && finding.code;
  if (code && CODE_KIND[code]) return CODE_KIND[code];
  return MODULE_KIND[moduleOf(finding)] || 'conn';
}

// ---- Words ----

const W = (standard, city) => ({ standard, city });

function me(ctx, cap) {
  const p = ctx && ctx.platform;
  if (ctx && ctx.mode === 'city') return cap ? 'Your post' : 'your post';
  const s = p === 'win32' ? 'this PC' : p === 'darwin' ? 'this Mac' : 'this computer';
  return cap ? s[0].toUpperCase() + s.slice(1) : s;
}
const say = (w, ctx) => String((w && w[ctx.mode === 'city' ? 'city' : 'standard']) || '').replace(/\{me\}/g, me(ctx)).replace(/\{Me\}/g, me(ctx, true));

const PANE = (darwin, win32) => ({ darwin, win32 });

// Per kind: the chip, the node labels, the city headline, what's known, the pane, the lesson, the checklist and
// the hand steps (only for kinds without a settings pane).
const KINDS = {
  port: {
    chip: W('Open port', 'Open socket'),
    via: W('Port · program', 'Socket'), to: W('Who can reach it', 'Who can ring in'),
    head: W('', 'A socket is open at your post'),
    what: W('A program on {me} is waiting for connections. Printers, file sync and developer tools do this. A program you don’t know shouldn’t.',
      'Something at {me} is waiting for calls. Printers and sync tools do this. A name you don’t know shouldn’t.'),
    pane: PANE('firewall', 'windows-firewall'), concept: 'wifi-and-mining',
    checklist: W(['Do you know the program on the line?', 'Is it something you use, like a printer, a sync app or a developer tool?', 'Is it open to your network, or only to {me}?', 'Search the program’s name with the port number.'],
      ['Do you know the name on the line?', 'Is it something you use, like a printer or a sync tool?', 'Can the street ring in, or only {me}?', 'Search the name with the socket number.']),
  },
  conn: {
    chip: W('Connection out', 'Line out'),
    via: W('Program', 'Caller'), to: W('Goes to', 'Rings'),
    head: W('', 'A line goes out from your post'),
    what: W('A program on {me} is talking to another computer on a port most apps don’t use. Games, chat and sync apps do this; a program you don’t know shouldn’t.',
      'A caller at {me} rings out on an unusual number. Games and chat tools do this. A name you don’t know shouldn’t.'),
    pane: null, concept: 'wifi-and-mining',
    checklist: W(['Do you know the program on the line?', 'Did you start it, or does it come with an app you use?', 'Search the program’s name with the port number.'],
      ['Do you know the caller’s name?', 'Is it part of a tool you use?', 'Search the name with the number it rings.']),
    steps: W(['Quit the program named on the line.', 'If it comes back, look for it in Things that start on their own.', 'Run the checkup again to see the line is gone.'],
      ['Shut down the caller named on the line.', 'If it comes back, look for it at The Door.', 'Sweep again to see the line is gone.']),
  },
  firewall: {
    chip: W('Firewall rule', 'Gate rule'),
    via: W('Rule', 'Rule'), to: W('Lets in', 'Lets through'),
    head: W('', 'The gate lets callers through'),
    what: W('The firewall decides which apps other computers can reach. Each app let in is one more way in; apps you no longer use don’t need it.',
      'The gate decides who may ring in. Each name on its list is one more way in.'),
    pane: PANE('firewall', 'windows-firewall'), concept: 'wifi-and-mining',
    checklist: W(['Do you use every app on the list?', 'Does each one need other computers to reach it (sharing, games, calls)?', 'Remove the ones you don’t use from the firewall’s list.'],
      ['Do you use every name on the gate’s list?', 'Does each one need callers to reach it?', 'Take off the names you don’t use.']),
  },
  dns: {
    chip: W('Name lookups', 'Directory line'),
    via: W('Website names', 'Names'), to: W('Looked up by', 'Answered by'),
    head: W('', 'Your directory line goes somewhere new'),
    what: W('Every website name {me} visits is looked up by these servers. Your internet provider, your router or a service you chose is expected. One you don’t know can see, and change, where names go.',
      'Every name {me} asks for is answered here. Your provider or your router is expected. One you don’t know sees every name.'),
    pane: PANE('dns', 'dns'), concept: 'wifi-and-mining',
    checklist: W(['Is this your router, your internet provider, or a service you chose (like a VPN or a family filter)?', 'Search the server address to see who runs it.', 'If you didn’t choose it, set DNS back to automatic.'],
      ['Is this your router, your provider, or a service you chose?', 'Search the address to see who runs it.', 'If you didn’t choose it, set it back to automatic.']),
  },
  profile: {
    chip: W('DNS profile', 'Directory relay'),
    via: W('Sends', 'Sends'), to: W('Goes through', 'Relayed by'),
    head: W('', 'Your directory line goes through a relay'),
    what: W('A filtering profile sends every website name {me} looks up to the profile’s account. Its owner can see those names.',
      'Every name {me} asks for passes through this relay. Whoever holds its account sees the names.'),
    ask: W('Whose profile is this? Yours, one a school or workplace set up, or someone else’s? If you can sign in to the provider and see this profile, it’s yours.',
      'Whose relay is it? If you can sign in to the provider and see it, it’s yours.'),
    pane: PANE('dns', 'dns'), concept: 'wifi-and-mining',
    checklist: W(['Can you sign in to the provider and see this profile in your account?', 'Did a school or workplace set it up for you?', 'If it isn’t yours, set DNS back to automatic and remove the profile.'],
      ['Can you sign in to the provider and see this relay?', 'Did a school or workplace set it up?', 'If it isn’t yours, set it back to automatic.']),
  },
  hosts: {
    chip: W('Address override', 'Rerouted name'),
    via: W('Website name', 'Name'), to: W('Sent to', 'Sent to'),
    head: W('', 'A name in your address book is rerouted'),
    what: W('The hosts file is an address book that wins over everything else. A website name sent to 0.0.0.0 or 127.0.0.1 is blocked (ad blockers do this). A name sent to another address goes wherever that line says.',
      'Your address book wins over the directory. A name sent nowhere is blocked. A name sent to another address goes there instead.'),
    pane: null, concept: 'wifi-and-mining',
    checklist: W(['Did you, or an ad blocker you installed, add this line?', 'Is the name a bank, email or shopping site? Those should never be sent somewhere else.', 'Search the address the name is sent to.'],
      ['Did you, or a blocker tool you use, add this line?', 'Is it a bank, mail or shop name? Those should never be rerouted.', 'Search the address it’s sent to.']),
    steps: {
      darwin: W(['Make a copy first: in Terminal, run sudo cp /etc/hosts /etc/hosts.bak', 'Open the file with sudo nano /etc/hosts and delete only the line with the name shown here.', 'Save (Control-O, Return, Control-X) and run the checkup again.', 'If it was a bank or email site, change that password from another device you trust.'],
        ['Copy the address book first (the steps are in the lesson).', 'Delete only the line with the name shown here.', 'Save and sweep again.', 'If it was a bank or mail name, change that password from another device you trust.']),
      win32: W(['Open Notepad as administrator, then open C:\\Windows\\System32\\drivers\\etc\\hosts.', 'Save a copy first (File > Save As, hosts.bak).', 'Delete only the line with the name shown here, save, and run the checkup again.', 'If it was a bank or email site, change that password from another device you trust.'],
        ['Copy the address book first (the steps are in the lesson).', 'Delete only the line with the name shown here.', 'Save and sweep again.', 'If it was a bank or mail name, change that password from another device you trust.']),
    },
  },
  proxy: {
    chip: W('Proxy', 'Relay'),
    via: W('Sends', 'Sends'), to: W('Goes through', 'Relayed by'),
    head: W('', 'Your calls go through a relay'),
    what: W('A proxy sits between {me} and every website. Some workplaces, schools and privacy tools use one. Whoever runs it can see where you go.',
      'A relay sits between {me} and the street. Whoever runs it sees where your calls go.'),
    pane: PANE('network', 'network'), concept: 'wifi-and-mining',
    checklist: W(['Did a workplace, school or app you use set this up?', 'Search the proxy’s name or address.', 'If you don’t know it, switch the proxy off in the network settings.'],
      ['Did a workplace, school or tool you use set this up?', 'Search the relay’s name or address.', 'If you don’t know it, switch the relay off.']),
  },
  sharing: {
    chip: W('Sharing', 'Party line'),
    via: W('Service', 'Line'), to: W('Who can reach {me}', 'Who can ring in'),
    head: W('', 'A party line is open at your post'),
    what: W('This lets other devices reach {me}: to see the screen, sign in, use files or a printer, or send things. If you use it, keep it. If you don’t, switching it off closes one way in.',
      'This lets others ring in to {me}. If you use it, keep it. If you don’t, closing it shuts one way in.'),
    pane: PANE('sharing', 'sharing'), concept: 'remote-access-scams',
    checklist: W(['Do you use this, or did someone set it up to help you?', 'Has anyone asked you to install or turn on a remote-access app?', 'If you don’t use it, switch it off in Sharing.'],
      ['Do you use this line, or did someone set it up for you?', 'Did anyone ask you to open this line?', 'If you don’t use it, close it.']),
  },
  wifi: {
    chip: W('Wi-Fi', 'Street line'),
    via: W('Wi-Fi network', 'Street line'), to: W('Protection', 'Lock'),
    head: W('', 'A street line with a weak lock'),
    what: W('Wi-Fi with no password, or an old kind of lock, lets others nearby see unprotected traffic. Saved networks join on their own when they’re in range.',
      'A street line with no lock, or an old lock, lets others nearby listen in. Saved lines join on their own.'),
    pane: PANE('network', 'network'), concept: 'wifi-and-mining',
    checklist: W(['Is this a network you trust, like your home?', 'On a public network, use a VPN or your phone’s hotspot for anything private.', 'Forget saved networks you don’t use.'],
      ['Is this a line you trust, like your home?', 'On a public line, keep private things for a safer line.', 'Forget saved lines you don’t use.']),
  },
  router: {
    chip: W('Router', 'Exchange'),
    via: W('Router setting', 'Exchange setting'), to: W('Opens', 'Opens'),
    head: W('', 'The exchange has a door open'),
    what: W('Your router connects every device at home to the internet. A setting that opens ports on its own, or a sign-in page open to the network, is one more way in.',
      'The exchange links every post to the street. A setting that opens doors on its own is one more way in.'),
    pane: null, concept: 'wifi-and-mining',
    checklist: W(['Is this your router’s address?', 'Do you know the sign-in for your router’s settings page?', 'Did you set up anything that needs it (a game console, a home camera)?'],
      ['Is this your exchange’s address?', 'Do you know the sign-in for the exchange?', 'Did you set up anything that needs this door?']),
    steps: W(['Open your router’s settings page: type the router address shown here into a web browser.', 'Sign in (the details are often on a sticker on the router).', 'Turn off UPnP and remote administration, save, and run the checkup again.'],
      ['Open the exchange’s settings page at the address shown here.', 'Sign in (the details are often on a sticker on the box).', 'Close the open door, save and sweep again.']),
  },
  vpn: {
    chip: W('VPN', 'Tunnel'),
    via: W('VPN', 'Tunnel'), to: W('Leaks', 'Leaks'),
    head: W('', 'Your tunnel has a gap'),
    what: W('Some of your traffic goes around the VPN. If you use the VPN for privacy, that part isn’t protected.',
      'Some calls go around your tunnel. If you use it for privacy, that part isn’t covered.'),
    pane: PANE('vpn', 'vpn'), concept: 'wifi-and-mining',
    checklist: W(['Do you rely on this VPN for privacy?', 'Is the VPN app set to send all traffic through it?', 'Check the VPN app’s settings, or ask its support.'],
      ['Do you rely on this tunnel?', 'Is it set to carry all your calls?', 'Check the tunnel tool’s settings.']),
  },
};

// Sharing services by data.service / tool, in plain words.
const SERVICE_NAMES = {
  ssh: W('Remote Login (SSH)', 'Remote sign-in line'),
  screen_sharing: W('Screen Sharing', 'Screen line'),
  remote_management: W('Remote Management', 'Remote control line'),
  remote_apple_events: W('Remote Apple Events', 'Remote command line'),
  file_sharing: W('File Sharing', 'File line'),
  printer_sharing: W('Printer Sharing', 'Printer line'),
  airdrop_everyone: W('AirDrop (everyone)', 'Drop box (anyone)'),
};

// ---- Reading the lines from the engine's data ----

const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const clip = (s) => {
  const t = String(s == null ? '' : s).trim();
  return t.length > MAX_VALUE ? `${t.slice(0, MAX_VALUE - 1)}…` : t;
};
const list = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v]);
const LOOPBACK = /^(127\.|::1$|\[::1\]|localhost$)/i;
const ANY = /^(0\.0\.0\.0|\*|::|\[::\])$/;
const BLOCKED = /^(0\.0\.0\.0|127\.0\.0\.1|::1?|::0)$/;

// A short text for a list entry of unknown shape.
function entryText(e) {
  if (!isObj(e)) return clip(e);
  for (const k of ['name', 'hostname', 'domain', 'server', 'ip', 'process', 'tool', 'share', 'rule_name', 'label', 'path']) {
    if (typeof e[k] === 'string' && e[k]) return clip(e[k]);
  }
  return clip(Object.values(e).filter((v) => typeof v === 'string' || typeof v === 'number').slice(0, 2).join(' '));
}

function reach(address, ctx) {
  const a = String(address || '').trim();
  if (LOOPBACK.test(a)) return { to: `Only ${me(ctx)}`, odd: false };
  if (ANY.test(a) || !a) return { to: ctx.mode === 'city' ? 'Anyone on the street' : 'Anyone on your network', odd: true };
  return { to: clip(a), odd: false };
}

// "Port 631 (ipp) - cupsd on 127.0.0.1" (listening_ports) or "3306 (mysqld) listening on 0.0.0.0" (exposed).
const PORT_LISTED = /^Port\s+(\d+)\s*\(([^)]*)\)\s*-\s*(.+?)\s+on\s+(\S+)$/;
const PORT_EXPOSED = /^(\d+)\s*\(([^)]*)\)\s*listening on\s+(\S+)$/;
// "relayd (PID 501) -> 198.51.100.23:31337" (network_connections_monitor).
const CONN = /^(.+?)\s+\(PID\s+(\d+)\)\s*->\s*(.+):(\d+)$/;

function portLines(d, ctx) {
  if (Array.isArray(d.ports) && d.ports.some((p) => typeof p === 'string')) {
    return d.ports.map((p) => {
      const s = String(p);
      let m = s.match(PORT_LISTED);
      if (m) return { via: clip(`port ${m[1]} · ${m[3]}`), ...reach(m[4], ctx) };
      m = s.match(PORT_EXPOSED);
      if (m) return { via: clip(`port ${m[1]} · ${m[2]}`), ...reach(m[3], ctx) };
      return { via: clip(s), to: ctx.mode === 'city' ? 'Unknown' : 'Not known' };
    });
  }
  if (d.process || d.port) {
    const ports = list(d.ports).length ? list(d.ports) : list(d.port);
    return [{ via: clip(`port ${ports.join(', ')} · ${d.process || '?'}`), ...reach('', ctx) }];
  }
  if (Array.isArray(d.processes)) return d.processes.map((p) => ({ via: entryText(p), to: `Only ${me(ctx)}` }));
  if (d.gateway_ip && d.port) return [{ via: clip(`port ${d.port} · ${d.service || ''}`), to: clip(d.gateway_ip), odd: true }];
  return [];
}

function connLines(d, ctx) {
  const out = [];
  for (const c of list(d.connections)) {
    const m = typeof c === 'string' && c.match(CONN);
    if (m) out.push({ via: clip(m[1]), to: clip(`${m[3]} · port ${m[4]}`), odd: true });
    else if (isObj(c)) out.push({ via: clip(c.process || '?'), to: clip(`${c.remote_addr || '?'} · port ${c.port || '?'}`), odd: true });
    else out.push({ via: clip(c), to: ctx.mode === 'city' ? 'Unknown' : 'Not known' });
  }
  if (out.length) return out;
  if (d.process) {
    const ports = list(d.ports).length ? list(d.ports) : list(d.port);
    const to = ports.length ? `port ${ports.join(', ')}` : `${d.count || 'many'} ${ctx.mode === 'city' ? 'calls' : 'connections'}`;
    return [{ via: clip(d.process), to: clip(to), odd: ports.length > 0 }];
  }
  for (const e of [...list(d.items), ...list(d.processes)]) {
    if (isObj(e)) out.push({ via: clip(e.process || entryText(e)), to: clip(`port ${list(e.ports).join(', ')}`) });
    else out.push({ via: clip(e), to: ctx.mode === 'city' ? 'Many calls' : 'Many connections' });
  }
  return out;
}

function firewallLines(d, ctx, finding) {
  const code = String(finding.code || '');
  const city = ctx.mode === 'city';
  if (code.endsWith('allow_signed_enabled')) return [{ via: city ? 'Signed callers' : 'Signed apps', to: city ? 'Let through without asking' : 'Let in without asking', odd: true }];
  if (Array.isArray(d.apps) || Array.isArray(d.allowed_apps)) {
    return list(d.apps || d.allowed_apps).map((a) => ({ via: city ? 'Allowed list' : 'Allowed apps', to: entryText(a) }));
  }
  if (d.rule_name) {
    const what = d.issue_type === 'all_programs' || code.endsWith('all_programs') ? (city ? 'Any caller' : 'Any program') : (city ? 'Every socket' : 'Every port');
    return [{ via: clip(`${d.rule_name}${d.profile ? ` (${d.profile})` : ''}`), to: what, odd: true }];
  }
  if (d.profile_name) return [{ via: clip(d.profile_name), to: city ? 'Callers in by default' : 'Connections in by default', odd: true }];
  if (d.rule_count != null || d.total_rules != null) return [{ via: city ? 'Gate rules' : 'Firewall rules', to: clip(`${d.rule_count != null ? d.rule_count : d.total_rules}`) }];
  return [];
}

function serverLines(servers, via, ctx, odd) {
  return list(servers).map((s) => ({ via, to: entryText(s), odd: !!odd }));
}

function dnsLines(d, ctx, finding) {
  const city = ctx.mode === 'city';
  const via = say(KINDS.dns.via, ctx);
  const code = String(finding.code || '');
  if (d.domain) return [{ via: clip(d.domain), to: clip(d.resolved_ip || '?'), odd: true }];
  if (d.non_vpn_servers) return serverLines(d.non_vpn_servers, city ? 'Around the tunnel' : 'Around the VPN', ctx, true);
  const odd = /malicious|suspicious/.test(code) || finding.severity === 'warning' || finding.severity === 'critical';
  const servers = d.servers || d.dns_servers;
  if (servers && !isObj(servers)) return serverLines(servers, via, ctx, odd);
  if (isObj(servers)) return Object.keys(servers).map((k) => ({ via: clip(k), to: list(servers[k]).map(entryText).join(', ') }));
  if (d.provider) return [{ via, to: clip(d.provider) }];
  return [];
}

function profileLines(d, ctx) {
  const via = ctx.mode === 'city' ? 'Every name' : 'Every website name';
  const servers = list(d.servers).map(entryText).filter(Boolean);
  const to = `${clip(d.provider || (ctx.mode === 'city' ? 'Unknown relay' : 'Unknown provider'))}${servers.length ? ` · ${servers.join(', ')}` : ''}`;
  return [{ via, to: clip(to), odd: false }];
}

function hostsLines(d, ctx) {
  const city = ctx.mode === 'city';
  const out = [];
  for (const e of list(d.entries || d.custom_entries)) {
    if (isObj(e) && (e.hostname || e.domain)) {
      const ip = String(e.ip || '');
      const blocked = BLOCKED.test(ip);
      out.push({ via: clip(e.hostname || e.domain), to: blocked ? (city ? 'Blocked (sent nowhere)' : `Blocked (${ip})`) : clip(ip || '?'), odd: !blocked });
    } else out.push({ via: entryText(e), to: city ? 'Rerouted' : 'Redirected' });
  }
  for (const n of list(d.blocked_domains)) out.push({ via: entryText(n), to: 'Blocked', odd: true });
  for (const n of [...list(d.redirected_domains), ...list(d.redirects)]) {
    if (isObj(n)) out.push({ via: entryText(n), to: clip(n.ip || n.target || '?'), odd: true });
    else out.push({ via: entryText(n), to: city ? 'Rerouted' : 'Somewhere else', odd: true });
  }
  if (!out.length && (d.count != null || d.entry_count != null || d.file_size != null || d.permission_issue)) {
    out.push({ via: city ? 'Address book' : 'Hosts file', to: clip(d.permission_issue || `${d.count != null ? d.count : d.entry_count != null ? d.entry_count : d.file_size} ${city ? 'lines' : 'entries'}`) });
  }
  return out;
}

function proxyLines(d, ctx) {
  const city = ctx.mode === 'city';
  const what = ctx.mode === 'city' ? 'Your calls' : 'Your web traffic';
  const via = (iface) => clip(iface ? `${what} (${iface})` : what);
  const iface = d.interface || d.target;
  const out = [];
  if (d.pac_url) out.push({ via: via(iface), to: clip(`Setup file: ${d.pac_url}`), odd: true });
  const servers = [d.http_server, d.https_server, d.socks_server, d.proxy_server, ...list(d.proxy_servers), ...list(d.proxies)]
    .filter((s) => s != null && s !== '').map(entryText);
  for (const s of [...new Set(servers)]) out.push({ via: via(iface), to: s, odd: true });
  if (isObj(d.env_proxies)) for (const [k, v] of Object.entries(d.env_proxies)) out.push({ via: clip(k), to: entryText(v), odd: true });
  if (d.netsh_proxy) out.push({ via: city ? 'System relay' : 'System proxy', to: entryText(d.netsh_proxy) });
  return out;
}

function sharingLines(d, ctx, finding) {
  const city = ctx.mode === 'city';
  const code = String(finding.code || '');
  const anyone = city ? 'Anyone who can reach your post' : 'Other devices on your network';
  if (code.includes('airdrop')) return [{ via: say(SERVICE_NAMES.airdrop_everyone, ctx), to: 'Anyone nearby', odd: true }];
  if (d.service) {
    const name = SERVICE_NAMES[d.service] ? say(SERVICE_NAMES[d.service], ctx) : clip(d.service);
    return [{ via: name, to: anyone, odd: true }];
  }
  if (d.rdp_enabled != null || d.rdp_port != null || code.includes('rdp')) {
    const via = `${city ? 'Remote screen line' : 'Remote Desktop'}${d.rdp_port ? ` · port ${d.rdp_port}` : ''}`;
    return [{ via: clip(via), to: d.nla_enabled === false ? (city ? 'Anyone, no sign-in step' : 'Anyone, with no sign-in step first') : anyone, odd: true }];
  }
  if (d.tool) return [{ via: clip(d.tool), to: city ? 'Whoever holds its code' : 'Whoever has its access code', odd: true }];
  if (Array.isArray(d.tools)) return d.tools.map((t) => ({ via: entryText(t), to: city ? 'Whoever holds its code' : 'Whoever has its access code', odd: true }));
  if (d.share) return [{ via: clip(`${d.share}${d.path ? ` (${d.path})` : ''}`), to: code.includes('write') ? (city ? 'Anyone can change files' : 'Everyone can change files') : anyone, odd: true }];
  if (Array.isArray(d.services)) return d.services.map((s) => ({ via: entryText(s), to: anyone }));
  return [];
}

function wifiLines(d, ctx) {
  const city = ctx.mode === 'city';
  if (d.network) return [{ via: clip(d.network), to: clip(d.security || (city ? 'Unknown lock' : 'Unknown')), odd: true }];
  if (Array.isArray(d.networks)) return d.networks.map((n) => ({ via: entryText(n), to: city ? 'Weak or no lock (saved)' : 'Weak or no password (saved)', odd: true }));
  if (d.current_network) return [{ via: clip(d.current_network), to: 'Connected' }];
  return [];
}

function routerLines(d, ctx, finding) {
  const city = ctx.mode === 'city';
  const code = String(finding.code || '');
  if (code.includes('upnp')) return [{ via: city ? 'Self-opening doors' : 'UPnP (opens ports on its own)', to: clip(d.gateway_ip || '?'), odd: true }];
  if (d.port) return [{ via: clip(`port ${d.port}${d.service ? ` · ${d.service}` : ''}`), to: clip(d.gateway_ip || d.target || '?'), odd: true }];
  if (d.gateway_ips || d.ip || d.ips) {
    const ips = [...list(d.gateway_ips), ...list(d.ip), ...list(d.ips)].map(entryText);
    return [{ via: clip(d.vendor || (city ? 'A device' : 'A device on your network')), to: clip(ips.join(', ')), odd: true }];
  }
  if (Array.isArray(d.gateways)) return d.gateways.map((g) => ({ via: city ? 'Exchange' : 'Router', to: entryText(g), odd: true }));
  if (d.device_count != null) return [{ via: city ? 'Posts on the street' : 'Devices on your network', to: clip(`${d.device_count}`), odd: true }];
  if (d.gateway_ip) return [{ via: city ? 'Exchange' : 'Router', to: clip(d.gateway_ip) }];
  return [];
}

function vpnLines(d, ctx) {
  const city = ctx.mode === 'city';
  const name = clip(d.vpn_name || (city ? 'Tunnel' : 'VPN'));
  if (Array.isArray(d.default_routes)) return [{ via: name, to: clip(`${city ? 'Two ways out' : 'More than one way out'}: ${d.default_routes.map(entryText).join(', ')}`), odd: true }];
  if (Array.isArray(d.vpn_configs)) return d.vpn_configs.map((v) => ({ via: entryText(v), to: city ? 'Not carrying calls' : 'Not connected' }));
  return [];
}

const READERS = { port: portLines, conn: connLines, firewall: firewallLines, dns: dnsLines, profile: profileLines,
  hosts: hostsLines, proxy: proxyLines, sharing: sharingLines, wifi: wifiLines, router: routerLines, vpn: vpnLines };

// { kind, lines: [{ via, to, odd }] (at most MAX_LINES), more } for one finding.
export function linesOf(finding, ctx) {
  const f = finding || {};
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const kind = lineKind(f);
  const d = isObj(f.data) ? f.data : {};
  let lines = [];
  try { lines = READERS[kind](d, c, f) || []; } catch (e) { lines = []; }
  lines = lines.filter((l) => l && l.via);
  if (!lines.length) {
    // A shape this game doesn't know: the kind's own words, never the finding's prose in city mode.
    const value = c.mode === 'city' ? '' : clip(f.title);
    lines = [{ via: say(KINDS[kind].via, c), to: value || (c.mode === 'city' ? 'Unknown' : 'Not known') }];
  }
  for (const l of lines) if (!l.to) l.to = c.mode === 'city' ? 'Unknown' : 'Not known';
  const more = Math.max(0, lines.length - MAX_LINES);
  return { kind, lines: lines.slice(0, MAX_LINES), more };
}

// ---- Decisions ----

function markable(finding) {
  const m = finding && finding.markable;
  return !!(m && typeof m === 'object' && MARK_KINDS.has(m.kind) && typeof m.id === 'string' && MARK_ID.test(m.id)
    && typeof m.group === 'string' && MARK_ID.test(m.group));
}

const plat = (ctx) => (ctx && ctx.platform === 'win32' ? 'win32' : 'darwin');

function paneFor(kind, finding, ctx) {
  const k = KINDS[kind];
  if (kind === 'sharing' && plat(ctx) === 'win32' && finding && finding.data && (finding.data.tool || Array.isArray(finding.data.tools))) return 'windows-apps';
  return k.pane ? k.pane[plat(ctx)] : null;
}

function stepsFor(kind, ctx) {
  const s = KINDS[kind].steps;
  if (!s) return [];
  const w = s.standard ? s : s[plat(ctx)];
  return (ctx.mode === 'city' ? w.city : w.standard).map((x) => x.replace(/\{me\}/g, me(ctx)));
}

const checklistFor = (kind, ctx) => (ctx.mode === 'city' ? KINDS[kind].checklist.city : KINDS[kind].checklist.standard).map((x) => x.replace(/\{me\}/g, me(ctx)));

export function decisions(item, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const f = (item && item.finding) || {};
  const kind = lineKind(f);
  const profile = kind === 'profile';
  const city = c.mode === 'city';

  const canMark = markable(f);
  const expected = {
    id: 'expected',
    label: profile ? W('It’s my profile', 'My own relay') : W('Expected', 'Expected line'),
    effect: canMark ? { kind: 'mark' } : { kind: 'keep' },
    hint: canMark
      ? (city ? 'Logs it as yours. It comes back if it changes.' : 'Marks it as yours. It comes back if it changes.')
      : (city ? 'Leaves the line as it is.' : 'Leaves it as it is.'),
  };

  let effect;
  let hint;
  const pane = paneFor(kind, f, c);
  if (f.fixable && typeof f.fixable === 'object') {
    effect = { kind: 'fix' };
    hint = city ? 'Shows what changes, and how to undo it.' : 'Shows what will change, and how to undo it.';
  } else if (pane) {
    effect = { kind: 'settings', pane };
    hint = city ? 'Opens the panel where it switches off.' : 'Opens the settings where you can switch it off.';
  } else {
    effect = { kind: 'odd', close: 'steps', steps: stepsFor(kind, c) };
    hint = city ? 'Shows the steps to cut it.' : 'Shows the steps to remove it.';
  }
  // R6: a change to something that can alert whoever set it up carries the removal warning (settings too).
  const alerting = !!(item && (item.removal_alert || f.removal_alert || (f.remediation && f.remediation.safety_note)));
  if (alerting) effect.warning = true;
  const odd = { id: 'odd', label: profile ? W('Not mine — undo', 'Cut the relay') : W('Odd — close it', 'Cut the line'), effect, hint };

  const closer = {
    id: 'closer',
    label: W('Look closer', 'Trace it'),
    effect: { kind: 'closer', checklist: checklistFor(kind, c) },
    hint: city ? 'What to check before you choose.' : 'What to check before you decide.',
  };
  return [expected, odd, closer];
}

// ---- Research ----

function lookupFor(kind, f, t, ctx) {
  const d = isObj(f.data) ? f.data : {};
  const first = t.lines[0] || {};
  const win = plat(ctx) === 'win32';
  switch (kind) {
    case 'port': case 'conn': {
      const name = d.process || String(first.via || '').replace(/^port\s+[\d, ]+·\s*/, '');
      const port = d.port || (String(first.via || '').match(/port\s+(\d+)/) || String(first.to || '').match(/port\s+(\d+)/) || [])[1] || '';
      return { kind: 'lookup', source: 'web', query: clip(`"${name}" ${port ? `port ${port}` : 'network'}`) };
    }
    case 'profile': return { kind: 'lookup', source: 'web', query: clip(`"${d.provider || ''}" DNS profile`) };
    case 'dns': return { kind: 'lookup', source: 'web', query: clip(`"${first.to || ''}" DNS server`) };
    case 'hosts': return { kind: 'lookup', source: win ? 'microsoft-support' : 'apple-support', query: 'hosts file' };
    case 'proxy': return { kind: 'lookup', source: win ? 'microsoft-support' : 'apple-support', query: 'proxy settings' };
    case 'sharing': return d.tool ? { kind: 'lookup', source: 'web', query: clip(`"${d.tool}" remote access`) }
      : { kind: 'lookup', source: win ? 'microsoft-support' : 'apple-support', query: clip(win ? 'Remote Desktop' : `Sharing ${first.via || ''}`) };
    case 'firewall': return { kind: 'lookup', source: win ? 'microsoft-support' : 'apple-support', query: 'firewall allowed apps' };
    case 'wifi': return { kind: 'lookup', source: win ? 'microsoft-support' : 'apple-support', query: 'Wi-Fi security' };
    case 'router': return { kind: 'lookup', source: 'web', query: 'turn off UPnP router' };
    case 'vpn': return { kind: 'lookup', source: 'web', query: clip(`"${d.vpn_name || 'VPN'}" send all traffic`) };
    default: return null;
  }
}

const didntFinish = (item) => !!(item && (item.unfinished === true || item.complete === false || (item.finding && item.finding.complete === false)));

export function research(item, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const f = (item && item.finding) || {};
  const kind = lineKind(f);
  const t = linesOf(f, c);
  let rows = [];
  try { rows = typeof c.evidenceRows === 'function' ? (c.evidenceRows(f, { mode: c.mode }) || []) : []; } catch (e) { rows = []; }
  const links = [];
  const pane = paneFor(kind, f, c);
  if (pane) links.push({ kind: 'settings', pane });
  if (kind === 'profile' && plat(c) === 'darwin') links.push({ kind: 'settings', pane: 'profiles' });
  const look = lookupFor(kind, f, t, c);
  if (look) links.push(look);
  links.push({ kind: 'lesson', concept: KINDS[kind].concept });
  const unfinished = didntFinish(item);
  const what = say(KINDS[kind].what, c);
  const out = { rows: Array.isArray(rows) ? rows : [], what, links, unfinished };
  if (KINDS[kind].ask) out.ask = say(KINDS[kind].ask, c);
  return out;
}

// ---- Render ----

function renderLine(l, kind, ctx) {
  const e = ctx.esc;
  const k = KINDS[kind];
  return `<li class="sb-line${l.odd ? ' sb-odd' : ''}">`
    + `<span class="sb-node sb-from"><small>${e(me(ctx, true))}</small></span>`
    + '<span class="sb-wire" aria-hidden="true"></span>'
    + `<span class="sb-node sb-via"><small>${e(say(k.via, ctx))}</small><code>${e(l.via)}</code></span>`
    + '<span class="sb-wire" aria-hidden="true"></span>'
    + `<span class="sb-node sb-to"><small>${e(say(k.to, ctx))}</small><code>${e(l.to)}</code></span>`
    + '</li>';
}

export function render(view, ctx) {
  const c = { mode: 'standard', platform: 'darwin', ...(ctx || {}) };
  const e = c.esc;
  const v = view || {};
  const item = v.item || {};
  const f = item.finding || {};
  const kind = lineKind(f);
  const k = KINDS[kind];
  const city = c.mode === 'city';
  const r = v.research || research(item, c);
  const t = linesOf(f, c);
  const title = city ? say(k.head, c) : (f.title || say(k.chip, c));
  const parts = [];
  parts.push(`<article class="sb-card sb-kind-${kind}${v.practice ? ' sb-practice' : ''}">`);
  parts.push(`<header class="sb-head"><span class="sb-chip">${e(say(k.chip, c))}</span>`
    + (v.total > 1 ? `<span class="sb-count">${e(`Line ${(v.index || 0) + 1} of ${v.total}`)}</span>` : '')
    + `<h3 class="sb-title">${e(title)}</h3></header>`);
  if (v.step && v.step.say) parts.push(`<aside class="sb-step" role="note">${e(say(v.step.say, c))}</aside>`);
  parts.push(`<ol class="sb-lines" aria-label="Where this line goes">${t.lines.map((l) => renderLine(l, kind, c)).join('')}</ol>`);
  if (t.more) parts.push(`<p class="sb-more">${e(`and ${t.more} more`)}</p>`);
  if (r.ask) parts.push(`<div class="sb-ask"><strong>${e(city ? 'Whose relay is it?' : 'Whose profile is this?')}</strong><p>${e(r.ask.replace(/^Whose (?:profile is this|relay is it)\?\s*/, ''))}</p></div>`);
  if (r.what) parts.push(`<p class="sb-what">${e(r.what)}</p>`);
  if (r.unfinished || didntFinish(item)) parts.push(`<p class="sb-unfinished">${e(city ? 'This sweep didn’t finish, so it may have missed lines.' : 'This check didn’t finish, so it may have missed some.')}</p>`);
  parts.push('</article>');
  return parts.join('');
}

// ---- Summary ----

function decisionId(r) {
  if (!r) return '';
  if (typeof r === 'string') return r;
  const d = r.decision;
  if (typeof d === 'string') return d;
  if (d && typeof d.id === 'string') return d.id;
  return typeof r.id === 'string' ? r.id : '';
}

export function summary(results, ctx) {
  const c = { mode: 'standard', ...(ctx || {}) };
  const e = c.esc || ((s) => String(s));
  const rs = Array.isArray(results) ? results : [];
  const n = { expected: 0, odd: 0, closer: 0 };
  for (const r of rs) { const id = decisionId(r); if (id in n) n[id] += 1; }
  const total = rs.length;
  const plural = (x, one, many) => `${x} ${x === 1 ? one : many}`;
  if (c.mode === 'city') {
    return `<div class="sb-summary"><p>${e(`Switchboard: ${plural(total, 'line', 'lines')} traced. ${n.expected} expected, ${n.odd} cut, ${n.closer} to trace again.`)}</p>`
      + `<p>${e('A traced line is one less unknown. Lines the sweep couldn’t reach aren’t on this board.')}</p></div>`;
  }
  return `<div class="sb-summary"><p>${e(`You traced ${plural(total, 'line', 'lines')}: ${n.expected} expected, ${n.odd} to close, ${n.closer} to look at more closely.`)}</p>`
    + `<p>${e('Each one you traced is one less unknown. It doesn’t rule out lines a check couldn’t see.')}</p></div>`;
}

// ---- Practice (synthetic only) ----

const practiceItem = (finding) => ({
  key: `practice:${finding.code}`, severity: finding.severity, finding: { category: 'security', ...finding },
  findings: [{ category: 'security', ...finding }], seen_in: [finding.module], marked: false, held: false, removal_alert: false,
});

export const practice = {
  items: [
    practiceItem({
      module: 'open_ports_scan', code: 'security.open_ports_scan.listening_ports', severity: 'warning',
      title: 'A printer service is listening', description: 'Practice: a made-up example.',
      data: { check: 'listening_ports', count: 1, ports: ['Port 631 (ipp) - cupsd on 127.0.0.1'] },
    }),
    practiceItem({
      module: 'suspicious_connections', code: 'security.suspicious_connections.unusual_listening_port', severity: 'warning',
      title: 'A program is listening on an unusual port', description: 'Practice: a made-up example.',
      data: { check: 'unusual_listening_port', pid: 4242, process: 'syncagentd', port: 4444, ports: [4444] },
    }),
    practiceItem({
      module: 'hosts_file_check', code: 'security.hosts_file_check.bank_domain_redirect', severity: 'critical',
      title: 'A bank website name is being redirected', description: 'Practice: a made-up example.',
      data: { check: 'bank_domain_redirect', count: 1, entries: [{ ip: '203.0.113.7', hostname: 'mybank.example' }] },
    }),
  ],
  script: [
    { item: 0, say: W('Follow the line: port 631 is the printer service (cupsd), and it only answers this computer. That’s expected.',
      'Follow the line: socket 631 is the printer service, and only your post can ring it. That’s expected.'), expect: 'expected' },
    { item: 1, say: W('You don’t know “syncagentd”, and anyone on your network could reach it. Don’t guess: look closer first.',
      'You don’t know “syncagentd”, and anyone on the street could ring it. Don’t guess: trace it first.'), expect: 'closer' },
    { item: 2, say: W('A bank’s name is sent to an address that isn’t the bank. That line is odd: close it.',
      'A bank’s name is sent to an address that isn’t the bank. That line is wrong: cut it.'), expect: 'odd' },
  ],
};

export default {
  type: 'switchboard',
  title: W('Network lines', 'The Switchboard'),
  concepts: ['wifi-and-mining', 'remote-access-scams'],
  covers,
  decisions,
  research,
  practice,
  render,
  summary,
};
