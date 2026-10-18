// The 'open-router' channel opens the router's own sign-in page. Only an IP
// address crosses IPC; the URL is built here. The address must be a private
// home-network IPv4 address (10/8, 172.16/12, 192.168/16), so the channel can
// never open a public site, a local file or another scheme.
const OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
const IPV4 = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

function isPrivateIpv4(ip) {
  if (typeof ip !== 'string') return false;
  const m = IPV4.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function routerUrlFor(ip) {
  return isPrivateIpv4(ip) ? `http://${ip}/` : null;
}

module.exports = { isPrivateIpv4, routerUrlFor };
