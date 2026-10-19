const test = require('node:test');
const assert = require('node:assert');
const { routerUrlFor, isPrivateIpv4 } = require('../router-url');

test('builds an http URL for private home-network addresses', () => {
  assert.strictEqual(routerUrlFor('192.168.0.1'), 'http://192.168.0.1/');
  assert.strictEqual(routerUrlFor('10.0.0.1'), 'http://10.0.0.1/');
  assert.strictEqual(routerUrlFor('172.16.0.1'), 'http://172.16.0.1/');
  assert.strictEqual(routerUrlFor('172.31.255.254'), 'http://172.31.255.254/');
});

test('refuses public, loopback, link-local and edge-of-range addresses', () => {
  for (const ip of ['8.8.8.8', '127.0.0.1', '169.254.1.1', '172.15.0.1', '172.32.0.1', '0.0.0.0', '192.169.0.1', '11.0.0.1']) {
    assert.strictEqual(routerUrlFor(ip), null, ip);
  }
});

test('refuses anything that is not a bare dotted IPv4 address', () => {
  for (const v of [
    'http://192.168.0.1/', '192.168.0.1/admin', '192.168.0.1:8080', '192.168.0.1@evil.example',
    '192.168.0.256', '192.168.0', '192.168.0.1.5', '192.168.00.1', ' 192.168.0.1', '192.168.0.1\n',
    'file:///etc/passwd', '', null, undefined, 3232235521, ['192.168.0.1'], { ip: '192.168.0.1' },
  ]) {
    assert.strictEqual(routerUrlFor(v), null, JSON.stringify(v));
    assert.strictEqual(isPrivateIpv4(v), false, JSON.stringify(v));
  }
});
