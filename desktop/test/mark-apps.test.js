// "It's mine" on a list of apps: names people recognise, bundle ids kept as
// evidence, and a neutral reason instead of the watching line.
const test = require('node:test');
const assert = require('node:assert');
const MarkFlow = require('../renderer/mark-flow.js');

const ITEM = {
  kind: 'sharing_service', id: 'aaaaaaaaaaaa', code: 'security.sharing_services.remote_login', group: '0123456789ab',
  label: 'Remote Login', monitoring: true, shows: [['Setting', 'Remote Login'], ['Now', 'On']],
  will_change: 'The checkup will stop warning you about Remote Login being on.',
  how_to_undo: ['Choose "Stop treating this as mine" on the item in this app'],
};

const APPS = {
  ...ITEM, kind: 'app_permissions', code: 'security.app_permissions.accessibility_access', label: '3 apps',
  shows: [['Apps', 'Caffeine, OBS Studio, com.x.unknown'], ['How many', '3']],
  apps: [
    { id: 'com.intelliscapesolutions.caffeine', name: 'Caffeine' },
    { id: 'com.obsproject.obs-studio', name: 'OBS Studio' },
    { id: 'com.x.unknown', name: 'com.x.unknown' },
  ],
  will_change: 'The checkup will stop warning you about this list of 3 apps.',
};

test('a list of apps shows each app by name, with the bundle ids under Technical details', () => {
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions', markable: APPS,
    made_by: [
      { subject: 'com.intelliscapesolutions.caffeine', name: 'Intelliscape Solutions', verified: true },
      { subject: 'com.obsproject.obs-studio', name: 'OBS Project', verified: false },
    ],
  });
  assert.match(html, /What you are saying is yours \(3 apps\)/);
  const rows = html.match(/<li class="mark-apps__row">/g) || [];
  assert.strictEqual(rows.length, 3, 'one row per app');
  assert.match(html, /<span class="mark-apps__name">Caffeine<\/span><span class="mark-apps__maker">Made by Intelliscape Solutions<\/span>/);
  assert.match(html, /Says it is made by OBS Project \(couldn’t verify\)/);
  const visible = html.split('<details')[0];
  assert.ok(!visible.includes('com.intelliscapesolutions.caffeine'), 'no bundle id outside the disclosure');
  assert.match(html, /<details class="mark-tech"><summary>Technical details<\/summary>/);
  for (const a of APPS.apps) assert.ok(html.includes(`<code>${a.id}</code>`), `evidence kept: ${a.id}`);
  assert.ok(html.includes(MarkFlow.NOT_SURE_LIST));
  assert.match(html, /data-mark-confirm>Yes, these are mine</);
  assert.match(html, /data-mark-panel hidden/, 'still a separate, deliberate click');
  assert.ok(!/type="checkbox"/.test(html), 'the whole list is one answer: no per-app ticks the engine would ignore');
});

test('an app list gets the neutral reason, not the watching line; the "only if yours" line stays', () => {
  const html = MarkFlow.markControlsHtml({ module: 'app_permissions', markable: APPS });
  assert.ok(html.includes(MarkFlow.ONLY_IF_YOURS));
  assert.ok(html.includes(MarkFlow.LIST_REASON));
  assert.ok(!html.includes(MarkFlow.COULD_WATCH));
  // Remote access, proxies, extensions keep the watching line.
  for (const kind of ['sharing_service', 'network_proxy', 'ssh_authorized_keys', 'system_extension', 'browser_extension']) {
    assert.ok(MarkFlow.markControlsHtml({ module: 'm', markable: { ...ITEM, kind } }).includes(MarkFlow.COULD_WATCH), kind);
  }
});

test('app names and makers from the engine are escaped; an older engine without apps falls back to the list', () => {
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions',
    markable: { ...APPS, apps: [{ id: 'a.b<img>', name: '<img src=x onerror=1>' }] },
    made_by: [{ subject: 'a.b<img>', name: '<script>', verified: true }],
  });
  assert.ok(!html.includes('<img') && !html.includes('<script>'));
  const old = MarkFlow.markControlsHtml({ module: 'app_permissions', markable: { ...APPS, apps: undefined } });
  assert.match(old, /<dl class="mark-shows">/);
  assert.match(old, /Caffeine, OBS Studio/);
});

test('the panel copy names no product', () => {
  const html = MarkFlow.markControlsHtml({ module: 'app_permissions', markable: APPS });
  assert.ok(!/Device Rescue/.test(html));
});
