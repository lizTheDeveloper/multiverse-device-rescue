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
  assert.match(html, /<span class="mark-apps__name">Caffeine<\/span><span class="mark-apps__id"> · <code>com\.intelliscapesolutions\.caffeine<\/code><\/span><\/span><span class="mark-apps__maker">Made by Intelliscape Solutions \(verified\)<\/span>/);
  assert.match(html, /Says it is made by OBS Project \(couldn’t verify\)/);
  const visible = html.split('<details')[0];
  for (const a of APPS.apps) assert.ok(visible.includes(a.id), `bundle id shown on its row: ${a.id}`);
  assert.ok(!html.includes(MarkFlow.NAME_MAKER_MISMATCH), 'names that fit their makers are not flagged');
  assert.match(html, /<details class="mark-tech"><summary>Technical details<\/summary>/);
  for (const a of APPS.apps) assert.ok(html.includes(`<code>${a.id}</code>`), `evidence kept: ${a.id}`);
  assert.ok(html.includes(MarkFlow.NOT_SURE_LIST));
  assert.match(html, /data-mark-confirm>Yes, these are mine</);
  assert.match(html, /data-mark-panel hidden/, 'still a separate, deliberate click');
  assert.ok(!/type="checkbox"/.test(html), 'the whole list is one answer: no per-app ticks the engine would ignore');
});

test('an app permission list keeps the watching line and adds the list reason; the "only if yours" line stays', () => {
  // Accessibility, screen recording, camera, microphone, input monitoring: all can watch a computer.
  for (const code of ['security.app_permissions.accessibility_access', 'security.app_permissions.screen_recording',
    'security.privacy_permissions_audit.camera_microphone_combo', 'security.accessibility_permissions.suspicious_accessibility']) {
    const html = MarkFlow.markControlsHtml({ module: 'app_permissions', markable: { ...APPS, code } });
    assert.ok(html.includes(MarkFlow.ONLY_IF_YOURS), code);
    assert.ok(html.includes(MarkFlow.COULD_WATCH), code);
    assert.ok(html.includes(MarkFlow.LIST_REASON), code);
  }
  // Remote access, proxies, extensions keep the watching line.
  for (const kind of ['sharing_service', 'network_proxy', 'ssh_authorized_keys', 'system_extension', 'browser_extension', 'app_permissions']) {
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

// The panel's raw list: what the person sees when the per-app view can't be trusted.
function fallbackList(html) {
  assert.ok(!/<li class="mark-apps__row">/.test(html), 'no per-app view');
  assert.match(html, /<dl class="mark-shows">/);
  assert.ok(html.includes('Caffeine, OBS Studio, com.x.unknown'), 'every item in the raw list is shown');
}

test('a malformed row never disappears: the panel falls back to the full raw list', () => {
  const bad = [
    [{ id: 'com.intelliscapesolutions.caffeine', name: 'Caffeine' }, { id: '', name: 'Ghost' }, APPS.apps[2]],
    [APPS.apps[0], { id: 'com.obsproject.obs-studio', name: 'x'.repeat(MarkFlow.MAX_APP_NAME + 1) }, APPS.apps[2]],
    [APPS.apps[0], { id: 'com.obsproject.obs-studio', name: 'Zoom\u202Eexe.gpj' }, APPS.apps[2]],
    [APPS.apps[0], { id: 'com.obsproject.obs-studio', name: 'Zo\u200Bom' }, APPS.apps[2]],
    [APPS.apps[0], { id: 'com.obsproject.obs-studio' }, APPS.apps[2]],
    [APPS.apps[0], null, APPS.apps[2]],
    [APPS.apps[0], APPS.apps[0], APPS.apps[2]],
  ];
  for (const apps of bad) fallbackList(MarkFlow.markControlsHtml({ module: 'app_permissions', markable: { ...APPS, apps } }));
});

test('the per-app view is shown only when the row count matches the app count', () => {
  fallbackList(MarkFlow.markControlsHtml({ module: 'app_permissions', markable: { ...APPS, apps: APPS.apps.slice(0, 2) } }));
  fallbackList(MarkFlow.markControlsHtml({
    module: 'app_permissions', markable: { ...APPS, shows: [['Apps', 'Caffeine, OBS Studio, com.x.unknown'], ['How many', '4']] },
  }));
  fallbackList(MarkFlow.markControlsHtml({
    module: 'app_permissions', markable: { ...APPS, shows: [['Apps', 'Caffeine, OBS Studio, com.x.unknown']] },
  }));
  const ok = MarkFlow.markControlsHtml({ module: 'app_permissions', markable: APPS });
  assert.strictEqual((ok.match(/<li class="mark-apps__row">/g) || []).length, Number(APPS.shows[1][1]));
});

test('a name at the engine limit, or the raw id as its name, is accepted', () => {
  const long = 'N'.repeat(MarkFlow.MAX_APP_NAME);
  const longId = `/Applications/${'d'.repeat(900)}.app`;
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions',
    markable: { ...APPS, apps: [APPS.apps[0], { id: 'com.obsproject.obs-studio', name: long }, { id: longId, name: longId }] },
  });
  assert.strictEqual((html.match(/<li class="mark-apps__row">/g) || []).length, 3);
});

test('two apps with the same name are two rows, each with its own bundle id', () => {
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions',
    markable: { ...APPS, apps: [{ id: 'us.zoom.xos', name: 'Zoom' }, { id: 'com.evil.zoom', name: 'Zoom' }, APPS.apps[2]] },
  });
  assert.strictEqual((html.match(/<span class="mark-apps__name">Zoom<\/span>/g) || []).length, 2);
  assert.ok(html.includes('<code>us.zoom.xos</code>') && html.includes('<code>com.evil.zoom</code>'));
});

test('a well-known name signed by someone else is flagged; an unverified maker is never "verified"', () => {
  const markable = { ...APPS, apps: [{ id: 'com.evil.zoom', name: 'Zoom' }, { id: 'us.zoom.xos', name: 'zoom.us' }, APPS.apps[2]] };
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions', markable,
    made_by: [
      { subject: 'com.evil.zoom', name: 'Evil Corp', verified: true },
      { subject: 'us.zoom.xos', name: 'Zoom Video Communications, Inc.', verified: true },
    ],
  });
  assert.match(html, /Made by Evil Corp \(verified\)<\/span><span class="mark-apps__flag">The name doesn’t match its maker<\/span>/);
  assert.strictEqual(html.split(MarkFlow.NAME_MAKER_MISMATCH).length - 1, 1, 'only the contradicting row is flagged');
  const unverified = MarkFlow.markControlsHtml({
    module: 'app_permissions', markable,
    made_by: [{ subject: 'com.evil.zoom', name: 'Zoom Video Communications, Inc.', verified: false }],
  });
  assert.ok(!unverified.includes('(verified)'));
  assert.ok(unverified.includes('Says it is made by Zoom Video Communications, Inc. (couldn’t verify)'));
});

test('control and format characters in the raw list are shown, not obeyed', () => {
  const html = MarkFlow.markControlsHtml({
    module: 'app_permissions',
    markable: { ...APPS, apps: undefined, shows: [['Apps', 'com.a\u202Eb'], ['How many', '1']] },
  });
  assert.ok(html.includes('com.a[U+202E]b'));
  assert.ok(!html.includes('\u202E'));
});
