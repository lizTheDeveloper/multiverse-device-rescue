'use strict';
// Tech abuse comes through more than one door: "work" monitoring on a
// person's own computer can be exploitation too. The help district names the
// US National Human Trafficking Hotline and a workers' rights group or legal
// aid, beside the domestic violence note, which stays as it was. Like every
// hotline, they stay in the help district: standard mode's screens quiet them,
// and city mode's screens never say them outside it.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');

const REPO = path.join(__dirname, '..', '..');
const GUIDE = fs.readFileSync(path.join(REPO, 'guides', 'remediation', 'respond_to_monitoring_software.md'), 'utf8');
const load = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const contract = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js')).href);

const TRAFFICKING = 'National Human Trafficking Hotline: 1-888-373-7888, or text 233733.';
const WORKERS = 'A workers’ rights group or legal aid can tell you what’s allowed where you live.';

test('the help district lists them, beside the unchanged domestic violence note', async () => {
  const c = await load('side-district.js');
  const byId = Object.fromEntries(c.HELP.map((x) => [x.id, x]));
  assert.strictEqual(byId.trafficking.text, TRAFFICKING);
  assert.strictEqual(byId.workers.text, WORKERS);
  assert.strictEqual(byId.hotline.text, 'National Domestic Violence Hotline: 1-800-799-7233. Text “START” to 88788.');
  const ids = c.HELP.map((x) => x.id);
  assert.ok(ids.indexOf('hotline') < ids.indexOf('trafficking'));
  const { renderSide } = await load('views/side-district.js');
  const { pickDistrict } = await load('district-names.js');
  const html = renderSide({ district: pickDistrict(7), held: [] });
  assert.ok(html.includes('1-888-373-7888, or text 233733'));
  assert.ok(html.includes('legal aid'));
  assert.ok(html.includes('1-800-799-7233'));
});

test('their sources: the monitoring check’s own safety note for the hotline, the guide for the workers’ line', () => {
  const ENGINE = fs.readFileSync(path.join(REPO, 'modules', 'security', 'stalkerware_scan', '__init__.py'), 'utf8');
  assert.ok(ENGINE.includes('National Human Trafficking Hotline'));
  assert.ok(ENGINE.includes('1-888-373-7888, or text 233733'));
  assert.ok(GUIDE.replace(/\s+/g, ' ').includes("a workers' rights group or legal aid can tell you what's allowed where you live"));
  // The guide's steps are shown on monitoring cards in standard mode: no trafficking hotline there.
  assert.doesNotMatch(GUIDE, /373-7888|233733|trafficking/i);
  assert.doesNotMatch(GUIDE + ENGINE, /illegal|against the law/i, 'never says work monitoring is illegal');
});

test('standard mode quiets the trafficking hotline sentence, as it does the domestic violence one', () => {
  for (const s of ['the US National Human Trafficking Hotline can help: 1-888-373-7888, or text 233733.', 'Call 1-888-373-7888.', 'Text 233733.']) {
    assert.ok(Q.MARKERS.test(s), s);
  }
  const text = 'Keep a record of it. If the same people control your work and where you live, the US National Human Trafficking Hotline can help: 1-888-373-7888, or text 233733. Use another device.';
  const quiet = Q.quiet(text);
  assert.doesNotMatch(quiet, /373-7888|233733|trafficking/i);
  assert.match(quiet, /Keep a record of it\./);
  assert.match(quiet, /Use another device\./);
  // The workers' rights pointer is not a hotline: it shows in standard mode.
  assert.strictEqual(Q.quiet(WORKERS), WORKERS);
});

test('a monitoring card’s guide steps in standard mode: the workers’ line, and no trafficking hotline', () => {
  const step = GUIDE.split('## Step 1')[1].split('## Step 2')[0];
  const f = { module: 'stalkerware_scan', code: 'security.stalkerware_scan.monitoring_software_found', severity: 'warning', title: 'x',
    description: 'A product.', remediation: { steps: [{ number: 1, title: 'Decide whether it’s safe to remove', body: step }] } };
  const card = Q.cardText('standard', f);
  for (const s of card.steps) assert.doesNotMatch(s.body, /373-7888|233733|trafficking/i);
  assert.match(card.steps[0].body, /workers' rights group or legal aid/);
});

test('city mode: the new number and word are stealth words outside the help district', async () => {
  const { CITY_FORBIDDEN } = await contract();
  for (const s of ['1-888-373-7888', 'text 233733', 'Human Trafficking Hotline', 'trafficking']) assert.ok(CITY_FORBIDDEN.test(s), s);
});
