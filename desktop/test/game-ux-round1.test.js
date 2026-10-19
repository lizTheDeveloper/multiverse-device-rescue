// UX round 1, city side (group B): the fixes the audit asked for.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const game = (f) => import(`../renderer/game/${f}`);
const CSS = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');

test('P1-1: [hidden] wins over component display rules inside the city', () => {
  // .fix-panel { display: grid } used to beat the attribute, so both confirm boxes showed.
  assert.match(CSS, /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/);
  const FixFlow = require('../renderer/fix-flow.js');
  const html = FixFlow.fixControlsHtml({ module: 'firewall_check', title: 't',
    fixable: { will_change: 'Turns on the firewall.', how_to_undo: ['Open System Settings.'] } }, {});
  assert.ok(html.includes('data-fix-confirm'));
  // The confirm button sits inside the panel, which is drawn hidden.
  assert.ok(html.indexOf('data-fix-panel hidden') >= 0 && html.indexOf('data-fix-panel') < html.indexOf('data-fix-confirm'));
});
