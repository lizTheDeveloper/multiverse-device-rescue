const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Q = require('../renderer/quiet-notes.js');
const { page, monitoring } = require('./page-harness.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const DV = /799-7233|88788|advocate|domestic\s+violence/i;
const REPO = path.join(__dirname, '..', '..');

test('standard mode: one line on monitoring software, nothing on anything else', () => {
  for (const mode of ['standard', null]) {
    for (const module of ['stalkerware_scan', 'keylogger_indicators', 'mvt_spyware_scan']) assert.strictEqual(Q.noteFor(mode, { module }), 'line', module);
    assert.strictEqual(Q.noteFor(mode, { module: 'remote_login_check' }), 'none');
  }
});

test('a hotline paragraph comes out of a description; the rest stays', () => {
  const text = 'Screen Sharing is on.\n\nIf you think someone close to you set this up, call 1-800-799-7233.\n\nWhat to do: turn it off.';
  assert.strictEqual(Q.quiet(text), 'Screen Sharing is on.\n\nWhat to do: turn it off.');
  assert.strictEqual(Q.quiet(''), '');
  assert.strictEqual(Q.quiet(null), '');
});

test('in a list, only the item that carries it comes out', () => {
  const body = '- If this is a work computer, call security.\n- If another person may be involved, talk to a domestic violence advocate before\n  you remove anything: 1-800-799-7233.\n- For everyone else, go ahead.';
  assert.strictEqual(Q.quiet(body), '- If this is a work computer, call security.\n- For everyone else, go ahead.');
});

test('a card for anything else has no such text, in its description or its steps', () => {
  const finding = { module: 'remote_login_check', description: 'Remote Login is on.\n\nTalk to an advocate first (1-800-799-7233).',
    remediation: { safety_note: 'Talk to an advocate.', steps: [{ number: 1, title: 'Turn it off', body: 'Open System Settings.\n\nCall 1-800-799-7233 first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'none');
  assert.doesNotMatch(card.description + card.steps.map((s) => s.body).join(' '), DV);
  assert.match(card.description, /Remote Login is on/);
  assert.match(card.steps[0].body, /Open System Settings/);
  assert.strictEqual(Q.lineHtml(card, esc), '');
});

test('monitoring software: one line with the full note behind it, and its own steps kept', () => {
  const finding = { module: 'stalkerware_scan', description: 'An app that records what you type.\n\nIf a partner set this up, call 1-800-799-7233.',
    remediation: { safety_note: 'Before you remove or turn anything off: talk to an advocate first.', steps: [{ number: 1, title: 'Decide', body: 'Talk to a domestic violence advocate first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'line');
  assert.doesNotMatch(card.description, DV);
  assert.deepStrictEqual(card.steps, finding.remediation.steps);
  const html = Q.lineHtml(card, esc);
  assert.match(html, /^<details class="finding-card__note"><summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  assert.match(html, /talk to an advocate first/);
  assert.match(html, /799-7233/);
  // With nothing of its own to say, the note still says it.
  assert.match(Q.lineHtml(Q.cardText('standard', { module: 'keylogger_indicators', description: 'x' }), esc), /799-7233/);
});

test('quietDoc quiets every finding but monitoring software, and leaves the scan alone', () => {
  const doc = { modules: [
    { name: 'remote_login_check', findings: [{ description: 'On.\n\nCall 1-800-799-7233.', remediation: { safety_note: 'n', steps: [{ title: 't', body: 'Call 88788.' }] } }] },
    { name: 'stalkerware_scan', findings: [{ description: 'Found.\n\nCall 1-800-799-7233.' }] },
  ] };
  const out = Q.quietDoc(doc);
  assert.strictEqual(out.modules[0].findings[0].description, 'On.');
  assert.strictEqual(out.modules[0].findings[0].remediation.steps[0].body, '');
  assert.ok(!('safety_note' in out.modules[0].findings[0].remediation));
  assert.strictEqual(out.modules[1], doc.modules[1], 'monitoring software is the game’s to hold (Task 7)');
  assert.match(doc.modules[0].findings[0].description, /799-7233/, 'the scan itself is untouched');
  assert.strictEqual(Q.quietDoc(null), null);
});

// The guides' steps, cut the way rescue/guides.py cuts them.
function guideSteps(body) {
  const heads = [...body.matchAll(/^## Step (\d+): (.+)$/gm)];
  return heads.map((h, i) => ({ title: h[2].trim(), body: body.slice(h.index + h[0].length, i + 1 < heads.length ? heads[i + 1].index : body.length).trim() }));
}
// The test's own sentence cut, plain on purpose and independent of the module's.
// Independent of QuietNotes.MARKERS on purpose, and narrower: case-sensitive,
// no bare "DV" (the /i flag made that match `codesign -dv`). A sentence this
// skips is one the module may take out; everything else must survive.
const GUIDE_DV = /799-7233|88788|text START to|DV Hotline|\b[Aa]dvocates?\b|[Dd]omestic [Vv]iolence/;
// The network guides' one condition sentence ("It matters most if … a
// partner, an ex …") is the module's to take out in standard mode as well. It
// carries no instruction: "Stop and read this before changing anything." is
// its own sentence, and stays. Only a sentence that starts this way may go.
const CONDITION = /^It matters most if\b/;
const norm = (t) => String(t).replace(/^\s*(?:[-*]|\d{1,3}\.)\s+/gm, ' ').replace(/\s+/g, ' ').trim();
const cut = (t) => norm(t).split(/(?<=[.!?][)"'”’*`]*)\s+(?=[A-Z(*`"“])/).filter(Boolean);
const guides = () => {
  const dir = path.join(REPO, 'guides', 'remediation');
  return fs.readdirSync(dir).filter((f) => f.endsWith('.md'))
    .map((file) => ({ file, body: fs.readFileSync(path.join(dir, file), 'utf8').replace(/^---[\s\S]*?---\n/, '') }));
};

test('every remediation guide, step by step: no hotline text left, never an empty step, every other sentence kept word for word', () => {
  let checked = 0;
  for (const { file, body } of guides()) {
    const steps = guideSteps(body);
    assert.ok(steps.length > 0, `${file}: has steps`);
    for (const [where, text] of [['the whole guide', body], ...steps.map((st) => [`step "${st.title}"`, st.body])]) {
      const quiet = Q.quiet(text);
      assert.doesNotMatch(quiet, GUIDE_DV, `${file}, ${where}`);
      assert.ok(quiet.trim().length > 0, `${file}, ${where}: nothing left`);
      for (const sentence of cut(text)) {
        if (GUIDE_DV.test(sentence) || CONDITION.test(sentence)) continue;
        checked += 1;
        assert.ok(norm(quiet).includes(sentence), `${file}, ${where}: lost "${sentence}"`);
      }
    }
  }
  assert.ok(checked > 200, `checked ${checked} sentences`);
});

test('the advice the reviewer found missing is kept, sentence by sentence', () => {
  const read = (f) => Q.quiet(fs.readFileSync(path.join(REPO, 'guides', 'remediation', f), 'utf8'));
  assert.match(read('secure_linux_accounts.md'), /don't\s+log in as it and don't delete it\./);
  assert.match(read('secure_linux_accounts.md'), /back up your files and reinstall/);
  assert.match(read('review_linux_startup_entries.md'), /computer-repair shop to help you reinstall\s+the system\./);
  assert.match(read('review_linux_startup_entries.md'), /They are evidence of what happened\./);
  assert.match(read('sign_out_everywhere.md'), /Change passwords from a device they have never had access to\./);
  assert.match(read('check_app_signatures.md'), /That is your record\./);
  assert.match(read('harden_linux_ssh_server.md'), /if you didn't turn SSH on yourself, ask why/);
});

test('the network guides keep "Stop and read this" in standard mode, and what follows it still reads', () => {
  const read = (f) => Q.quiet(fs.readFileSync(path.join(REPO, 'guides', 'remediation', f), 'utf8'));
  for (const f of ['review_unknown_lan_devices.md', 'respond_to_arp_spoofing.md', 'secure_home_router.md']) {
    const q = read(f);
    assert.match(q, /Stop\s+and\s+read\s+this\s+before\s+changing\s+anything\./, f);
    assert.doesNotMatch(q, /partner,\s+an\s+ex|It\s+matters\s+most\s+if/, f);
    assert.doesNotMatch(q, /\bthat person\b/, `${f}: no "that person" left without the sentence that named them`);
    assert.match(q, /has\s+ever\s+frightened\s+you,\s+the\s+safest\s+order\s+of\s+operations/, f);
  }
  // "They can help you plan" had no one to refer to once the advocate sentence went.
  assert.doesNotMatch(read('respond_to_monitoring_software.md'), /^They can help/m);
  assert.doesNotMatch(read('respond_to_monitoring_software.md'), /\bThey\s+can\s+help\s+you\s+plan\b/);
});

test('only hotline sentences come out; the sentences around them, and a plain "partner", stay', () => {
  assert.strictEqual(Q.quiet("Don't delete the entry. Talk to an advocate first (1-800-799-7233). Take a photo."), "Don't delete the entry. Take a photo.");
  assert.strictEqual(Q.quiet('Ask your partner to check the router. Partner apps are fine.'), 'Ask your partner to check the router. Partner apps are fine.');
  assert.strictEqual(Q.quiet('Use a trusted app, e.g. Signal. Call 88788.'), 'Use a trusted app, e.g. Signal.');
  assert.strictEqual(Q.quiet('- Keep it.\n- Or text START to\n  88788. Back up first.'), '- Keep it.\n- Back up first.');
});

test('no step title in any guide carries hotline text', () => {
  for (const { file, body } of guides()) {
    for (const st of guideSteps(body)) {
      assert.doesNotMatch(st.title, Q.MARKERS, `${file}: "${st.title}"`);
      assert.doesNotMatch(st.title, GUIDE_DV, `${file}: "${st.title}"`);
    }
  }
});

test('the full note gives the hotline once', () => {
  const SN = 'Before you remove or turn anything off: talk to an advocate first. In the US: 1-800-799-7233, or text START to 88788.';
  const both = Q.lineHtml(Q.cardText('standard', { module: 'stalkerware_scan', description: 'Found.\n\nIf a partner set this up, call 1-800-799-7233.', remediation: { safety_note: SN, steps: [] } }), esc);
  assert.strictEqual(both.split('799-7233').length, 2, 'once, not twice');
  assert.match(both, /talk to an advocate first/);
  const descOnly = Q.lineHtml(Q.cardText('standard', { module: 'stalkerware_scan', description: 'Found.\n\nIf a partner set this up, call 1-800-799-7233.' }), esc);
  assert.strictEqual(descOnly.split('799-7233').length, 2, 'the description says it; the default is not added');
  assert.match(descOnly, /If a partner set this up/);
});

test('the scan screen and the results never carry the banner or the reminder any more', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  assert.doesNotMatch(html, /scan-safety|results-next-safety|799-7233/);
});

test('the list in standard mode: no hotline text except the one line on monitoring software', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [
    { name: 'remote_login_check', category: 'security', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 'Remote Login is on',
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.', category: 'security', data: {} }] },
    ...monitoring.modules,
  ] });
  p.answer('known'); // the follow-up (Task 5)
  const html = p.byId('results-groups').innerHTML;
  assert.strictEqual(html.split('Removing this can alert whoever installed it. Read this first.').length, 2, 'the one line, once');
  assert.doesNotMatch(html.replace(/<details class="finding-card__note">[\s\S]*?<\/details>/g, ''), DV);
});

test('the game’s mission screens read the same quiet text', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const ctl = createController({ win, storage: null, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  const doc = { schema_version: 1, platform: 'darwin', modules: [{ name: 'remote_login_check', category: 'security', status: 'ok', supported: true,
    findings: [{ title: 'Remote Login is on', severity: 'warning', category: 'security', data: {},
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.' }] }] };
  ctl.show(doc, { id: 'unsure' });
  const id = findingsToCity(doc).districts[0].missions[0].id;
  const el = { getAttribute: (k) => (k === 'data-go' ? `mission:${id}` : null) };
  clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  assert.match(frame.innerHTML, /Remote Login is on/);
  assert.doesNotMatch(frame.innerHTML, /799-7233/);
});

test('the monitoring checks are the same three app.js names', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'app.js'), 'utf8');
  const m = /const ALWAYS_SAFETY_MODULES = new Set\(\[([^\]]*)\]\)/.exec(src);
  assert.ok(m, 'ALWAYS_SAFETY_MODULES is still in app.js');
  const names = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]).sort();
  assert.deepStrictEqual(names, [...Q.MONITORING_MODULES].sort());
});

test('the extra warning on the fix and "It\'s mine" controls follows the mode: on in city mode only', async () => {
  for (const [stored, want] of [['city', true], ['standard', false]]) {
    const p = page({ store: { 'device-rescue.display': stored }, ready: false });
    const seen = [];
    p.sandbox.FixFlow.fixControlsHtml = (_f, opts) => { seen.push(['fix', opts && opts.watched]); return ''; };
    p.sandbox.MarkFlow.markControlsHtml = (_f, opts) => { seen.push(['mark', opts && opts.watched]); return ''; };
    p.byId('btn-get-started').click();
    p.pick('hacked');
    p.byId('btn-run-scan').click();
    await p.finish({ schema_version: 1, platform: 'darwin', modules: [{ name: 'remote_login_check', category: 'security', status: 'ok', supported: true,
      findings: [{ severity: 'warning', title: 'Remote Login is on', description: 'On.', category: 'security', data: {} }] }] });
    assert.deepStrictEqual(p.shown(), ['results'], stored);
    assert.deepStrictEqual(seen, [['fix', want], ['mark', want]], stored);
  }
});

test('every codesign sentence, and every sentence with a command in backticks, survives in every guide', () => {
  let codesign = 0;
  let commands = 0;
  for (const { file, body } of guides()) {
    for (const [where, text] of [['the whole guide', body], ...guideSteps(body).map((st) => [`step "${st.title}"`, st.body])]) {
      const quiet = norm(Q.quiet(text));
      for (const sentence of cut(text)) {
        if (/codesign/.test(sentence)) { codesign += 1; assert.ok(quiet.includes(sentence), `${file}, ${where}: lost "${sentence}"`); }
        if (/`[^`]+`/.test(sentence)) { commands += 1; assert.ok(quiet.includes(sentence), `${file}, ${where}: lost "${sentence}"`); }
      }
    }
  }
  assert.ok(codesign >= 7, `checked ${codesign} codesign sentences`);
  assert.ok(commands > 20, `checked ${commands} command sentences`);
});

test('a command flag like -dv is not hotline wording', () => {
  const text = "Verify the binary's code signature: `codesign -dv <path-to-binary>`. Then run `spctl -a -vv`.";
  assert.strictEqual(Q.quiet(text), text);
  assert.strictEqual(Q.quiet('Run codesign -dv /Applications/X.app to see who signed it.'), 'Run codesign -dv /Applications/X.app to see who signed it.');
  assert.strictEqual(Q.quiet('Keep it. US National DV Hotline: call 1-800-799-7233.'), 'Keep it.');
});
