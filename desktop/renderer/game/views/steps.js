// A mission's walkthrough steps, written for people. Pure.
// The engine's remediation text is written for developers: backticks, module
// ids, `<path-to-plist>` placeholders, inline lists and **bold**. Here the
// placeholders get the values the scan already found, module ids become words,
// the Markdown is drawn (the same small subset as the list's renderMiniMarkdown),
// and anything with a shell command goes behind FOR TECH HELPERS.
import { esc } from '../escape.js';
// Sets globalThis.StepFill (a plain script the list loads too).
import '../../step-fill.js';

// What a check is, in words, where a step names it by id.
const CHECK_WORDS = {
  launch_agent_audit: 'the background-task check',
  launchd_persistence_audit: 'the startup-task check',
  gatekeeper_quarantine_check: 'the app-protection check',
  sip_gatekeeper: 'the system-protection check',
  kext_audit: 'the system-extension check',
  mdm_enrollment: 'the device-management check',
  remote_login_check: 'the remote-login check',
  sharing_preferences_audit: 'the sharing check',
};
const MODULE_ID = /`?\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b`?/g;

// `<path-to-plist>` -> '/the/plist/the/scan/found': the list's own rule, one
// module for both (renderer/step-fill.js). Only values plainly safe in a
// terminal, always quoted, and only for a POSIX shell (`platform` darwin or
// linux); anything else leaves the placeholder as it was.
const SF = globalThis.StepFill;
export const shellSafe = SF.shellSafe;
export const fillPlaceholders = (text, data, platform = null) => SF.fillPlaceholders(text, data, platform);
// The list's rule for a step: lines for another computer left out, then the placeholders filled.
export const fillStep = (text, data, platform = null) => SF.fillStep(text, data, platform);

// `launchd_persistence_audit` -> "the startup-task check". Only real check
// names (the scan's modules, or the ones above) change; other words stay.
// `names`: the scan's own names for its checks (check_name), as the list says
// them: "the Background tasks check".
export function wordsForModules(text, modules = [], names = {}) {
  const known = new Set([...Object.keys(CHECK_WORDS), ...(modules || []), ...Object.keys(names || {})]);
  const named = (id) => (names && typeof names[id] === 'string' && names[id].trim() ? `the ${names[id].trim()} check` : null);
  return String(text == null ? '' : text).replace(MODULE_ID, (all, id) => (known.has(id) ? named(id) || CHECK_WORDS[id] || 'this checkup' : all));
}

const inline = (v) => esc(v)
  .replace(/`([^`]+)`/g, '<code>$1</code>')
  .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

// Paragraphs, numbered and bulleted lists, `code`, **bold** and ```fences```.
// Everything is escaped first.
export function miniMarkdown(text) {
  const out = [];
  let list = null; // { kind, items: [raw text] }
  let para = [];
  let fence = null;
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  // Items are joined raw, so a `code span` wrapped onto the next line stays one span.
  const closeList = () => {
    if (list) { out.push(`<${list.kind}>${list.items.map((x) => `<li>${inline(x)}</li>`).join('')}</${list.kind}>`); list = null; }
  };
  for (const raw of String(text || '').split('\n')) {
    if (fence !== null) {
      if (/^\s*```/.test(raw)) { out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`); fence = null; } else fence.push(raw);
      continue;
    }
    if (/^\s*```/.test(raw)) { flushPara(); closeList(); fence = []; continue; }
    const ol = raw.match(/^\s*\d+\.\s+(.*)$/);
    const ul = raw.match(/^\s*[-*]\s+(.*)$/);
    if (ol || ul) {
      flushPara();
      const kind = ol ? 'ol' : 'ul';
      if (!list || list.kind !== kind) { closeList(); list = { kind, items: [] }; }
      list.items.push((ol || ul)[1]);
    } else if (raw.trim() === '') {
      flushPara(); closeList();
    } else if (list && /^\s+\S/.test(raw)) {
      list.items[list.items.length - 1] += ` ${raw.trim()}`;
    } else {
      closeList(); para.push(raw.trim());
    }
  }
  if (fence !== null) out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`);
  flushPara(); closeList();
  return out.join('');
}

// Inline `code` or a fence: something to type into a terminal.
const HAS_CODE = /`[^`]+`|```/;

// One step body as [what everyone sees, what's for tech helpers]. Blocks are
// split at blank lines; a block with a command goes to tech helpers, and so
// does a lead-in ("For each flagged label:") whose list went there.
export function splitBody(body) {
  const blocks = String(body || '').split(/\n\s*\n/).filter((b) => b.trim());
  const tech = blocks.map((b) => HAS_CODE.test(b));
  for (let i = blocks.length - 2; i >= 0; i -= 1) if (!tech[i] && tech[i + 1] && /:\s*$/.test(blocks[i])) tech[i] = true;
  return [blocks.filter((_, i) => !tech[i]).join('\n\n'), blocks.filter((_, i) => tech[i]).join('\n\n')];
}

// The steps list. `data`: the finding's evidence (fills the placeholders,
// on `platform` darwin or linux only);
// `modules`: the scan's check ids (made into words).
export function stepsHtml(steps, { data = null, modules = [], platform = null, names = {} } = {}) {
  return (steps || []).map((s) => {
    const prep = (t) => wordsForModules(fillStep(t, data, platform), modules, names);
    const title = prep(s.title).replace(/\*\*([^*]+)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1');
    const [plain, tech] = splitBody(prep(s.body));
    const body = (plain ? `<div class="step-body">${miniMarkdown(plain)}</div>` : '')
      + (tech ? `<details class="tech"><summary>FOR TECH HELPERS</summary><div class="step-body">${miniMarkdown(tech)}</div></details>` : '');
    return `
      <li class="step"><span class="step-n">${esc(s.number)}</span>
        <span class="step-t">${esc(title)}${body}</span></li>`;
  }).join('');
}

// A description as paragraphs, with "What to do:" picked out.
export function descriptionHtml(text) {
  return String(text || '').split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean).map((p) => {
    const at = p.search(/\bwhat to do:/i);
    if (at < 0) return `<p class="intel">${inline(p)}</p>`;
    const head = p.slice(0, at).trim();
    const todo = p.slice(at + 'what to do:'.length).trim();
    return `${head ? `<p class="intel">${inline(head)}</p>` : ''}<p class="intel todo"><strong>What to do:</strong> ${inline(todo)}</p>`;
  }).join('');
}
