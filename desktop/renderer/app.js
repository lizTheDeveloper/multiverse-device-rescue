'use strict';

/*
 * Device Rescue renderer app.
 *
 * Pure helpers (detectOS, groupFindingsBySeverity) live at the top and are
 * exported for Node so they can be sanity-checked outside the browser. The
 * DOM-wiring code below only runs when a `document` is present (i.e. inside
 * Electron's renderer process).
 */

const SEVERITY_ORDER = ['critical', 'warning', 'info'];
const SEVERITY_LABELS = {
  critical: 'Needs attention now',
  warning: 'Worth a look',
  info: 'Good to know',
};
const SEVERITY_DESCRIPTIONS = {
  critical: 'These are the most important findings from your checkup.',
  warning: 'These are worth reviewing when you have a moment.',
  info: 'Background details and reassurance-level notes.',
};

/**
 * The "what's worrying you?" choices. Each runs one profile from profiles/
 * (null = every check) and links to that situation's step-by-step guide.
 * Worded the way a frightened person would say it, not the way we name things.
 */
const SITUATIONS = [
  { id: 'hacked', icon: '\u{1F513}', title: 'I think I\u2019ve been hacked',
    sub: 'Strange logins, passwords changed, accounts acting on their own',
    profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/' },
  { id: 'watched', icon: '\u{1F440}', title: 'I think someone is watching me',
    sub: 'A partner, ex, or housemate may have put something on this computer',
    profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/', safety: true },
  { id: 'wifi', icon: '\u{1F4F6}', title: 'Someone is on my Wi-Fi, or my computer is hot and slow',
    sub: 'Unknown devices, a hijacked router, or hidden crypto-mining',
    profile: 'home_network_intrusion', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/home-network-intrusion/' },
  { id: 'identity', icon: '\u{1FAAA}', title: 'Someone stole my identity',
    sub: 'Accounts opened in my name, money missing, credit alerts',
    profile: 'identity_theft_recovery', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/identity-theft-recovery/' },
  { id: 'sketchy', icon: '\u{1F41B}', title: 'I installed something sketchy',
    sub: 'A bad npm or pip package, an AI tool, a coding extension',
    profile: 'ai_worm_response', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/ai-worm-response/' },
  { id: 'phone', icon: '\u{1F4F1}', title: 'I\u2019m worried about spyware on my iPhone',
    sub: 'Needs a backup of the iPhone saved on this computer',
    profile: 'iphone_spyware_check', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/iphone-spyware-check/' },
  { id: 'helping', icon: '\u{1F381}', title: 'I\u2019m helping a family member',
    sub: 'A friendly tune-up and safety check on someone else\u2019s computer',
    profile: 'home_for_the_holidays', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/home-for-the-holidays/' },
  { id: 'unsure', icon: '\u{1F937}', title: 'I\u2019m not sure \u2014 check everything',
    sub: 'The full checkup. It takes longer: often 10 minutes or more',
    profile: null, guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/' },
];

const CATEGORY_PHRASES = {
  security: 'Looking for security problems',
  integrity: 'Checking that your system is healthy',
  performance: 'Checking speed and storage',
  network: 'Checking your network',
  bloatware: 'Looking for unwanted software',
};

/** Render a traced command for the technical log, shell-style. */
function formatExec(ev) {
  const argv = (ev.argv || []).map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${String(a).replace(/'/g, "'\\''")}'`));
  const outcome = ev.returncode == null ? `did not start${ev.error ? `: ${ev.error}` : ''}` : `exit ${ev.returncode}`;
  return `    $ ${argv.join(' ')}   (${outcome}, ${ev.seconds}s)`;
}

/**
 * Turn an engine progress event into words for the status line, e.g.
 * {phase:'start', index:23, total:120, module:'launch_agent_audit', category:'security'}
 *  -> { headline: 'Looking for security problems', detail: 'Launch agent audit · check 23 of 120', percent: 18 }
 */
function describeProgress(ev) {
  const words = String(ev.module || '').replace(/_/g, ' ');
  const name = words.charAt(0).toUpperCase() + words.slice(1);
  const done = ev.phase === 'done' ? ev.index : ev.index - 1;
  return {
    headline: CATEGORY_PHRASES[ev.category] || 'Checking your computer',
    detail: `${name} \u00b7 check ${ev.index} of ${ev.total}`,
    percent: ev.total ? Math.round((done / ev.total) * 100) : 0,
  };
}

/**
 * "Who made it?" One plain line per program a finding names, from the engine's
 * `made_by` entries ({subject, name, verified, how, location_note}).
 * tone 'ok' = calm green, 'warn' = amber.
 */
const MADE_BY_VERIFIED_LABEL = {
  'Developer ID signature': 'verified signature',
  'Authenticode signature': 'verified signature',
  'Mac App Store signature': 'App Store signature',
  'Apple system file': 'part of macOS',
  'Homebrew package': 'Homebrew package',
  'system package': 'installed by your system package manager',
};
const MADE_BY_REASON = {
  unsigned: 'not signed',
  'ad-hoc signed': 'only self-signed by whoever built it',
  'development certificate': "signed with a developer's test certificate, not a published one",
  'unrecognised signature': 'its signature could not be recognised',
  'not part of any installed package': 'not part of any installed package',
};

function describeMadeBy(entry) {
  const e = entry || {};
  const name = e.name || 'Unknown maker';
  const note = e.location_note ? String(e.location_note).trim() : '';
  const subject = String(e.subject || '').split(/[\\/]/).filter(Boolean).pop() || '';
  if (e.verified) {
    const label = MADE_BY_VERIFIED_LABEL[e.how] || e.how || 'verified';
    // A verified maker running from a risky folder deserves a second look.
    const mark = note ? '⚠' : '✓';
    return { tone: note ? 'warn' : 'ok', text: `${mark} Made by ${name} (${label})${note ? '. ' + note : ''}`, subject };
  }
  if (e.how === 'script') {
    return { tone: 'warn', text: `⚠ Unknown maker: ${note || 'a script, not signed; check who created it.'}`, subject };
  }
  const reason = MADE_BY_REASON[e.how] || e.how || 'not verified';
  const head = name === 'Unknown maker' ? 'Unknown maker' : `Made by ${name}, but it cannot be verified`;
  return { tone: 'warn', text: `⚠ ${head}: ${reason}.${note ? ' ' + note : ''}`, subject };
}

function madeByHtml(entries, esc) {
  if (!Array.isArray(entries) || entries.length === 0) return '';
  const lines = entries.map((entry) => {
    const d = describeMadeBy(entry);
    const who = entries.length > 1 && d.subject ? `<span class="made-by__subject">${esc(d.subject)}</span> ` : '';
    return `<li class="made-by__line made-by__line--${d.tone}">${who}${esc(d.text)}</li>`;
  }).join('');
  return `<div class="made-by"><ul class="made-by__list">${lines}</ul>
    <details class="made-by__explainer"><summary>What does this mean?</summary>
      <p>Programs can be digitally signed by the company that made them, like a seal on a package. A <strong>verified signature</strong> means the seal is real and names the maker. An <strong>unknown maker</strong> is not proof of anything bad, but nobody has vouched for it, so be more careful, especially if it runs from a temporary folder or one you did not install into.</p>
    </details></div>`;
}

/**
 * A deliberately tiny Markdown renderer for the fix walkthroughs: paragraphs,
 * numbered and bulleted lists, `code`, **bold**, and ```fenced``` blocks.
 * Everything is HTML-escaped first, so walkthrough text can never inject markup.
 */
function renderMiniMarkdown(text) {
  const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const inline = (v) => esc(v)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  const out = [];
  let list = null; // 'ol' | 'ul'
  let para = [];
  let fence = null;
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of String(text || '').split('\n')) {
    if (fence !== null) {
      if (/^\s*```/.test(raw)) { out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`); fence = null; }
      else fence.push(raw);
      continue;
    }
    if (/^\s*```/.test(raw)) { flushPara(); closeList(); fence = []; continue; }
    const ol = raw.match(/^\s*\d+\.\s+(.*)$/);
    const ul = raw.match(/^\s*[-*]\s+(.*)$/);
    if (ol || ul) {
      flushPara();
      const kind = ol ? 'ol' : 'ul';
      if (list !== kind) { closeList(); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${inline((ol || ul)[1])}</li>`);
    } else if (raw.trim() === '') {
      flushPara(); closeList();
    } else if (list && /^\s+\S/.test(raw)) {
      // continuation of the previous list item
      out[out.length - 1] = out[out.length - 1].replace(/<\/li>$/, ` ${inline(raw.trim())}</li>`);
    } else {
      closeList(); para.push(raw.trim());
    }
  }
  if (fence !== null) out.push(`<pre><code>${esc(fence.join('\n'))}</code></pre>`);
  flushPara(); closeList();
  return out.join('');
}

const OS_LABELS = {
  macos: 'macOS',
  windows: 'Windows',
  linux: 'Linux',
};

/**
 * Map a scan-result `platform` value (Node's process.platform strings, e.g.
 * "darwin"/"win32"/"linux") or a browser's navigator.userAgent to one of the
 * keys used in permissions-content.json: "macos" | "windows" | "linux".
 */
function detectOS(platformHint) {
  if (platformHint === 'darwin') return 'macos';
  if (platformHint === 'win32') return 'windows';
  if (platformHint === 'linux') return 'linux';

  const ua =
    (typeof navigator !== 'undefined' && navigator.userAgent) || '';
  if (/Mac/i.test(ua)) return 'macos';
  if (/Win/i.test(ua)) return 'windows';
  if (/Linux/i.test(ua)) return 'linux';

  // Sensible default when we truly can't tell.
  return 'macos';
}

/**
 * Group every finding across every module by severity, and collect the
 * modules that failed to run at all. Unknown/missing severities fall back
 * to "info" so nothing silently disappears.
 *
 * @param {{modules?: Array<{name:string,status:string,error:?string,findings?:Array}>}} doc
 * @returns {{groups: {critical: Array, warning: Array, info: Array}, erroredModules: Array<{name:string,error:?string}>}}
 */
function groupFindingsBySeverity(doc) {
  const groups = { critical: [], warning: [], info: [] };
  const erroredModules = [];
  const modules = (doc && doc.modules) || [];

  for (const mod of modules) {
    if (mod && mod.status === 'error') {
      erroredModules.push({ name: mod.name, error: mod.error || null });
    } else if (mod && mod.supported === false) {
      // Could not run here: not a clean result, so it must not read as one.
      erroredModules.push({ name: mod.name, error: mod.unsupported_reason || null });
    }
    const findings = (mod && mod.findings) || [];
    for (const finding of findings) {
      const sev = Object.prototype.hasOwnProperty.call(groups, finding.severity)
        ? finding.severity
        : 'info';
      groups[sev].push(Object.assign({}, finding, { module: mod.name }));
    }
  }

  return { groups, erroredModules };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectOS,
    groupFindingsBySeverity,
    SITUATIONS,
    describeProgress,
    formatExec,
    renderMiniMarkdown,
    describeMadeBy,
    madeByHtml,
    SEVERITY_ORDER,
    SEVERITY_LABELS,
  };
}

// ---------------------------------------------------------------------------
// Browser-only wiring below. Guarded so this file stays importable in Node
// for the pure helpers above (used by a small sanity-check script).
// ---------------------------------------------------------------------------

if (typeof document !== 'undefined') {
  (function () {
    const screens = {
      welcome: document.getElementById('screen-welcome'),
      worry: document.getElementById('screen-worry'),
      permissions: document.getElementById('screen-permissions'),
      scan: document.getElementById('screen-scan'),
      results: document.getElementById('screen-results'),
    };
    const stepDots = document.querySelectorAll('[data-step-dot]');

    let permissionsContent = null;
    let lastKnownPlatform = null; // e.g. "darwin" | "win32" | "linux", once we have a scan result
    let situation = null; // the SITUATIONS entry the person picked

    function showScreen(name) {
      Object.keys(screens).forEach((key) => {
        if (!screens[key]) return;
        screens[key].hidden = key !== name;
      });
      stepDots.forEach((dot) => {
        dot.classList.toggle('step-dot--active', dot.dataset.stepDot === name);
      });
      window.scrollTo(0, 0);
    }

    function escapeHtml(value) {
      const div = document.createElement('div');
      div.textContent = String(value == null ? '' : value);
      return div.innerHTML;
    }

    async function loadPermissionsContent() {
      if (permissionsContent) return permissionsContent;
      const response = await fetch('permissions-content.json');
      if (!response.ok) {
        throw new Error('Could not load the permissions walkthrough.');
      }
      permissionsContent = await response.json();
      return permissionsContent;
    }

    function renderPermissionsSteps(content, osKey) {
      const container = document.getElementById('permissions-steps');
      const steps = (content && content[osKey]) || [];

      if (steps.length === 0) {
        container.innerHTML =
          '<p class="muted">No special permission steps are needed for your system.</p>';
        return;
      }

      const osLabel = OS_LABELS[osKey] || osKey;
      const heading = `<p class="muted steps-list__os">Showing steps for ${escapeHtml(osLabel)}.</p>`;

      const stepsHtml = steps
        .map((step, index) => {
          const button =
            step.setting_url && step.action_label
              ? `<button type="button" class="btn btn--secondary btn--small" data-setting-url="${escapeHtml(step.setting_url)}">${escapeHtml(step.action_label)}</button>`
              : '';
          return `
            <li class="step-card">
              <div class="step-card__index" aria-hidden="true">${index + 1}</div>
              <div class="step-card__body">
                <h3>${escapeHtml(step.title)}</h3>
                <p>${escapeHtml(step.body)}</p>
                ${button}
              </div>
            </li>
          `;
        })
        .join('');

      container.innerHTML = `${heading}<ol class="steps-list__items">${stepsHtml}</ol>`;

      container.querySelectorAll('[data-setting-url]').forEach((btn) => {
        btn.addEventListener('click', () => {
          window.rescue.openSetting(btn.getAttribute('data-setting-url'));
        });
      });
    }

    function renderSituations() {
      const list = document.getElementById('situations');
      list.innerHTML = SITUATIONS.map(
        (s) => `
          <li>
            <button type="button" class="situation" data-situation="${escapeHtml(s.id)}">
              <span class="situation__icon" aria-hidden="true">${escapeHtml(s.icon)}</span>
              <span class="situation__text">
                <span class="situation__title">${escapeHtml(s.title)}</span>
                <span class="situation__sub">${escapeHtml(s.sub)}</span>
              </span>
            </button>
          </li>`
      ).join('');
      list.querySelectorAll('[data-situation]').forEach((btn) => {
        btn.addEventListener('click', () => {
          situation = SITUATIONS.find((s) => s.id === btn.dataset.situation) || null;
          goToPermissions();
        });
      });
    }

    function renderScanIntro() {
      document.getElementById('scan-situation').textContent = situation
        ? `Checking for: ${situation.title}`
        : '';
      document.getElementById('scan-safety').hidden = !(situation && situation.safety);
    }

    function renderNextStep() {
      const box = document.getElementById('results-next');
      if (!situation || !situation.guide) {
        box.hidden = true;
        return;
      }
      box.hidden = false;
      document.getElementById('results-next-safety').hidden = !situation.safety;
    }

    function renderSeverityGroup(severity, findings) {
      if (findings.length === 0) return '';
      const items = findings
        .map(
          (finding) => `
            <li class="finding-card finding-card--${severity}">
              <div class="finding-card__header">
                <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
                <h3>${escapeHtml(finding.title || 'Untitled finding')}</h3>
              </div>
              <p>${escapeHtml(finding.description || '')}</p>
              ${madeByHtml(finding.made_by, escapeHtml)}
              ${FixFlow.fixControlsHtml(finding, { watched: !!(situation && situation.id === 'watched') })}
              ${finding.remediation ? `
              <details class="fix-steps">
                <summary>${finding.fixable ? 'Or fix it yourself, step by step' : 'How to fix this'}${finding.remediation.estimated_time ? ` <span class="muted">(about ${escapeHtml(finding.remediation.estimated_time)})</span>` : ''}</summary>
                <ol class="fix-steps__list">
                  ${(finding.remediation.steps || []).map((step) => `
                    <li>
                      <h4>${escapeHtml(step.title)}</h4>
                      <div class="fix-steps__body">${renderMiniMarkdown(step.body)}</div>
                    </li>`).join('')}
                </ol>
              </details>` : ''}
              ${askButtonHtml(finding)}
              <details class="tech-details">
                <summary>Technical details</summary>
                <pre class="tech-log">${escapeHtml(JSON.stringify({
                  check: finding.module,
                  code: finding.code || null,
                  category: finding.category,
                  confidence: finding.confidence == null ? null : finding.confidence,
                  evidence: finding.data || {},
                }, null, 2))}</pre>
              </details>
            </li>
          `
        )
        .join('');

      return `
        <section class="results-group results-group--${severity}">
          <h2>
            <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
            <span class="results-group__count">${findings.length}</span>
          </h2>
          <p class="muted">${escapeHtml(SEVERITY_DESCRIPTIONS[severity])}</p>
          <ul class="findings-list">${items}</ul>
        </section>
      `;
    }

    function renderResults(doc) {
      const { groups, erroredModules } = groupFindingsBySeverity(doc);
      const total = SEVERITY_ORDER.reduce((sum, sev) => sum + groups[sev].length, 0);

      const summaryEl = document.getElementById('results-summary');
      if (total === 0 && erroredModules.length > 0) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out in the checks that ran. Some checks couldn\'t run on this computer &mdash; they\'re listed at the bottom.</p>';
      } else if (total === 0) {
        summaryEl.innerHTML =
          '<p class="results-summary__all-clear">Nothing stood out during this checkup. Nice and tidy.</p>';
      } else {
        summaryEl.innerHTML = `<p>We found <strong>${total}</strong> thing${total === 1 ? '' : 's'} worth a look, grouped by how important they are.</p>`;
      }

      const groupsEl = document.getElementById('results-groups');
      groupsEl.innerHTML = SEVERITY_ORDER.map((sev) => renderSeverityGroup(sev, groups[sev])).join('');

      const errorsSection = document.getElementById('results-errors');
      const errorsList = document.getElementById('results-errors-list');
      if (erroredModules.length > 0) {
        errorsList.innerHTML = erroredModules
          .map(
            (mod) =>
              `<li><strong>${escapeHtml(mod.name)}</strong>${mod.error ? ` &mdash; ${escapeHtml(mod.error)}` : ''}</li>`
          )
          .join('');
        errorsSection.hidden = false;
      } else {
        errorsSection.hidden = true;
        errorsList.innerHTML = '';
      }
    }

    function setScanBusy(isBusy) {
      const runButton = document.getElementById('btn-run-scan');
      const progress = document.getElementById('scan-progress');
      const errorNote = document.getElementById('scan-error');
      runButton.disabled = isBusy;
      runButton.hidden = isBusy;
      progress.hidden = !isBusy;
      document.getElementById('scan-title').textContent = isBusy
        ? 'Your checkup is running'
        : 'Ready for your checkup';
      if (isBusy) errorNote.hidden = true;
    }

    function showScanError(message) {
      const errorNote = document.getElementById('scan-error');
      const errorText = document.getElementById('scan-error-text');
      errorText.textContent =
        message || "We couldn't finish the checkup. Please try again.";
      errorNote.hidden = false;
    }

    let lastScanDoc = null;
    let foundSoFar = 0;

    function resetProgress() {
      foundSoFar = 0;
      document.getElementById('scan-status').textContent = 'Getting ready\u2026';
      document.getElementById('scan-substatus').textContent = 'Starting the checkup engine.';
      document.getElementById('scan-bar-fill').style.width = '0%';
      document.getElementById('scan-bar').setAttribute('aria-valuenow', '0');
      document.getElementById('scan-log').textContent = '';
    }

    function appendLog(text) {
      const log = document.getElementById('scan-log');
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
      log.textContent += text + '\n';
      if (atBottom) log.scrollTop = log.scrollHeight;
    }

    function onScanEvent(ev) {
      if (ev.type === 'log') {
        appendLog(ev.line);
        return;
      }
      if (ev.type === 'exec') {
        appendLog(formatExec(ev));
        return;
      }
      if (ev.type !== 'progress') return;
      const p = describeProgress(ev);
      document.getElementById('scan-bar-fill').style.width = `${p.percent}%`;
      document.getElementById('scan-bar').setAttribute('aria-valuenow', String(p.percent));
      if (ev.phase === 'start') {
        document.getElementById('scan-status').textContent = `${p.headline}\u2026`;
        const found = foundSoFar
          ? ` \u00b7 ${foundSoFar} thing${foundSoFar === 1 ? '' : 's'} noted so far`
          : '';
        document.getElementById('scan-substatus').textContent = p.detail + found;
        appendLog(`[${ev.index}/${ev.total}] ${ev.module} ...`);
      } else {
        foundSoFar += ev.findings || 0;
        appendLog(`[${ev.index}/${ev.total}] ${ev.module}: ${
          ev.error ? `could not run (${ev.error})` : `${ev.findings} finding(s)`}`);
      }
    }

    async function runCheckup() {
      setScanBusy(true);
      resetProgress();
      const unsubscribe = window.rescue.onScanEvent(onScanEvent);
      try {
        const doc = await window.rescue.runScan(situation ? situation.profile : null);
        if (doc && typeof doc.platform === 'string') {
          lastKnownPlatform = doc.platform;
        }
        lastScanDoc = doc;
        renderResults(doc);
        renderNextStep();
        setScanBusy(false);
        showScreen('results');
      } catch (err) {
        setScanBusy(false);
        showScanError(err && err.message ? err.message : String(err));
      } finally {
        unsubscribe();
      }
    }

    function resetToWelcome() {
      const runButton = document.getElementById('btn-run-scan');
      runButton.disabled = false;
      runButton.hidden = false;
      document.getElementById('scan-progress').hidden = true;
      document.getElementById('scan-error').hidden = true;
      situation = null;
      showScreen('welcome');
    }

    // "Fix it for me": delegated, so it keeps working when results are re-rendered.
    FixFlow.attach(document.getElementById('results-groups'), window.rescue);

    document.getElementById('btn-get-started').addEventListener('click', () => {
      showScreen('worry');
    });

    async function goToPermissions() {
      showScreen('permissions');
      try {
        const content = await loadPermissionsContent();
        renderPermissionsSteps(content, detectOS(lastKnownPlatform));
      } catch (err) {
        const container = document.getElementById('permissions-steps');
        container.innerHTML = `<p class="muted">We couldn't load the permissions walkthrough (${escapeHtml(
          err && err.message ? err.message : String(err)
        )}). You can still continue.</p>`;
      }
    }

    document.getElementById('btn-permissions-continue').addEventListener('click', () => {
      renderScanIntro();
      showScreen('scan');
    });

    document.getElementById('btn-copy-json').addEventListener('click', async () => {
      const status = document.getElementById('copy-json-status');
      try {
        await navigator.clipboard.writeText(JSON.stringify(lastScanDoc, null, 2));
        status.textContent = ' Copied.';
      } catch (err) {
        status.textContent = ` Couldn\u2019t copy (${err && err.message ? err.message : err}).`;
      }
    });

    document.getElementById('btn-open-guide').addEventListener('click', () => {
      if (situation && situation.guide) window.rescue.openGuide(situation.guide);
    });

    document.getElementById('btn-run-scan').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-retry').addEventListener('click', runCheckup);
    document.getElementById('btn-start-over').addEventListener('click', resetToWelcome);

    renderSituations();
    showScreen('welcome');
  })();
}
