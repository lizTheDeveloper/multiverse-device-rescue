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
      permissions: document.getElementById('screen-permissions'),
      scan: document.getElementById('screen-scan'),
      results: document.getElementById('screen-results'),
    };
    const stepDots = document.querySelectorAll('[data-step-dot]');

    let permissionsContent = null;
    let lastKnownPlatform = null; // e.g. "darwin" | "win32" | "linux", once we have a scan result

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
      if (total === 0) {
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
      progress.hidden = !isBusy;
      if (isBusy) errorNote.hidden = true;
    }

    function showScanError(message) {
      const errorNote = document.getElementById('scan-error');
      const errorText = document.getElementById('scan-error-text');
      errorText.textContent =
        message || "We couldn't finish the checkup. Please try again.";
      errorNote.hidden = false;
    }

    async function runCheckup() {
      setScanBusy(true);
      try {
        const doc = await window.rescue.runScan();
        if (doc && typeof doc.platform === 'string') {
          lastKnownPlatform = doc.platform;
        }
        renderResults(doc);
        setScanBusy(false);
        showScreen('results');
      } catch (err) {
        setScanBusy(false);
        showScanError(err && err.message ? err.message : String(err));
      }
    }

    function resetToWelcome() {
      const runButton = document.getElementById('btn-run-scan');
      runButton.disabled = false;
      document.getElementById('scan-progress').hidden = true;
      document.getElementById('scan-error').hidden = true;
      showScreen('welcome');
    }

    document.getElementById('btn-get-started').addEventListener('click', async () => {
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
    });

    document.getElementById('btn-permissions-continue').addEventListener('click', () => {
      showScreen('scan');
    });

    document.getElementById('btn-run-scan').addEventListener('click', runCheckup);
    document.getElementById('btn-scan-retry').addEventListener('click', runCheckup);
    document.getElementById('btn-start-over').addEventListener('click', resetToWelcome);

    showScreen('welcome');
  })();
}
