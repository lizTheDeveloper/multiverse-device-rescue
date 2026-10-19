'use strict';

/*
 * "It's mine": the button, the in-page confirmation, and the result. Also
 * "Stop treating this as mine" on a marked item. One mechanism for every kind
 * the engine offers: background tasks, sharing settings, proxies, extensions,
 * app permission lists, remote-login keys, AI tool settings.
 *
 * Nothing is saved until the person presses "Yes, it's mine". Only the
 * engine's mark id is sent back, so what is saved is what the scan showed. A
 * marked item is never hidden: the engine keeps listing it as "marked as
 * yours". Everything that comes from the engine is HTML-escaped before it is
 * shown. Findings from the monitoring-software checks never offer it.
 *
 * Loaded as a plain script in the renderer (global `MarkFlow`) and required
 * from Node by the tests.
 */
const MarkFlow = (function () {
  const MARK_ID = /^[0-9a-f]{12}$/;
  const ONLY_IF_YOURS = 'Only do this if you set this up yourself. If you’re not sure, leave it as it is.';
  const COULD_WATCH = 'Something like this can be used to watch or get into a computer. That is why we ask.';
  // Why we ask about a list of apps: an ordinary list, not an accusation.
  const LIST_REASON = 'We ask so the list stays accurate: if a new app appears, you’ll hear about it.';
  const NOT_SURE_LIST = 'Not sure about one? Leave the whole list as it is.';
  // Kinds that are about watching a computer or getting into it: remote access,
  // sharing, proxies, extensions, and app permission lists (accessibility,
  // screen recording, camera, microphone, input monitoring, full disk access).
  const WATCH_KINDS = new Set([
    'sharing_service', 'network_proxy', 'system_extension', 'browser_extension', 'ssh_authorized_keys',
    'app_permissions',
  ]);
  // Kinds that are a list of apps: one row per app, "Yes, these are mine".
  const LIST_KINDS = new Set(['app_permissions']);
  // Same limits as the engine (rescue/app_names.py _MAX_NAME): a name is at
  // most 128 characters, or it is the raw entry (bundle id or path) itself.
  const MAX_APP_NAME = 128;
  const MAX_APP_ID = 1024;
  const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}]/u;
  const NAME_MAKER_MISMATCH = 'The name doesn’t match its maker';
  // Well-known app names and the makers that really publish them. Only used to
  // flag a plain contradiction between a verified maker and the name an app
  // gives itself; it never clears anything.
  const KNOWN_APP_MAKERS = [
    [/^zoom(\.us)?$|^zoom workplace$/, /zoom/],
    [/^(google )?chrome$/, /google/],
    [/^microsoft |^(microsoft )?(teams|edge|outlook|word|excel|powerpoint|onedrive)$/, /microsoft/],
    [/^skype$/, /skype|microsoft/],
    [/^slack$/, /slack/],
    [/^(mozilla )?firefox$/, /mozilla/],
    [/^dropbox$/, /dropbox/],
    [/^1password( \d+)?$/, /agilebits|1password/],
    [/^teamviewer$/, /teamviewer/],
    [/^anydesk$/, /anydesk|philandro/],
    [/^discord$/, /discord/],
    [/^whatsapp$/, /whatsapp|meta/],
    [/^spotify$/, /spotify/],
    [/^signal$/, /signal/],
    [/^telegram$/, /telegram/],
    [/^brave( browser)?$/, /brave/],
    [/^(safari|finder|messages|facetime|mail|photos|system settings|system preferences|terminal|screen sharing|xcode)$/, /apple/],
  ];
  const ITEM_KINDS = new Set([
    'sharing_service', 'network_proxy', 'system_extension', 'browser_extension',
    'app_permissions', 'ssh_authorized_keys', 'ai_tooling',
  ]);
  // Checks for monitoring software: "It's mine" is never offered on them.
  const NEVER_MARKABLE_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  // One plain answer per kind of thing.
  const BUTTON = {
    background_task: 'I set this up — it’s mine',
    sharing_service: 'I turned this on — it’s mine',
    network_proxy: 'I set this up — it’s mine',
    system_extension: 'I installed this — it’s mine',
    browser_extension: 'I installed this — it’s mine',
    app_permissions: 'I know these apps — they’re mine',
    ssh_authorized_keys: 'I added these keys — they’re mine',
    ai_tooling: 'I set this up — it’s mine',
  };
  // Lists that can be marked entry by entry (rescue/known_items.py ENTRY_KIND_FOR).
  const ENTRY_LIST_KINDS = new Set(['app_permissions', 'ssh_authorized_keys']);
  const ENTRY_NOUNS = { app_permissions: ['app', 'apps'], ssh_authorized_keys: ['key', 'keys'] };
  const ENTRY_BUTTON = { app_permissions: 'Some of these apps are mine', ssh_authorized_keys: 'Some of these keys are mine' };
  const ENTRY_LEGEND = { app_permissions: 'Tick the apps you know and use', ssh_authorized_keys: 'Tick the keys you added yourself' };
  const ENTRY_REASON = 'We ask so the list stays accurate: anything you leave unticked, or that appears later, keeps its warning.';
  const CANT_ALONE = 'We couldn’t check who made this one just now, so it can only be marked with the whole list.';
  const STALE_ROW = 'Marked as yours before, but it has changed since.';
  // The engine couldn't look this one up this time: never say it changed.
  const UNCHECKED_ROW = 'Marked as yours before. We couldn’t check this one this time, so its warning is back. That doesn’t mean it changed. For now it can only be marked with the whole list.';
  const WHOLE_BUTTON = 'The whole list is mine';
  const WHOLE_HEAD = 'You’re saying the whole list is yours, as one answer:';
  const WHOLE_CHANGES = 'If anything on this list changes, its warning comes back.';
  function wholeIncludes(n) {
    return `This includes ${n} we couldn’t check who made.`;
  }
  // The shared checklist (checklist.js): a global in the page, required in Node.
  const CL = typeof Checklist !== 'undefined' ? Checklist
    : (typeof require === 'function' ? require('./checklist.js') : null);

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function clean(s, max) {
    return typeof s === 'string' && s.length > 0 && s.length < (max || 1024) && !s.includes('\0');
  }

  function textList(list) {
    return Array.isArray(list) && list.length > 0 && list.every((s) => typeof s === 'string' && s.trim() !== '');
  }

  // The engine's `markable` block, or null if missing, malformed, or on a
  // finding that must never be marked.
  function markableOf(finding) {
    const m = finding && finding.markable;
    if (!m || typeof m !== 'object') return null;
    if (finding && NEVER_MARKABLE_MODULES.has(finding.module)) return null;
    if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
    if (typeof m.will_change !== 'string' || m.will_change.trim() === '') return null;
    if (!textList(m.how_to_undo)) return null;
    if (ITEM_KINDS.has(m.kind)) {
      if (typeof m.group !== 'string' || !MARK_ID.test(m.group)) return null;
      if (typeof m.code === 'string' && NEVER_MARKABLE_MODULES.has(m.code.split('.')[1])) return null;
      return m;
    }
    if (m.kind !== 'background_task') return null;
    if (!clean(m.label, 256) || m.label.startsWith('-')) return null;
    if (!clean(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
    if (!clean(m.plist) || !m.plist.startsWith('/')) return null;
    return m;
  }

  // The mark id on a finding the person already marked, or null.
  function markedIdOf(finding) {
    const d = finding && finding.data;
    if (!d || d.marked_by_user !== true) return null;
    return typeof d.known_item_id === 'string' && MARK_ID.test(d.known_item_id) ? d.known_item_id : null;
  }

  // Asks for the stronger confirmation: anything that could be used to watch
  // someone, any background task, and everything when the person said
  // "someone is watching me". A missing flag counts as yes.
  function needsStrongConfirm(m, opts) {
    if (opts && opts.watched) return true;
    if (m.kind === 'background_task') return true;
    return m.monitoring !== false;
  }

  function buttonLabel(m) {
    return BUTTON[m.kind] || BUTTON.background_task;
  }

  // Every mark id the engine grouped with this one (same item, other checks), own id first.
  function groupOf(ownId, list) {
    const ids = Array.isArray(list) ? list.filter((x) => typeof x === 'string' && MARK_ID.test(x)) : [];
    return [ownId, ...ids].filter((x, i, a) => a.indexOf(x) === i);
  }

  function coversHtml(count, kind) {
    if (count < 2) return '';
    const what = kind === 'background_task' ? 'this task' : 'this';
    return `<p class="fix-panel__line">That is ${count} warnings about ${what} on this checkup; one answer covers them all.</p>`;
  }

  // The engine's wording names the command-line tool; the app is Reclaim City.
  function appWords(s) {
    // Never inside a path: the folder on disk keeps its real name.
    return String(s == null ? '' : s).replace(/(?<![/\w])Device Rescue\b(?!\/)/g, 'Reclaim City');
  }
  // A line for people at a command line ("rescue known remove <id>").
  const CLI_LINE = /\bcommand line\b|^\s*rescue\s|`rescue\s/i;

  // The undo steps. Command-line ones go under "For tech helpers".
  function undoListHtml(steps) {
    const all = (steps || []).map(appWords);
    const plain = all.filter((s) => !CLI_LINE.test(s));
    const tech = all.filter((s) => CLI_LINE.test(s));
    return `<ol class="fix-undo">${plain.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`
      + (tech.length ? `<details class="tech-details"><summary>For tech helpers</summary>${tech.map((s) => `<p>${esc(s)}</p>`).join('')}</details>` : '');
  }

  // Control and format characters (bidi overrides, zero-width spaces) shown as
  // [U+XXXX], so text can't reorder or hide itself on screen.
  function visible(s) {
    return String(s).replace(/[\p{Cc}\p{Cf}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  }

  function validAppRow(r) {
    if (!r || typeof r !== 'object') return false;
    if (typeof r.id !== 'string' || !r.id || r.id.length > MAX_APP_ID || r.id.includes('\0')) return false;
    if (r.name === r.id) return true; // the raw-id fallback
    return typeof r.name === 'string' && r.name.trim() !== '' && r.name.length <= MAX_APP_NAME
      && !CONTROL_OR_FORMAT.test(r.name);
  }

  // The engine's per-app rows ({id, name}) on a list of apps, or null when the
  // panel must show the full raw list instead. Rows are never dropped: if any
  // row is malformed, an id repeats, or the number of rows isn't the number of
  // apps the engine counted, the person sees the whole `shows` list.
  function appRowsOf(m, shownRows) {
    if (!m || !LIST_KINDS.has(m.kind) || !Array.isArray(m.apps) || !m.apps.length) return null;
    if (!m.apps.every(validAppRow)) return null;
    if (new Set(m.apps.map((r) => r.id)).size !== m.apps.length) return null;
    const count = (shownRows.find(([k]) => k === 'How many') || [])[1];
    if (!/^\d+$/.test(count || '') || Number(count) !== m.apps.length) return null;
    return m.apps;
  }

  // The finding's `made_by` entry for this id, if it names a maker.
  function makerEntry(madeBy, id) {
    const e = Array.isArray(madeBy) ? madeBy.find((x) => x && x.subject === id) : null;
    if (!e || typeof e.name !== 'string' || !e.name.trim() || e.name === 'Unknown maker') return null;
    return e;
  }

  // "Made by …" for one app, from the scan's own signature check.
  function makerText(e) {
    if (!e) return '';
    return e.verified === true ? `Made by ${e.name} (verified)` : `Says it is made by ${e.name} (couldn’t verify)`;
  }

  // True when a well-known name plainly contradicts the verified maker
  // (an app calling itself "Zoom", signed by someone else).
  function nameContradictsMaker(name, e) {
    if (!e || e.verified !== true || typeof name !== 'string') return false;
    const n = name.trim().toLowerCase();
    const maker = e.name.toLowerCase();
    return KNOWN_APP_MAKERS.some(([nameRe, makerRe]) => nameRe.test(n) && !makerRe.test(maker));
  }

  function appsHtml(rows, madeBy, count) {
    const items = rows.map((r) => {
      const e = makerEntry(madeBy, r.id);
      const maker = makerText(e);
      const named = r.name !== r.id;
      return `<li class="mark-apps__row"><span class="mark-apps__who"><span class="mark-apps__name">${esc(visible(r.name))}</span>`
        + (named ? `<span class="mark-apps__id"> · <code>${esc(visible(r.id))}</code></span>` : '')
        + '</span>'
        + (maker ? `<span class="mark-apps__maker">${esc(visible(maker))}</span>` : '')
        + (nameContradictsMaker(r.name, e) ? `<span class="mark-apps__flag">${esc(NAME_MAKER_MISMATCH)}</span>` : '')
        + '</li>';
    }).join('');
    const ids = rows.map((r) => `<li><code>${esc(visible(r.id))}</code>${r.name !== r.id ? ` (${esc(visible(r.name))})` : ''}</li>`).join('');
    return `<p class="fix-panel__line"><strong>What you are saying is yours${count ? ` (${esc(count)} apps)` : ''}:</strong></p>
          <ul class="mark-apps">${items}</ul>
          <p class="fix-panel__line muted">${esc(NOT_SURE_LIST)}</p>
          <details class="mark-tech"><summary>Technical details</summary>
            <p class="fix-panel__line">The names the permission list uses for these apps (bundle IDs):</p>
            <ul class="mark-tech__ids">${ids}</ul>
          </details>`;
  }

  function shownRowsOf(m) {
    return Array.isArray(m.shows)
      ? m.shows.filter((r) => Array.isArray(r) && r.length === 2 && typeof r[0] === 'string' && typeof r[1] === 'string')
      : [];
  }

  function showsHtml(m, finding) {
    const rows = shownRowsOf(m);
    const apps = appRowsOf(m, rows);
    if (apps) return appsHtml(apps, finding && finding.made_by, String(apps.length));
    if (m.kind === 'background_task') {
      rows.unshift(['Task', m.label], ['Program', m.program]);
    }
    if (!rows.length) return '';
    return `<p class="fix-panel__line"><strong>What you are saying is yours:</strong></p>
          <dl class="mark-shows">${rows.map(([k, v]) => `<dt>${esc(visible(k))}</dt><dd>${esc(visible(v))}</dd>`).join('')}</dl>`;
  }

  // Why we ask: the watching line for anything that can watch or get into a
  // computer (an app permission list can: accessibility, screen recording...),
  // plus, on a list of apps, why the whole list is one answer.
  function reasonHtml(m, strong) {
    if (!strong || m.kind === 'background_task') return '';
    const lines = [];
    if (WATCH_KINDS.has(m.kind)) lines.push(COULD_WATCH);
    if (LIST_KINDS.has(m.kind)) lines.push(LIST_REASON);
    return lines.map((t) => `<p class="fix-panel__line">${esc(t)}</p>`).join('');
  }

  // One row of the engine's markable.items, or false if anything is off.
  function validEntry(it) {
    if (!it || typeof it !== 'object') return false;
    if (typeof it.key !== 'string' || !it.key || it.key.length > MAX_APP_ID || it.key.includes('\0')) return false;
    if (typeof it.label !== 'string' || !it.label.trim()) return false;
    if (it.label !== it.key && (it.label.length > MAX_APP_NAME || CONTROL_OR_FORMAT.test(it.label))) return false;
    if (it.detail != null && (typeof it.detail !== 'string' || it.detail.length > MAX_APP_ID || it.detail.includes('\0'))) return false;
    if (it.marked === true) return typeof it.id === 'string' && MARK_ID.test(it.id);
    return it.id === null || (typeof it.id === 'string' && MARK_ID.test(it.id));
  }

  // The engine's entries for a list, or null when the panel must show the
  // whole list as before: no checklist component, a malformed row, a repeat,
  // or rows that don't line up with the apps (or keys) the engine counted.
  function entryRowsOf(m, rows) {
    if (!CL || !m || !ENTRY_LIST_KINDS.has(m.kind) || !Array.isArray(m.items) || !m.items.length) return null;
    if (!m.items.every(validEntry)) return null;
    const keys = m.items.map((i) => i.key);
    if (new Set(keys).size !== keys.length) return null;
    const ids = m.items.map((i) => i.id).filter((x) => x);
    if (new Set(ids).size !== ids.length || ids.includes(m.id)) return null;
    if (m.kind === 'app_permissions') {
      const appRows = appRowsOf(m, rows);
      if (!appRows || appRows.length !== keys.length || !appRows.every((a) => keys.includes(a.id))) return null;
    } else {
      const count = (rows.find(([k]) => k === 'Saved keys') || [])[1];
      if (!/^\d+$/.test(count || '') || Number(count) !== keys.length) return null;
    }
    return m.items;
  }

  function rowText(e) {
    return e.detail && e.detail !== e.label ? `${e.label} · ${e.detail}` : e.label;
  }

  // The maker line and the name/maker flag for one app row (none for keys).
  function entryEvidence(m, finding, e) {
    if (m.kind !== 'app_permissions') return '';
    const maker = makerEntry(finding && finding.made_by, e.key);
    const text = makerText(maker);
    return (text ? `<span class="mark-apps__maker">${esc(visible(text))}</span>` : '')
      + (nameContradictsMaker(e.label, maker) ? `<span class="mark-apps__flag">${esc(NAME_MAKER_MISMATCH)}</span>` : '');
  }

  // A row with its own "Stop treating this as mine".
  function unmarkRowHtml(id, text, attrs) {
    return `<li class="mark-apps__row" data-mark-entry="${esc(id)}"${attrs || ''}>`
      + `<span class="mark-apps__who">${esc(visible(text))}</span>`
      + `<button type="button" class="btn btn--secondary btn--small" data-unmark-item="${esc(id)}">Stop treating this as mine</button>`
      + '<span class="fix-status" data-unmark-item-status role="status" aria-live="polite" hidden></span></li>';
  }

  // The whole list as one answer, as before: only offered when a row can't be
  // marked on its own, so that row still has a way to be marked.
  function wholeConfirmHtml(m, finding, alone) {
    const reasons = [COULD_WATCH, ...(LIST_KINDS.has(m.kind) ? [LIST_REASON] : [])];
    return `
          <div data-mark-whole-confirm hidden>
            <p class="fix-panel__line"><strong data-mark-whole-head tabindex="-1">${esc(WHOLE_HEAD)}</strong></p>
            ${showsHtml(m, finding)}
            ${alone > 0 ? `<p class="fix-panel__line">${esc(wholeIncludes(alone))}</p>` : ''}
            <p class="fix-panel__line"><strong>This will:</strong> ${esc(appWords(m.will_change))}</p>
            <p class="fix-panel__line">${esc(WHOLE_CHANGES)}</p>
            <p class="fix-panel__line"><strong>To undo later:</strong></p>
            ${undoListHtml(m.how_to_undo)}
            <p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>
            ${reasons.map((t) => `<p class="fix-panel__line">${esc(t)}</p>`).join('')}
            <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
            <div class="fix-panel__actions">
              <button type="button" class="btn btn--primary btn--small" data-mark-confirm>Yes, the whole list is mine</button>
              <button type="button" class="btn btn--secondary btn--small" data-mark-items-back>Back</button>
            </div>
          </div>`;
  }

  function entryControlsHtml(m, finding, entries, opts) {
    const noun = ENTRY_NOUNS[m.kind];
    const marked = entries.filter((e) => e.marked === true);
    const open = entries.filter((e) => e.marked !== true);
    const selectable = open.filter((e) => e.id);
    const alone = open.length - selectable.length; // rows only the whole list can mark
    const checklist = CL.html({
      id: `mark-${m.id}`,
      // Element ids distinct per panel, even if two checks show the same list.
      scope: typeof m.code === 'string' && m.code ? m.code : m.kind,
      legend: `${ENTRY_LEGEND[m.kind]} (${open.length} not marked as yours yet)`,
      items: open.map((e, i) => ({
        key: e.id || `none-${i}`,
        label: e.label,
        detail: e.detail && e.detail !== e.label ? e.detail : '',
        evidenceHtml: entryEvidence(m, finding, e),
        disabled: !e.id,
        note: e.unchecked === true ? UNCHECKED_ROW : !e.id ? CANT_ALONE : (e.stale ? STALE_ROW : ''),
      })),
      actions: [{ id: 'mark', verb: 'Mark', noun, suffix: 'as mine', min: 1 }],
      selectAll: true,
      theme: opts && opts.theme === 'game' ? 'game' : 'plain',
    });
    const already = marked.length
      ? `<p class="fix-panel__line"><strong>Already marked as yours (${marked.length}):</strong></p>
          <ul class="mark-apps">${marked.map((e) => unmarkRowHtml(e.id, rowText(e))).join('')}</ul>`
      : '';
    const confirmRows = selectable.map((e) => `<li class="mark-apps__row" data-mark-items-row="${esc(e.id)}" hidden>`
      + `<span class="mark-apps__who">${esc(visible(rowText(e)))}</span>${entryEvidence(m, finding, e)}</li>`).join('');
    const doneRows = selectable.map((e) => unmarkRowHtml(e.id, rowText(e), ` data-mark-items-done-row="${esc(e.id)}" hidden`)).join('');
    const openLabel = selectable.length ? ENTRY_BUTTON[m.kind] : buttonLabel(m);
    return `
      <div class="mark-mine" data-mark-card data-mark-entries data-mark-kind="${esc(m.kind)}" data-mark-id="${esc(m.id)}" data-mark-group="${esc(m.id)}" data-mark-selectable="${selectable.length}" data-mark-alone="${alone}">
        ${already}
        ${open.length ? `<button type="button" class="btn btn--secondary btn--small" data-mark-open>${esc(openLabel)}</button>` : ''}
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Choose which are yours">
          <div data-mark-items-pick>
            ${checklist}
            <p class="muted fix-panel__note">Ticking changes nothing. You’ll see what you picked before anything is saved.</p>
            <div class="fix-panel__actions">
              ${alone ? `<button type="button" class="btn btn--secondary btn--small" data-mark-whole-open>${esc(WHOLE_BUTTON)}</button>` : ''}
              <button type="button" class="btn btn--secondary btn--small" data-mark-cancel>Cancel</button>
            </div>
          </div>
          <div data-mark-items-confirm hidden>
            <p class="fix-panel__line"><strong data-mark-items-head tabindex="-1">You’re saying these are yours:</strong></p>
            <ul class="mark-apps">${confirmRows}</ul>
            <p class="fix-panel__line"><strong>This will:</strong> ${esc(appWords(m.items_will_change || m.will_change))}</p>
            <p class="fix-panel__line"><strong>To undo later:</strong></p>
            ${undoListHtml(m.how_to_undo)}
            <p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>
            <p class="fix-panel__line">${esc(COULD_WATCH)}</p>
            <p class="fix-panel__line">${esc(ENTRY_REASON)}</p>
            <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
            <div class="fix-panel__actions">
              <button type="button" class="btn btn--primary btn--small" data-mark-items-yes>Yes, these are mine</button>
              <button type="button" class="btn btn--secondary btn--small" data-mark-items-back>Back</button>
            </div>
          </div>
          ${alone ? wholeConfirmHtml(m, finding, alone) : ''}
        </div>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" tabindex="-1" hidden></div>
        <ul class="mark-apps" data-mark-items-done hidden>${doneRows}</ul>
      </div>`;
  }

  // A list marked entry by entry (every entry): data.marked_items, or null.
  function markedEntriesOf(finding) {
    const d = finding && finding.data;
    if (!d || d.marked_by_user !== true || !Array.isArray(d.marked_items) || !d.marked_items.length) return null;
    if (NEVER_MARKABLE_MODULES.has(finding.module)) return null;
    const ok = d.marked_items.every((x) => x && typeof x.id === 'string' && MARK_ID.test(x.id)
      && typeof x.shown === 'string' && x.shown.trim() !== '' && x.shown.length <= 1200 && !x.shown.includes('\0'));
    return ok ? d.marked_items : null;
  }

  function markedEntriesHtml(list) {
    const ids = list.map((x) => x.id);
    return `
      <div class="mark-mine" data-mark-card data-mark-entries-done>
        <p class="fix-panel__line"><strong>Marked as yours (${list.length}):</strong></p>
        <ul class="mark-apps">${list.map((x) => unmarkRowHtml(x.id, x.shown)).join('')}</ul>
        ${list.length > 1 ? `<button type="button" class="btn btn--secondary btn--small" data-unmark-items="${esc(ids.join(' '))}">Stop treating all of these as mine</button>` : ''}
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
  }

  // opts.watched: the person said "I think someone is watching me".
  function markControlsHtml(finding, opts) {
    const m = markableOf(finding);
    if (m) {
      const entries = entryRowsOf(m, shownRowsOf(m));
      if (entries) return entryControlsHtml(m, finding, entries, opts);
      const group = groupOf(m.id, m.ids);
      const strong = needsStrongConfirm(m, opts);
      return `
      <div class="mark-mine" data-mark-card data-mark-kind="${esc(m.kind)}" data-mark-id="${esc(m.id)}" data-mark-group="${esc(group.join(' '))}">
        <button type="button" class="btn btn--secondary btn--small" data-mark-open>${esc(buttonLabel(m))}</button>
        <div class="fix-panel" data-mark-panel hidden role="group" aria-label="Confirm this is yours">
          ${showsHtml(m, finding)}
          <p class="fix-panel__line"><strong>This will:</strong> ${esc(appWords(m.will_change))}</p>
          ${coversHtml(group.length, m.kind)}
          <p class="fix-panel__line"><strong>To undo later:</strong></p>
          ${undoListHtml(m.how_to_undo)}
          ${strong ? `<p class="fix-panel__line fix-panel__warning"><strong>${esc(ONLY_IF_YOURS)}</strong></p>` : ''}
          ${reasonHtml(m, strong)}
          <p class="muted fix-panel__note">Nothing on your computer is changed or turned off.</p>
          <div class="fix-panel__actions">
            <button type="button" class="btn btn--primary btn--small" data-mark-confirm>${LIST_KINDS.has(m.kind) ? 'Yes, these are mine' : 'Yes, it’s mine'}</button>
            <button type="button" class="btn btn--secondary btn--small" data-mark-cancel>Cancel</button>
          </div>
        </div>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
    }
    const done = markedEntriesOf(finding);
    if (done) return markedEntriesHtml(done);
    const id = markedIdOf(finding);
    if (id) {
      const group = groupOf(id, finding.marked_ids);
      return `
      <div class="mark-mine" data-mark-card data-unmark-id="${esc(id)}" data-unmark-group="${esc(group.join(' '))}">
        <button type="button" class="btn btn--secondary btn--small" data-unmark>Stop treating this as mine</button>
        <div class="fix-status" data-mark-status role="status" aria-live="polite" hidden></div>
      </div>`;
    }
    return '';
  }

  // Words for the engine's answer. Never says "saved" unless the engine did.
  function describeMarkResult(result) {
    const r = result && typeof result === 'object' ? result : {};
    const undo = Array.isArray(r.how_to_undo) ? r.how_to_undo.filter((s) => typeof s === 'string') : [];
    if (r.status === 'marked' || r.status === 'already_marked') {
      return {
        tone: 'success', done: true,
        headline: 'Marked as yours.',
        detail: 'This is remembered: from your next checkup it will be listed as “marked as yours” instead of being flagged.',
        undo,
      };
    }
    if (r.status === 'removed') {
      return { tone: 'info', done: true, headline: 'No longer marked as yours.', detail: 'Its warning comes back on your next checkup.', undo: [] };
    }
    if (r.error === 'scan_running') {
      return { tone: 'info', headline: 'The checkup is still running.',
        detail: 'You can do this once it’s done. Nothing was changed.', undo: [] };
    }
    if (r.error === 'not_allowed' || r.status === 'refused') {
      const said = typeof r.message === 'string' ? r.message.trim() : '';
      // The main process's refusals already say it; never twice.
      const detail = /Nothing was changed\./.test(said) ? said : `${said ? said + ' ' : ''}Nothing was changed.`;
      return { tone: 'error', headline: 'We couldn’t mark this one.', detail, undo: [] };
    }
    return {
      tone: 'error', headline: 'That didn’t go through.',
      detail: `${typeof r.message === 'string' ? r.message + ' ' : ''}Nothing was confirmed. Run the checkup again to see where things stand.`.trim(),
      undo: [],
    };
  }

  function resultHtml(result) {
    const d = describeMarkResult(result);
    return `
      <div class="fix-status--${d.tone} fix-status__box">
        <p class="fix-status__headline"><strong>${esc(d.headline)}</strong></p>
        ${d.detail ? `<p class="fix-status__detail">${esc(d.detail)}</p>` : ''}
        ${d.undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(d.undo)}` : ''}
      </div>`;
  }

  // Shown on the other cards about the same item once one card's answer covered them.
  function siblingHtml(kind) {
    const d = kind === 'marked'
      ? {
        tone: 'success', headline: 'Marked as yours.',
        detail: 'Marked together with the other warning about this. From your next checkup it will be listed as “marked as yours” instead of being flagged.',
      }
      : {
        tone: 'info', headline: 'No longer marked as yours.',
        detail: 'Removed together with the other warning about this. Its warning comes back on your next checkup.',
      };
    return `
      <div class="fix-status--${d.tone} fix-status__box">
        <p class="fix-status__headline"><strong>${esc(d.headline)}</strong></p>
        <p class="fix-status__detail">${esc(d.detail)}</p>
      </div>`;
  }

  // After some entries were marked: how many, and what happens to the rest.
  function itemsResultHtml(n, rest, undo) {
    const others = rest === 1 ? 'The other one keeps its warning.' : `The other ${rest} keep their warning.`;
    const detail = rest > 0
      ? `${others} From your next checkup, the ones you marked are listed as “marked as yours”.`
      : 'From your next checkup the whole list is listed as “marked as yours” instead of being flagged.';
    return `
      <div class="fix-status--success fix-status__box">
        <p class="fix-status__headline"><strong>${esc(`Marked ${n} as yours.`)}</strong></p>
        <p class="fix-status__detail">${esc(detail)}</p>
        ${undo && undo.length ? `<p class="fix-status__detail"><strong>To undo later:</strong></p>${undoListHtml(undo)}` : ''}
      </div>`;
  }

  function idsAttr(card, name) {
    return String(card.getAttribute(name) || '').split(/\s+/).filter((x) => MARK_ID.test(x));
  }

  const CLICK_TARGETS = '[data-mark-open],[data-mark-confirm],[data-mark-cancel],[data-unmark],'
    + '[data-unmark-items],[data-unmark-item],[data-mark-items-yes],[data-mark-items-back],[data-mark-whole-open]';

  function splitIds(value) {
    return String(value || '').split(/\s+/).filter((x) => MARK_ID.test(x));
  }

  // Delegated handlers on a container that survives re-renders. `api` is the
  // preload bridge: api.markMine(id, itemIds?), api.unmarkMine(idOrIds). `hooks` (optional):
  // onMarked(cards) and onUnmarked(cards) after the engine saved or removed
  // marks, with every card the answer covered. Returns {unmark(card)} so the
  // "Cleared" list can offer Undo.
  // onResult({kind, result, described}) after the engine answers (game mode).
  function attach(root, api, hooks) {
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    const state = new WeakMap(); // card -> 'confirming' | 'confirming-items' | 'confirming-whole' | 'running'
    const rowState = new WeakMap(); // entry row -> true while its undo runs
    const on = hooks || {};
    let clApi = null; // the checklist's handlers, set below

    function cardOf(el) {
      return el && el.closest ? el.closest('[data-mark-card]') : null;
    }

    function showPick(card) {
      const pick = card.querySelector('[data-mark-items-pick]');
      const confirm = card.querySelector('[data-mark-items-confirm]');
      const whole = card.querySelector('[data-mark-whole-confirm]');
      if (pick) pick.hidden = false;
      if (confirm) confirm.hidden = true;
      if (whole) whole.hidden = true;
    }

    // Closing the panel forgets the ticks: it opens again with nothing ticked.
    function untick(card) {
      card.querySelectorAll('[data-cl-list]').forEach((list) => {
        list.querySelectorAll('[data-cl-item]').forEach((b) => { b.checked = false; });
        if (clApi) clApi.update(list);
      });
    }

    function closePanel(card) {
      const panel = card.querySelector('[data-mark-panel]');
      if (panel) panel.hidden = true;
      showPick(card);
      untick(card);
      state.delete(card);
    }

    function focusOn(el) {
      if (el && !el.hidden && typeof el.focus === 'function') el.focus();
    }

    // Back to the checklist: its button, or the first box while nothing is ticked.
    function focusPick(card) {
      const action = card.querySelector('[data-mark-items-pick] [data-cl-action]');
      if (action && action.disabled !== true) { focusOn(action); return; }
      const box = Array.from(card.querySelectorAll('[data-mark-items-pick] [data-cl-item]')).find((b) => b.disabled !== true);
      focusOn(box || action);
    }

    // Closed by the person (Cancel, Escape): back to the button that opened it.
    function closeByPerson(card) {
      closePanel(card);
      focusOn(card.querySelector('[data-mark-open]'));
    }

    // Entries the engine just marked: out of the checklist, into the
    // "marked" list with their own undo. Undo puts a row back.
    function entriesMarked(card, ids) {
      let n = 0;
      for (const id of ids) {
        const box = card.querySelector(`[data-cl-key="${id}"]`);
        if (box && box.disabled !== true) {
          box.checked = false;
          box.disabled = true;
          const li = box.closest ? box.closest('li') : null;
          if (li && li !== box) li.hidden = true;
          n += 1;
        }
        const row = card.querySelector(`[data-mark-items-row="${id}"]`);
        if (row) row.setAttribute('data-mark-items-marked', '');
        const done = card.querySelector(`[data-mark-items-done-row="${id}"]`);
        if (done) {
          done.hidden = false;
          const b = done.querySelector('[data-unmark-item]');
          const st = done.querySelector('[data-unmark-item-status]');
          if (b) b.hidden = false;
          if (st) { st.hidden = true; st.textContent = ''; }
        }
      }
      const left = Math.max(0, (Number(card.getAttribute('data-mark-selectable')) || 0) - n);
      card.setAttribute('data-mark-selectable', String(left));
      card.querySelectorAll('[data-cl-list]').forEach((list) => { if (clApi) clApi.update(list); });
    }

    function entryUnmarked(card, id) {
      const box = card.querySelector(`[data-cl-key="${id}"]`);
      if (!box || box.disabled !== true || !card.querySelector(`[data-mark-items-done-row="${id}"]`)) return;
      box.disabled = false;
      const li = box.closest ? box.closest('li') : null;
      if (li && li !== box) li.hidden = false;
      const row = card.querySelector(`[data-mark-items-row="${id}"]`);
      if (row) row.removeAttribute('data-mark-items-marked');
      card.setAttribute('data-mark-selectable', String((Number(card.getAttribute('data-mark-selectable')) || 0) + 1));
      card.querySelectorAll('[data-cl-list]').forEach((list) => { if (clApi) clApi.update(list); });
    }

    function setButtons(card, hidden) {
      card.querySelectorAll('[data-mark-open],[data-unmark]').forEach((b) => { b.hidden = hidden; });
    }

    // A card that was just marked can be unmarked again ("Undo"): it learns
    // the ids the engine saved for it.
    function becomeMarked(card, ids) {
      const own = card.getAttribute('data-mark-id');
      if (!own || !ids.includes(own)) return;
      card.setAttribute('data-unmark-id', own);
      card.setAttribute('data-unmark-group', [own, ...ids.filter((x) => x !== own)].join(' '));
      card.setAttribute('data-marked-now', '');
    }

    // After an unmark, a card that was marked in this session offers the button again.
    function becomeUnmarked(card) {
      if (!card.hasAttribute || !card.hasAttribute('data-marked-now')) return;
      card.removeAttribute('data-marked-now');
      card.removeAttribute('data-unmark-id');
      card.removeAttribute('data-unmark-group');
      setButtons(card, false);
    }

    // The same item is often reported by more than one check, so it has more
    // than one card. Once the engine has saved (or removed) the marks for all
    // of them, the other cards say so instead of offering the button again.
    function updateSiblings(card, kind, result) {
      if (typeof root.querySelectorAll !== 'function') return [];
      const ownAttr = kind === 'marked' ? 'data-mark-id' : 'data-unmark-id';
      const groupAttr = kind === 'marked' ? 'data-mark-group' : 'data-unmark-group';
      const own = card.getAttribute(ownAttr);
      let ids = idsAttr(card, groupAttr).filter((x) => x !== own);
      // When the engine lists what it saved or removed, only those.
      if (result && Array.isArray(result.ids)) ids = ids.filter((x) => result.ids.includes(x));
      if (!ids.length) return [];
      const touched = [];
      for (const other of Array.from(root.querySelectorAll(`[${ownAttr}]`))) {
        if (other === card || !ids.includes(other.getAttribute(ownAttr))) continue;
        if (state.get(other) === 'running') continue;
        closePanel(other);
        setButtons(other, true);
        const status = other.querySelector('[data-mark-status]');
        if (status) { status.hidden = false; status.innerHTML = siblingHtml(kind); }
        other.setAttribute('data-mark-handled-by-other', '');
        if (kind === 'marked') becomeMarked(other, [own, ...ids]);
        else becomeUnmarked(other);
        touched.push(other);
      }
      return touched;
    }

    // kind: 'marked', 'removed', or 'marked-items' (some entries; `chosen` are their ids).
    async function send(card, call, kind, chosen) {
      state.set(card, 'running');
      const panel = card.querySelector('[data-mark-panel]');
      const status = card.querySelector('[data-mark-status]');
      if (panel) panel.hidden = true;
      setButtons(card, true);
      status.hidden = false;
      status.innerHTML = '<p class="fix-status__headline fix-status--running">Saving…</p>';
      let d;
      try {
        const result = await call();
        status.innerHTML = resultHtml(result);
        d = describeMarkResult(result);
        if (onResult) { try { onResult({ kind, result, described: d }); } catch (_) { /* never break a mark */ } }
        const r = result || {};
        if (kind === 'marked' && (r.status === 'marked' || r.status === 'already_marked')) {
          const own = card.getAttribute('data-mark-id');
          const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x)) : [own];
          const others = updateSiblings(card, kind, r);
          becomeMarked(card, saved.length ? saved : [own]);
          if (typeof on.onMarked === 'function') on.onMarked([card, ...others]);
        }
        if (kind === 'marked-items' && (r.status === 'marked' || r.status === 'already_marked')) {
          const saved = Array.isArray(r.ids) ? r.ids.filter((x) => MARK_ID.test(x) && (chosen || []).includes(x)) : [];
          const open = Number(card.getAttribute('data-mark-selectable')) || 0;
          // Rows only the whole list can mark keep their warning too.
          const alone = Number(card.getAttribute('data-mark-alone')) || 0;
          const rest = Math.max(0, open - saved.length) + alone;
          status.innerHTML = itemsResultHtml(saved.length, rest, d.undo);
          const done = card.querySelector('[data-mark-items-done]');
          if (done && saved.length) done.hidden = false;
          entriesMarked(card, saved);
          // Rows still warn: the button stays, so they can be marked without a re-check.
          if (rest > 0) card.querySelectorAll('[data-mark-open]').forEach((b) => { b.hidden = false; });
          // Every entry it could mark is now marked: the card leaves the list, as a whole mark would.
          if (saved.length && rest === 0 && typeof on.onMarked === 'function') on.onMarked([card]);
        }
        if (kind === 'removed' && r.status === 'removed') {
          const others = updateSiblings(card, kind, r);
          state.delete(card);
          becomeUnmarked(card);
          if (card.hasAttribute && card.hasAttribute('data-mark-entries-done')) {
            card.querySelectorAll('[data-unmark-items],[data-unmark-item]').forEach((b) => { b.hidden = true; });
          }
          if (typeof on.onUnmarked === 'function') on.onUnmarked([card, ...others]);
        }
      } catch (_) {
        status.innerHTML = resultHtml(null);
        d = { done: false };
      }
      state.delete(card);
      if (!d.done) setButtons(card, false);
      // The panel that had focus is gone: the result is read out from here.
      if (kind === 'marked-items') focusOn(status);
    }

    function unmark(card) {
      if (!card || state.get(card) === 'running') return undefined;
      const id = card.getAttribute('data-unmark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.unmarkMine(id), 'removed');
    }

    // "Stop treating this as mine" on one entry: only that entry's mark.
    async function unmarkItem(btn) {
      const row = btn.closest ? btn.closest('[data-mark-entry]') : null;
      const id = btn.getAttribute('data-unmark-item');
      if (!row || rowState.get(row) || typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      rowState.set(row, true);
      const status = row.querySelector('[data-unmark-item-status]');
      btn.hidden = true;
      if (status) { status.hidden = false; status.textContent = 'Saving…'; }
      let ok = false;
      try {
        const r = await api.unmarkMine([id]);
        ok = !!r && r.status === 'removed';
        const d = describeMarkResult(r);
        if (status) status.textContent = ok ? 'No longer marked as yours. Its warning comes back on your next checkup.' : d.headline;
        if (onResult) { try { onResult({ kind: 'removed', result: r, described: d }); } catch (_) { /* never break an undo */ } }
        // A card cleared as fully marked comes back to the list.
        const card = cardOf(row);
        if (ok && card) entryUnmarked(card, id);
        if (ok && card && typeof on.onUnmarked === 'function') on.onUnmarked([card]);
      } catch (_) {
        if (status) status.textContent = describeMarkResult(null).headline;
      }
      rowState.delete(row);
      if (!ok) btn.hidden = false;
      return undefined;
    }

    // The checklist's button: show exactly the ticked rows the panel rendered, and ask.
    function openItemsConfirm(card, keys) {
      const rows = Array.from(card.querySelectorAll('[data-mark-items-row]')).filter((r) => !r.hasAttribute('data-mark-items-marked'));
      const allowed = new Set(rows.map((r) => r.getAttribute('data-mark-items-row')));
      const ids = [...new Set(keys)].filter((k) => MARK_ID.test(k) && allowed.has(k));
      const confirm = card.querySelector('[data-mark-items-confirm]');
      if (!ids.length || !confirm) return;
      card.querySelectorAll('[data-mark-items-row]').forEach((row) => { row.hidden = true; });
      rows.forEach((row) => { row.hidden = !ids.includes(row.getAttribute('data-mark-items-row')); });
      const head = card.querySelector('[data-mark-items-head]');
      if (head) head.textContent = ids.length === 1 ? 'You’re saying this one is yours:' : `You’re saying these ${ids.length} are yours:`;
      const yes = card.querySelector('[data-mark-items-yes]');
      if (yes) yes.textContent = ids.length === 1 ? 'Yes, this one is mine' : `Yes, these ${ids.length} are mine`;
      confirm.setAttribute('data-mark-items-chosen', ids.join(' '));
      const pick = card.querySelector('[data-mark-items-pick]');
      if (pick) pick.hidden = true;
      confirm.hidden = false;
      state.set(card, 'confirming-items');
      focusOn(head);
    }

    // The checklist listens first: some callers' roots keep only the last click handler.
    if (CL) {
      clApi = CL.attach(root, {
        onAction(listId, actionId, keys) {
          if (actionId !== 'mark' || typeof listId !== 'string' || !listId.startsWith('mark-')) return;
          const id = listId.slice('mark-'.length);
          const card = Array.from(root.querySelectorAll('[data-mark-entries]')).find((c) => c.getAttribute('data-mark-id') === id);
          if (card && state.get(card) === 'confirming') openItemsConfirm(card, keys);
        },
      });
    }

    root.addEventListener('click', (event) => {
      const target = event.target && event.target.closest ? event.target.closest(CLICK_TARGETS) : null;
      if (target && target.hasAttribute('data-unmark-item')) return unmarkItem(target);
      const card = cardOf(target);
      if (!target || !card || state.get(card) === 'running') return undefined;
      if (target.hasAttribute('data-mark-open')) {
        const panel = card.querySelector('[data-mark-panel]');
        const status = card.querySelector('[data-mark-status]');
        if (status) { status.hidden = true; status.innerHTML = ''; }
        showPick(card);
        if (panel) panel.hidden = false;
        state.set(card, 'confirming');
        return undefined;
      }
      if (target.hasAttribute('data-mark-cancel')) {
        closeByPerson(card);
        return undefined;
      }
      if (target.hasAttribute('data-unmark')) return unmark(card);
      if (target.hasAttribute('data-unmark-items')) {
        const ids = splitIds(target.getAttribute('data-unmark-items'));
        return ids.length ? send(card, () => api.unmarkMine(ids), 'removed') : undefined;
      }
      if (target.hasAttribute('data-mark-items-back')) {
        const s = state.get(card);
        if (s === 'confirming-items' || s === 'confirming-whole') { showPick(card); state.set(card, 'confirming'); focusPick(card); }
        return undefined;
      }
      if (target.hasAttribute('data-mark-whole-open')) {
        const whole = card.querySelector('[data-mark-whole-confirm]');
        const pick = card.querySelector('[data-mark-items-pick]');
        if (state.get(card) !== 'confirming' || !whole) return undefined;
        if (pick) pick.hidden = true;
        whole.hidden = false;
        state.set(card, 'confirming-whole');
        focusOn(card.querySelector('[data-mark-whole-head]'));
        return undefined;
      }
      if (target.hasAttribute('data-mark-items-yes')) {
        if (state.get(card) !== 'confirming-items') return undefined;
        const confirm = card.querySelector('[data-mark-items-confirm]');
        const ids = splitIds(confirm && confirm.getAttribute('data-mark-items-chosen'));
        const id = card.getAttribute('data-mark-id');
        if (!ids.length || typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
        // The finding's id and the ticked entry ids only; main checks each against its scan.
        return send(card, () => api.markMine(id, ids), 'marked-items', ids);
      }
      // On a checklist card the whole-list "Yes" counts only from its own confirmation.
      const asked = card.hasAttribute('data-mark-entries') ? 'confirming-whole' : 'confirming';
      if (!target.hasAttribute('data-mark-confirm') || state.get(card) !== asked) return undefined;
      // Only the engine's id is sent; the main process looks up what it showed.
      const id = card.getAttribute('data-mark-id');
      if (typeof id !== 'string' || !MARK_ID.test(id)) return undefined;
      return send(card, () => api.markMine(id), 'marked');
    });

    root.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const card = cardOf(event.target);
      const s = card && state.get(card);
      if (s === 'confirming' || s === 'confirming-items' || s === 'confirming-whole') {
        closeByPerson(card);
        // Handled: the page's own Esc (back to the city) leaves it alone.
        if (typeof event.preventDefault === 'function') event.preventDefault();
      }
    });

    return { unmark };
  }

  return {
    ONLY_IF_YOURS, COULD_WATCH, LIST_REASON, NOT_SURE_LIST, NAME_MAKER_MISMATCH, MAX_APP_NAME, BUTTON, NEVER_MARKABLE_MODULES,
    ENTRY_REASON, CANT_ALONE, STALE_ROW, UNCHECKED_ROW, ENTRY_BUTTON, WHOLE_BUTTON, WHOLE_HEAD, WHOLE_CHANGES, wholeIncludes, groupOf, markableOf, markedIdOf,
    needsStrongConfirm, markControlsHtml, describeMarkResult, resultHtml, attach, esc,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MarkFlow;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.MarkFlow = MarkFlow;
}
