const { app, BrowserWindow, ipcMain, shell, net, protocol } = require('electron');
const path = require('path');
const { askAbout, buildAskBody, ASK_ENDPOINT } = require('./ask-about');
const { buildAiPrompt } = require('./ai-prompt');
const { createExecLog, runScan, runFix, runAction, runUndo, runMark, runUnmark, runRecheck, stopRunningScans } = require('./engine-runner');
const { handleRecheck, applyScanResult, joinsLastScan } = require('./recheck');
const { createMarkPolicy, handleMark, handleUnmark } = require('./mark-policy');
const { createFixPolicy, handleRunFix, handleRunAction, handleRunUndo } = require('./fix-policy');
const { createScanGate, fixRefusal, markRefusal, recheckRefusal } = require('./scan-gate');
const { isAllowedSettingUrl, isAllowedGuideUrl } = require('./setting-urls');
const { routerUrlFor, browserDisplayName } = require('./router-url');
const { isAllowedMissionLink } = require('./mission-links');
const { isAllowedLookupUrl } = require('./lookup-url');
const { APP_ORIGIN, serveApp } = require('./app-protocol');
const { userDataDir } = require('./user-data');

// Before anything reads it: keep saved data in the folder earlier versions used.
app.setPath('userData', userDataDir(app.getPath('appData')));

// Must run before the app is ready. "standard" gives app:// a real origin, so
// ES modules, fetch() of local JSON and the CSP's 'self' all work.
protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } },
]);

function createWindow() {
  const win = new BrowserWindow({
    width: 1100, height: 860,
    minWidth: 720, minHeight: 600,
    title: 'Reclaim City',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadURL(`${APP_ORIGIN}index.html`);

  // The renderer only ever loads the bundled local page; it has no reason to
  // navigate away or spawn windows.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => event.preventDefault());
}
app.whenReady().then(() => {
  app.setAboutPanelOptions({ applicationName: 'Reclaim City' });
  protocol.handle('app', (request) => serveApp(request.url, __dirname));
  // Modules the engine itself marked fixable in the scans this process ran.
  const fixPolicy = createFixPolicy();
  // Findings the engine offered as "This is mine" in the scans this process ran.
  const markPolicy = createMarkPolicy();
  // The last full scan this process ran, with any re-checks merged in.
  let lastDoc = null;
  // Fixes, undos and marks wait for the scan to finish (scan-gate.js).
  const gate = createScanGate();
  // The commands each check ran in the last scan (engine-runner.js createExecLog).
  const execLog = createExecLog();
  ipcMain.handle('run-scan', (e, profile) => gate.runScan(async () => {
    // One optional check on its own (the iPhone backup sweep) joins the last
    // full scan instead of replacing it, and keeps the other checks' commands.
    const joins = joinsLastScan(profile, lastDoc);
    if (joins) execLog.resetModule('mvt_spyware_scan'); else execLog.reset();
    const doc = await runScan(undefined, profile, (ev) => {
      if (ev.type === 'exec') execLog.add(ev);
      if (!e.sender.isDestroyed()) e.sender.send('scan-event', ev);
    });
    // A checkup that stopped before the end is shown, never acted on: the
    // policies themselves ignore it (actionableDoc), whoever calls remember.
    lastDoc = applyScanResult({ profile, lastDoc, doc, policies: [fixPolicy, markPolicy] });
    return doc;
  }, () => { if (!e.sender.isDestroyed()) e.sender.send('scan-event', { type: 'wait', reason: 'change' }); }));
  // Read-only: what one check ran, for its findings' Evidence block.
  ipcMain.handle('module-commands', (_e, name) => execLog.get(name));
  ipcMain.handle('run-fix', (_e, moduleName) => gate.runChange(() =>
    handleRunFix(moduleName, { policy: fixPolicy, runFix }), fixRefusal(moduleName)));
  ipcMain.handle('run-fix-action', (_e, action, target) => gate.runChange(() =>
    handleRunAction(action, target, { policy: fixPolicy, runAction }), fixRefusal(action)));
  ipcMain.handle('undo-fix', (_e, quarantineId) => gate.runChange(() =>
    handleRunUndo(quarantineId, { policy: fixPolicy, runUndo }), fixRefusal('undo')));
  // Only an id crosses IPC; the main process uses the target it stored from its own scan.
  ipcMain.handle('mark-mine', (_e, id, itemIds) => gate.runChange(() =>
    handleMark(id, { policy: markPolicy, runMark }, itemIds), markRefusal()));
  ipcMain.handle('unmark-mine', (_e, idOrIds) => gate.runChange(() =>
    handleUnmark(idOrIds, { policy: markPolicy, runUnmark }), markRefusal()));
  ipcMain.handle('recheck-module', (_e, name) => gate.runChange(() =>
    handleRecheck(name, {
      getLastDoc: () => lastDoc,
      setLastDoc: (d) => { lastDoc = d; },
      runRecheck: (n) => runRecheck(n),
      policies: [fixPolicy, markPolicy],
    }), recheckRefusal()));
  ipcMain.handle('open-guide', (_e, url) => {
    if (!isAllowedGuideUrl(url)) {
      return false;
    }
    shell.openExternal(url);
    return true;
  });
  // A link inside a Reclaim City mission (an account's security page). Only the
  // exact links in the game's own data open; the renderer shows anything else as
  // text to copy.
  ipcMain.handle('open-mission-link', (_e, url) => {
    if (!isAllowedMissionLink(url)) return false;
    shell.openExternal(url);
    return true;
  });
  // A look-up from a little mission (standard mode only; city mode shows it as
  // text). Only research.js's templates open: host and path checked again here.
  ipcMain.handle('open-lookup', (_e, url) => {
    if (!isAllowedLookupUrl(url)) return false;
    shell.openExternal(url);
    return true;
  });
  ipcMain.handle('open-setting', (_e, url) => {
    if (!isAllowedSettingUrl(url)) {
      return false;
    }
    shell.openExternal(url);
    return true;
  });
  // The router's sign-in page. Only an IP address crosses IPC; the URL is
  // built here, for private home-network addresses only (router-url.js).
  ipcMain.handle('open-router', (_e, ip) => {
    const url = routerUrlFor(ip);
    if (!url) return false;
    shell.openExternal(url);
    return true;
  });
  // The default browser's name ("Safari"), so the router button can say where it opens.
  ipcMain.handle('default-browser', () => {
    try {
      return browserDisplayName(app.getApplicationNameForProtocol('http://'));
    } catch {
      return null;
    }
  });
  // Redacted text for the person to paste into any AI; nothing is sent.
  ipcMain.handle('ai-prompt', (_e, payload) => buildAiPrompt(payload));
  // The exact redacted body askAbout would send, so the person can read it first.
  ipcMain.handle('ask-preview', (_e, payload) => {
    const body = buildAskBody(payload);
    return body ? { endpoint: ASK_ENDPOINT, body } : null;
  });
  ipcMain.handle('ask-about', (e, payload) =>
    askAbout(payload, {
      fetch: (url, init) => net.fetch(url, init),
      onWarming: () => { if (!e.sender.isDestroyed()) e.sender.send('ask-warming'); },
    }));
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
// Quitting mid-scan stops the engine: SIGTERM, so its handler also stops the
// commands its checks started (rescue/orchestrator.py stop_commands_on_signals).
app.on('before-quit', () => stopRunningScans());
