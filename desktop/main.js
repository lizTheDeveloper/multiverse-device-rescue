const { app, BrowserWindow, ipcMain, shell, net, protocol } = require('electron');
const path = require('path');
const { askAbout, buildAskBody, ASK_ENDPOINT } = require('./ask-about');
const { buildAiPrompt } = require('./ai-prompt');
const { runScan, runFix, runAction, runUndo, runMark, runUnmark, runRecheck } = require('./engine-runner');
const { handleRecheck } = require('./recheck');
const { createMarkPolicy, handleMark, handleUnmark } = require('./mark-policy');
const { createFixPolicy, handleRunFix, handleRunAction, handleRunUndo } = require('./fix-policy');
const { isAllowedSettingUrl, isAllowedGuideUrl } = require('./setting-urls');
const { isAllowedMissionLink } = require('./mission-links');
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
  ipcMain.handle('run-scan', async (e, profile) => {
    const doc = await runScan(undefined, profile, (ev) => {
      if (!e.sender.isDestroyed()) e.sender.send('scan-event', ev);
    });
    fixPolicy.remember(doc);
    markPolicy.remember(doc);
    lastDoc = doc;
    return doc;
  });
  ipcMain.handle('run-fix', (_e, moduleName) =>
    handleRunFix(moduleName, { policy: fixPolicy, runFix }));
  ipcMain.handle('run-fix-action', (_e, action, target) =>
    handleRunAction(action, target, { policy: fixPolicy, runAction }));
  ipcMain.handle('undo-fix', (_e, quarantineId) =>
    handleRunUndo(quarantineId, { policy: fixPolicy, runUndo }));
  // Only an id crosses IPC; the main process uses the target it stored from its own scan.
  ipcMain.handle('mark-mine', (_e, id, itemIds) =>
    handleMark(id, { policy: markPolicy, runMark }, itemIds));
  ipcMain.handle('unmark-mine', (_e, idOrIds) =>
    handleUnmark(idOrIds, { policy: markPolicy, runUnmark }));
  ipcMain.handle('recheck-module', (_e, name) =>
    handleRecheck(name, {
      getLastDoc: () => lastDoc,
      setLastDoc: (d) => { lastDoc = d; },
      runRecheck: (n) => runRecheck(n),
      policies: [fixPolicy, markPolicy],
    }));
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
  ipcMain.handle('open-setting', (_e, url) => {
    if (!isAllowedSettingUrl(url)) {
      return false;
    }
    shell.openExternal(url);
    return true;
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
