const { app, BrowserWindow, ipcMain, shell, net, protocol } = require('electron');
const path = require('path');
const { askAbout, buildAskBody, ASK_ENDPOINT } = require('./ask-about');
const { buildAiPrompt } = require('./ai-prompt');
const { runScan, runWatch, runFix, runAction, runUndo, runMark, runUnmark, runRecheck } = require('./engine-runner');
const { handleRecheck } = require('./recheck');
const { handleWatch, stopActiveWatch, quitActiveWatch, SCAN_BUSY_MESSAGE } = require('./watch');
const { createMarkPolicy, handleMark, handleUnmark } = require('./mark-policy');
const { createFixPolicy, handleRunFix, handleRunAction, handleRunUndo } = require('./fix-policy');
const { isAllowedSettingUrl, isAllowedGuideUrl } = require('./setting-urls');
const { routerUrlFor, browserDisplayName } = require('./router-url');
const { isAllowedMissionLink } = require('./mission-links');
const { APP_ORIGIN, serveApp } = require('./app-protocol');
const { userDataDir } = require('./user-data');

// Before anything reads it: keep saved data in the folder earlier versions used.
app.setPath('userData', userDataDir(app.getPath('appData')));

// The running connection watch ({promise, stop, kill}), or null.
let activeWatch = null;

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
  // A checkup or a connection watch is running: one at a time. A refused
  // checkup rejects like a failed one, so the window shows the message.
  let busy = false;
  ipcMain.handle('run-scan', async (e, profile) => {
    if (busy) throw new Error(SCAN_BUSY_MESSAGE);
    busy = true;
    try {
      const doc = await runScan(undefined, profile, (ev) => {
        if (!e.sender.isDestroyed()) e.sender.send('scan-event', ev);
      });
      fixPolicy.remember(doc);
      markPolicy.remember(doc);
      lastDoc = doc;
      return doc;
    } finally {
      busy = false;
    }
  });
  // The connection watch. Only the minutes (checked against a list in
  // watch.js) and the lookups switch (a boolean) cross IPC; its result is
  // merged into lastDoc and goes nowhere else.
  ipcMain.handle('run-watch', (e, minutes, lookups) =>
    handleWatch(minutes, {
      lookups,
      getLastDoc: () => lastDoc,
      setLastDoc: (d) => { lastDoc = d; },
      policies: [fixPolicy, markPolicy],
      isBusy: () => busy,
      onEvent: (ev) => { if (!e.sender.isDestroyed()) e.sender.send('watch-event', ev); },
      runWatch: (m, onEvent, on) => {
        busy = true;
        const watch = runWatch(m, onEvent, undefined, { lookups: on });
        activeWatch = watch;
        // The window went away: nobody is left to press Stop.
        const onGone = () => quitActiveWatch(watch);
        e.sender.once('destroyed', onGone);
        return watch.promise.finally(() => {
          busy = false;
          if (activeWatch === watch) activeWatch = null;
          e.sender.removeListener('destroyed', onGone);
        });
      },
    }));
  ipcMain.handle('stop-watch', () => {
    if (!activeWatch) return false;
    stopActiveWatch(activeWatch);
    return true;
  });
  ipcMain.handle('run-fix', (_e, moduleName) =>
    handleRunFix(moduleName, { policy: fixPolicy, runFix }));
  ipcMain.handle('run-fix-action', (_e, action, target) =>
    handleRunAction(action, target, { policy: fixPolicy, runAction }));
  ipcMain.handle('undo-fix', (_e, quarantineId) =>
    handleRunUndo(quarantineId, { policy: fixPolicy, runUndo }));
  // Only an id crosses IPC; the main process uses the target it stored from its own scan.
  ipcMain.handle('mark-mine', (_e, id) =>
    handleMark(id, { policy: markPolicy, runMark }));
  ipcMain.handle('unmark-mine', (_e, id) =>
    handleUnmark(id, { policy: markPolicy, runUnmark }));
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
// The watch's engine must not outlive the app: hold the quit, stop it twice
// (watching and lookups; killed if it hasn't exited within 5 s), then quit.
let quitWaiting = false;
let quitReady = false;
app.on('before-quit', (event) => {
  if (!activeWatch || quitReady) return;
  event.preventDefault();
  if (quitWaiting) return;
  quitWaiting = true;
  quitActiveWatch(activeWatch).then(() => {
    quitReady = true;
    app.quit();
  });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
