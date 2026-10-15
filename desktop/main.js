const { app, BrowserWindow, ipcMain, shell, net } = require('electron');
const path = require('path');
const { askAbout, buildAskBody, ASK_ENDPOINT } = require('./ask-about');
const { buildAiPrompt } = require('./ai-prompt');
const { runScan, runFix, runAction, runUndo } = require('./engine-runner');
const { createFixPolicy, handleRunFix, handleRunAction, handleRunUndo } = require('./fix-policy');
const { isAllowedSettingUrl, isAllowedGuideUrl } = require('./setting-urls');

function createWindow() {
  const win = new BrowserWindow({
    width: 1100, height: 860,
    minWidth: 720, minHeight: 600,
    title: 'Device Rescue',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // The renderer only ever loads the bundled local page; it has no reason to
  // navigate away or spawn windows.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => event.preventDefault());
}
app.whenReady().then(() => {
  // Modules the engine itself marked fixable in the scans this process ran.
  const fixPolicy = createFixPolicy();
  ipcMain.handle('run-scan', async (e, profile) => {
    const doc = await runScan(undefined, profile, (ev) => {
      if (!e.sender.isDestroyed()) e.sender.send('scan-event', ev);
    });
    fixPolicy.remember(doc);
    return doc;
  });
  ipcMain.handle('run-fix', (_e, moduleName) =>
    handleRunFix(moduleName, { policy: fixPolicy, runFix }));
  ipcMain.handle('run-fix-action', (_e, action, target) =>
    handleRunAction(action, target, { policy: fixPolicy, runAction }));
  ipcMain.handle('undo-fix', (_e, quarantineId) =>
    handleRunUndo(quarantineId, { policy: fixPolicy, runUndo }));
  ipcMain.handle('open-guide', (_e, url) => {
    if (!isAllowedGuideUrl(url)) {
      return false;
    }
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
