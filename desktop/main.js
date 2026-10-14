const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { runScan, runFix } = require('./engine-runner');
const { createFixPolicy, handleRunFix } = require('./fix-policy');
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
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
