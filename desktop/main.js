const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { runScan } = require('./engine-runner');
const { isAllowedSettingUrl } = require('./setting-urls');

function createWindow() {
  const win = new BrowserWindow({
    width: 900, height: 680,
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
  ipcMain.handle('run-scan', () => runScan());
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
