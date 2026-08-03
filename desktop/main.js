const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { runScan } = require('./engine-runner');

function createWindow() {
  const win = new BrowserWindow({
    width: 900, height: 680,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}
app.whenReady().then(() => {
  ipcMain.handle('run-scan', () => runScan());
  ipcMain.handle('open-setting', (_e, url) => shell.openExternal(url));
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
