const { contextBridge, ipcRenderer, shell } = require('electron');
contextBridge.exposeInMainWorld('rescue', {
  runScan: () => ipcRenderer.invoke('run-scan'),
  openSetting: (url) => ipcRenderer.invoke('open-setting', url),
});
