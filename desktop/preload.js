const { contextBridge, ipcRenderer, shell } = require('electron');
contextBridge.exposeInMainWorld('rescue', {
  runScan: (profile) => ipcRenderer.invoke('run-scan', profile),
  runFix: (moduleName) => ipcRenderer.invoke('run-fix', moduleName),
  openGuide: (url) => ipcRenderer.invoke('open-guide', url),
  onScanEvent: (cb) => {
    const listener = (_e, ev) => cb(ev);
    ipcRenderer.on('scan-event', listener);
    return () => ipcRenderer.removeListener('scan-event', listener);
  },
  openSetting: (url) => ipcRenderer.invoke('open-setting', url),
  askAbout: (payload) => ipcRenderer.invoke('ask-about', payload),
  onAskWarming: (cb) => {
    const listener = () => cb();
    ipcRenderer.on('ask-warming', listener);
    return () => ipcRenderer.removeListener('ask-warming', listener);
  },
});
