const { contextBridge, ipcRenderer, shell } = require('electron');
contextBridge.exposeInMainWorld('rescue', {
  // Read-only: which OS this is ("darwin", "win32", "linux"), known before any scan.
  platform: process.platform,
  runScan: (profile) => ipcRenderer.invoke('run-scan', profile),
  runFix: (moduleName) => ipcRenderer.invoke('run-fix', moduleName),
  runAction: (action, target) => ipcRenderer.invoke('run-fix-action', action, target),
  undoFix: (quarantineId) => ipcRenderer.invoke('undo-fix', quarantineId),
  markMine: (id) => ipcRenderer.invoke('mark-mine', id),
  unmarkMine: (id) => ipcRenderer.invoke('unmark-mine', id),
  recheckModule: (name) => ipcRenderer.invoke('recheck-module', name),
  openGuide: (url) => ipcRenderer.invoke('open-guide', url),
  openMissionLink: (url) => ipcRenderer.invoke('open-mission-link', url),
  onScanEvent: (cb) => {
    const listener = (_e, ev) => cb(ev);
    ipcRenderer.on('scan-event', listener);
    return () => ipcRenderer.removeListener('scan-event', listener);
  },
  openSetting: (url) => ipcRenderer.invoke('open-setting', url),
  aiPrompt: (payload) => ipcRenderer.invoke('ai-prompt', payload),
  askPreview: (payload) => ipcRenderer.invoke('ask-preview', payload),
  askAbout: (payload) => ipcRenderer.invoke('ask-about', payload),
  onAskWarming: (cb) => {
    const listener = () => cb();
    ipcRenderer.on('ask-warming', listener);
    return () => ipcRenderer.removeListener('ask-warming', listener);
  },
});
