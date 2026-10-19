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
  // The connection watch: minutes from the app's list; progress arrives as {progress: {...}}.
  runWatch: (minutes) => ipcRenderer.invoke('run-watch', minutes),
  stopWatch: () => ipcRenderer.invoke('stop-watch'),
  onWatchEvent: (cb) => {
    const listener = (_e, ev) => cb(ev);
    ipcRenderer.on('watch-event', listener);
    return () => ipcRenderer.removeListener('watch-event', listener);
  },
  openSetting: (url) => ipcRenderer.invoke('open-setting', url),
  openRouter: (ip) => ipcRenderer.invoke('open-router', ip),
  defaultBrowser: () => ipcRenderer.invoke('default-browser'),
  aiPrompt: (payload) => ipcRenderer.invoke('ai-prompt', payload),
  askPreview: (payload) => ipcRenderer.invoke('ask-preview', payload),
  askAbout: (payload) => ipcRenderer.invoke('ask-about', payload),
  onAskWarming: (cb) => {
    const listener = () => cb();
    ipcRenderer.on('ask-warming', listener);
    return () => ipcRenderer.removeListener('ask-warming', listener);
  },
});
