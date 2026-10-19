const { contextBridge, ipcRenderer, shell } = require('electron');
contextBridge.exposeInMainWorld('rescue', {
  // Read-only: which OS this is ("darwin", "win32", "linux"), known before any scan.
  platform: process.platform,
  runScan: (profile) => ipcRenderer.invoke('run-scan', profile),
  runFix: (moduleName) => ipcRenderer.invoke('run-fix', moduleName),
  runAction: (action, target) => ipcRenderer.invoke('run-fix-action', action, target),
  undoFix: (quarantineId) => ipcRenderer.invoke('undo-fix', quarantineId),
  // itemIds: some entries of one list finding (main checks each against its scan).
  markMine: (id, itemIds) => ipcRenderer.invoke('mark-mine', id, itemIds),
  unmarkMine: (idOrIds) => ipcRenderer.invoke('unmark-mine', idOrIds),
  recheckModule: (name) => ipcRenderer.invoke('recheck-module', name),
  // Read-only: the commands one check ran in the last scan
  // ([{argv, returncode, seconds, times}]), for its Evidence block.
  moduleCommands: (name) => ipcRenderer.invoke('module-commands', name),
  openGuide: (url) => ipcRenderer.invoke('open-guide', url),
  openMissionLink: (url) => ipcRenderer.invoke('open-mission-link', url),
  // A little mission's look-up (main opens only research.js's templates).
  openLookup: (url) => ipcRenderer.invoke('open-lookup', url),
  onScanEvent: (cb) => {
    const listener = (_e, ev) => cb(ev);
    ipcRenderer.on('scan-event', listener);
    return () => ipcRenderer.removeListener('scan-event', listener);
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
