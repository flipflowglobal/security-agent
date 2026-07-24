const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getOfflineStatus: () => ipcRenderer.invoke('get-offline-status'),
  listSkills: () => ipcRenderer.invoke('list-skills'),
  showSkill: (name) => ipcRenderer.invoke('show-skill', name),
  listTools: () => ipcRenderer.invoke('list-tools'),
  askAgent: (query) => ipcRenderer.invoke('ask-agent', query),
  planScan: (configPath) => ipcRenderer.invoke('plan-scan', configPath),
  runCustomCmd: (argsString) => ipcRenderer.invoke('run-custom-cmd', argsString),
  onCmdOutput: (callback) => {
    ipcRenderer.on('cmd-output', (event, data) => callback(data));
  }
});
