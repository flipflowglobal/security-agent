const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    getBinaryPath: () => ipcRenderer.invoke('get-binary-path'),
    runCommand: (args) => ipcRenderer.invoke('run-command', args),
    runStreaming: (args) => ipcRenderer.invoke('run-streaming', args),
    nativeList: () => ipcRenderer.invoke('native-list'),
    nativeRun: (id, args) => ipcRenderer.invoke('native-run', id, args),
    selectFile: (options) => ipcRenderer.invoke('select-file', options),
    saveFile: (options) => ipcRenderer.invoke('save-file', options),
    writeFile: (filePath, content) => ipcRenderer.invoke('write-file', filePath, content),
    openExternal: (url) => ipcRenderer.invoke('open-external', url),
    onStreamChunk: (callback) => {
        ipcRenderer.on('stream-chunk', (_event, chunk) => callback(chunk));
    },
    removeStreamListeners: () => {
        ipcRenderer.removeAllListeners('stream-chunk');
    },
});
