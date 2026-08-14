const { contextBridge, ipcRenderer } = require('electron');

// Minimal, vetted API surface. Every handler below exists for a reason:
//   runCommand/runStreaming/cancelRun — execute the wrapped binary
//   setNetworkMode                  — Offline/Online toggle (enforced in main)
//   getWorkspace/getToolCatalog     — read-only state the UI renders
//   writeFile/readFile              — confined to the workspace root (main enforces)
//   saveFile/selectFile             — user-dialog only; save also writes the file
//   startListener/listenerStdin/stopListener — live reverse-shell listener
//     (main enforces Online mode, owns the child process, and forwards
//     stdout → listener-output, stderr → listener-event, close → listener-status)
//   genShell/getShellTypes          — local payload generation (offline-safe)
//   onStreamChunk/onLogLine/onListener* — push events for live output / logs
// Anything else is intentionally NOT exposed.
contextBridge.exposeInMainWorld('api', {
    getAppInfo: () => ipcRenderer.invoke('get-app-info'),
    setNetworkMode: (mode) => ipcRenderer.invoke('set-network-mode', mode),
    runCommand: (args) => ipcRenderer.invoke('run-command', args),
    runStreaming: (args) => ipcRenderer.invoke('run-streaming', args),
    cancelRun: () => ipcRenderer.invoke('cancel-run'),
    readFile: (filePath) => ipcRenderer.invoke('read-file', filePath),
    writeFile: (filePath, content) => ipcRenderer.invoke('write-file', filePath, content),
    saveFile: (options, content) => ipcRenderer.invoke('save-file', options, content),
    selectFile: (options) => ipcRenderer.invoke('select-file', options),
    getWorkspace: () => ipcRenderer.invoke('get-workspace'),
    getToolCatalog: () => ipcRenderer.invoke('get-tool-catalog'),
    startListener: (options) => ipcRenderer.invoke('start-listener', options),
    listenerStdin: (line) => ipcRenderer.invoke('listener-stdin', line),
    stopListener: () => ipcRenderer.invoke('stop-listener'),
    genShell: (shellType, lhost, lport) => ipcRenderer.invoke('gen-shell', shellType, lhost, lport),
    getShellTypes: () => ipcRenderer.invoke('get-shell-types'),
    onStreamChunk: (callback) => {
        ipcRenderer.on('stream-chunk', (_event, chunk) => callback(chunk));
    },
    removeStreamListeners: () => {
        ipcRenderer.removeAllListeners('stream-chunk');
    },
    onLogLine: (callback) => {
        ipcRenderer.on('log-line', (_event, entry) => callback(entry));
    },
    onModelStatus: (callback) => {
        ipcRenderer.on('model-status', (_event, status) => callback(status));
    },
    removeLogListeners: () => {
        ipcRenderer.removeAllListeners('log-line');
    },
    onListenerOutput: (callback) => {
        ipcRenderer.on('listener-output', (_event, chunk) => callback(chunk));
    },
    removeListenerOutputListeners: () => {
        ipcRenderer.removeAllListeners('listener-output');
    },
    onListenerEvent: (callback) => {
        ipcRenderer.on('listener-event', (_event, chunk) => callback(chunk));
    },
    removeListenerEventListeners: () => {
        ipcRenderer.removeAllListeners('listener-event');
    },
    onListenerStatus: (callback) => {
        ipcRenderer.on('listener-status', (_event, status) => callback(status));
    },
    removeListenerStatusListeners: () => {
        ipcRenderer.removeAllListeners('listener-status');
    },
});
