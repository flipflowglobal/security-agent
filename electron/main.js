const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { execFile, spawn } = require('child_process');
const fs = require('fs');

let mainWindow = null;
let binaryPath = null;

function resolveBinaryPath() {
    const baseDir = path.dirname(process.resourcesPath || __dirname);
    const candidates = [
        path.join(baseDir, 'security-agent'),
        path.join(baseDir, 'bin', 'security-agent'),
        path.join(__dirname, '..', 'target', 'release', 'security-agent'),
        path.join(__dirname, '..', 'target', 'debug', 'security-agent'),
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    return null;
}

function createWindow() {
    const isWindows = process.platform === 'win32';
    const isMac = process.platform === 'darwin';

    const windowOptions = {
        width: 1280,
        height: 860,
        minWidth: 900,
        minHeight: 600,
        backgroundColor: '#0d1117',
        title: 'Security-Agent',
        icon: undefined,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
        },
    };

    if (isMac) {
        windowOptions.titleBarStyle = 'hiddenInset';
        windowOptions.trafficLightPosition = { x: 16, y: 18 };
    } else if (isWindows) {
        windowOptions.titleBarStyle = 'hidden';
        windowOptions.titleBarOverlay = {
            color: '#161b22',
            symbolColor: '#e6edf3',
            height: 40,
        };
    }

    mainWindow = new BrowserWindow(windowOptions);

    mainWindow.loadFile(path.join(__dirname, 'index.html'));
    mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
    binaryPath = resolveBinaryPath();
    createWindow();
    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// ── IPC Handlers ──────────────────────────────────────────────────────────

ipcMain.handle('get-binary-path', () => binaryPath);

ipcMain.handle('run-command', async (_event, args) => {
    return new Promise((resolve) => {
        if (!binaryPath) {
            resolve({ ok: false, stdout: '', stderr: 'security-agent binary not found', exitCode: 1 });
            return;
        }
        const proc = execFile(binaryPath, args, {
            timeout: 120_000,
            maxBuffer: 1024 * 1024,
            encoding: 'utf-8',
        }, (error, stdout, stderr) => {
            if (error) {
                const code = error.code != null ? error.code : 1;
                resolve({ ok: code === 0, stdout: stdout || '', stderr: stderr || String(error), exitCode: code });
            } else {
                resolve({ ok: true, stdout: stdout || '', stderr: stderr || '', exitCode: 0 });
            }
        });
    });
});

ipcMain.handle('run-streaming', async (_event, args) => {
    return new Promise((resolve) => {
        if (!binaryPath) {
            resolve({ ok: false, stdout: '', stderr: 'security-agent binary not found', exitCode: 1 });
            return;
        }
        const proc = spawn(binaryPath, args, {
            env: { ...process.env, TERM: 'dumb' },
        });
        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', (data) => {
            const chunk = data.toString();
            stdout += chunk;
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('stream-chunk', chunk);
            }
        });
        proc.stderr.on('data', (data) => {
            const chunk = data.toString();
            stderr += chunk;
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('stream-chunk', chunk);
            }
        });
        proc.on('close', (code) => {
            resolve({ ok: code === 0, stdout, stderr, exitCode: code || 0 });
        });
        proc.on('error', (err) => {
            resolve({ ok: false, stdout, stderr: String(err), exitCode: 1 });
        });
    });
});

ipcMain.handle('select-file', async (_event, options) => {
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openFile'],
        filters: options?.filters || [],
    });
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
});

ipcMain.handle('save-file', async (_event, options) => {
    const result = await dialog.showSaveDialog(mainWindow, {
        filters: options?.filters || [],
    });
    if (result.canceled || !result.filePath) return null;
    return result.filePath;
});

ipcMain.handle('open-external', async (_event, url) => {
    await shell.openExternal(url);
});

ipcMain.handle('write-file', async (_event, filePath, content) => {
    try {
        fs.writeFileSync(filePath, content, 'utf-8');
        return { ok: true };
    } catch (err) {
        return { ok: false, error: String(err) };
    }
});
