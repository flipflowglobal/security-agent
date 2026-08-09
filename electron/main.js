const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { execFile, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');

const nativeTools = require('./tools');

let mainWindow = null;
let binaryPath = null;

// ── Verbose logging ─────────────────────────────────────────────────────────
// Every log line is written to the main-process console AND forwarded to the
// renderer, where it appears in the collapsible Log Console (bottom bar).
const LOG_BUFFER = [];
const LOG_MAX_BUFFER = 500;

function emitLog(level, message) {
    const entry = { ts: Date.now(), level, message: String(message) };
    LOG_BUFFER.push(entry);
    if (LOG_BUFFER.length > LOG_MAX_BUFFER) LOG_BUFFER.shift();
    const line = `[${new Date(entry.ts).toISOString()}] [${level.toUpperCase()}] ${entry.message}`;
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
    if (mainWindow && !mainWindow.isDestroyed()) {
        try { mainWindow.webContents.send('log-line', entry); } catch (_e) { /* window gone */ }
    }
}

function resolveBinaryPath() {
    const resourcesPath = process.resourcesPath || path.join(__dirname, '..');
    const baseDir = path.dirname(resourcesPath);

    // Explicit override for debugging / CI.
    if (process.env.SECURITY_AGENT_BIN) {
        const override = process.env.SECURITY_AGENT_BIN;
        if (fs.existsSync(override)) {
            emitLog('info', `Binary resolved via SECURITY_AGENT_BIN: ${override}`);
            return override;
        }
        emitLog('warn', `SECURITY_AGENT_BIN set but not found: ${override}`);
    }

    const isWindows = process.platform === 'win32';
    const names = isWindows ? ['security-agent.exe', 'security-agent'] : ['security-agent'];

    // Every plausible location the binary can live, in priority order.
    const roots = [
        resourcesPath,                                // packaged: <app>/resources/security-agent.exe
        baseDir,                                      // installer root
        path.join(baseDir, 'bin'),
        path.join(__dirname, '..', 'target', 'release'),
        path.join(__dirname, '..', 'target', 'debug'),
        path.join(baseDir, '..', 'vendor', 'win'),    // vendored Windows binary
        path.join(baseDir, 'vendor', 'win'),
    ];

    for (const root of roots) {
        for (const name of names) {
            const candidate = path.join(root, name);
            try {
                if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
                    emitLog('info', `Binary resolved: ${candidate}`);
                    return candidate;
                }
            } catch (_e) { /* race — try next candidate */ }
        }
    }

    emitLog('warn', 'security-agent binary not found. Checked: ' +
        roots.map((r) => r).join(', '));
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
    emitLog('info', 'Main window created (contextIsolation=true, nodeIntegration=false)');
}

app.whenReady().then(() => {
    emitLog('info', 'Security-Agent main process starting (platform=' + process.platform + ', electron=' + process.versions.electron + ')');
    binaryPath = resolveBinaryPath();
    emitLog(binaryPath ? 'info' : 'warn', binaryPath ? 'Using binary: ' + binaryPath : 'NO binary available — binary-backed commands will report errors');
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

ipcMain.handle('get-logs', () => LOG_BUFFER.slice());

ipcMain.handle('get-app-info', () => ({
    platform: process.platform,
    electron: process.versions.electron,
    node: process.versions.node,
    chrome: process.versions.chrome,
    binaryPath,
    binaryFound: !!binaryPath,
}));

// ── Native in-process tools (no binary spawn needed) ────────────────────────

ipcMain.handle('native-list', () => nativeTools.listTools());

ipcMain.handle('native-run', (_event, id, args) => {
    emitLog('info', `native-run: ${id} args=${JSON.stringify(args)}`);
    const result = nativeTools.runTool(id, args);
    emitLog(result.ok ? 'info' : 'error', `native-run: ${id} -> ok=${result.ok} ms=${result.ms}`);
    return result;
});

ipcMain.handle('run-command', async (_event, args) => {
    emitLog('info', 'run-command: ' + (Array.isArray(args) ? args.join(' ') : String(args)));
    return new Promise((resolve) => {
        if (!binaryPath) {
            emitLog('error', 'run-command refused: binary not found');
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
                emitLog('warn', `run-command finished exit=${code} stderr=${(stderr || String(error)).slice(0, 200)}`);
                resolve({ ok: code === 0, stdout: stdout || '', stderr: stderr || String(error), exitCode: code });
            } else {
                emitLog('info', `run-command finished exit=0 stdoutBytes=${(stdout || '').length}`);
                resolve({ ok: true, stdout: stdout || '', stderr: stderr || '', exitCode: 0 });
            }
        });
    });
});

ipcMain.handle('run-streaming', async (_event, args) => {
    emitLog('info', 'run-streaming: ' + (Array.isArray(args) ? args.join(' ') : String(args)));
    return new Promise((resolve) => {
        if (!binaryPath) {
            emitLog('error', 'run-streaming refused: binary not found');
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
            emitLog('info', `run-streaming finished exit=${code} stdoutBytes=${stdout.length} stderrBytes=${stderr.length}`);
            resolve({ ok: code === 0, stdout, stderr, exitCode: code || 0 });
        });
        proc.on('error', (err) => {
            emitLog('error', 'run-streaming spawn error: ' + String(err));
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

// ── Real-path scanning for combo-box suggestions ────────────────────────────
// Returns ONLY paths that actually exist on disk, scanned from every common
// user folder in priority order (home, Desktop, Documents, Downloads, ...,
// temp, the app's own install folders). The renderer uses this so path
// fields never suggest a made-up location.

const SKIP_DIR_NAMES = new Set([
    'node_modules', '.git', '.hg', '.svn', '.idea', '.vscode',
    'appdata', '.cache', 'caches', 'temp', 'tmp', '.npm', '.m2',
    '.gradle', '.rustup', '.cargo', 'site-packages', '$recycle.bin',
    'system volume information', 'program files', 'program files (x86)',
    'windows', 'programdata', 'recovery',
].map((s) => s.toLowerCase()));

function candidateScanDirs() {
    const home = os.homedir();
    const resourcesPath = process.resourcesPath || path.join(__dirname, '..');
    const baseDir = path.dirname(resourcesPath);
    const raw = [
        home,
        path.join(home, 'Desktop'),
        path.join(home, 'Documents'),
        path.join(home, 'Downloads'),
        path.join(home, 'Pictures'),
        path.join(home, 'Music'),
        path.join(home, 'Videos'),
        path.join(home, 'OneDrive', 'Desktop'),
        path.join(home, 'OneDrive', 'Documents'),
        path.join(home, 'OneDrive', 'Downloads'),
        os.tmpdir(),
        process.cwd(),
        resourcesPath,
        __dirname,
        path.join(__dirname, '..'),
        baseDir,
        path.join(baseDir, 'electron'),
        path.join(baseDir, 'scripts'),
        path.join(baseDir, 'vendor', 'win'),
        path.join(baseDir, 'fixtures'),
        path.join(baseDir, 'output'),
        path.join(baseDir, 'logs'),
    ];
    const out = [];
    const seen = new Set();
    for (const d of raw) {
        if (!d) continue;
        const resolved = path.resolve(d);
        if (resolved.toLowerCase().indexOf('.asar') !== -1) continue; // asar-virtual dirs are not real paths for tools
        const key = resolved.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        try {
            if (fs.statSync(resolved).isDirectory()) out.push(resolved);
        } catch (_e) { /* not present — skip */ }
    }
    return out;
}

// Deep coverage applies only to the user's own folders, so subfolder files
// (e.g. Desktop\reports\findings.jsonl) are discovered too. System/work dirs
// (temp, app resources) stay shallow to keep the scan bounded.
function isDeepScanRoot(dir) {
    const home = os.homedir().toLowerCase();
    const d = dir.toLowerCase();
    if (d === home) return true;
    if (d.indexOf('onedrive') !== -1) return true;
    const deepNames = ['desktop', 'documents', 'downloads', 'pictures', 'music', 'videos'];
    for (const name of deepNames) {
        if (d === path.join(home, name).toLowerCase()) return true;
    }
    return false;
}

function walkScanDir(root, depth, maxDepth, exts, withDirs, isWin, files, dirs, seenFiles, seenDirs, fileCap, dirCap) {
    if (files.length >= fileCap && (!withDirs || dirs.length >= dirCap)) return;
    let entries;
    try {
        entries = fs.readdirSync(root, { withFileTypes: true });
    } catch (_e) {
        return;
    }
    for (const entry of entries) {
        if (files.length >= fileCap && (!withDirs || dirs.length >= dirCap)) return;
        const name = entry.name;
        if (name.startsWith('.') || name === '$Recycle.Bin') continue;
        const full = path.join(root, name);
        if (full.toLowerCase().indexOf('.asar') !== -1) continue; // never suggest asar-virtual paths
        const key = isWin ? full.toLowerCase() : full;
        if (entry.isDirectory()) {
            if (depth < maxDepth && !SKIP_DIR_NAMES.has(name.toLowerCase())) {
                walkScanDir(full, depth + 1, maxDepth, exts, withDirs, isWin, files, dirs, seenFiles, seenDirs, fileCap, dirCap);
            }
            if (withDirs && dirs.length < dirCap && !seenDirs.has(key)) {
                seenDirs.add(key);
                dirs.push(full);
            }
        } else if (entry.isFile()) {
            const ext = path.extname(name).toLowerCase();
            if (exts.length > 0 && !exts.includes(ext)) continue;
            if (seenFiles.has(key)) continue;
            seenFiles.add(key);
            if (files.length < fileCap) files.push(full);
        }
    }
}

ipcMain.handle('scan-paths', async (_event, options) => {
    const exts = Array.isArray(options?.exts)
        ? options.exts.map((e) => String(e).toLowerCase())
        : [];
    const withDirs = options?.withDirs !== false;
    const fileCap = Math.min(Math.max(Number(options?.cap) || 300, 1), 1000);
    const dirCap = 60;
    const isWin = process.platform === 'win32';
    const files = [];
    const dirs = [];
    const seenFiles = new Set();
    const seenDirs = new Set();

    for (const dir of candidateScanDirs()) {
        const maxDepth = isDeepScanRoot(dir) ? 3 : 1;
        walkScanDir(dir, 1, maxDepth, exts, withDirs, isWin, files, dirs, seenFiles, seenDirs, fileCap, dirCap);
    }

    files.sort((a, b) => a.localeCompare(b));
    dirs.sort((a, b) => a.localeCompare(b));
    return { files, dirs };
});
