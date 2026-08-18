const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { execFile, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');

// ── Native NAPI module (embedded Rust cognitive layer) ────────────────────────
let nativeModule = null;
function loadNativeModule() {
    if (nativeModule) return nativeModule;
    // Platform-specific shared library extension
    const ext = process.platform === 'win32' ? 'node' : 'so';
    const dll = process.platform === 'win32' ? 'dll' : 'so';
    const base = `security_agent.${ext}`;
    const alt  = `security_agent.${dll}`;
    const soFile = `libsecurity_agent.so`;  // Linux cargo output name
    // All candidate filenames to search (in order)
    const names = [base, alt, soFile];
    // Search roots: packaged resources, dev build dirs
    const roots = [
        process.resourcesPath || '',
        path.join(__dirname, '..'),
        path.join(__dirname, '..', '..'),
    ];
    const subdirs = ['target/release', 'target/debug', ''];
    const candidates = [];
    for (const root of roots) {
        for (const sub of subdirs) {
            for (const name of names) {
                candidates.push(path.join(root, sub, name));
            }
        }
    }
    for (const candidate of candidates) {
        try {
            if (fs.existsSync(candidate)) {
                nativeModule = require(candidate);
                emitLog('info', `Loaded native module: ${candidate}`);
                return nativeModule;
            }
        } catch (e) {
            emitLog('warn', `Failed to load native module from ${candidate}: ${e.message}`);
        }
    }
    emitLog('warn', 'Native module not found — falling back to binary spawning');
    return null;
}

let mainWindow = null;
let binaryPath = null;

// ── Bundled real tools ─────────────────────────────────────────────────────
// The app ships real tool binaries in a `tools/` directory (dev:
// `electron/tools`, packaged: `<app>/resources/tools`). SECURITY_AGENT_TOOL_DIR
// points the Rust binary at that directory so `--list-tools` reports those
// tools as executable even when they are not installed on PATH.
function bundledToolsDir() {
    const root = process.resourcesPath || path.join(__dirname, '..');
    const dirs = [path.join(root, 'tools')];
    // Multi-file tools keep their runtime folders (hashcat needs modules/,
    // john needs its run/ tree, nmap needs its data files); each is scanned.
    for (const sub of ['hashcat', path.join('john', 'run'), 'aircrack-ng', 'nmap', 'ncrack', path.join('python', 'Scripts')]) {
        dirs.push(path.join(root, 'tools', sub));
    }
    const existing = dirs.filter((d) => fs.existsSync(d));
    return existing.length ? existing.join(path.delimiter) : null;
}

function binaryEnv() {
    const env = { ...process.env, TERM: 'dumb' };
    const tools = bundledToolsDir();
    if (tools) env.SECURITY_AGENT_TOOL_DIR = tools;
    return env;
}

// ── Bundled offline LLM ─────────────────────────────────────────────────────
// The real local transformer ships with the app (dev: `assets/model` at the
// repo root, packaged: `<app>/resources/assets/model`). The renderer must not
// guess paths, so the main process resolves the directory and injects
// `--model <dir>` into LM-backed runs — guaranteeing the chat page uses the
// real model rather than the tiny bundled fallback.
function bundledModelDir() {
    const roots = [];
    if (process.resourcesPath) roots.push(process.resourcesPath);
    roots.push(path.join(__dirname, '..'));
    for (const root of roots) {
        const dir = path.join(root, 'assets', 'model');
        try {
            if (fs.existsSync(path.join(dir, 'config.json')) &&
                fs.existsSync(path.join(dir, 'tokenizer.json')) &&
                fs.existsSync(path.join(dir, 'model.safetensors'))) {
                return dir;
            }
        } catch (_e) { /* keep scanning */ }
    }
    return null;
}

// The optional `--model <dir>` back-end is only compiled into binaries built
// with `--features inference`; default release builds reject the flag (exit
// 2). Probe once at startup so the GUI never injects `--model` into a binary
// that cannot use it — otherwise every chat reply would fail. null = not yet
// probed; true/false = cached result.
let binarySupportsModel = null;

// Push the latest bundled-model support state to the renderer so the chat
// page's model chip can label "offline LLM active" vs "toy model fallback".
function emitModelStatus() {
    try {
        mainWindow.webContents.send('model-status', {
            supported: binarySupportsModel,
            modelDir: bundledModelDir(),
        });
    } catch (_e) { /* window gone */ }
}

// Promised probe: resolves with whether the current binary accepts `--model`
// (i.e. was built with `--features inference`). The result is cached, so the
// GUI never injects `--model` into a binary that would reject it, and the
// chat chip can label itself accurately without blocking on a slow model
// load. Runs in the background; the renderer is pushed the result.
let binarySupportsModelPromise = null;
function bundledModelSupport() {
    if (binarySupportsModel !== null) return Promise.resolve(binarySupportsModel);
    if (binarySupportsModelPromise) return binarySupportsModelPromise;
    const dir = bundledModelDir();
    if (!dir || !binaryPath) {
        binarySupportsModel = false;
        emitModelStatus();
        return Promise.resolve(false);
    }
    binarySupportsModelPromise = new Promise((resolve) => {
        execFile(binaryPath, ['--chat-reply', '--model', dir, 'ping'], {
            timeout: 20_000,
            maxBuffer: 1024 * 1024,
            encoding: 'utf-8',
            windowsHide: true,
            env: binaryEnv(),
        }, (error, stdout, stderr) => {
            const text = (stderr || '') + (error ? String(error) : '');
            binarySupportsModel = !/requires a build with `--features inference`/.test(text);
            binarySupportsModelPromise = null;
            emitLog(binarySupportsModel ? 'info' : 'warn',
                'bundled offline model ' + (binarySupportsModel ? 'supported (inference build)' : 'NOT supported by this binary (no --features inference) — chat falls back to the toy model'));
            emitModelStatus();
            resolve(binarySupportsModel);
        });
    });
    return binarySupportsModelPromise;
}

// Startup kick-off (the probe runs in the background and pushes its result).
function probeBundledModelSupport() {
    bundledModelSupport();
}

// Adds `--model <dir>` right after the command for LM-backed runs (`--chat-reply`
// and `--agent`), unless the caller already chose a model. Runs the check on the
// original args so a user-supplied `--model` always wins.
function injectBundledModel(args) {
    if (!Array.isArray(args) || args.length === 0) return args;
    if (args.includes('--model')) return args;
    if (binarySupportsModel !== true) return args;
    const first = args[0];
    if (first !== '--chat-reply' && first !== '--agent') return args;
    const dir = bundledModelDir();
    if (!dir) return args;
    emitLog('info', 'injecting bundled offline model: ' + dir);
    return [first, '--model', dir].concat(args.slice(1));
}

// ── Run tracking (for Cancel) ─────────────────────────────────────────────
// Every live child is tracked in a Set so cancel-run can terminate the whole
// group, and a second run never silently orphans the first.
const liveChildren = new Set();
const STREAM_MAX_BYTES = 16 * 1024 * 1024;   // cap accumulated streamed output
const RUN_TIMEOUT_MS = 10 * 60 * 1000;       // streaming runs: 10 minute ceiling
// The wrapped binary spawns a background LM/asset thread that can keep stdout
// open after all real output has been printed, so the process never exits on a
// normal pipe. To avoid a 10-minute hang on every streamed command, terminate
// the child once stdout has been silent for this long AND we have received data.
// Override with SECAGENT_IDLE_KILL_MS (ms).
const IDLE_KILL_MS = Number(process.env.SECAGENT_IDLE_KILL_MS) || 30 * 1000;

// ── Network opt-in (trust boundary) ───────────────────────────────────────
// "Offline by default" is enforced HERE, in the main process, not just in the
// renderer. The renderer's Offline/Online toggle calls set-network-mode; a
// compromised renderer cannot pass --allow-network/--listen/--execute while
// the main process is offline.
let networkMode = false;

// ── Workspace root (write/read confinement) ───────────────────────────────
const WORKSPACE_BASE = path.join(os.homedir(), 'Security-Agent-Workspace');
const WORKSPACE_SUBDIRS = ['engagements', 'findings', 'reports', 'exports', 'runs'];

// Is this path allowed for renderer-requested file I/O? Only paths inside the
// per-user workspace (never the app's own files, never outside the workspace).
function assertWorkspacePath(p) {
    if (typeof p !== 'string' || !p) return 'path must be a non-empty string';
    const resolved = path.resolve(p);
    const base = path.resolve(WORKSPACE_BASE);
    if (resolved === base || resolved.startsWith(base + path.sep)) return null;
    // Never let the renderer touch the app's own files even inside the tree.
    const appRoot = path.resolve(path.join(__dirname, '..'));
    if (resolved === appRoot || resolved.startsWith(appRoot + path.sep)) {
        return 'writing to application files is not allowed';
    }
    return 'path is outside the workspace: ' + resolved;
}

// ── Verbose logging ─────────────────────────────────────────────────────────
// Every log line is written to the main-process console AND forwarded to the
// renderer, where it appears in the collapsible Log Console (bottom bar).
// Command arguments are redacted before logging so secrets never reach the
// log buffer or the renderer.
const LOG_BUFFER = [];
const LOG_MAX_BUFFER = 500;
const REDACTED_ARG_FLAGS = new Set([
    '--password-strength', '--obfuscate-ps', '--ask', '--agent', '--llm-generate',
    '--llm-perplexity', '--analyze-payload', '--gen-shell', '--gen-wordlist',
    '--hash-id', '--analyze-passwd', '--analyze-sudoers', '--analyze-keys',
    '--analyze-hosts', '--analyze-handshake', '--wps-pin', '--fragment-payload',
    '--ip-checksum', '--analyze-deauth', '--audit-wifi',
]);

function redactArgs(args) {
    if (!Array.isArray(args)) return String(args);
    const out = args.map(String);
    for (let i = 0; i < out.length; i++) {
        if (REDACTED_ARG_FLAGS.has(out[i]) && i + 1 < out.length) {
            out[i + 1] = '[redacted]';
            i++;
        }
    }
    return out;
}

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

    emitLog('warn', 'security-agent binary not found. Checked: ' + roots.join(', '));
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
        // In dev the icon asset sits next to main.js; in a packaged build the
        // icon is embedded in the exe and electron uses it automatically, so we
        // only set an explicit icon when the asset is actually present.
        icon: fs.existsSync(path.join(__dirname, 'assets', isWindows ? 'icon.ico' : 'icon.png'))
            ? path.join(__dirname, 'assets', isWindows ? 'icon.ico' : 'icon.png')
            : undefined,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
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
    emitLog('info', 'Main window created (contextIsolation=true, nodeIntegration=false, sandbox=true)');
}

// When this module is required by an alternate entry (e.g. system-test.js), the
// IPC handlers below are still registered at module load, but we must NOT spin
// up a second BrowserWindow or a second app lifecycle. Only the direct entry
// (electron .) owns the window/activate flow.
if (require.main === module) {
    app.whenReady().then(() => {
        emitLog('info', 'Security-Agent main process starting (platform=' + process.platform + ', electron=' + process.versions.electron + ')');
        binaryPath = resolveBinaryPath();
        emitLog(binaryPath ? 'info' : 'warn', binaryPath ? 'Using binary: ' + binaryPath : 'NO binary available — binary-backed commands will report errors');
        probeBundledModelSupport();
        createWindow();
        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createWindow();
        });
    });
}

    app.on('window-all-closed', () => {
        if (process.platform !== 'darwin') app.quit();
    });

// ── Agent tool-usage config ─────────────────────────────────────────────────
// Serves config/agent-tools.json — the desktop tool catalog the agent uses to
// choose tools and resolve their inputs/outputs inside the workspace, so the
// user never has to type file locations.
ipcMain.handle('get-agent-config', async (event) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const file = path.join(__dirname, 'config', 'agent-tools.json');
    try {
        const text = await fs.promises.readFile(file, 'utf-8');
        const cfg = JSON.parse(text);
        return { ok: true, config: cfg };
    } catch (err) {
        emitLog('error', 'get-agent-config failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});

// Allow an alternate entry (test harness) to point the handlers at its own
// BrowserWindow and resolved binary path before driving the renderer.
function setMainWindow(window) { mainWindow = window; }
function setBinaryPath(path) { binaryPath = path; }

module.exports = { setMainWindow, setBinaryPath };

// ── IPC Handlers ──────────────────────────────────────────────────────────

// Only accept IPC from our own main window's renderer.
function trusted(event) {
    return !!mainWindow && !mainWindow.isDestroyed() && event.sender === mainWindow.webContents;
}

ipcMain.handle('get-app-info', (event) => {
    if (!trusted(event)) return null;
    return {
        platform: process.platform,
        electron: process.versions.electron,
        node: process.versions.node,
        chrome: process.versions.chrome,
        binaryPath,
        binaryFound: !!binaryPath,
        binarySupportsModel, // null = probe still in flight; true/false = result
        bundledModelDir: bundledModelDir(),
    };
});

ipcMain.handle('set-network-mode', (event, mode) => {
    if (!trusted(event)) return { ok: false };
    const next = mode === 'online';
    networkMode = next;
    emitLog('warn', 'network mode set to ' + (next ? 'ONLINE' : 'offline'));
    return { ok: true, networkMode };
});

// ── Command execution ─────────────────────────────────────────────────────

function gateNetworkArgs(args) {
    // While offline, refuse any run that would opt into live/active behavior.
    if (networkMode) return null;
    const live = ['--allow-network', '--listen', '--execute', '--run-external-tool'];
    for (const flag of live) {
        if (Array.isArray(args) && args.includes(flag)) {
            return `refused: '${flag}' requires online mode (Offline/Online toggle in the header)`;
        }
    }
    return null;
}

ipcMain.handle('run-command', (event, args) => {
    if (!trusted(event)) return { ok: false, stdout: '', stderr: 'untrusted sender', exitCode: 1 };
    emitLog('info', 'run-command: ' + redactArgs(args).join(' '));
    return new Promise((resolve) => {
        if (!binaryPath) {
            emitLog('error', 'run-command refused: binary not found');
            resolve({ ok: false, stdout: '', stderr: 'security-agent binary not found', exitCode: 1 });
            return;
        }
        const refused = gateNetworkArgs(args);
        if (refused) {
            emitLog('warn', 'run-command refused (offline): ' + refused);
            resolve({ ok: false, stdout: '', stderr: refused, exitCode: 1 });
            return;
        }
        const proc = execFile(binaryPath, injectBundledModel(args), {
            timeout: 120_000,
            maxBuffer: 1024 * 1024,
            encoding: 'utf-8',
            windowsHide: true,
            env: binaryEnv(),
        }, (error, stdout, stderr) => {
            liveChildren.delete(proc);
            const cancelled = !!proc._cancelled;
            if (error) {
                const code = error.code != null ? error.code : 1;
                emitLog('warn', `run-command finished exit=${code} cancelled=${cancelled} stderr=${(stderr || String(error)).slice(0, 200)}`);
                resolve({ ok: !cancelled && code === 0, stdout: stdout || '', stderr: stderr || String(error), exitCode: cancelled ? 130 : code, cancelled });
            } else {
                emitLog('info', `run-command finished exit=0 stdoutBytes=${(stdout || '').length}`);
                resolve({ ok: true, stdout: stdout || '', stderr: stderr || '', exitCode: 0, cancelled: false });
            }
        });
        liveChildren.add(proc);
    });
});

ipcMain.handle('run-streaming', (event, args) => {
    if (!trusted(event)) return { ok: false, stdout: '', stderr: 'untrusted sender', exitCode: 1 };
    emitLog('info', 'run-streaming: ' + redactArgs(args).join(' '));
    return new Promise((resolve) => {
        if (!binaryPath) {
            emitLog('error', 'run-streaming refused: binary not found');
            resolve({ ok: false, stdout: '', stderr: 'security-agent binary not found', exitCode: 1 });
            return;
        }
        const refused = gateNetworkArgs(args);
        if (refused) {
            emitLog('warn', 'run-streaming refused (offline): ' + refused);
            resolve({ ok: false, stdout: '', stderr: refused, exitCode: 1 });
            return;
        }
        const proc = spawn(binaryPath, injectBundledModel(args), {
            env: binaryEnv(),
            windowsHide: true,
        });
        liveChildren.add(proc);
        let stdout = '';
        let stderr = '';
        let stdoutTruncated = false;
        let stderrTruncated = false;
        let lastChunkTs = 0;
        const killTimer = setTimeout(() => {
            if (!proc._cancelled) {
                proc._cancelled = true;
                emitLog('warn', `run-streaming timed out after ${RUN_TIMEOUT_MS / 1000}s — terminating pid=${proc.pid}`);
                killTree(proc);
            }
        }, RUN_TIMEOUT_MS);
        if (killTimer.unref) killTimer.unref();
        // Idle watchdog: once we've seen output, if stdout stays silent for
        // IDLE_KILL_MS the binary has effectively finished (lingering thread
        // holding the pipe open). Terminate and report success.
        const idleTimer = setInterval(() => {
            if (lastChunkTs > 0 && Date.now() - lastChunkTs > IDLE_KILL_MS &&
                !proc._cancelled && !proc._idleDone) {
                proc._idleDone = true;
                emitLog('info', `run-streaming idle ${IDLE_KILL_MS / 1000}s after last output — terminating pid=${proc.pid}`);
                killTree(proc);
            }
        }, 5000);
        if (idleTimer.unref) idleTimer.unref();

        proc.stdout.on('data', (data) => {
            const chunk = data.toString();
            if (chunk.length > 0) lastChunkTs = Date.now();
            if (stdout.length + chunk.length > STREAM_MAX_BYTES) {
                stdoutTruncated = true;
                stdout += chunk.slice(0, Math.max(0, STREAM_MAX_BYTES - stdout.length));
            } else {
                stdout += chunk;
            }
            if (!stdoutTruncated && mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('stream-chunk', chunk);
            }
        });
        proc.stderr.on('data', (data) => {
            const chunk = data.toString();
            if (stderr.length + chunk.length > STREAM_MAX_BYTES) {
                stderrTruncated = true;
                stderr += chunk.slice(0, Math.max(0, STREAM_MAX_BYTES - stderr.length));
            } else {
                stderr += chunk;
            }
            // stderr is NOT forwarded as stream chunks; it lands in res.stderr
            // so consumers render it once in their own stderr element.
        });
        proc.on('close', (code) => {
            clearTimeout(killTimer);
            clearInterval(idleTimer);
            liveChildren.delete(proc);
            const cancelled = !!proc._cancelled;
            const idleDone = !!proc._idleDone;
            // An idle-terminated run that produced output is a success.
            const exitCode = code == null ? (cancelled ? 130 : (idleDone ? 0 : 1)) : code;
            if (stdoutTruncated) stdout += '\n[output truncated at 16 MiB]';
            if (stderrTruncated) stderr += '\n[output truncated at 16 MiB]';
            emitLog('info', `run-streaming finished exit=${exitCode} cancelled=${cancelled} idleDone=${idleDone} stdoutBytes=${stdout.length} stderrBytes=${stderr.length}`);
            resolve({ ok: !cancelled && (code === 0 || idleDone), stdout, stderr, exitCode, cancelled });
        });
        proc.on('error', (err) => {
            clearTimeout(killTimer);
            clearInterval(idleTimer);
            liveChildren.delete(proc);
            emitLog('error', 'run-streaming spawn error: ' + String(err));
            resolve({ ok: false, stdout, stderr: String(err), exitCode: 1 });
        });
    });
});

// Terminates a child and, on Windows, its whole process tree.
function killTree(proc) {
    if (!proc || proc.pid == null) return;
    try {
        if (process.platform === 'win32') {
            spawn('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { windowsHide: true });
        } else {
            try { process.kill(-proc.pid, 'SIGKILL'); } catch (_e) { proc.kill('SIGKILL'); }
        }
    } catch (_e) { /* already gone */ }
    try { proc.kill('SIGKILL'); } catch (_e) { /* already gone */ }
}

// Cancels every live child process.
ipcMain.handle('cancel-run', (event) => {
    if (!trusted(event)) return { ok: true, cancelled: false };
    if (liveChildren.size === 0) return { ok: true, cancelled: false };
    emitLog('warn', `cancel-run: terminating ${liveChildren.size} child process(es)`);
    for (const proc of liveChildren) {
        proc._cancelled = true;
        killTree(proc);
    }
    liveChildren.clear();
    return { ok: true, cancelled: true };
});

// ── Listener (Server view) ────────────────────────────────────────────────
// Long-lived reverse-shell listener. The wrapped binary's --listen relay is
// line-oriented: operator stdin lines are forwarded to the connected shell,
// remote shell output is written to stdout, and status/banner lines go to
// stderr. We spawn it with pipes so the renderer gets an interactive
// terminal: stdout → 'listener-output' (session data), stderr →
// 'listener-event' (status lines), and listener-stdin writes commands to the
// connected shell. 'exit' on stdin (or Ctrl-D) only closes the CURRENT
// session — the listener keeps accepting, so Stop terminates the process.
let listenerProc = null;

function listenerRunning() {
    return !!listenerProc && listenerProc.pid != null && !listenerProc.killed;
}

ipcMain.handle('start-listener', (event, options) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    if (listenerRunning()) return { ok: false, error: 'a listener is already running' };
    const opts = options || {};
    const port = parseInt(opts.port, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return { ok: false, error: 'port must be an integer between 1 and 65535' };
    }
    // Opening a listening socket is live/active behavior: it requires the
    // explicit online opt-in. Enforced HERE in main, never only in the UI.
    if (!networkMode) {
        return { ok: false, error: 'starting a listener requires Online mode (Offline/Online toggle in the sidebar)' };
    }
    if (!binaryPath) return { ok: false, error: 'security-agent binary not found' };

    const args = ['--allow-network', '--listen', String(port)];
    const maxConn = parseInt(opts.maxConnections, 10);
    if (Number.isInteger(maxConn) && maxConn > 0) args.push(String(maxConn));
    const bind = (typeof opts.bindAddress === 'string' && opts.bindAddress.trim()) ? opts.bindAddress.trim() : '0.0.0.0';
    args.push(bind);
    if (opts.sessionLog) {
        args.push('--log', path.join(WORKSPACE_BASE, 'runs', 'listener-sessions.jsonl'));
    }
    emitLog('warn', 'start-listener: ' + redactArgs(args).join(' '));

    return new Promise((resolve) => {
        const proc = spawn(binaryPath, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: { ...process.env, TERM: 'dumb' },
            windowsHide: true,
        });
        listenerProc = proc;
        liveChildren.add(proc);

        let settled = false;
        const settle = (res) => { if (!settled) { settled = true; resolve(res); } };

        proc.stdout.on('data', (data) => {
            // Session data coming back from the connected shell.
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('listener-output', data.toString());
            }
        });
        proc.stderr.on('data', (data) => {
            // Status/banner lines from the listener itself.
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('listener-event', data.toString());
            }
        });
        proc.on('close', (code) => {
            liveChildren.delete(proc);
            const cancelled = !!proc._cancelled;
            if (listenerProc === proc) listenerProc = null;
            emitLog('warn', `start-listener exited code=${code} cancelled=${cancelled}`);
            settle({ ok: !cancelled && code === 0, running: false, exitCode: code, cancelled });
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('listener-status', { running: false, exitCode: code, cancelled });
            }
        });
        proc.on('error', (err) => {
            liveChildren.delete(proc);
            if (listenerProc === proc) listenerProc = null;
            emitLog('error', 'start-listener spawn error: ' + String(err));
            settle({ ok: false, error: String(err), running: false });
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send('listener-status', { running: false, error: String(err) });
            }
        });
        // The spawn itself is enough to report "running"; the banner on stderr
        // updates the UI with bind details shortly after.
        settle({ ok: true, running: true, pid: proc.pid, args: redactArgs(args) });
    });
});

// Writes one command line to the connected shell via the listener's stdin.
ipcMain.handle('listener-stdin', (event, line) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    if (!listenerRunning()) return { ok: false, error: 'listener is not running' };
    const text = String(line == null ? '' : line);
    if (text.length > 65536) return { ok: false, error: 'line too long (>64 KiB)' };
    try {
        listenerProc.stdin.write(text + '\n');
        return { ok: true };
    } catch (err) {
        return { ok: false, error: String(err) };
    }
});

// Terminates the listener process tree (equivalent to pressing Ctrl-C in the
// binary, but enforced from here because we control the child's lifetime).
ipcMain.handle('stop-listener', (event) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    if (!listenerRunning()) return { ok: true, stopped: false };
    emitLog('warn', 'stop-listener: terminating listener pid=' + listenerProc.pid);
    listenerProc._cancelled = true;
    killTree(listenerProc);
    return { ok: true, stopped: true };
});

// ── Payload generation (Server view) ───────────────────────────────────────
// --gen-shell is a LOCAL operation (no socket, no network) so it works in
// offline mode, but the payload text is sensitive: it is redacted from logs
// (see REDACTED_ARG_FLAGS) and never persisted to history by the renderer.

ipcMain.handle('gen-shell', (event, shellType, lhost, lport) => {
    if (!trusted(event)) return { ok: false, stdout: '', stderr: 'untrusted sender', exitCode: 1 };
    emitLog('info', 'gen-shell: type=' + String(shellType) + ' lhost=' + String(lhost) + ' lport=' + String(lport));
    return new Promise((resolve) => {
        if (!binaryPath) {
            resolve({ ok: false, stdout: '', stderr: 'security-agent binary not found', exitCode: 1 });
            return;
        }
        execFile(binaryPath, ['--gen-shell', String(shellType), String(lhost), String(lport)], {
            timeout: 30_000,
            maxBuffer: 1024 * 1024,
            encoding: 'utf-8',
            windowsHide: true,
            env: binaryEnv(),
        }, (error, stdout, stderr) => {
            if (error) {
                const code = error.code != null ? error.code : 1;
                emitLog('warn', `gen-shell failed exit=${code} stderr=${(stderr || String(error)).slice(0, 200)}`);
                resolve({ ok: code === 0, stdout: stdout || '', stderr: stderr || String(error), exitCode: code });
            } else {
                emitLog('info', `gen-shell ok stdoutBytes=${(stdout || '').length}`);
                resolve({ ok: true, stdout: stdout || '', stderr: stderr || '', exitCode: 0 });
            }
        });
    });
});

// Returns the shell payload catalog for the Server view's type dropdown.
// Parsed from --gen-shell --list; falls back to the known catalog if the
// binary is missing or the parse fails, so the UI never breaks.
ipcMain.handle('get-shell-types', async (event) => {
    if (!trusted(event)) return { ok: false, types: [], error: 'untrusted sender' };
    const fallback = [
        { id: 'powershell', name: 'PowerShell Reverse Shell', aliases: 'powershell, ps, ps1', platform: 'Windows (PowerShell 2.0+)', desc: 'One-liner PowerShell reverse shell (plain TCP client + process launch).' },
        { id: 'bash', name: 'Reverse Bash Shell', aliases: 'bash, sh', platform: 'Linux / Unix', desc: 'One-line bash reverse shell using /dev/tcp.' },
        { id: 'netcat', name: 'Reverse Netcat Shell', aliases: 'netcat, nc', platform: 'Linux / Unix', desc: 'Reverse shell via netcat + named pipe.' },
        { id: 'python', name: 'Reverse Python Shell', aliases: 'python, python3, py', platform: 'Linux / Unix / Windows', desc: 'Reverse shell via python3 socket + os.dup2.' },
        { id: 'perl', name: 'Reverse Perl Shell', aliases: 'perl', platform: 'Linux / Unix', desc: 'Reverse shell via perl Socket module.' },
        { id: 'ruby', name: 'Reverse Ruby Shell', aliases: 'ruby', platform: 'Linux / Unix', desc: 'Reverse shell via ruby -rsocket.' },
        { id: 'php', name: 'Reverse PHP Shell', aliases: 'php', platform: 'Linux / Unix', desc: 'Reverse shell via php fsockopen.' },
        { id: 'tcp', name: 'Reverse TCP Shell', aliases: 'tcp', platform: 'Linux x86_64', desc: 'Raw x86_64 reverse TCP shellcode (syscall-based).' },
        { id: 'bind', name: 'Bind TCP Shell', aliases: 'bind, bindtcp', platform: 'Linux / Unix', desc: 'Bind shell: the target listens and you connect to it.' },
        { id: 'meterpreter', name: 'Meterpreter Reverse TCP', aliases: 'meterpreter, msf', platform: 'Windows / Linux', desc: 'Meterpreter reverse TCP stage (requires local msfvenom).' },
        { id: 'http', name: 'Reverse HTTP Shell', aliases: 'http', platform: 'Windows / Linux', desc: 'Meterpreter reverse HTTP stager (requires local msfvenom).' },
        { id: 'https', name: 'Reverse HTTPS Shell', aliases: 'https', platform: 'Windows / Linux', desc: 'Meterpreter reverse HTTPS stager (requires local msfvenom).' },
    ];
    if (!binaryPath) return { ok: false, types: fallback, error: 'binary not found' };
    try {
        const listOut = await new Promise((resolve, reject) => {
            execFile(binaryPath, ['--gen-shell', '--list'], { timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true, env: binaryEnv() },
                (error, stdout) => error ? reject(error) : resolve(stdout));
        });
        const types = [];
        const lines = listOut.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
            const m = lines[i].match(/^(.*?)\s+aliases:\s*(.+)$/);
            if (!m) continue;
            const name = m[1].trim();
            const aliases = m[2].split(',').map((s) => s.trim()).filter(Boolean);
            if (aliases.length === 0) continue;
            const platform = (lines[i + 1] || '').match(/^\s*platform:\s*(.+)$/);
            const desc = (lines[i + 2] || '').trim();
            types.push({
                id: aliases[0],
                name: name,
                aliases: aliases.join(', '),
                platform: platform ? platform[1].trim() : '',
                desc: desc,
            });
        }
        if (types.length > 0) {
            emitLog('info', `shell payload catalog: ${types.length} types`);
            return { ok: true, types };
        }
        return { ok: true, types: fallback };
    } catch (err) {
        emitLog('error', 'get-shell-types failed: ' + String(err));
        return { ok: false, types: fallback, error: String(err) };
    }
});

ipcMain.handle('select-file', async (event, options) => {
    if (!trusted(event)) return null;
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openFile'],
        filters: options?.filters || [],
    });
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
});

// Save dialog + write in one step so renderer-supplied paths never bypass the
// user's explicit "Save as" choice.
ipcMain.handle('save-file', async (event, options, content) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const result = await dialog.showSaveDialog(mainWindow, {
        filters: options?.filters || [],
    });
    if (result.canceled || !result.filePath) return null;
    const text = String(content == null ? '' : content);
    if (text.length > 16 * 1024 * 1024) return { ok: false, error: 'content too large to save (>16 MiB)' };
    try {
        await fs.promises.writeFile(result.filePath, text, 'utf-8');
        return { ok: true, path: result.filePath };
    } catch (err) {
        return { ok: false, error: String(err) };
    }
});

// Writes a text file — only inside the workspace. Rejects symlinks/junctions
// so a pre-planted link inside the workspace cannot redirect the write to a
// path outside the sandbox (path.resolve is lexical and does not follow
// Windows junctions).
ipcMain.handle('write-file', async (event, filePath, content) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const violation = assertWorkspacePath(filePath);
    if (violation) return { ok: false, error: violation };
    const text = String(content == null ? '' : content);
    if (text.length > 16 * 1024 * 1024) return { ok: false, error: 'content too large to write (>16 MiB)' };
    try {
        await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
        const parent = await fs.promises.realpath(path.dirname(filePath));
        await fs.promises.mkdir(WORKSPACE_BASE, { recursive: true });
        const base = await fs.promises.realpath(WORKSPACE_BASE);
        if (parent !== base && !parent.startsWith(base + path.sep)) {
            return { ok: false, error: 'workspace path traverses a junction/symlink outside the workspace' };
        }
        const target = path.join(parent, path.basename(filePath));
        try {
            const stats = await fs.promises.lstat(target);
            if (stats.isSymbolicLink()) return { ok: false, error: 'symlinks are not allowed' };
        } catch (_e) { /* target does not exist yet — fine */ }
        await fs.promises.writeFile(target, text, 'utf-8');
        return { ok: true };
    } catch (err) {
        return { ok: false, error: String(err) };
    }
});

// Reads a text file — only inside the workspace, never a symlink, 2 MiB cap.
ipcMain.handle('read-file', async (event, filePath) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const violation = assertWorkspacePath(filePath);
    if (violation) return { ok: false, error: violation };
    try {
        const stats = await fs.promises.lstat(filePath);
        if (stats.isSymbolicLink()) return { ok: false, error: 'symlinks are not allowed' };
        if (!stats.isFile()) return { ok: false, error: 'not a regular file' };
        if (stats.size > 2 * 1024 * 1024) return { ok: false, error: 'file too large to preview (>2 MiB)' };
        const text = await fs.promises.readFile(filePath, 'utf-8');
        return { ok: true, content: text };
    } catch (err) {
        return { ok: false, error: String(err) };
    }
});

// Resolves (and lazily creates) a per-user workspace for generated configs,
// findings logs, reports, and exported artifacts.
ipcMain.handle('get-workspace', async (event) => {
    if (!trusted(event)) return { ok: false, base: '', subdirs: [] };
    const subdirs = WORKSPACE_SUBDIRS;
    const paths = {};
    try {
        for (const sub of subdirs) {
            const dir = path.join(WORKSPACE_BASE, sub);
            await fs.promises.mkdir(dir, { recursive: true });
            paths[sub] = dir;
        }
        return { ok: true, base: WORKSPACE_BASE, subdirs, paths };
    } catch (err) {
        emitLog('error', 'get-workspace failed: ' + String(err));
        return { ok: false, error: String(err), base: WORKSPACE_BASE, subdirs, paths };
    }
});

// ── Tool catalog cache (parsed from the binary's --list-tools) ─────────────
let toolCatalogCache = null;

ipcMain.handle('get-tool-catalog', async (event) => {
    if (!trusted(event)) return { ok: false, tools: [], skills: 0, error: 'untrusted sender' };
    if (toolCatalogCache) return toolCatalogCache;
    if (!binaryPath) return { ok: false, tools: [], skills: 0, error: 'binary not found' };
    try {
        const run = (flag) => new Promise((resolve, reject) => {
            execFile(binaryPath, [flag], { timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true, env: binaryEnv() },
                (error, stdout, stderr) => error ? reject(error) : resolve(stdout));
        });
        const [listOut, statusOut] = await Promise.all([run('--list-tools'), run('--offline-status')]);
        const tools = listOut.split(/\r?\n/).filter(Boolean).map((line) => {
            const cols = line.split('\t');
            return {
                name: cols[0] || '',
                kind: cols[1] || 'cataloged',
                executable: cols.find((c) => c.startsWith('executable='))?.slice(11) || null,
                integrity: cols.find((c) => c.startsWith('integrity='))?.slice(10) || 'built-in',
            };
        }).filter((t) => t.name);
        const status = {};
        for (const line of statusOut.split(/\r?\n/).filter(Boolean)) {
            const idx = line.indexOf('=');
            if (idx > 0) status[line.slice(0, idx)] = line.slice(idx + 1);
        }
        toolCatalogCache = {
            ok: true,
            tools,
            skills: parseInt(status.embedded_skills || '0', 10),
            builtIn: parseInt(status.built_in_substitute_tools || '0', 10),
            executable: parseInt(status.locally_executable_tools || '0', 10),
            integrity: parseInt(status.integrity_verified_tools || '0', 10),
            coverage: status.capability_coverage || 'unknown',
        };
        emitLog('info', `tool catalog cached: ${toolCatalogCache.tools.length} tools, ${toolCatalogCache.skills} skills`);
        return toolCatalogCache;
    } catch (err) {
        emitLog('error', 'get-tool-catalog failed: ' + String(err));
        return { ok: false, tools: [], skills: 0, error: String(err) };
    }
});

// ── Native module IPC handlers ──────────────────────────────────────────────

ipcMain.handle('native-model-info', async (event) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const native = loadNativeModule();
    if (!native) return { ok: false, error: 'native module not loaded' };
    try {
        const info = await native.init_bundled_model();
        return { ok: true, ...info };
    } catch (err) {
        emitLog('error', 'native-model-info failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});

ipcMain.handle('native-list-tools', async (event) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const native = loadNativeModule();
    if (!native) return { ok: false, error: 'native module not loaded' };
    try {
        const tools = await native.list_tools();
        return { ok: true, tools };
    } catch (err) {
        emitLog('error', 'native-list-tools failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});

ipcMain.handle('native-execute-tool', async (event, name, args, timeoutSecs) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const native = loadNativeModule();
    if (!native) return { ok: false, error: 'native module not loaded' };
    try {
        const result = await native.execute_tool(name, args || [], timeoutSecs);
        return { ok: true, ...result };
    } catch (err) {
        emitLog('error', 'native-execute-tool failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});

ipcMain.handle('native-run-agent', async (event, goal, options) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const native = loadNativeModule();
    if (!native) return { ok: false, error: 'native module not loaded' };
    try {
        const agent = new native.CognitiveAgentHandle(
            options?.maxSteps ?? 8,
            options?.maxTokensPerCall ?? 256,
            options?.toolTimeoutSecs ?? 120,
            options?.tokenLimit ?? 8000
        );
        const result = await agent.run(goal);
        return { ok: true, ...result };
    } catch (err) {
        emitLog('error', 'native-run-agent failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});

ipcMain.handle('native-test-inference', async (event, prompt, maxTokens) => {
    if (!trusted(event)) return { ok: false, error: 'untrusted sender' };
    const native = loadNativeModule();
    if (!native) return { ok: false, error: 'native module not loaded' };
    try {
        const result = await native.test_inference(prompt, maxTokens ?? 64);
        return { ok: true, text: result };
    } catch (err) {
        emitLog('error', 'native-test-inference failed: ' + String(err));
        return { ok: false, error: String(err) };
    }
});
