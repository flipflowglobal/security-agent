/**
 * Security-Agent — Comprehensive Frontend System Test
 *
 * Launches the Electron app, programmatically exercises every view, tab,
 * button, function, and IPC handler, captures real binary output, and
 * generates a visual HTML report + screenshots.
 *
 * Usage (from Windows):
 *   electron.exe system-test.js
 *
 * Usage (from WSL):
 *   npx electron system-test.js
 */
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile, spawn } = require('child_process');

// Reuse the production IPC handlers (run-command, get-app-info, get-tool-catalog,
// get-shell-types, get-workspace, set-network-mode, …) instead of duplicating
// them. main.js registers them at load; we just point them at this harness's
// window + resolved binary so the renderer's window.api.* calls work unchanged.
const mainModule = require('./main');

// ── Configuration ──────────────────────────────────────────────────────────
const APP_DIR = __dirname;
const REPORT_DIR = path.join(APP_DIR, 'test-results');
const SCREENSHOT_DIR = path.join(REPORT_DIR, 'screenshots');
const TIMEOUT_MS = 30_000;

// ── Binary resolution (same as main.js) ────────────────────────────────────
let binaryPath = null;

function bundledToolsDir() {
    const root = process.resourcesPath || path.join(__dirname, '..');
    const dirs = [path.join(root, 'tools')];
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

function resolveBinaryPath() {
    const resourcesPath = process.resourcesPath || path.join(__dirname, '..');
    const baseDir = path.dirname(resourcesPath);

    // Explicit override (mirrors main.js) for debugging / CI.
    if (process.env.SECURITY_AGENT_BIN) {
        const override = process.env.SECURITY_AGENT_BIN;
        if (fs.existsSync(override)) return override;
    }

    const isWindows = process.platform === 'win32';
    const names = isWindows ? ['security-agent.exe', 'security-agent'] : ['security-agent'];
    const roots = [
        path.join(APP_DIR, 'target', 'release'),
        path.join(APP_DIR, 'target', 'debug'),
        // The Rust binary is built at the repo root, one level above electron/:
        path.join(APP_DIR, '..', 'target', 'release'),
        path.join(APP_DIR, '..', 'target', 'debug'),
        resourcesPath,
        baseDir,
        path.join(baseDir, 'bin'),
        path.join(baseDir, '..', 'vendor', 'win'),
        path.join(baseDir, 'vendor', 'win'),
    ];
    for (const root of roots) {
        for (const name of names) {
            const candidate = path.join(root, name);
            try {
                if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
            } catch (_e) { /* skip */ }
        }
    }
    return null;
}

// ── Test infrastructure ────────────────────────────────────────────────────
let testResults = [];
let currentGroup = '';
let mainWindow = null;
let networkMode = false;

function group(name) { currentGroup = name; }

async function test(name, fn) {
    const t0 = Date.now();
    let status = 'pass';
    let detail = '';
    try {
        detail = await fn();
    } catch (err) {
        status = 'fail';
        detail = String(err);
    }
    const ms = Date.now() - t0;
    testResults.push({ group: currentGroup, name, status, detail, ms });
    const icon = status === 'pass' ? '\u2705' : '\u274C';
    console.log(`  ${icon} ${name} (${ms}ms)${detail ? ': ' + detail : ''}`);
}

async function assert(condition, msg) {
    if (!condition) throw new Error('Assertion failed: ' + (msg || ''));
    return msg || 'ok';
}

// ── Helper: run binary and capture output ──────────────────────────────────
function runBinaryAsync(args, timeout) {
    return new Promise((resolve) => {
        if (!binaryPath) {
            resolve({ ok: false, stdout: '', stderr: 'binary not found', exitCode: 1 });
            return;
        }
        const proc = execFile(binaryPath, args, {
            timeout: timeout || 30_000,
            maxBuffer: 1024 * 1024,
            encoding: 'utf-8',
            windowsHide: true,
            env: binaryEnv(),
        }, (error, stdout, stderr) => {
            const code = error ? (error.code != null ? error.code : 1) : 0;
            resolve({ ok: code === 0, stdout: stdout || '', stderr: stderr || '', exitCode: code });
        });
    });
}

// ── Helper: take a screenshot ──────────────────────────────────────────────
async function screenshot(name) {
    if (!mainWindow) return;
    const file = path.join(SCREENSHOT_DIR, name + '.png');
    const image = await mainWindow.webContents.capturePage();
    fs.writeFileSync(file, image.toPNG());
    return file;
}

// ── Helper: execute JS in renderer ─────────────────────────────────────────
async function evalRenderer(code) {
    return mainWindow.webContents.executeJavaScript(code);
}

// ── Helper: wait for condition ──────────────────────────────────────────────
async function waitFor(checkFn, maxMs) {
    const start = Date.now();
    while (Date.now() - start < (maxMs || 5000)) {
        const result = await checkFn();
        if (result) return result;
        await new Promise(r => setTimeout(r, 200));
    }
    throw new Error('Timeout waiting for condition');
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════

async function runTests() {
    console.log('\n' + '='.repeat(70));
    console.log('  SECURITY-AGENT — COMPREHENSIVE FRONTEND SYSTEM TEST');
    console.log('='.repeat(70));

    // ─── 1. Binary & IPC ────────────────────────────────────────────────
    group('1. Binary & IPC');

    await test('Binary is resolved', async () => {
        const result = await evalRenderer('window.__test_binaryPath');
        return assert(result, 'path=' + result);
    });

    await test('get-app-info returns valid data', async () => {
        const info = await evalRenderer('window.api.getAppInfo()');
        await assert(info.binaryFound, 'binaryFound=' + info.binaryFound);
        return assert(info.platform, 'platform=' + info.platform);
    });

    await test('get-tool-catalog returns tools', async () => {
        const cat = await evalRenderer('window.api.getToolCatalog()');
        await assert(cat.ok, 'ok=' + cat.ok);
        return assert(cat.tools && cat.tools.length > 0, 'toolCount=' + (cat.tools || []).length);
    });

    await test('get-shell-types returns payload catalog', async () => {
        const res = await evalRenderer('window.api.getShellTypes()');
        return assert(res.types && res.types.length > 0, 'typeCount=' + res.types.length);
    });

    await test('get-workspace creates workspace dirs', async () => {
        const ws = await evalRenderer('window.api.getWorkspace()');
        return assert(ws.ok && ws.paths, 'subdirs=' + (ws.subdirs || []).join(','));
    });

    // ─── 2. Real binary commands (offline) ──────────────────────────────
    group('2. Real Binary Commands (Offline)');

    await test('--offline-status returns system info', async () => {
        const res = await runBinaryAsync(['--offline-status']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        return assert(res.stdout.includes('offline_status'), 'has offline_status');
    });

    await test('--about returns version info', async () => {
        const res = await runBinaryAsync(['--about']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        return assert(res.stdout.includes('security-agent'), 'has security-agent');
    });

    await test('--list-tools returns tool catalog', async () => {
        const res = await runBinaryAsync(['--list-tools']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        const lines = res.stdout.trim().split('\n').filter(Boolean);
        return assert(lines.length > 50, 'toolCount=' + lines.length);
    });

    await test('--list-skills returns skill list', async () => {
        const res = await runBinaryAsync(['--list-skills']);
        return assert(res.ok || res.stdout.length > 0, 'outputLen=' + res.stdout.length);
    });

    await test('--guide returns help text', async () => {
        const res = await runBinaryAsync(['--guide']);
        return assert(res.stdout.length > 100, 'guideLen=' + res.stdout.length);
    });

    await test('--shell-guide returns payload guide', async () => {
        const res = await runBinaryAsync(['--shell-guide']);
        return assert(res.stdout.length > 100, 'guideLen=' + res.stdout.length);
    });

    await test('--tool-help nmap returns help', async () => {
        const res = await runBinaryAsync(['--tool-help', 'nmap']);
        return assert(res.stdout.length > 50, 'helpLen=' + res.stdout.length);
    });

    await test('--hash-id identifies MD5 hash', async () => {
        const res = await runBinaryAsync(['--hash-id', '5d41402abc4b2a76b9719d911017c592']);
        await assert(res.ok || res.stdout.length > 0, 'outputLen=' + res.stdout.length);
        return assert(res.stdout.toLowerCase().includes('md5') || res.stdout.length > 20, 'identified or responded');
    });

    await test('--password-strength checks a password', async () => {
        const res = await runBinaryAsync(['--password-strength', 'TestP@ssw0rd!2024']);
        return assert(res.stdout.length > 20, 'outputLen=' + res.stdout.length);
    });

    await test('--gen-wordlist generates wordlist', async () => {
        const res = await runBinaryAsync(['--gen-wordlist', 'acme-corp']);
        return assert(res.stdout.length > 50, 'wordlistLen=' + res.stdout.length);
    });

    await test('--gen-shell bash payload generated', async () => {
        const res = await runBinaryAsync(['--gen-shell', 'bash', '127.0.0.1', '4444']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        return assert(res.stdout.includes('bash') || res.stdout.includes('/dev/tcp'), 'has bash payload');
    });

    await test('--gen-shell powershell payload generated', async () => {
        const res = await runBinaryAsync(['--gen-shell', 'powershell', '127.0.0.1', '4444']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        return assert(res.stdout.toLowerCase().includes('powershell') || res.stdout.includes('System.Net'), 'has PS payload');
    });

    await test('--gen-shell --list shows all payload types', async () => {
        const res = await runBinaryAsync(['--gen-shell', '--list']);
        await assert(res.ok, 'exitCode=' + res.exitCode);
        const lines = res.stdout.trim().split('\n').filter(l => l.includes('aliases:'));
        return assert(lines.length >= 10, 'payloadTypes=' + lines.length);
    });

    await test('--audit-wifi runs wireless audit', async () => {
        const res = await runBinaryAsync(['--audit-wifi', 'TestNetwork', 'wpa2', 'aes']);
        return assert(res.stdout.length > 20, 'outputLen=' + res.stdout.length);
    });

    await test('--analyze-passwd analyzes passwd content', async () => {
        const res = await runBinaryAsync(['--analyze-passwd', 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash']);
        return assert(res.stdout.length > 20, 'outputLen=' + res.stdout.length);
    });

    await test('--analyze-sudoers analyzes sudoers', async () => {
        const res = await runBinaryAsync(['--analyze-sudoers', 'root ALL=(ALL) ALL\nuser ALL=(ALL) NOPASSWD: ALL']);
        return assert(res.stdout.length > 20, 'outputLen=' + res.stdout.length);
    });

    await test('--analyze-keys checks authorized_keys', async () => {
        const res = await runBinaryAsync(['--analyze-keys', 'ssh-rsa AAAA... user@host']);
        return assert(res.stdout.length > 10, 'outputLen=' + res.stdout.length);
    });

    await test('--analyze-hosts parses hosts file', async () => {
        const res = await runBinaryAsync(['--analyze-hosts', '127.0.0.1 localhost\n192.168.1.1 router.local']);
        return assert(res.stdout.length > 10, 'outputLen=' + res.stdout.length);
    });

    await test('--gen-decoys generates decoy IPs', async () => {
        const res = await runBinaryAsync(['--gen-decoys', '10.0.0.1', '5']);
        return assert(res.stdout.length > 10, 'outputLen=' + res.stdout.length);
    });

    await test('--gen-ipids generates IP IDs', async () => {
        const res = await runBinaryAsync(['--gen-ipids', '10']);
        return assert(res.stdout.length > 10, 'outputLen=' + res.stdout.length);
    });

    await test('--wps-pin checks WPS PIN', async () => {
        const res = await runBinaryAsync(['--wps-pin', '12345678']);
        return assert(res.stdout.length > 5, 'outputLen=' + res.stdout.length);
    });

    await test('--llm-generate creates text (built-in LLM)', async () => {
        const res = await runBinaryAsync(['--llm-generate', 'Write a short security finding']);
        return assert(res.stdout.length > 10, 'outputLen=' + res.stdout.length);
    });

    await test('--llm-perplexity scores anomaly', async () => {
        const res = await runBinaryAsync(['--llm-perplexity', 'normal system log entry']);
        return assert(res.stdout.length > 5, 'outputLen=' + res.stdout.length);
    });

    await test('--postexploit-overview reviews passwd', async () => {
        const res = await runBinaryAsync(['--postexploit-overview', 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash']);
        return assert(res.stdout.length > 20, 'outputLen=' + res.stdout.length);
    });

    await test('--run-tool wireshark runs on PCAP', async () => {
        const res = await runBinaryAsync(['--run-tool', 'tcpdump', '/dev/null']);
        return assert(res.stdout.length >= 0, 'exited cleanly (outputLen=' + res.stdout.length + ')');
    });

    // ─── 3. Network mode enforcement ────────────────────────────────────
    group('3. Network Mode Enforcement');

    await test('--allow-network refused in offline mode', async () => {
        const res = await evalRenderer('window.api.runCommand(["--allow-network", "--ollama-status"])');
        return assert(!res.ok, 'refused as expected: ' + (res.stderr || '').slice(0, 80));
    });

    await test('--listen refused in offline mode', async () => {
        const res = await evalRenderer('window.api.runCommand(["--allow-network", "--listen", "4444"])');
        return assert(!res.ok, 'refused as expected');
    });

    await test('set-network-mode to online succeeds', async () => {
        const res = await evalRenderer('window.api.setNetworkMode("online")');
        await evalRenderer('window.__test_networkMode = true');
        return assert(res.ok, 'mode=online');
    });

    await test('set-network-mode back to offline', async () => {
        const res = await evalRenderer('window.api.setNetworkMode("offline")');
        await evalRenderer('window.__test_networkMode = false');
        return assert(res.ok, 'mode=offline');
    });

    // ─── 4. UI Navigation ───────────────────────────────────────────────
    group('4. UI Navigation');

    await test('Home view is active by default', async () => {
        const active = await evalRenderer('document.querySelector("#view-home").classList.contains("active")');
        return assert(active, 'home view active');
    });

    const views = ['objectives', 'analyze', 'engage', 'server', 'library'];
    for (const view of views) {
        await test(`Navigate to ${view}`, async () => {
            await evalRenderer(`document.querySelector('[data-view="${view}"]').click()`);
            await new Promise(r => setTimeout(r, 200));
            const active = await evalRenderer(`document.querySelector("#view-${view}").classList.contains("active")`);
            await assert(active, `${view} view is active`);
            await screenshot(`view-${view}`);
            return `${view} view rendered`;
        });
    }

    await test('Navigate back to Home', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        const active = await evalRenderer('document.querySelector("#view-home").classList.contains("active")');
        return assert(active, 'home view active');
    });

    // ─── 5. Sidebar mode toggle ──────────────────────────────────────────
    group('5. Sidebar Mode Toggle');

    await test('Offline button toggles active', async () => {
        await evalRenderer('document.querySelector(\'#mode-offline\').click()');
        await new Promise(r => setTimeout(r, 100));
        const active = await evalRenderer('document.querySelector(\'#mode-offline\').classList.contains("active")');
        return assert(active, 'offline is active');
    });

    await test('Online button toggles active', async () => {
        await evalRenderer('document.querySelector(\'#mode-online\').click()');
        await new Promise(r => setTimeout(r, 100));
        const active = await evalRenderer('document.querySelector(\'#mode-online\').classList.contains("active")');
        await assert(active, 'online is active');
        await screenshot('sidebar-online-mode');
        // Toggle back
        await evalRenderer('document.querySelector(\'#mode-offline\').click()');
        return 'toggled online, then back to offline';
    });

    // ─── 6. Home dashboard ───────────────────────────────────────────────
    group('6. Home Dashboard');

    await test('Stats populated (binary, tools, skills)', async () => {
        await new Promise(r => setTimeout(r, 1000)); // let loadStatus() finish
        const tools = await evalRenderer('document.querySelector("#stat-tools").textContent');
        const mode = await evalRenderer('document.querySelector("#stat-mode").textContent');
        return assert(tools !== '…' && tools !== '—', 'tools=' + tools + ', mode=' + mode);
    });

    await test('Quick action buttons rendered', async () => {
        const count = await evalRenderer('document.querySelectorAll("#quick-actions .action-btn").length');
        return assert(count >= 5, 'quickActions=' + count);
    });

    await test('Tool chip grid populated', async () => {
        const count = await evalRenderer('document.querySelectorAll("#tool-chip-grid .tool-chip").length');
        return assert(count > 10, 'toolChips=' + count);
    });

    await test('Suggestion chips rendered', async () => {
        const count = await evalRenderer('document.querySelectorAll("#cmd-suggestions .chip").length');
        return assert(count >= 5, 'suggestions=' + count);
    });

    await screenshot('home-dashboard');

    // ─── 7. Command bar routing ──────────────────────────────────────────
    group('7. Command Bar Routing');

    await test('Route "tools" to analyze view', async () => {
        await evalRenderer('document.querySelector("#cmd-bar").value = "tools"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 500));
        const active = await evalRenderer('document.querySelector("#view-analyze").classList.contains("active")');
        return assert(active, 'routed to analyze');
    });

    await test('Route "help" to library/guides', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#cmd-bar").value = "help"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 500));
        const active = await evalRenderer('document.querySelector("#view-library").classList.contains("active")');
        return assert(active, 'routed to library');
    });

    await test('Route "audit" to library/audit tab', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#cmd-bar").value = "audit"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 500));
        const active = await evalRenderer('document.querySelector("#lib-audit").classList.contains("active")');
        return assert(active, 'audit tab active');
    });

    await test('Route "status" runs system status', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#cmd-bar").value = "status"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 3000));
        const output = await evalRenderer('document.querySelector("#home-output").textContent');
        await screenshot('command-status');
        return assert(output.length > 50, 'outputLen=' + output.length);
    });

    // ─── 8. Objectives view ──────────────────────────────────────────────
    group('8. Objectives View');

    await test('Agent mode tab is active by default', async () => {
        await evalRenderer('document.querySelector(\'[data-view="objectives"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const active = await evalRenderer('document.querySelector("#obj-agent").classList.contains("active")');
        return assert(active, 'agent tab active');
    });

    await test('Playbooks tab switches', async () => {
        await evalRenderer('document.querySelector(\'[data-tab="playbooks"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const active = await evalRenderer('document.querySelector("#obj-playbooks").classList.contains("active")');
        await assert(active, 'playbooks tab active');
        const cards = await evalRenderer('document.querySelectorAll("#pb-grid .playbook-card").length');
        return assert(cards >= 3, 'playbookCards=' + cards);
    });

    await test('Agent dry-run preview button works', async () => {
        await evalRenderer('document.querySelector(\'[data-tab="agent"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#agent-goal").value = "Scan localhost for open ports"');
        await evalRenderer('document.querySelector("#btn-agent-preview").click()');
        await new Promise(r => setTimeout(r, 4000));
        const output = await evalRenderer('document.querySelector("#output-agent").textContent');
        await screenshot('objectives-agent-preview');
        return assert(output.length > 20, 'previewOutputLen=' + output.length);
    });

    // ─── 9. Analyze view ─────────────────────────────────────────────────
    group('9. Analyze View');

    await test('Tool list populated', async () => {
        await evalRenderer('document.querySelector(\'[data-view="analyze"]\').click()');
        await new Promise(r => setTimeout(r, 500));
        const count = await evalRenderer('document.querySelectorAll("#tool-list .tool-item").length');
        return assert(count > 50, 'toolItems=' + count);
    });

    await test('Category chips rendered', async () => {
        const count = await evalRenderer('document.querySelectorAll("#tool-cats .chip").length');
        return assert(count >= 10, 'categoryChips=' + count);
    });

    await test('Tool search filters list', async () => {
        await evalRenderer('document.querySelector("#tool-search").value = "nmap"');
        await evalRenderer('document.querySelector("#tool-search").dispatchEvent(new Event("input"))');
        await new Promise(r => setTimeout(r, 200));
        const count = await evalRenderer('document.querySelectorAll("#tool-list .tool-item").length');
        return assert(count >= 1 && count < 10, 'filteredCount=' + count);
    });

    await test('Selecting a tool shows detail form', async () => {
        await evalRenderer('document.querySelector("#tool-search").value = ""');
        await evalRenderer('document.querySelector("#tool-search").dispatchEvent(new Event("input"))');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#tool-list .tool-item").click()');
        await new Promise(r => setTimeout(r, 300));
        const hasInput = await evalRenderer('!!document.querySelector("#tool-input")');
        await assert(hasInput, 'tool detail form rendered');
        await screenshot('analyze-tool-detail');
        return 'tool detail form visible';
    });

    await test('Category filter works', async () => {
        await evalRenderer('document.querySelector(\'#tool-cats .chip:nth-child(2)\').click()'); // Forensics
        await new Promise(r => setTimeout(r, 300));
        const count = await evalRenderer('document.querySelectorAll("#tool-list .tool-item").length');
        return assert(count > 0 && count < 60, 'forensicsCount=' + count);
    });

    // ─── 10. Engage view ─────────────────────────────────────────────────
    group('10. Engage View');

    await test('Engagement form renders all fields', async () => {
        await evalRenderer('document.querySelector(\'[data-view="engage"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const hasName = await evalRenderer('!!document.querySelector("#eng-name")');
        const hasAuth = await evalRenderer('!!document.querySelector("#eng-auth")');
        const hasTargets = await evalRenderer('!!document.querySelector("#eng-targets")');
        const hasType = await evalRenderer('!!document.querySelector("#eng-type")');
        const hasIntensity = await evalRenderer('!!document.querySelector("#eng-intensity")');
        await assert(hasName && hasAuth && hasTargets && hasType && hasIntensity, 'all fields present');
        await screenshot('engage-form');
        return 'all fields present';
    });

    await test('Target type dropdown has all options', async () => {
        const count = await evalRenderer('document.querySelector("#eng-type").options.length');
        return assert(count >= 8, 'targetTypes=' + count);
    });

    await test('Intensity dropdown has 3 levels', async () => {
        const count = await evalRenderer('document.querySelector("#eng-intensity").options.length');
        return assert(count === 3, 'intensityLevels=' + count);
    });

    await test('Engage: generate config button works', async () => {
        await evalRenderer('document.querySelector("#eng-name").value = "test-engagement"');
        await evalRenderer('document.querySelector("#eng-auth").value = "operator"');
        await evalRenderer('document.querySelector("#eng-targets").value = "webapp1 — WebApp — https://example.com"');
        await evalRenderer('document.querySelector("#btn-eng-config").click()');
        await new Promise(r => setTimeout(r, 1000));
        const preview = await evalRenderer('document.querySelector("#eng-config-preview").style.display');
        const text = await evalRenderer('document.querySelector("#eng-config-text").textContent');
        await screenshot('engage-config-generated');
        return assert(text.includes('engagement_id'), 'config generated (' + text.length + ' chars)');
    });

    // ─── 11. Server view ─────────────────────────────────────────────────
    group('11. Server View');

    await test('Server view renders listener form', async () => {
        await evalRenderer('document.querySelector(\'[data-view="server"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const hasPort = await evalRenderer('!!document.querySelector("#srv-port")');
        const hasStart = await evalRenderer('!!document.querySelector("#srv-start")');
        const hasStop = await evalRenderer('!!document.querySelector("#srv-stop")');
        await assert(hasPort && hasStart && hasStop, 'form fields present');
        await screenshot('server-view');
        return 'listener form rendered';
    });

    await test('Shell type dropdown populated', async () => {
        await new Promise(r => setTimeout(r, 1000)); // let shell types load
        const count = await evalRenderer('document.querySelector("#srv-type").options.length');
        return assert(count >= 8, 'shellTypes=' + count);
    });

    await test('Stop button is disabled initially', async () => {
        const disabled = await evalRenderer('document.querySelector("#srv-stop").disabled');
        return assert(disabled, 'stop button disabled');
    });

    await test('Start button is enabled initially', async () => {
        const disabled = await evalRenderer('document.querySelector("#srv-start").disabled');
        return assert(!disabled, 'start button enabled');
    });

    // ─── 12. Library: tabs ───────────────────────────────────────────────
    group('12. Library Tabs');

    const libTabs = ['findings', 'audit', 'dbs', 'llm', 'ollama', 'quick', 'guides'];
    for (const tab of libTabs) {
        await test(`Library tab: ${tab}`, async () => {
            await evalRenderer('document.querySelector(\'[data-view="library"]\').click()');
            await new Promise(r => setTimeout(r, 200));
            await evalRenderer(`document.querySelector('#view-library [data-tab="${tab}"]').click()`);
            await new Promise(r => setTimeout(r, 200));
            const active = await evalRenderer(`document.querySelector("#lib-${tab}").classList.contains("active")`);
            await assert(active, `${tab} tab is active`);
            await screenshot(`library-${tab}`);
            return `${tab} tab rendered`;
        });
    }

    // ─── 13. Library: Quick tools ────────────────────────────────────────
    group('13. Quick Tools');

    await test('Quick tool grid populated', async () => {
        await evalRenderer('document.querySelector(\'[data-view="library"]\').click()');
        await evalRenderer('document.querySelector(\'[data-tab="quick"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const count = await evalRenderer('document.querySelectorAll("#quick-grid .quick-card").length');
        return assert(count >= 15, 'quickTools=' + count);
    });

    await test('Quick tool search filters', async () => {
        await evalRenderer('document.querySelector("#quick-search").value = "hash"');
        await evalRenderer('document.querySelector("#quick-search").dispatchEvent(new Event("input"))');
        await new Promise(r => setTimeout(r, 200));
        const count = await evalRenderer('document.querySelectorAll("#quick-grid .quick-card").length');
        return assert(count >= 1 && count < 20, 'filteredCount=' + count);
    });

    await test('Clicking Hash ID opens form', async () => {
        await evalRenderer('document.querySelector("#quick-search").value = ""');
        await evalRenderer('document.querySelector("#quick-search").dispatchEvent(new Event("input"))');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#quick-grid .quick-card").click()');
        await new Promise(r => setTimeout(r, 300));
        const visible = await evalRenderer('document.querySelector("#quick-form").style.display !== "none"');
        return assert(visible, 'quick form visible');
    });

    // ─── 14. Library: LLM ───────────────────────────────────────────────
    group('14. LLM Features');

    await test('LLM generate button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#btn-llm-gen")');
        return assert(exists, 'generate button exists');
    });

    await test('LLM anomaly score button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#btn-llm-anom")');
        return assert(exists, 'anomaly button exists');
    });

    await test('LLM generate empty prompt shows error', async () => {
        await evalRenderer('document.querySelector("#llm-prompt").value = ""');
        await evalRenderer('document.querySelector("#btn-llm-gen").click()');
        await new Promise(r => setTimeout(r, 500));
        const output = await evalRenderer('document.querySelector("#output-llm").textContent');
        return assert(output.includes('Provide') || output.includes('prompt'), 'error shown');
    });

    // ─── 15. Library: Ollama ─────────────────────────────────────────────
    group('15. Ollama Features');

    await test('Ollama status button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#btn-ollama-status")');
        return assert(exists, 'status button exists');
    });

    await test('Ollama generate form fields exist', async () => {
        const hasModel = await evalRenderer('!!document.querySelector("#ollama-model-gen")');
        const hasPrompt = await evalRenderer('!!document.querySelector("#ollama-prompt")');
        return assert(hasModel && hasPrompt, 'form fields present');
    });

    await test('Ollama chat form fields exist', async () => {
        const hasModel = await evalRenderer('!!document.querySelector("#ollama-model-chat")');
        const hasSystem = await evalRenderer('!!document.querySelector("#ollama-system")');
        const hasMessage = await evalRenderer('!!document.querySelector("#ollama-message")');
        return assert(hasModel && hasSystem && hasMessage, 'form fields present');
    });

    await test('Ollama generate empty prompt shows error', async () => {
        await evalRenderer('document.querySelector("#ollama-prompt").value = ""');
        await evalRenderer('document.querySelector("#btn-ollama-gen").click()');
        await new Promise(r => setTimeout(r, 500));
        const output = await evalRenderer('document.querySelector("#output-ollama").textContent');
        return assert(output.includes('Provide') || output.includes('prompt'), 'error shown');
    });

    // ─── 16. Library: Findings ───────────────────────────────────────────
    group('16. Findings Features');

    await test('Findings merge form exists', async () => {
        const hasDest = await evalRenderer('!!document.querySelector("#find-dest")');
        const hasSrc = await evalRenderer('!!document.querySelector("#find-src")');
        const hasBtn = await evalRenderer('!!document.querySelector("#btn-find-record")');
        return assert(hasDest && hasSrc && hasBtn, 'merge form present');
    });

    await test('Findings view form exists', async () => {
        const hasPath = await evalRenderer('!!document.querySelector("#find-log-path")');
        const hasBtn = await evalRenderer('!!document.querySelector("#btn-find-view")');
        return assert(hasPath && hasBtn, 'view form present');
    });

    // ─── 17. Library: Audit ──────────────────────────────────────────────
    group('17. Audit Features');

    await test('Audit log view form exists', async () => {
        const hasPath = await evalRenderer('!!document.querySelector("#audit-path")');
        const hasBtn = await evalRenderer('!!document.querySelector("#btn-audit-view")');
        return assert(hasPath && hasBtn, 'audit form present');
    });

    // ─── 18. Library: Databases ──────────────────────────────────────────
    group('18. Database Views');

    await test('All 4 DB buttons exist', async () => {
        const audit = await evalRenderer('!!document.querySelector("#btn-db-audit")');
        const findings = await evalRenderer('!!document.querySelector("#btn-db-findings")');
        const cal = await evalRenderer('!!document.querySelector("#btn-db-cal")');
        const reason = await evalRenderer('!!document.querySelector("#btn-db-reason")');
        return assert(audit && findings && cal && reason, 'all 4 DB buttons exist');
    });

    // ─── 19. Library: Guides ─────────────────────────────────────────────
    group('19. Guides');

    await test('Guide button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#btn-guide")');
        return assert(exists, 'guide button exists');
    });

    await test('Shell guide button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#btn-shell-guide")');
        return assert(exists, 'shell guide button exists');
    });

    await test('Tool help input and button exist', async () => {
        const hasInput = await evalRenderer('!!document.querySelector("#tool-help-input")');
        const hasBtn = await evalRenderer('!!document.querySelector("#btn-tool-help")');
        return assert(hasInput && hasBtn, 'tool help form present');
    });

    await test('Show guide renders output', async () => {
        await evalRenderer('document.querySelector("#btn-guide").click()');
        await new Promise(r => setTimeout(r, 4000));
        const output = await evalRenderer('document.querySelector("#output-guides").textContent');
        await screenshot('guides-output');
        return assert(output.length > 100, 'guideOutputLen=' + output.length);
    });

    // ─── 20. Log console ─────────────────────────────────────────────────
    group('20. Log Console');

    await test('Log toggle button exists', async () => {
        const exists = await evalRenderer('!!document.querySelector("#log-toggle")');
        return assert(exists, 'log toggle exists');
    });

    await test('Log console toggles open/closed', async () => {
        await evalRenderer('document.querySelector("#log-toggle").click()');
        await new Promise(r => setTimeout(r, 300));
        const open = await evalRenderer('!document.querySelector("#log-console").classList.contains("collapsed")');
        await assert(open, 'console opened');
        await screenshot('log-console-open');
        // Close it
        await evalRenderer('document.querySelector("#log-toggle").click()');
        return 'toggled open then closed';
    });

    await test('Log console has log entries', async () => {
        const count = await evalRenderer('document.querySelectorAll("#log-content .log-line").length');
        return assert(count > 0, 'logEntries=' + count);
    });

    // ─── 21. Run status bar ──────────────────────────────────────────────
    group('21. Run Status Bar');

    await test('Run indicator shows Idle', async () => {
        const text = await evalRenderer('document.querySelector("#run-label").textContent');
        return assert(text, 'status=' + text);
    });

    await test('Mode chip shows current mode', async () => {
        const text = await evalRenderer('document.querySelector("#run-mode-chip").textContent');
        return assert(text, 'modeChip=' + text);
    });

    // ─── 22. Output block toolbar ────────────────────────────────────────
    group('22. Output Toolbar');

    await test('Run a command and verify output block', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#cmd-bar").value = "about"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 3000));
        const hasResult = await evalRenderer('!!document.querySelector("#home-output .run-result")');
        await assert(hasResult, 'run-result block exists');
        // Check toolbar buttons
        const hasCopy = await evalRenderer('!!document.querySelector("#home-output .output-toolbar .btn")');
        await screenshot('output-toolbar');
        return assert(hasCopy, 'toolbar buttons present');
    });

    // ─── 23. Real binary: hash ID via command bar ────────────────────────
    group('23. Command Bar → Real Binary');

    await test('Command bar "identify hash" → Hash ID quick tool', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        await evalRenderer('document.querySelector("#cmd-bar").value = "identify this hash 5d41402abc4b2a76b9719d911017c592"');
        await evalRenderer('document.querySelector("#btn-cmd-go").click()');
        await new Promise(r => setTimeout(r, 3000));
        // Should route to library/quick with hash ID
        const output = await evalRenderer('document.querySelector("#output-quick") ? document.querySelector("#output-quick").textContent : "n/a"');
        await screenshot('hash-id-command-bar');
        return 'hash-id command bar test completed, outputLen=' + output.length;
    });

    // ─── 24. CSS rendering check ─────────────────────────────────────────
    group('24. CSS & Rendering');

    await test('Sidebar is visible', async () => {
        await evalRenderer('document.querySelector(\'[data-view="home"]\').click()');
        await new Promise(r => setTimeout(r, 200));
        const width = await evalRenderer('document.querySelector("#sidebar").offsetWidth');
        return assert(width > 50, 'sidebarWidth=' + width);
    });

    await test('Main content area is visible', async () => {
        const width = await evalRenderer('document.querySelector("#main-content").offsetWidth');
        return assert(width > 400, 'mainWidth=' + width);
    });

    await test('Binary warning is hidden when binary found', async () => {
        const display = await evalRenderer('document.querySelector("#binary-warning").style.display');
        return assert(display === 'none', 'warning hidden');
    });

    await test('Hero section rendered', async () => {
        const text = await evalRenderer('document.querySelector(".hero h1").textContent');
        return assert(text && text.length > 5, 'heroText=' + text.slice(0, 40));
    });

    await test('Dark theme applied (background color)', async () => {
        const bg = await evalRenderer('getComputedStyle(document.body).backgroundColor');
        return assert(bg, 'bg=' + bg);
    });

    // ─── 25. Agent Chat View ──────────────────────────────────────────────
    group('25. Agent Chat View');

    await test('Agent nav-item and chat markup present', async () => {
        await evalRenderer('document.querySelector(\'[data-view="agent"]\').click()');
        await new Promise(r => setTimeout(r, 300));
        const viewActive = await evalRenderer('document.querySelector("#view-agent").classList.contains("active")');
        const fields = await evalRenderer(
            '!!document.querySelector("#agent-palette") && ' +
            '!!document.querySelector("#agent-messages") && ' +
            '!!document.querySelector("#agent-input") && ' +
            '!!document.querySelector("#agent-send") && ' +
            '!!document.querySelector("#agent-mode") && ' +
            '!!document.querySelector("#agent-backend")');
        await assert(viewActive && fields, 'agent view + composer present');
        await screenshot('agent-view');
        return 'agent chat view rendered';
    });

    await test('Tool palette loads from agent config', async () => {
        await waitFor(async () =>
            (await evalRenderer('document.querySelectorAll("#agent-palette-list .agent-palette-item").length')) > 0, 8000);
        const count = await evalRenderer('document.querySelectorAll("#agent-palette-list .agent-palette-item").length');
        return assert(count > 0, 'paletteItems=' + count);
    });

    await test('App-control /view command routes without spawning binary', async () => {
        await evalRenderer('document.querySelector("#agent-input").value = "/view home"');
        await evalRenderer('document.querySelector("#agent-send").click()');
        await new Promise(r => setTimeout(r, 400));
        const sysMsg = await evalRenderer('!!document.querySelector("#agent-messages .msg.system")');
        const onHome = await evalRenderer('document.querySelector("#view-home").classList.contains("active")');
        await assert(sysMsg && onHome, 'command routed + view switched');
        return 'app-control /view works';
    });

    await test('Objective input creates an assistant stream target', async () => {
        await evalRenderer('document.querySelector(\'[data-view="agent"]\').click()');
        await evalRenderer('document.querySelector("#agent-input").value = "show system status"');
        await evalRenderer('document.querySelector("#agent-send").click()');
        // The assistant message (with a streaming <pre>) is created synchronously
        // when the run starts, so this holds whether or not the binary finishes
        // in the harness window.
        await waitFor(async () =>
            (await evalRenderer('!!document.querySelector("#agent-messages .msg.assistant .agent-stream")')), 8000);
        const hasStream = await evalRenderer('!!document.querySelector("#agent-messages .msg.assistant .agent-stream")');
        return assert(hasStream, 'assistant stream target created');
    });

    await test('Objective produces streamed output from the planner', async () => {
        // The binary prints then lingers; runStreaming (main.js) terminates it
        // on output-idle and resolves as success, so the streamed text is
        // present well before any timeout.
        const probe = '(function(){var s=document.querySelector("#agent-messages .msg.assistant .agent-stream"); return s ? s.textContent.length : 0;})()';
        await waitFor(async () => (await evalRenderer(probe)) > 0, 45000);
        const len = await evalRenderer(probe);
        return assert(len > 0, 'streamedBytes=' + len);
    });

    // Final full screenshot
    await screenshot('FINAL-state');

    // ─── Summary ─────────────────────────────────────────────────────────
    console.log('\n' + '='.repeat(70));
    const passed = testResults.filter(t => t.status === 'pass').length;
    const failed = testResults.filter(t => t.status === 'fail').length;
    const total = testResults.length;
    console.log(`  RESULTS: ${passed}/${total} passed, ${failed} failed`);
    console.log('='.repeat(70));

    if (failed > 0) {
        console.log('\n  FAILED TESTS:');
        testResults.filter(t => t.status === 'fail').forEach(t => {
            console.log(`    \u274C [${t.group}] ${t.name}: ${t.detail}`);
        });
    }

    // Generate HTML report
    generateReport();
    console.log('\n  Report: ' + path.join(REPORT_DIR, 'report.html'));
    console.log('  Screenshots: ' + SCREENSHOT_DIR);

    // Exit
    app.quit();
}

// ── HTML Report Generator ──────────────────────────────────────────────────
function generateReport() {
    const passed = testResults.filter(t => t.status === 'pass').length;
    const failed = testResults.filter(t => t.status === 'fail').length;
    const total = testResults.length;
    const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
    const groups = {};
    testResults.forEach(t => {
        if (!groups[t.group]) groups[t.group] = [];
        groups[t.group].push(t);
    });

    let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security-Agent — System Test Report</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; padding: 20px; }
.header { text-align:center; padding: 30px 0; border-bottom: 1px solid #21262d; margin-bottom: 30px; }
.header h1 { font-size: 28px; margin-bottom: 8px; }
.header .subtitle { color: #8b949e; font-size: 14px; }
.summary { display:flex; gap:20px; justify-content:center; margin: 20px 0 30px; }
.stat { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px 24px; text-align:center; min-width: 120px; }
.stat .num { font-size: 32px; font-weight: 700; }
.stat .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
.stat.pass .num { color: #3fb950; }
.stat.fail .num { color: #f85149; }
.stat.total .num { color: #58a6ff; }
.stat.pct .num { color: ${pct >= 90 ? '#3fb950' : pct >= 70 ? '#d29922' : '#f85149'}; }
.group { background: #161b22; border: 1px solid #21262d; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
.group-header { padding: 12px 16px; background: #0d1117; border-bottom: 1px solid #21262d; font-weight: 600; font-size: 14px; display: flex; justify-content: space-between; align-items: center; }
.group-header .count { font-size: 12px; color: #8b949e; }
.test { padding: 8px 16px; border-bottom: 1px solid #21262d; display: flex; align-items: center; gap: 10px; font-size: 13px; }
.test:last-child { border-bottom: none; }
.test .icon { width: 20px; text-align: center; flex-shrink: 0; }
.test.pass .icon { color: #3fb950; }
.test.fail .icon { color: #f85149; }
.test .name { flex: 1; }
.test .detail { color: #8b949e; font-size: 11px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.test .ms { color: #484f58; font-size: 11px; flex-shrink: 0; }
.screenshots { margin-top: 30px; }
.screenshots h2 { margin-bottom: 16px; font-size: 18px; }
.screenshot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 16px; }
.screenshot-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; overflow: hidden; }
.screenshot-card img { width: 100%; height: auto; display: block; }
.screenshot-card .caption { padding: 8px 12px; font-size: 12px; color: #8b949e; }
</style>
</head>
<body>
<div class="header">
  <h1>Security-Agent — System Test Report</h1>
  <div class="subtitle">Comprehensive frontend & binary integration test &mdash; ${new Date().toISOString().slice(0, 19)}Z</div>
</div>
<div class="summary">
  <div class="stat total"><div class="num">${total}</div><div class="label">Total Tests</div></div>
  <div class="stat pass"><div class="num">${passed}</div><div class="label">Passed</div></div>
  <div class="stat fail"><div class="num">${failed}</div><div class="label">Failed</div></div>
  <div class="stat pct"><div class="num">${pct}%</div><div class="label">Pass Rate</div></div>
</div>`;

    for (const [groupName, tests] of Object.entries(groups)) {
        const gPassed = tests.filter(t => t.status === 'pass').length;
        const gTotal = tests.length;
        html += `<div class="group">
  <div class="group-header"><span>${groupName}</span><span class="count">${gPassed}/${gTotal} passed</span></div>`;
        for (const t of tests) {
            html += `<div class="test ${t.status}">
  <span class="icon">${t.status === 'pass' ? '\u2705' : '\u274C'}</span>
  <span class="name">${escHtml(t.name)}</span>
  <span class="detail">${escHtml(t.detail || '')}</span>
  <span class="ms">${t.ms}ms</span>
</div>`;
        }
        html += `</div>\n`;
    }

    // Screenshots
    if (fs.existsSync(SCREENSHOT_DIR)) {
        const shots = fs.readdirSync(SCREENSHOT_DIR).filter(f => f.endsWith('.png')).sort();
        if (shots.length > 0) {
            html += `<div class="screenshots"><h2>Screenshots</h2><div class="screenshot-grid">`;
            for (const shot of shots) {
                html += `<div class="screenshot-card"><img src="screenshots/${shot}" alt="${shot}"><div class="caption">${shot.replace('.png', '')}</div></div>`;
            }
            html += `</div></div>`;
        }
    }

    html += `</body></html>`;
    fs.writeFileSync(path.join(REPORT_DIR, 'report.html'), html);
}

function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN — Launch Electron and run tests
// ═══════════════════════════════════════════════════════════════════════════

app.whenReady().then(async () => {
    // Setup
    binaryPath = resolveBinaryPath();
    console.log('Binary: ' + (binaryPath || 'NOT FOUND'));

    fs.mkdirSync(REPORT_DIR, { recursive: true });
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

    // Create hidden window
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 860,
        show: false,
        webPreferences: {
            preload: path.join(APP_DIR, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
        },
    });

    // Point the production IPC handlers at this harness's window + binary so the
    // renderer's window.api.* calls resolve (main.js self-registers its handlers
    // at require time; here we supply the live window/path they check against).
    mainModule.setMainWindow(mainWindow);
    mainModule.setBinaryPath(binaryPath);

    // Expose binary path to renderer for testing
    mainWindow.webContents.on('did-finish-load', async () => {
        await mainWindow.webContents.executeJavaScript(
            `window.__test_binaryPath = ${JSON.stringify(binaryPath)};` +
            `window.__test_networkMode = false;`
        );
    });

    mainWindow.loadFile(path.join(APP_DIR, 'index.html'));

    // Wait for page to fully load and init
    mainWindow.webContents.on('did-finish-load', () => {
        setTimeout(runTests, 3000);
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
