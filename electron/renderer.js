// ═══════════════════════════════════════════════════════════════════════════
// Security-Agent Console — Renderer (UI logic, v2.0)
// Minimal-input console over the real security-agent binary surface:
//   • Command bar with a keyword router that maps plain phrases to real commands
//   • Objectives: agent mode (--agent) + multi-tool playbooks
//   • Analyze: the real 89-tool catalog launcher
//   • Engage: guided plan → execute → report chain (auto-generated config)
//   • Library: findings / audit / databases / LLM / quick tools / guides
// ═══════════════════════════════════════════════════════════════════════════

(function () {
    'use strict';

    // ── Utilities ──────────────────────────────────────────────────────────
    const $ = (sel, ctx) => (ctx || document).querySelector(sel);
    const $$ = (sel, ctx) => Array.prototype.slice.call((ctx || document).querySelectorAll(sel));

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function fmtTime(tsMs) {
        const d = new Date(tsMs);
        const p = (n) => String(n).padStart(2, '0');
        return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }

    // Cross-platform path join (paths come from the main process, so only the
    // separator differs between Windows and macOS).
    const PATH_SEP = navigator.userAgent.indexOf('Windows') !== -1 ? '\\' : '/';
    function joinPath() {
        const parts = Array.prototype.slice.call(arguments).filter(Boolean);
        return parts.join(PATH_SEP);
    }

    // ── State ──────────────────────────────────────────────────────────────
    const state = {
        view: 'home',
        libraryTab: 'findings',
        objTab: 'agent',
        mode: 'offline',
        catalog: null,
        workspace: null,
        currentTool: null,
        currentCategory: 'all',
        currentPlaybook: null,
        currentQuick: null,
        engConfig: null,
        engFindings: null,
        engConfigText: '',
        running: false,
    };

    // ── History (localStorage) ─────────────────────────────────────────────
    const HISTORY_KEY = 'sa_history_v2';
    // Flags whose VALUE is a potential secret — never persisted to localStorage.
    const SENSITIVE_VALUE_FLAGS = new Set([
        '--password-strength', '--obfuscate-ps', '--ask', '--agent', '--llm-generate',
        '--llm-perplexity', '--analyze-payload', '--gen-shell', '--hash-id',
        '--analyze-passwd', '--analyze-sudoers', '--analyze-keys', '--analyze-hosts',
        '--analyze-handshake', '--wps-pin', '--fragment-payload', '--ip-checksum',
        '--analyze-deauth',
    ]);
    // Flags that need an explicit re-confirmation before re-running.
    const DANGEROUS_FLAGS = ['--allow-network', '--listen', '--execute'];
    function redactArgsForHistory(args) {
        const out = (args || []).map(String);
        let redacted = false;
        for (let i = 0; i < out.length; i++) {
            if (SENSITIVE_VALUE_FLAGS.has(out[i]) && i + 1 < out.length) {
                out[i + 1] = '[redacted]';
                redacted = true;
                i++;
            }
        }
        return { args: out, redacted };
    }
    function loadHistory() {
        try {
            const raw = localStorage.getItem(HISTORY_KEY);
            const parsed = raw ? JSON.parse(raw) : [];
            return Array.isArray(parsed) ? parsed : [];
        } catch (_e) { return []; }
    }
    function saveHistory() {
        try { localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history)); } catch (_e) { /* ignore */ }
    }
    function addHistory(entry) {
        const scrubbed = redactArgsForHistory(entry.args);
        state.history.unshift({
            ts: Date.now(),
            label: entry.label,
            args: scrubbed.args,
            redacted: scrubbed.redacted,
            needsConfirm: (entry.args || []).some(function (a) { return DANGEROUS_FLAGS.indexOf(a) !== -1; }),
            ok: !!entry.ok,
            cancelled: !!entry.cancelled,
        });
        if (state.history.length > 20) state.history.length = 20;
        saveHistory();
    }

    // ── Run status bar ─────────────────────────────────────────────────────
    function setRunIndicator(kind, label) {
        const dot = $('#run-indicator');
        const lbl = $('#run-label');
        const cancel = $('#btn-run-cancel');
        dot.className = 'run-indicator ' + (kind === 'idle' ? 'idle' : kind);
        if (label != null) lbl.textContent = label;
        cancel.style.display = (kind === 'running') ? 'inline-flex' : 'none';
        $('#run-mode-chip').textContent = state.mode;
        $('#run-mode-chip').classList.toggle('online', state.mode === 'online');
    }

    // ── Run manager ────────────────────────────────────────────────────────
    let streamTarget = null; // element receiving live chunks
    let activeLoadingEl = null; // last output block setLoading() targeted

    function routeChunk(chunk) {
        if (streamTarget) {
            streamTarget.textContent += chunk;
            streamTarget.scrollTop = streamTarget.scrollHeight;
        }
    }

    function runBinary(args, opts) {
        opts = opts || {};
        const label = (opts.label || args.join(' '));
        if (state.running) {
            return Promise.resolve({
                ok: false, stdout: '', stderr: 'Refused: another task is already running. Cancel it or wait for it to finish.',
                exitCode: 1, cancelled: false, ms: 0, label: label,
                argsLabel: opts.argsLabel != null ? opts.argsLabel : args.join(' '),
            });
        }
        state.running = true;
        setRunIndicator('running', label);
        const t0 = Date.now();
        let promise;
        if (opts.stream) {
            streamTarget = opts.streamTarget || null;
            // Live-stream into the current output block when no explicit target
            // was given, so agent/quick/engage runs show output as it arrives.
            if (!streamTarget && activeLoadingEl) {
                const pre = document.createElement('pre');
                pre.className = 'output-stdout stream-live';
                activeLoadingEl.appendChild(pre);
                streamTarget = pre;
            }
            promise = window.api.runStreaming(args);
        } else {
            streamTarget = null;
            promise = window.api.runCommand(args);
        }
        return promise.then(function (res) {
            state.running = false;
            const ms = Date.now() - t0;
            const status = res.cancelled ? 'cancelled' : (res.ok ? 'ok' : 'err');
            setRunIndicator(status,
                (res.cancelled ? 'Cancelled' : (res.ok ? 'Finished' : 'Failed')) + ' — ' + label +
                (res.cancelled ? '' : ' (exit ' + res.exitCode + ')'));
            addHistory({ label: label, args: args, ok: res.ok, cancelled: !!res.cancelled });
            streamTarget = null;
            return Object.assign({}, res, {
                ms: ms, label: label,
                argsLabel: opts.argsLabel != null ? opts.argsLabel : args.join(' '),
            });
        }, function (err) {
            state.running = false;
            streamTarget = null;
            const ms = Date.now() - t0;
            setRunIndicator('err', 'Failed — ' + label);
            return { ok: false, stdout: '', stderr: String(err), exitCode: 1, cancelled: false, ms: ms, label: label };
        });
    }

    async function cancelRun() {
        const r = await window.api.cancelRun();
        if (r && r.cancelled) {
            setRunIndicator('idle', 'Cancelled');
            streamTarget = null;
        } else {
            setRunIndicator(state.running ? 'running' : 'idle', state.running ? $('#run-label').textContent : 'Idle');
        }
    }

    // ── Output blocks ──────────────────────────────────────────────────────
    function clearOutput(el) {
        if (!el) return;
        el.classList.remove('loading');
        el.classList.remove('error');
        el.innerHTML = '';
    }

    function setLoading(el, msg) {
        clearOutput(el);
        el.classList.add('loading');
        activeLoadingEl = el;
        el.innerHTML = '<span class="loading-text"><span class="spinner"></span> ' + esc(msg) + '</span>';
    }

    function preEl(cls, text) {
        const pre = document.createElement('pre');
        if (cls) pre.className = cls;
        pre.textContent = text || '';
        return pre;
    }

    function renderRunResult(el, res, label) {
        clearOutput(el);
        const status = res.cancelled ? 'cancelled' : (res.ok ? 'ok' : 'err');
        const box = document.createElement('div');
        box.className = 'run-result';
        const title = document.createElement('div');
        title.className = 'run-title';
        const dot = document.createElement('span');
        dot.className = 'rt-status ' + status;
        const name = document.createElement('span');
        name.textContent = (label || res.label || 'Run') + (res.ms != null ? ' · ' + res.ms + ' ms' : '');
        const cmd = document.createElement('span');
        cmd.className = 'rt-cmd';
        cmd.textContent = res.argsLabel || '';
        title.appendChild(dot); title.appendChild(name); title.appendChild(cmd);
        box.appendChild(title);
        const stdout = (res.stdout || '').trim();
        const stderr = (res.stderr || '').trim();
        if (stdout) box.appendChild(preEl('output-stdout', stdout));
        if (stderr) box.appendChild(preEl('output-stderr', stderr));
        if (!stdout && !stderr) {
            box.appendChild(preEl(null, res.cancelled ? '(cancelled)' : '(no output)'));
        }
        el.appendChild(box);
        if (!res.ok && !res.cancelled) el.classList.add('error');
        addToolbar(el);
    }

    // Copy / save toolbar (one per output block)
    function addToolbar(el) {
        let wrapper = el.closest('.output-wrapper');
        if (!wrapper) {
            wrapper = document.createElement('div');
            wrapper.className = 'output-wrapper';
            el.parentNode.insertBefore(wrapper, el);
            wrapper.appendChild(el);
        }
        let bar = wrapper.querySelector('.output-toolbar');
        if (!bar) {
            bar = document.createElement('div');
            bar.className = 'output-toolbar';
            const copy = document.createElement('button');
            copy.className = 'btn small';
            copy.textContent = 'Copy';
            copy.title = 'Copy output to clipboard';
            copy.onclick = async function () {
                const text = el.textContent || '';
                try {
                    await navigator.clipboard.writeText(text);
                    copy.textContent = 'Copied!';
                    setTimeout(function () { copy.textContent = 'Copy'; }, 1200);
                } catch (_e) { /* clipboard unavailable */ }
            };
            const save = document.createElement('button');
            save.className = 'btn small';
            save.textContent = 'Save';
            save.title = 'Save output to file';
            save.onclick = async function () {
                const text = el.textContent || '';
                const res = await window.api.saveFile({ filters: [{ name: 'Text', extensions: ['txt'] }] }, text);
                if (res && !res.ok) alert('Could not save: ' + res.error);
            };
            const clear = document.createElement('button');
            clear.className = 'btn small';
            clear.textContent = 'Clear';
            clear.onclick = function () { clearOutput(el); wrapper.remove(); };
            bar.appendChild(copy); bar.appendChild(save); bar.appendChild(clear);
            wrapper.appendChild(bar);
        }
    }

    // ── Navigation ─────────────────────────────────────────────────────────
    function switchView(name) {
        state.view = name;
        $$('.nav-item').forEach(function (b) { b.classList.toggle('active', b.dataset.view === name); });
        $$('.view').forEach(function (v) { v.classList.toggle('active', v.id === 'view-' + name); });
        $('#main-content').scrollTop = 0;
    }

    function setLibraryTab(tab) {
        state.libraryTab = tab;
        $$('#view-library .tab').forEach(function (b) { b.classList.toggle('active', b.dataset.tab === tab); });
        $$('#view-library .tab-panel').forEach(function (p) { p.classList.toggle('active', p.id === 'lib-' + tab); });
    }

    function setObjTab(tab) {
        state.objTab = tab;
        $$('#view-objectives .tab').forEach(function (b) { b.classList.toggle('active', b.dataset.tab === tab); });
        $$('#view-objectives .tab-panel').forEach(function (p) { p.classList.toggle('active', p.id === 'obj-' + tab); });
        if (tab === 'playbooks') renderPlaybooks('');
    }

    // ── Command bar router ─────────────────────────────────────────────────
    // Maps plain English to real commands. Never invents a tool that does not
    // exist in the binary's command set.
    function afterKeyword(text, kw) {
        const idx = text.toLowerCase().indexOf(kw.toLowerCase());
        if (idx === -1) return '';
        return text.slice(idx + kw.length).replace(/^[\s:,-]+/, '').trim();
    }

    function routeCommand(text) {
        const t = text.trim();
        const low = t.toLowerCase();
        if (!t) return null;

        // Navigation intents
        if (/^(tools?|list tools?|show tools?|what tools|tool catalog)/.test(low)) {
            return { type: 'nav', view: 'analyze' };
        }
        if (/^(skills?|list skills?|show skills?)/.test(low)) {
            return { type: 'run', args: ['--list-skills'], label: 'list skills' };
        }
        if (/^(help|guide|how do i|what can you do)/.test(low)) {
            return { type: 'nav', view: 'library', tab: 'guides' };
        }
        if (/plan.*scan|scan.*plan|engagement|pentest|pen test/.test(low)) {
            return { type: 'nav', view: 'engage' };
        }
        if (/audit/.test(low)) return { type: 'nav', view: 'library', tab: 'audit' };
        if (/findings/.test(low)) return { type: 'nav', view: 'library', tab: 'findings' };
        if (/objective|playbook|multi.*tool|chain/.test(low)) {
            return { type: 'nav', view: 'objectives' };
        }

        // Status / identity
        if (/^(status|system status|health|offline status|are you ok|are you healthy)/.test(low)) {
            return { type: 'run', args: ['--offline-status'], label: 'system status' };
        }
        if (/^(about|who are you|version|mission)/.test(low)) {
            return { type: 'run', args: ['--about'], label: 'about' };
        }

        // Hash identification (look for a hex blob)
        if (/hash/.test(low)) {
            const m = t.match(/[a-fA-F0-9]{16,64}/);
            if (m) return { type: 'quick', tool: 'hash', values: { hash: m[0] }, auto: true };
            return { type: 'quick', tool: 'hash', values: {}, auto: false };
        }
        // Password strength
        if (/pass(word|phrase)/.test(low)) {
            const rest = afterKeyword(t, /pass(word|phrase)/.exec(low)[0]);
            return { type: 'quick', tool: 'password', values: { password: rest }, auto: !!rest };
        }
        // Wordlist
        if (/wordlist/.test(low)) {
            const rest = afterKeyword(t, 'wordlist');
            const target = rest || afterKeyword(t, 'generate');
            return { type: 'quick', tool: 'wordlist', values: { target: target }, auto: !!target };
        }
        // Shell payload
        if (/shell|payload/.test(low) && !/analy|fragment|deauth/.test(low)) {
            return { type: 'quick', tool: 'shell', values: {}, auto: false };
        }
        // Decoys
        if (/decoy/.test(low)) {
            const ip = t.match(/\b\d{1,3}(\.\d{1,3}){3}\b/);
            return { type: 'quick', tool: 'decoys', values: { ip: ip ? ip[0] : '' }, auto: !!ip };
        }
        // WiFi audit
        if (/wifi|wireless/.test(low)) {
            const rest = afterKeyword(t, /wifi|wireless/.exec(low)[0]);
            const words = rest.split(/\s+/).filter(Boolean);
            return {
                type: 'quick', tool: 'wifi',
                values: { essid: words[0] || '', security: words[1] || 'wpa2', encryption: words[2] || 'aes' },
                auto: !!words[0],
            };
        }
        // WPS
        if (/wps/.test(low)) {
            const rest = afterKeyword(t, 'wps');
            return { type: 'quick', tool: 'wps', values: { pin: rest }, auto: !!rest };
        }
        // Obfuscation
        if (/obfuscat/.test(low)) {
            const rest = afterKeyword(t, /obfuscat\w*/.exec(low)[0]);
            return { type: 'quick', tool: 'evasion', values: { cmd: rest }, auto: false };
        }
        // LLM generate
        const genMatch = low.match(/^(generate|write|llm|compose)(\s+|:)/);
        if (genMatch) {
            const rest = t.slice(genMatch[0].length).trim();
            if (!rest) return { type: 'err', message: 'Please include the text to generate from.' };
            return { type: 'run', args: ['--llm-generate', rest], label: 'generate text', stream: true };
        }
        // Anomaly score
        if (/anomaly/.test(low)) {
            const rest = afterKeyword(t, 'anomaly');
            if (!rest) return { type: 'err', message: 'Please include the log text to score for anomalies.' };
            return { type: 'run', args: ['--llm-perplexity', rest], label: 'anomaly score' };
        }
        // Server view (listener + payloads). Bare "server"/"listener"/
        // "payload" open the dedicated Server view; "listen on 4444" still
        // falls through to the one-shot --listen confirm-run below.
        if (/^(server|listener|listen|payload|reverse shell|catch a shell)$/.test(low)) {
            return { type: 'nav', view: 'server' };
        }
        // Listen (requires explicit online opt-in)
        if (/listen/.test(low)) {
            const port = (t.match(/\b\d{4,5}\b/) || [])[0] || '4444';
            return { type: 'confirm-run', args: ['--allow-network', '--listen', port], label: 'listen on ' + port, warn: 'Starting a live listener opens a network socket. This requires the --allow-network opt-in and is intended for authorized engagements only.' };
        }

        // Fallback: let the embedded NLU try
        return { type: 'run', args: ['--ask', t], label: 'ask: ' + t, stream: true };
    }

    async function handleCommand(text) {
        const route = routeCommand(text);
        if (!route) return;
        switch (route.type) {
            case 'nav':
                switchView(route.view);
                if (route.tab) setLibraryTab(route.tab);
                break;
            case 'err':
                alert(route.message || 'Missing input.');
                break;
            case 'run': {
                const out = $('#home-output');
                setLoading(out, 'Running: ' + esc(route.args.join(' ')));
                const res = await runBinary(route.args, { stream: route.stream, label: route.label });
                renderRunResult(out, res, route.label);
                switchView('home');
                break;
            }
            case 'confirm-run': {
                if (!confirm(route.warn + '\n\nRun: security-agent ' + route.args.join(' ') + ' ?')) break;
                const out = $('#home-output');
                setLoading(out, 'Running: ' + esc(route.args.join(' ')));
                const res = await runBinary(route.args, { stream: true, label: route.label });
                renderRunResult(out, res, route.label);
                switchView('home');
                break;
            }
            case 'quick': {
                switchView('library');
                setLibraryTab('quick');
                openQuickTool(route.tool, route.values);
                if (route.auto) runQuickTool(true);
                break;
            }
        }
    }

    // ── Home ───────────────────────────────────────────────────────────────
    async function loadStatus() {
        const info = await window.api.getAppInfo();
        const dot = $('#status-dot');
        const txt = $('#status-text');
        if (info.binaryFound) {
            dot.className = 'status-dot ok';
            txt.textContent = 'Binary ready · ' + (info.binaryPath || '').split(/[\\/]/).pop();
        } else {
            dot.className = 'status-dot err';
            txt.textContent = 'Binary not found';
            $('#binary-warning').style.display = 'flex';
        }
        $('#stat-binary').textContent = info.binaryFound ? 'Ready' : 'Missing';
        $('#stat-mode').textContent = state.mode === 'offline' ? 'Offline' : 'Online';

        const cat = await window.api.getToolCatalog();
        state.catalog = cat;
        if (cat && cat.ok) {
            $('#stat-tools').textContent = (cat.tools || []).length;
            $('#stat-builtin').textContent = cat.builtIn || 0;
            $('#stat-skills').textContent = cat.skills || 0;
            $('#stat-coverage').textContent = cat.coverage || 'unknown';
            $('#tool-count-badge').textContent = (cat.tools || []).length;
        } else {
            $('#stat-tools').textContent = '—';
            $('#stat-builtin').textContent = '—';
            $('#stat-skills').textContent = '—';
            $('#stat-coverage').textContent = '—';
        }
        renderToolLauncher();
    }

    const QUICK_ACTIONS = [
        { icon: '⚡', title: 'Run a tool', sub: 'Analyze a file with any cataloged tool', action: function () { switchView('analyze'); } },
        { icon: '🎯', title: 'Start an objective', sub: 'Chain multiple tools toward a goal', action: function () { switchView('objectives'); } },
        { icon: '🔍', title: 'Plan a scan', sub: 'Authorized engagement wizard', action: function () { switchView('engage'); } },
        { icon: '🔑', title: 'Identify a hash', sub: 'Quick: type a hash', action: function () { openQuickFromHome('hash'); } },
        { icon: '🔐', title: 'Check a password', sub: 'Entropy + crack resistance', action: function () { openQuickFromHome('password'); } },
        { icon: '📊', title: 'System status', sub: 'Binary, tools, coverage', action: function () { runStatusInline(); } },
    ];

    function renderQuickActions() {
        const grid = $('#quick-actions');
        grid.innerHTML = '';
        QUICK_ACTIONS.forEach(function (qa) {
            const btn = document.createElement('button');
            btn.className = 'action-btn';
            btn.innerHTML = '<span class="action-icon">' + qa.icon + '</span><span>' + esc(qa.title) + '<span class="action-sub">' + esc(qa.sub) + '</span></span>';
            btn.onclick = qa.action;
            grid.appendChild(btn);
        });
    }

    function openQuickFromHome(id) {
        switchView('library');
        setLibraryTab('quick');
        openQuickTool(id, {});
        $('#quick-search').focus();
    }

    // Dashboard tool launcher — every cataloged tool, one click to open.
    function toolChipStatus(t) {
        if (toolHasReal(t)) {
            return { label: 'real', cls: 'badge-ok', title: 'Native in-app engine + executable detected' };
        }
        return { label: 'native', cls: 'badge-info', title: 'Native in-app engine (no external executable detected)' };
    }

    function renderToolLauncher() {
        const grid = $('#tool-chip-grid');
        if (!grid) return;
        grid.innerHTML = '';
        const tools = (state.catalog && state.catalog.tools) || [];
        const ordered = tools.slice().sort(function (a, b) {
            const ra = toolHasReal(a) ? 0 : 1;
            const rb = toolHasReal(b) ? 0 : 1;
            if (ra !== rb) return ra - rb;
            return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
        });
        ordered.forEach(function (t) {
            const chip = document.createElement('button');
            chip.className = 'tool-chip';
            const name = document.createElement('span');
            name.className = 'tc-name';
            name.textContent = t.name;
            const st = toolChipStatus(t);
            const badge = document.createElement('span');
            badge.className = 'badge ' + st.cls;
            badge.textContent = st.label;
            chip.appendChild(name);
            chip.appendChild(badge);
            chip.title = st.title;
            chip.onclick = function () { openToolFromHome(t); };
            grid.appendChild(chip);
        });
        const count = $('#tool-chip-count');
        if (count) count.textContent = tools.length + ' tools';
        if (!tools.length) {
            grid.innerHTML = '<div class="empty-state">Tool catalog unavailable.</div>';
        }
    }

    function openToolFromHome(tool) {
        state.currentTool = tool;
        renderToolDetail(tool);
        renderToolList($('#tool-search').value);
        switchView('analyze');
    }

    async function runStatusInline() {
        const out = $('#home-output');
        setLoading(out, 'Checking system status…');
        const res = await runBinary(['--offline-status'], { label: 'system status' });
        renderRunResult(out, res, 'System status');
    }

    function renderHistory() {
        const list = $('#recent-list');
        list.innerHTML = '';
        if (!state.history.length) {
            list.innerHTML = '<div class="empty-state">Nothing run yet. Your last tasks will appear here for one-click re-runs.</div>';
            return;
        }
        state.history.forEach(function (h, i) {
            if (i >= 8) return;
            const item = document.createElement('div');
            item.className = 'recent-item';
            const status = document.createElement('span');
            status.className = 'ri-status ' + (h.cancelled ? 'cancelled' : (h.ok ? 'ok' : 'err'));
            const label = document.createElement('span');
            label.className = 'ri-label';
            label.textContent = h.label;
            const time = document.createElement('span');
            time.className = 'ri-time';
            time.textContent = fmtTime(h.ts);
            item.appendChild(status); item.appendChild(label); item.appendChild(time);
            item.title = 'Re-run: ' + (h.args || []).join(' ');
            item.onclick = function () {
                if (h.needsConfirm && !confirm(
                    'This run opts into live/active behavior (network, listener, or execution).\n\n' +
                    'security-agent ' + (h.args || []).join(' ') + '\n\nRe-run it?')) {
                    return;
                }
                if (h.redacted) {
                    alert('The original input for this run was not saved for security. Re-run it from the tool itself.');
                    return;
                }
                const out = $('#home-output');
                setLoading(out, 'Re-running: ' + esc((h.args || []).join(' ')));
                runBinary(h.args || [], { stream: true, label: h.label }).then(function (res) {
                    renderRunResult(out, res, h.label);
                });
            };
            list.appendChild(item);
        });
    }

    // ── Objectives: agent mode ─────────────────────────────────────────────
    // Optional flags shared by preview and run: model-proposed actions and a
    // persistent memory file for the proposal prompt.
    function agentExtraArgs() {
        const args = [];
        if ($('#agent-proposals').checked) args.push('--model-proposals');
        const memory = $('#agent-memory').value.trim();
        if (memory) args.push('--memory', memory);
        return args;
    }

    async function agentPreview() {
        const goal = $('#agent-goal').value.trim();
        if (!goal) return;
        const args = ['--agent', goal, '--dry-run', ...agentExtraArgs()];
        const out = $('#output-agent');
        setLoading(out, 'Planning objective…');
        const res = await runBinary(args, { label: 'agent plan' });
        renderRunResult(out, res, 'Objective plan (dry run)');
    }

    async function agentRun() {
        const goal = $('#agent-goal').value.trim();
        if (!goal) return;
        const args = ['--agent', goal, ...agentExtraArgs()];
        if ($('#agent-dryrun').checked) args.push('--dry-run');
        if ($('#agent-network').checked) args.push('--allow-network');
        args.push('--max-steps', $('#agent-steps').value);
        const out = $('#output-agent');
        setLoading(out, 'Running objective…');
        const res = await runBinary(args, { stream: true, label: 'objective: ' + goal });
        renderRunResult(out, res, 'Objective: ' + goal);
    }

    // ── Objectives: playbooks ──────────────────────────────────────────────
    // Every step maps to a real binary command. Some steps consume the output
    // of earlier steps (e.g. the wordlist generated by step 2 feeds step 3).
    const PLAYBOOKS = [
        {
            id: 'file-deep', icon: '🧪', name: 'Deep-analyze a file',
            desc: 'Four forensic analyzers against one file — offline substitutes for binwalk, foremost, bulk_extractor and hashdeep.',
            stepsText: 'binwalk → foremost → bulk_extractor → hashdeep',
            fields: [
                { id: 'file', label: 'File to analyze', type: 'file', required: true, placeholder: 'Choose a file…' },
            ],
            build: function (v) {
                return ['binwalk', 'foremost', 'bulk_extractor', 'hashdeep'].map(function (t) {
                    return { label: t + ' analysis', args: ['--run-tool', t, v.file] };
                });
            },
        },
        {
            id: 'pcap', icon: '📦', name: 'Investigate a PCAP',
            desc: 'Parse a packet capture with the offline Wireshark substitute, then the tcpdump substitute, side by side.',
            stepsText: 'wireshark → tcpdump',
            fields: [
                { id: 'file', label: 'Capture file (.pcap/.pcapng)', type: 'file', required: true, placeholder: 'Choose a capture…' },
            ],
            build: function (v) {
                return [
                    { label: 'wireshark parse', args: ['--run-tool', 'wireshark', v.file] },
                    { label: 'tcpdump parse', args: ['--run-tool', 'tcpdump', v.file] },
                ];
            },
        },
        {
            id: 'hash-crack', icon: '🔓', name: 'Hash-crack prep',
            desc: 'Identify the hash type, then generate a targeted wordlist for the target — the two ingredients for a crack attempt.',
            stepsText: 'hash-id → gen-wordlist',
            fields: [
                { id: 'hash', label: 'Hash', required: true, placeholder: 'Paste the hash to identify' },
                { id: 'target', label: 'Wordlist target', required: true, placeholder: 'Wordlist target' },
                { id: 'company', label: 'Company (optional)', placeholder: 'Company name' },
                { id: 'year', label: 'Year (optional)', placeholder: 'Year' },
            ],
            build: function (v) {
                const steps = [{ label: 'hash-id', args: ['--hash-id', v.hash] }];
                const wl = ['--gen-wordlist', v.target];
                if (v.company) wl.push('--company', v.company);
                if (v.year) wl.push('--year', v.year);
                steps.push({ label: 'gen-wordlist', args: wl });
                return steps;
            },
        },
        {
            id: 'postexploit', icon: '🧰', name: 'Post-exploit review',
            desc: 'Review passwd, sudoers, authorized_keys and hosts in one pass — each analyzer runs on the files you provide.',
            stepsText: 'passwd → sudoers → keys → hosts → overview',
            fields: [
                { id: 'passwd', label: 'passwd file', type: 'file', required: true, placeholder: 'Choose /etc/passwd export…' },
                { id: 'sudoers', label: 'sudoers file (optional)', type: 'file' },
                { id: 'keys', label: 'authorized_keys file (optional)', type: 'file' },
                { id: 'hosts', label: 'hosts file (optional)', type: 'file' },
            ],
            build: function (v) {
                const steps = [];
                if (v.passwd) steps.push({ label: 'analyze passwd', args: ['--analyze-passwd', v.passwd] });
                if (v.sudoers) steps.push({ label: 'analyze sudoers', args: ['--analyze-sudoers', v.sudoers] });
                if (v.keys) steps.push({ label: 'analyze keys', args: ['--analyze-keys', v.keys] });
                if (v.hosts) steps.push({ label: 'analyze hosts', args: ['--analyze-hosts', v.hosts] });
                if (v.passwd) {
                    const ov = ['--postexploit-overview', v.passwd];
                    if (v.sudoers) ov.push('--sudoers', v.sudoers);
                    if (v.keys) ov.push('--keys', v.keys);
                    if (v.hosts) ov.push('--hosts', v.hosts);
                    steps.push({ label: 'post-exploit overview', args: ov });
                }
                return steps;
            },
        },
        {
            id: 'wireless', icon: '📶', name: 'Wireless security audit',
            desc: 'Audit the network configuration, and if you captured a handshake or PIN, analyze those too.',
            stepsText: 'audit-wifi [+ handshake] [+ wps-pin]',
            fields: [
                { id: 'essid', label: 'ESSID', required: true, placeholder: 'Network name (ESSID)' },
                { id: 'security', label: 'Security', type: 'select', options: ['open', 'wep', 'wpa', 'wpa2', 'wpa3'], default: 'wpa2' },
                { id: 'encryption', label: 'Encryption', type: 'select', options: ['none', 'wep', 'tkip', 'aes', 'ccmp'], default: 'aes' },
                { id: 'frames', label: 'EAPOL hex frames (optional)', type: 'textarea', placeholder: 'Space-separated hex frames…' },
                { id: 'pin', label: 'WPS PIN (optional)', placeholder: '8-digit WPS PIN' },
            ],
            build: function (v) {
                const steps = [{ label: 'wireless audit', args: ['--audit-wifi', v.essid, v.security, v.encryption] }];
                if (v.frames) steps.push({ label: 'handshake analysis', args: ['--analyze-handshake', v.frames] });
                if (v.pin) steps.push({ label: 'wps pin analysis', args: ['--wps-pin', v.pin] });
                return steps;
            },
        },
    ];

    function renderPlaybooks(filter) {
        const grid = $('#pb-grid');
        grid.innerHTML = '';
        PLAYBOOKS.filter(function (pb) {
            return !filter || pb.name.toLowerCase().indexOf(filter) !== -1 || pb.id.indexOf(filter) !== -1;
        }).forEach(function (pb) {
            const card = document.createElement('div');
            card.className = 'playbook-card';
            card.innerHTML =
                '<div class="pb-icon">' + pb.icon + '</div>' +
                '<h4>' + esc(pb.name) + '</h4>' +
                '<p>' + esc(pb.desc) + '</p>' +
                '<div class="pb-steps">' + esc(pb.stepsText) + '</div>';
            card.onclick = function () { renderPlaybookDetail(pb); };
            grid.appendChild(card);
        });
    }

    function renderPlaybookDetail(pb) {
        state.currentPlaybook = pb;
        const det = $('#pb-detail');
        det.style.display = 'block';
        det.innerHTML = '';
        const h = document.createElement('h3');
        h.textContent = pb.icon + ' ' + pb.name + ' — ' + pb.stepsText;
        det.appendChild(h);
        const form = document.createElement('div');
        form.className = 'form-grid';
        pb.fields.forEach(function (f) {
            const group = document.createElement('div');
            group.className = 'form-group' + (f.type === 'textarea' ? ' full-width' : '');
            const label = document.createElement('label');
            label.textContent = f.label + (f.required ? '' : ' (optional)');
            group.appendChild(label);
            if (f.type === 'file') {
                const wrap = document.createElement('div');
                wrap.className = 'input-with-button';
                const input = document.createElement('input');
                input.type = 'text';
                input.id = 'pb-' + f.id;
                input.placeholder = f.placeholder || '';
                const btn = document.createElement('button');
                btn.className = 'btn secondary small';
                btn.textContent = 'Browse';
                btn.onclick = async function () {
                    const fp = await window.api.selectFile({ filters: [{ name: 'All', extensions: ['*'] }] });
                    if (fp) input.value = fp;
                };
                wrap.appendChild(input); wrap.appendChild(btn);
                group.appendChild(wrap);
            } else if (f.type === 'select') {
                const sel = document.createElement('select');
                sel.id = 'pb-' + f.id;
                (f.options || []).forEach(function (o) {
                    const opt = document.createElement('option');
                    opt.value = o; opt.textContent = o;
                    if (o === f.default) opt.selected = true;
                    sel.appendChild(opt);
                });
                group.appendChild(sel);
            } else if (f.type === 'textarea') {
                const ta = document.createElement('textarea');
                ta.id = 'pb-' + f.id;
                ta.rows = 2;
                ta.placeholder = f.placeholder || '';
                group.appendChild(ta);
            } else {
                const input = document.createElement('input');
                input.type = 'text';
                input.id = 'pb-' + f.id;
                input.placeholder = f.placeholder || '';
                if (f.default) input.value = f.default;
                group.appendChild(input);
            }
            form.appendChild(group);
        });
        det.appendChild(form);
        const stepList = document.createElement('div');
        stepList.className = 'pb-step-list';
        const sh = document.createElement('div');
        sh.style.cssText = 'font-size:12px;color:var(--text-faint);margin-bottom:4px;';
        sh.textContent = 'Steps that will run:';
        stepList.appendChild(sh);
        const steps = pb.build(readPbValues(pb), state.workspace || {});
        steps.forEach(function (s, i) {
            const row = document.createElement('div');
            row.className = 'pb-step';
            row.innerHTML = '<span class="ps-num">' + (i + 1) + '</span><code>' + esc(s.args.join(' ')) + '</code>';
            stepList.appendChild(row);
        });
        det.appendChild(stepList);
        const bar = document.createElement('div');
        bar.className = 'action-bar';
        const run = document.createElement('button');
        run.className = 'btn primary';
        run.textContent = 'Run objective (' + steps.length + ' steps)';
        run.onclick = function () { runPlaybook(pb); };
        bar.appendChild(run);
        det.appendChild(bar);
    }

    function readPbValues(pb) {
        const values = {};
        pb.fields.forEach(function (f) {
            const el = $('#pb-' + f.id);
            values[f.id] = el ? el.value.trim() : '';
        });
        return values;
    }

    async function runPlaybook(pb) {
        const values = readPbValues(pb);
        const missing = (pb.fields || []).filter(function (f) { return f.required && !values[f.id]; });
        if (missing.length) {
            alert('Missing required field: ' + missing[0].label);
            return;
        }
        const steps = pb.build(values, state.workspace || {});
        if (!steps.length) { alert('No steps to run.'); return; }
        const out = $('#output-playbooks');
        clearOutput(out);
        for (let i = 0; i < steps.length; i++) {
            const s = steps[i];
            const block = document.createElement('div');
            block.className = 'run-result';
            block.innerHTML = '<div class="run-title"><span class="rt-status err"></span><span>Step ' + (i + 1) + '/' + steps.length + ': ' + esc(s.label) + '</span><span class="rt-cmd">' + esc(s.args.join(' ')) + '</span></div>';
            const pre = document.createElement('pre');
            pre.className = 'output-stdout';
            block.appendChild(pre);
            out.appendChild(block);
            setRunIndicator('running', 'Objective step ' + (i + 1) + '/' + steps.length + ': ' + s.label);
            const res = await runBinary(s.args, { stream: true, streamTarget: pre, label: s.label });
            const dot = block.querySelector('.rt-status');
            dot.className = 'rt-status ' + (res.cancelled ? 'cancelled' : (res.ok ? 'ok' : 'err'));
            if (res.stderr) {
                const errPre = document.createElement('pre');
                errPre.className = 'output-stderr';
                errPre.textContent = res.stderr;
                block.appendChild(errPre);
            }
            if (res.cancelled) break;
            out.scrollTop = out.scrollHeight;
        }
        setRunIndicator('idle', 'Objective finished');
        addToolbar(out);
    }

    // ── Analyze: tool catalog ──────────────────────────────────────────────
    const CATEGORIES = [
        { id: 'all', label: 'All' },
        { id: 'forensic', label: 'Forensics' },
        { id: 'credential', label: 'Credential' },
        { id: 'web', label: 'Web' },
        { id: 'wireless', label: 'Wireless' },
        { id: 'recon', label: 'Recon' },
        { id: 'payload', label: 'Payload' },
        { id: 'privesc', label: 'Priv-esc' },
        { id: 'source', label: 'Source' },
        { id: 'evasion', label: 'Evasion' },
        { id: 'sniffer', label: 'Sniffer' },
        { id: 'mobile', label: 'Mobile' },
    ];

    // Tool → category mapping, mirroring src/arsenal/mod.rs dispatch_category.
    const TOOL_CATEGORY = {
        hashcat: 'credential', john: 'credential', ophcrack: 'credential', rcrack: 'credential',
        hydra: 'credential', medusa: 'credential', ncrack: 'credential', crackmapexec: 'credential',
        netexec: 'credential', 'evil-winrm': 'credential', smbmap: 'credential',
        crunch: 'credential', cewl: 'credential',
        sqlmap: 'web', nikto: 'web', wpscan: 'web', whatweb: 'web', wafw00f: 'web', nuclei: 'web',
        skipfish: 'web', wfuzz: 'web', ffuf: 'web', gobuster: 'web', dirb: 'web', feroxbuster: 'web',
        burpsuite: 'web', httrack: 'web', cutycapt: 'web', 'beef-xss': 'web',
        'aircrack-ng': 'wireless', wifite: 'wireless', pyrit: 'wireless', reaver: 'wireless',
        kismet: 'wireless', giskismet: 'wireless', bettercap: 'wireless', mfoc: 'wireless',
        mfterm: 'wireless', chirpw: 'wireless',
        nmap: 'recon', zenmap: 'recon', masscan: 'recon', netdiscover: 'recon', amass: 'recon',
        subfinder: 'recon', dmitry: 'recon', enum4linux: 'recon', 'ike-scan': 'recon',
        msfconsole: 'payload', msfpc: 'payload', setoolkit: 'payload', searchsploit: 'payload',
        chkrootkit: 'privesc', lynis: 'privesc', termineter: 'privesc',
        semgrep: 'source',
        macchanger: 'evasion', yersinia: 'evasion', 'thc-ipv6': 'evasion',
        tcpdump: 'sniffer', 'netsniff-ng': 'sniffer', ettercap: 'sniffer', driftnet: 'sniffer',
        mitmproxy: 'sniffer',
        androguard: 'mobile', apkleaks: 'mobile', apksigner: 'mobile', apktool: 'mobile',
        dex2jar: 'mobile', jadx: 'mobile', drozer: 'mobile', frida: 'mobile', objection: 'mobile',
        qark: 'mobile', mobsf: 'mobile', trueseeing: 'mobile', 'mariana-trench': 'mobile',
        galleta: 'forensic', 'mdb-sql': 'forensic', sqlitebrowser: 'forensic', keepnote: 'forensic',
        recordmydesktop: 'forensic',
        autopsy: 'forensic', volatility: 'forensic', wireshark: 'sniffer', binwalk: 'forensic',
        foremost: 'forensic', bulk_extractor: 'forensic', hashdeep: 'forensic',
    };

    function catOf(name) { return TOOL_CATEGORY[name] || 'forensic'; }

    function renderCats() {
        const wrap = $('#tool-cats');
        wrap.innerHTML = '';
        CATEGORIES.forEach(function (c) {
            const chip = document.createElement('button');
            chip.className = 'chip' + (c.id === state.currentCategory ? ' active' : '');
            chip.textContent = c.label;
            chip.onclick = function () {
                state.currentCategory = c.id;
                renderCats();
                renderToolList($('#tool-search').value);
            };
            wrap.appendChild(chip);
        });
    }

    // Every cataloged tool is served by an in-app native engine; the real
    // external binary (when actually installed) is only an optional advanced
    // path. main.js reports executable=not-installed when absent.
    function toolHasReal(tool) {
        return !!(tool && tool.executable && tool.executable !== 'not-installed');
    }

    function renderToolList(filter) {
        const list = $('#tool-list');
        list.innerHTML = '';
        if (!state.catalog || !state.catalog.tools) {
            list.innerHTML = '<div class="empty-state">Tool catalog unavailable.</div>';
            return;
        }
        const f = (filter || '').toLowerCase();
        state.catalog.tools
            .filter(function (t) {
                if (state.currentCategory !== 'all' && catOf(t.name) !== state.currentCategory) return false;
                if (f && t.name.indexOf(f) === -1) return false;
                return true;
            })
            .forEach(function (t) {
                const item = document.createElement('div');
                item.className = 'tool-item' + (state.currentTool && state.currentTool.name === t.name ? ' active' : '');
                const name = document.createElement('span');
                name.className = 'ti-name';
                name.textContent = t.name;
                const kind = document.createElement('span');
                kind.className = 'badge ' + (toolHasReal(t) ? 'badge-ok' : 'badge-info');
                kind.textContent = toolHasReal(t) ? 'native + real' : 'native';
                item.appendChild(name); item.appendChild(kind);
                item.onclick = function () { state.currentTool = t; renderToolDetail(t); renderToolList($('#tool-search').value); };
                list.appendChild(item);
            });
        if (!list.children.length) {
            list.innerHTML = '<div class="empty-state">No tools match.</div>';
        }
    }

    function renderToolDetail(tool) {
        const det = $('#tool-detail');
        det.innerHTML = '';
        const h = document.createElement('h3');
        h.innerHTML = esc(tool.name) + ' <span class="badge badge-info">native (in-app)</span>' +
            (toolHasReal(tool) ? ' <span class="badge badge-ok">real binary available</span>' : '');
        det.appendChild(h);
        const hint = document.createElement('p');
        hint.className = 'field-hint';
        hint.textContent = 'Runs fully inside the app with the in-house engine — no external install needed.' +
            (toolHasReal(tool) ? ' The real ' + tool.name + ' binary is also detected; optional advanced runs can use it below.' : '');
        det.appendChild(hint);

        const form = document.createElement('div');
        form.className = 'form-grid';

        // Input file
        const g1 = document.createElement('div');
        g1.className = 'form-group full-width';
        const l1 = document.createElement('label');
        l1.textContent = 'Input file or folder';
        const w1 = document.createElement('div');
        w1.className = 'input-with-button';
        const input = document.createElement('input');
        input.type = 'text';
        input.id = 'tool-input';
        input.placeholder = 'Choose the file to analyze…';
        const browse = document.createElement('button');
        browse.className = 'btn secondary small';
        browse.textContent = 'Browse';
        browse.onclick = async function () {
            const fp = await window.api.selectFile({ filters: [{ name: 'All', extensions: ['*'] }] });
            if (fp) input.value = fp;
        };
        w1.appendChild(input); w1.appendChild(browse);
        g1.appendChild(l1); g1.appendChild(w1);
        form.appendChild(g1);

        // Optional output .txt
        const g2 = document.createElement('div');
        g2.className = 'form-group full-width';
        const l2 = document.createElement('label');
        l2.textContent = 'Save report to file (optional)';
        const w2 = document.createElement('div');
        w2.className = 'input-with-button';
        const out = document.createElement('input');
        out.type = 'text';
        out.id = 'tool-output';
        out.placeholder = 'Leave empty to print below';
        const browseOut = document.createElement('button');
        browseOut.className = 'btn secondary small';
        browseOut.textContent = 'Browse';
        browseOut.onclick = async function () {
            const fp = await window.api.saveFile({ filters: [{ name: 'Text', extensions: ['txt'] }] });
            if (fp) out.value = fp;
        };
        w2.appendChild(out); w2.appendChild(browseOut);
        g2.appendChild(l2); g2.appendChild(w2);
        form.appendChild(g2);

        // Advanced: optional real-binary execution (de-emphasized — the in-app
        // native engine is the primary path and always works offline). Shown
        // for every tool; the controls are disabled when the binary is absent.
        {
            const realAvailable = toolHasReal(tool);
            const details = document.createElement('details');
            details.className = 'advanced-options';
            const summary = document.createElement('summary');
            summary.textContent = 'Advanced: run the real ' + tool.name + ' binary (optional)';
            details.appendChild(summary);
            const note = document.createElement('p');
            note.className = 'field-hint';
            if (realAvailable) {
                note.textContent = 'Detected at ' + tool.executable + '. Checking this invokes the real binary via --run-external-tool; live tools need the Online mode opt-in.';
            } else {
                note.textContent = 'The ' + tool.name + ' binary is not installed on this system. The in-app engine is used instead — nothing to configure.';
            }
            details.appendChild(note);
            const g3 = document.createElement('div');
            g3.className = 'form-group full-width';
            const lab = document.createElement('label');
            lab.className = 'checkbox-label';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.id = 'tool-real';
            cb.disabled = !realAvailable;
            const span = document.createElement('span');
            span.textContent = realAvailable
                ? 'Use the real ' + tool.name + ' binary instead of the in-app engine'
                : 'Real binary not installed — in-app engine will be used';
            lab.appendChild(cb); lab.appendChild(span);
            g3.appendChild(lab);
            const g4 = document.createElement('div');
            g4.className = 'form-group full-width conditional';
            const lab4 = document.createElement('label');
            lab4.className = 'checkbox-label';
            const cb4 = document.createElement('input');
            cb4.type = 'checkbox';
            cb4.id = 'tool-network';
            const span4 = document.createElement('span');
            span4.textContent = 'Allow network / active testing (--allow-network)';
            lab4.appendChild(cb4); lab4.appendChild(span4);
            g4.appendChild(lab4);
            const g5 = document.createElement('div');
            g5.className = 'form-group full-width';
            const l5 = document.createElement('label');
            l5.textContent = 'Tool arguments (for the real binary)';
            const a5 = document.createElement('input');
            a5.type = 'text';
            a5.id = 'tool-args';
            a5.placeholder = 'Arguments for the real binary';
            g5.appendChild(l5); g5.appendChild(a5);
            details.appendChild(g3); details.appendChild(g4); details.appendChild(g5);
            form.appendChild(details);
        }

        det.appendChild(form);
        const bar = document.createElement('div');
        bar.className = 'action-bar';
        const run = document.createElement('button');
        run.className = 'btn primary';
        run.textContent = 'Run ' + tool.name;
        run.onclick = function () { runTool(); };
        bar.appendChild(run);
        det.appendChild(bar);
    }

    async function runTool() {
        const tool = state.currentTool;
        if (!tool) return;
        const input = $('#tool-input') ? $('#tool-input').value.trim() : '';
        const out = $('#output-tools');
        if (!input) { alert('Choose an input file first.'); return; }
        const output = $('#tool-output') ? $('#tool-output').value.trim() : '';

        let args;
        let label;
        if ($('#tool-real') && $('#tool-real').checked) {
            if (!toolHasReal(tool)) {
                alert('The real ' + tool.name + ' binary is not installed on this system.\nRunning the in-app native engine instead.');
                $('#tool-real').checked = false;
            } else {
                const realArgs = $('#tool-args') ? $('#tool-args').value.trim().split(/\s+/).filter(Boolean) : [];
                args = ['--run-external-tool'];
                if ($('#tool-network') && $('#tool-network').checked) args.push('--allow-network');
                args.push(tool.name);
                args = args.concat(realArgs);
                label = 'real ' + tool.name;
            }
        }
        if (!args) {
            args = ['--run-tool', tool.name, input];
            if (output) args.push('--output', output);
            label = tool.name + ' (native)';
        }
        setLoading(out, 'Running: ' + esc(args.join(' ')));
        const res = await runBinary(args, { stream: true, label: label });
        renderRunResult(out, res, label);
    }

    // ── Engage: guided engagement chain ─────────────────────────────────────
    function parseTargetLines() {
        const text = $('#eng-targets').value;
        const lines = text.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
        const targets = [];
        lines.forEach(function (line) {
            // Accept "label", "label — type — address", "label,type,address"
            const parts = line.split(/[—,\t]/).map(function (p) { return p.trim(); }).filter(Boolean);
            const id = parts[0] || ('target-' + (targets.length + 1));
            const type = parts[1] || $('#eng-type').value;
            const address = parts[2] || '';
            targets.push({ id: id, type: type, address: address, criticality: $('#eng-criticality').value || '5' });
        });
        return targets;
    }

    function buildConfigText(name, auth, targets, intensity) {
        const now = Math.floor(Date.now() / 1000);
        const lines = [];
        lines.push('# Auto-generated by Security-Agent Console');
        lines.push('engagement_id=' + name);
        lines.push('authorized_by=' + (auth || 'operator'));
        lines.push('authorized_by_role=SecurityAdmin');
        lines.push('time_window_start=' + now);
        lines.push('time_window_end=' + (now + 7 * 24 * 3600));
        lines.push('in_scope_targets=' + targets.map(function (t) { return t.id; }).join(','));
        lines.push('allowed_techniques=PassiveRecon,ConfigurationAudit,Sast,Dast,ApiSecurity,DependencyAudit,SecretScan,ThreatModeling,AttackPathAnalysis');
        lines.push('max_intensity=' + intensity);
        lines.push('high_impact_approved=' + (intensity === 'Aggressive' ? 'true' : 'false'));
        lines.push('penetrative_testing_approved=' + (intensity === 'Aggressive' ? 'true' : 'false'));
        targets.forEach(function (t) {
            lines.push('');
            lines.push('[target]');
            lines.push('id=' + t.id);
            lines.push('target_type=' + t.type);
            lines.push('criticality=' + t.criticality);
            if (t.address) lines.push('network_address=' + t.address);
        });
        return lines.join('\n');
    }

    async function ensureWorkspace() {
        if (state.workspace) return state.workspace;
        const ws = await window.api.getWorkspace();
        if (ws && ws.ok) {
            state.workspace = ws;
            return ws;
        }
        return { ok: false, base: '', subdirs: [] };
    }

    async function generateConfig() {
        const ws = await ensureWorkspace();
        if (!ws.ok) { alert('Could not create a workspace folder.'); return null; }
        // Sanitize the engagement name so it can never escape the workspace
        // or collide with the config/artifact files (main also confines writes).
        const name = ($('#eng-name').value.trim() || ('eng-' + new Date().toISOString().slice(0, 10)))
            .replace(/[^A-Za-z0-9_-]+/g, '-');
        const auth = $('#eng-auth').value.trim();
        const intensity = $('#eng-intensity').value;
        const targets = parseTargetLines();
        if (!targets.length) { alert('Add at least one target line.'); return null; }
        const text = buildConfigText(name, auth, targets, intensity);
        const cfgPath = joinPath(ws.paths && ws.paths.engagements, name + '.config');
        const wr = await window.api.writeFile(cfgPath, text);
        if (!wr.ok) { alert('Could not write config: ' + wr.error); return null; }
        state.engConfig = cfgPath;
        state.engConfigText = text;
        const preview = $('#eng-config-preview');
        preview.style.display = 'block';
        $('#eng-config-text').textContent = text;
        return cfgPath;
    }

    function pipelineStage(id, name, cmd) {
        const pipe = $('#pipeline');
        let el = $('#' + id);
        if (!el) {
            el = document.createElement('div');
            el.className = 'pipe-stage';
            el.id = id;
            el.innerHTML = '<span class="ps-status pending"></span><span class="ps-name">' + esc(name) + '</span><span class="ps-cmd">' + esc(cmd) + '</span>';
            pipe.appendChild(el);
        }
        return el;
    }

    async function engPlan() {
        const cfg = state.engConfig || (await generateConfig());
        if (!cfg) return;
        const args = ['--plan-scan', cfg];
        if ($('#eng-network').checked) args.push('--allow-network');
        if ($('#eng-cognitive').checked) args.push('--cognitive-review');
        pipelineStage('stage-plan', 'Plan scan', args.join(' '));
        const out = $('#output-engage');
        setLoading(out, 'Planning scan…');
        const res = await runBinary(args, { stream: true, label: 'plan scan' });
        const stage = $('#stage-plan');
        stage.querySelector('.ps-status').className = 'ps-status ' + (res.ok ? 'done' : 'failed');
        renderRunResult(out, res, 'Plan scan');
    }

    async function engRun() {
        const cfg = state.engConfig || (await generateConfig());
        if (!cfg) return;
        const ws = await ensureWorkspace();
        const name = ($('#eng-name').value.trim().replace(/[^A-Za-z0-9_-]+/g, '-') || 'eng') + '-' + Date.now();
        const findingsPath = joinPath(ws.paths && ws.paths.findings, name + '.jsonl');
        state.engFindings = findingsPath;
        const args = ['--run-engagement', cfg];
        if ($('#eng-network').checked) args.push('--allow-network');
        if ($('#eng-cognitive').checked) args.push('--cognitive-review');
        if ($('#eng-findings').checked) args.push('--findings-log', findingsPath);
        if ($('#eng-report').checked) {
            args.push('--report-out', joinPath(ws.paths && ws.paths.reports, name + '.md'), '--report-format', 'markdown');
        }
        pipelineStage('stage-run', 'Run engagement', args.join(' '));
        const out = $('#output-engage');
        setLoading(out, 'Running engagement… (this may take a while)');
        const res = await runBinary(args, { stream: true, label: 'run engagement' });
        const stage = $('#stage-run');
        stage.querySelector('.ps-status').className = 'ps-status ' + (res.ok ? 'done' : 'failed');
        renderRunResult(out, res, 'Run engagement');
    }

    async function engReport() {
        if (!state.engFindings) { alert('Run the engagement first so a findings log exists.'); return; }
        const args = ['--report', state.engFindings, '--format', 'markdown'];
        pipelineStage('stage-report', 'Generate report', args.join(' '));
        const out = $('#output-engage');
        setLoading(out, 'Generating report…');
        const res = await runBinary(args, { stream: true, label: 'report' });
        const stage = $('#stage-report');
        stage.querySelector('.ps-status').className = 'ps-status ' + (res.ok ? 'done' : 'failed');
        renderRunResult(out, res, 'Report (markdown)');
    }

    async function engRetest() {
        if (!state.engFindings) { alert('Run the engagement first so a findings log exists.'); return; }
        const args = ['--schedule-retest', state.engFindings];
        pipelineStage('stage-retest', 'Schedule retest', args.join(' '));
        const out = $('#output-engage');
        setLoading(out, 'Scheduling retest…');
        const res = await runBinary(args, { stream: true, label: 'retest' });
        const stage = $('#stage-retest');
        stage.querySelector('.ps-status').className = 'ps-status ' + (res.ok ? 'done' : 'failed');
        renderRunResult(out, res, 'Retest schedule');
    }

    // ── Library: quick tools ───────────────────────────────────────────────
    const QUICK_TOOLS = [
        { id: 'hash', icon: '🔑', title: 'Hash ID', desc: 'Identify hash type', cmd: ['--hash-id'], fields: [{ id: 'hash', label: 'Hash', required: true, placeholder: 'Paste the hash to identify' }] },
        { id: 'password', icon: '🔐', title: 'Password Strength', desc: 'Entropy + crack resistance', cmd: ['--password-strength'], fields: [{ id: 'password', label: 'Password', required: true, placeholder: 'Enter the password' }] },
        { id: 'wordlist', icon: '📄', title: 'Gen Wordlist', desc: 'Targeted wordlist for a target', cmd: ['--gen-wordlist'], fields: [
            { id: 'target', label: 'Target', required: true, placeholder: 'Wordlist target' },
            { id: 'company', label: 'Company (optional)', flag: '--company', placeholder: 'Company name' },
            { id: 'year', label: 'Year (optional)', flag: '--year', placeholder: 'Year' },
        ] },
        { id: 'shell', icon: '💻', title: 'Gen Shell Payload', desc: 'Reverse/bind shell one-liner', cmd: ['--gen-shell'], fields: [
            { id: 'type', label: 'Type', type: 'select', options: ['bash', 'netcat', 'python', 'perl', 'ruby', 'php', 'tcp', 'powershell', 'bind', 'meterpreter', 'http', 'https'], required: true },
            { id: 'lhost', label: 'LHOST', required: true, placeholder: 'Your IP / hostname' },
            { id: 'lport', label: 'LPORT', required: true, type: 'number', placeholder: 'Port' },
        ] },
        { id: 'payload', icon: '🧬', title: 'Analyze Payload', desc: 'Shellcode / detection risk', cmd: ['--analyze-payload'], fields: [{ id: 'payload', label: 'Payload or file path', type: 'textarea', required: true }] },
        { id: 'evasion', icon: '🎭', title: 'PS Obfuscation', desc: 'Obfuscate a PowerShell command', cmd: ['--obfuscate-ps'], fields: [{ id: 'cmd', label: 'PowerShell command', type: 'textarea', required: true }] },
        { id: 'decoys', icon: '🎲', title: 'Gen Decoys', desc: 'Decoy IPs for scan obfuscation', cmd: ['--gen-decoys'], fields: [
            { id: 'ip', label: 'Real IP', required: true, placeholder: 'Your IP / hostname' },
            { id: 'count', label: 'Count', type: 'number', default: '5' },
        ] },
        { id: 'handshake', icon: '📡', title: 'Analyze Handshake', desc: 'WPA EAPOL frame completeness', cmd: ['--analyze-handshake'], fields: [{ id: 'frames', label: 'EAPOL hex frames', type: 'textarea', required: true, placeholder: 'Space-separated hex frames…' }] },
        { id: 'wps', icon: '🔢', title: 'WPS PIN', desc: 'Default/vulnerable PIN check', cmd: ['--wps-pin'], fields: [{ id: 'pin', label: 'WPS PIN', required: true, placeholder: '8-digit WPS PIN' }] },
        { id: 'wifi', icon: '📶', title: 'Audit WiFi', desc: 'Wireless config security audit', cmd: ['--audit-wifi'], fields: [
            { id: 'essid', label: 'ESSID', required: true, placeholder: 'Network name (ESSID)' },
            { id: 'security', label: 'Security', type: 'select', options: ['open', 'wep', 'wpa', 'wpa2', 'wpa3'], required: true, default: 'wpa2' },
            { id: 'encryption', label: 'Encryption', type: 'select', options: ['none', 'wep', 'tkip', 'aes', 'ccmp'], required: true, default: 'aes' },
        ] },
        { id: 'passwd', icon: '👤', title: 'Analyze passwd', desc: 'Priv-esc indicators', cmd: ['--analyze-passwd'], fields: [{ id: 'content', label: 'File path or content', type: 'textarea', required: true }] },
        { id: 'sudoers', icon: '🛡️', title: 'Analyze sudoers', desc: 'Risky sudo rules', cmd: ['--analyze-sudoers'], fields: [{ id: 'content', label: 'File path or content', type: 'textarea', required: true }] },
        { id: 'keys', icon: '🗝️', title: 'Analyze keys', desc: 'authorized_keys lateral movement', cmd: ['--analyze-keys'], fields: [{ id: 'content', label: 'File path or content', type: 'textarea', required: true }] },
        { id: 'hosts', icon: '🌐', title: 'Analyze hosts', desc: 'Internal network mapping', cmd: ['--analyze-hosts'], fields: [{ id: 'content', label: 'File path or content', type: 'textarea', required: true }] },
        { id: 'overview', icon: '🧰', title: 'Post-Exploit Overview', desc: 'Combined host review', cmd: ['--postexploit-overview'], fields: [
            { id: 'passwd', label: 'passwd path/content', required: true },
            { id: 'shadow', label: 'shadow (optional)', flag: '--shadow' },
            { id: 'sudoers', label: 'sudoers (optional)', flag: '--sudoers' },
            { id: 'keys', label: 'authorized_keys (optional)', flag: '--keys' },
            { id: 'hosts', label: 'hosts (optional)', flag: '--hosts' },
        ] },
        { id: 'fragment', icon: '✂️', title: 'Fragment Payload', desc: 'DPI evasion splitting', cmd: ['--fragment-payload'], fields: [
            { id: 'payload', label: 'Payload', type: 'textarea', required: true },
            { id: 'mtu', label: 'MTU', type: 'number', default: '1400', flag: '--mtu' },
        ] },
        { id: 'ipids', icon: '🆔', title: 'Gen IP IDs', desc: 'Randomized IP ID values', cmd: ['--gen-ipids'], fields: [{ id: 'count', label: 'Count', type: 'number', required: true }] },
        { id: 'checksum', icon: '➗', title: 'IP Checksum', desc: 'Calculate header checksum', cmd: ['--ip-checksum'], fields: [{ id: 'hex', label: 'Hex header', required: true, placeholder: 'IPv4 header bytes in hex' }] },
        { id: 'deauth', icon: '📵', title: 'Analyze Deauth', desc: '802.11 deauth frame', cmd: ['--analyze-deauth'], fields: [{ id: 'frame', label: 'Hex 802.11 frame', required: true }] },
    ];

    function renderQuickTools(filter) {
        const grid = $('#quick-grid');
        grid.innerHTML = '';
        const f = (filter || '').toLowerCase();
        QUICK_TOOLS.filter(function (q) {
            return !f || q.title.toLowerCase().indexOf(f) !== -1 || q.id.indexOf(f) !== -1 || q.desc.toLowerCase().indexOf(f) !== -1;
        }).forEach(function (q) {
            const card = document.createElement('button');
            card.className = 'quick-card';
            card.innerHTML = '<span class="qc-title">' + q.icon + ' ' + esc(q.title) + '</span><span class="qc-desc">' + esc(q.desc) + '</span>';
            card.onclick = function () { openQuickTool(q.id, {}); };
            grid.appendChild(card);
        });
    }

    function openQuickTool(id, values) {
        const q = QUICK_TOOLS.find(function (x) { return x.id === id; });
        if (!q) return;
        state.currentQuick = q;
        const form = $('#quick-form');
        form.style.display = 'block';
        form.innerHTML = '';
        const h = document.createElement('h3');
        h.textContent = q.icon + ' ' + q.title;
        form.appendChild(h);
        const grid = document.createElement('div');
        grid.className = 'form-grid';
        q.fields.forEach(function (f) {
            const group = document.createElement('div');
            group.className = 'form-group' + (f.type === 'textarea' ? ' full-width' : '');
            const label = document.createElement('label');
            label.textContent = f.label + (f.required ? '' : ' (optional)');
            group.appendChild(label);
            if (f.type === 'select') {
                const sel = document.createElement('select');
                sel.id = 'qt-' + f.id;
                (f.options || []).forEach(function (o) {
                    const opt = document.createElement('option');
                    opt.value = o; opt.textContent = o;
                    if ((values && values[f.id]) || o === f.default) opt.selected = true;
                    sel.appendChild(opt);
                });
                group.appendChild(sel);
            } else if (f.type === 'textarea') {
                const ta = document.createElement('textarea');
                ta.id = 'qt-' + f.id;
                ta.rows = 3;
                ta.placeholder = f.placeholder || '';
                if (values && values[f.id]) ta.value = values[f.id];
                group.appendChild(ta);
            } else {
                const input = document.createElement('input');
                input.type = 'text';
                input.id = 'qt-' + f.id;
                input.placeholder = f.placeholder || '';
                if (values && values[f.id] !== undefined) input.value = values[f.id];
                else if (f.default) input.value = f.default;
                group.appendChild(input);
            }
            grid.appendChild(group);
        });
        form.appendChild(grid);
        const bar = document.createElement('div');
        bar.className = 'action-bar';
        const run = document.createElement('button');
        run.className = 'btn primary';
        run.textContent = 'Run ' + q.title;
        run.onclick = function () { runQuickTool(false); };
        bar.appendChild(run);
        form.appendChild(bar);
    }

    function readQuickValues() {
        const q = state.currentQuick;
        if (!q) return {};
        const values = {};
        q.fields.forEach(function (f) {
            const el = $('#qt-' + f.id);
            values[f.id] = el ? el.value.trim() : '';
        });
        return values;
    }

    async function runQuickTool(auto) {
        const q = state.currentQuick;
        if (!q) return;
        const values = readQuickValues();
        const missing = (q.fields || []).filter(function (f) { return f.required && !values[f.id]; });
        if (missing.length) {
            if (auto) return; // partial values from the command bar: let the user finish
            alert('Missing required field: ' + missing[0].label);
            return;
        }
        const args = q.cmd.slice();
        q.fields.forEach(function (f) {
            const v = values[f.id];
            if (!v) return;
            if (f.flag) { args.push(f.flag, v); }
            else { args.push(v); }
        });
        const out = $('#output-quick');
        setLoading(out, 'Running: ' + esc(args.join(' ')));
        const res = await runBinary(args, { stream: true, label: q.title });
        renderRunResult(out, res, q.title);
    }

    // ── Library: findings / audit / dbs / llm / guides ─────────────────────
    function bindBrowse(btnId, inputId) {
        const btn = $(btnId);
        const input = $(inputId);
        if (!btn || !input) return;
        btn.onclick = async function () {
            const fp = await window.api.selectFile({ filters: [{ name: 'All', extensions: ['*'] }] });
            if (fp) input.value = fp;
        };
    }

    function bindView(btnId, inputId, cmdPrefix, outputId, label) {
        const btn = $(btnId);
        const input = $(inputId);
        const out = $(outputId);
        if (!btn || !input || !out) return;
        btn.onclick = async function () {
            const path = input.value.trim();
            if (!path) { alert('Enter a file path first.'); return; }
            const args = cmdPrefix.concat([path]);
            setLoading(out, 'Viewing…');
            const res = await runBinary(args, { stream: true, label: label || cmdPrefix[0] });
            renderRunResult(out, res, label || cmdPrefix[0]);
        };
    }

    async function bindRecordFindings() {
        const btn = $('#btn-find-record');
        const out = $('#output-findings');
        btn.onclick = async function () {
            const dest = $('#find-dest').value.trim();
            const src = $('#find-src').value.trim();
            if (!dest || !src) { alert('Enter both destination and source paths.'); return; }
            setLoading(out, 'Merging findings…');
            const res = await runBinary(['--record-findings', dest, src], { stream: true, label: 'record findings' });
            renderRunResult(out, res, 'Record findings');
        };
    }

    // ── Log console ────────────────────────────────────────────────────────
    let logCount = 0;
    function initLogConsole() {
        $('#log-toggle').onclick = function () {
            $('#log-console').classList.toggle('collapsed');
        };
        $('#log-clear').onclick = function () {
            $('#log-content').innerHTML = '';
            logCount = 0;
            $('#log-badge').textContent = '0';
        };
        // Clear any listeners left by a previous renderer load so log lines
        // are never processed twice after a window reload.
        window.api.removeLogListeners();
        window.api.onLogLine(function (entry) {
            const line = document.createElement('div');
            line.className = 'log-line log-' + (entry.level || 'info');
            const ts = new Date(entry.ts).toLocaleTimeString();
            line.textContent = '[' + ts + '] [' + (entry.level || 'info').toUpperCase() + '] ' + entry.message;
            $('#log-content').appendChild(line);
            while ($('#log-content').children.length > 500) $('#log-content').removeChild($('#log-content').firstChild);
            logCount++;
            $('#log-badge').textContent = String(logCount);
        });
    }

    function logUi(level, msg) {
        const line = document.createElement('div');
        line.className = 'log-line log-' + level;
        line.textContent = '[' + new Date().toLocaleTimeString() + '] [' + level.toUpperCase() + '] ' + msg;
        const content = $('#log-content');
        if (content) {
            content.appendChild(line);
            while (content.children.length > 500) content.removeChild(content.firstChild);
            logCount++;
            $('#log-badge').textContent = String(logCount);
        }
    }

    // ── Server view (listener + payloads) ──────────────────────────────────
    // Drives the --listen reverse-shell listener and --gen-shell payload
    // generator. The main process owns the child process and enforces the
    // Online-mode gate; this renderer code only renders what main forwards.
    let server = {
        running: false,
        sessionActive: false,
        payloadText: '',
    };
    let serverOutTail = null; // current open session-output block

    // A session starts when the listener reports an inbound connection /
    // active shell; it ends on session-ended, next-wait, or shutdown lines.
    const SESSION_START_RE = /SESSION_ACTIVE|Shell session active|CONNECTED #/;
    const SESSION_END_RE = /SESSION_ENDED|Waiting for next connection|LISTENER_SHUTDOWN|Session #\d+ ended|Remote shell closed|LISTENER_WARNING/;

    function serverAppendLine(kind, text) {
        serverOutTail = null; // new logical block; session output restarts
        const out = $('#srv-term-out');
        if (!out) return;
        const placeholder = out.querySelector('.term-placeholder');
        if (placeholder) placeholder.remove();
        const line = document.createElement('div');
        line.className = 'term-line term-' + (kind === 'out' ? 'o' : (kind || 'o'));
        line.textContent = text;
        out.appendChild(line);
        out.scrollTop = out.scrollHeight;
        while (out.children.length > 1200) out.removeChild(out.firstChild);
    }

    // Session data from the connected shell arrives as raw byte chunks and
    // may split lines; keep appending to the current output block.
    function serverAppendOut(chunk) {
        const out = $('#srv-term-out');
        if (!out) return;
        const placeholder = out.querySelector('.term-placeholder');
        if (placeholder) placeholder.remove();
        if (!serverOutTail) {
            serverOutTail = document.createElement('div');
            serverOutTail.className = 'term-line term-o';
            out.appendChild(serverOutTail);
        }
        serverOutTail.textContent += chunk;
        out.scrollTop = out.scrollHeight;
        while (out.children.length > 1200) out.removeChild(out.firstChild);
    }

    function updateServerUi() {
        const start = $('#srv-start');
        const stop = $('#srv-stop');
        const statusEl = $('#srv-listen-status');
        const statusText = $('#srv-listen-status-text');
        const pill = $('#srv-session-pill');
        const input = $('#srv-term-input');
        const send = $('#srv-term-send');
        if (start) start.disabled = server.running;
        if (stop) stop.disabled = !server.running;
        if (statusEl) statusEl.className = 'srv-status ' + (server.running ? 'running' : 'stopped');
        if (statusText) statusText.textContent = server.running ? 'Listening — waiting for connections' : 'Stopped';
        if (pill) {
            pill.className = 'srv-session-pill ' + (server.sessionActive ? 'active' : 'idle');
            pill.textContent = server.sessionActive ? 'session active' : 'no session';
        }
        if (input) input.disabled = !server.running;
        if (send) send.disabled = !server.running;
    }

    async function serverStart() {
        const port = parseInt($('#srv-port').value, 10);
        const maxRaw = $('#srv-max').value;
        const res = await window.api.startListener({
            port: port,
            maxConnections: maxRaw ? parseInt(maxRaw, 10) : 0,
            bindAddress: $('#srv-bind').value.trim() || '0.0.0.0',
            sessionLog: $('#srv-log').checked,
        });
        if (!res || !res.ok) {
            serverAppendLine('err', '[start failed] ' + ((res && res.error) || 'unknown error'));
            return;
        }
        server.running = true;
        updateServerUi();
        serverAppendLine('sys', '[*] Listener process started (pid ' + res.pid + ')');
        logUi('info', 'listener started on port ' + port);
    }

    async function serverStop() {
        const res = await window.api.stopListener();
        if (!res || !res.ok) {
            serverAppendLine('err', '[stop failed] ' + ((res && res.error) || 'unknown error'));
        }
        // The running:false transition arrives via listener-status (close).
    }

    async function serverGenPayload() {
        const type = $('#srv-type').value;
        const lhost = $('#srv-lhost').value.trim() || '127.0.0.1';
        const lport = $('#srv-lport').value.trim() || '4444';
        const out = $('#srv-payload');
        out.textContent = 'Generating…';
        const res = await window.api.genShell(type, lhost, lport);
        if (!res || !res.ok) {
            out.textContent = 'Generation failed: ' + ((res && res.stderr) || 'unknown error');
            $('#srv-copy').disabled = true;
            return;
        }
        server.payloadText = res.stdout;
        out.textContent = res.stdout;
        $('#srv-copy').disabled = false;
    }

    async function serverCopyPayload() {
        if (!server.payloadText) return;
        try {
            await navigator.clipboard.writeText(server.payloadText);
            const btn = $('#srv-copy');
            btn.textContent = 'Copied!';
            setTimeout(function () { btn.textContent = 'Copy payload'; }, 1200);
        } catch (_e) { /* clipboard unavailable */ }
    }

    function serverSendLine() {
        const input = $('#srv-term-input');
        const line = input.value;
        input.value = '';
        if (!line.trim()) return;
        // The relay forwards stdin lines to the shell; echo locally so the
        // operator sees what was sent (remote socket shells rarely echo).
        serverAppendLine('in', '$ ' + line);
        window.api.listenerStdin(line).then(function (res) {
            if (!res || !res.ok) {
                serverAppendLine('err', '[send failed] ' + ((res && res.error) || 'listener not running'));
            }
        });
    }

    function serverTermInterrupt() {
        // Best-effort Ctrl-C: the relay sends the 0x03 byte to the shell.
        window.api.listenerStdin('\u0003').then(function (res) {
            if (!res || !res.ok) {
                serverAppendLine('err', '[interrupt failed] ' + ((res && res.error) || 'listener not running'));
            }
        });
    }

    function serverTermExit() {
        // 'exit' on the listener stdin closes the CURRENT session; the
        // listener keeps accepting until Stop is pressed.
        window.api.listenerStdin('exit').then(function (res) {
            if (!res || !res.ok) {
                serverAppendLine('err', '[exit failed] ' + ((res && res.error) || 'listener not running'));
            }
        });
    }

    function serverTermClear() {
        serverOutTail = null;
        const out = $('#srv-term-out');
        if (!out) return;
        out.innerHTML = '';
        const span = document.createElement('span');
        span.className = 'term-placeholder';
        span.textContent = 'Terminal cleared — start the listener to catch another session.';
        out.appendChild(span);
    }

    function handleListenerEvent(chunk) {
        const lines = String(chunk || '').split(/\r?\n/);
        lines.forEach(function (line) {
            const trimmed = line.replace(/\s+$/, '');
            if (trimmed) serverAppendLine('sys', trimmed);
        });
        if (SESSION_START_RE.test(String(chunk))) {
            server.sessionActive = true;
            updateServerUi();
            // Auto-open the on-screen interactive terminal when a shell
            // connects: bring the Server view forward and focus the input.
            switchView('server');
            const input = $('#srv-term-input');
            if (input) input.focus();
        }
        if (SESSION_END_RE.test(String(chunk)) && server.sessionActive) {
            server.sessionActive = false;
            updateServerUi();
        }
    }

    function handleListenerStatus(status) {
        if (!status) return;
        if (status.running) {
            server.running = true;
            updateServerUi();
        } else {
            server.running = false;
            server.sessionActive = false;
            updateServerUi();
            if (status.error) serverAppendLine('err', '[listener error] ' + status.error);
            else serverAppendLine('sys', status.cancelled ? '[*] Listener stopped.' : '[*] Listener exited (code ' + status.exitCode + ').');
        }
    }

    async function serverLoadShellTypes() {
        const res = await window.api.getShellTypes();
        const types = (res && res.types) || [];
        const sel = $('#srv-type');
        if (!sel) return;
        sel.innerHTML = '';
        types.forEach(function (t) {
            const opt = document.createElement('option');
            opt.value = t.id;
            opt.textContent = t.name + ' (' + t.aliases + ')';
            opt.title = (t.platform ? t.platform + ' — ' : '') + (t.desc || '');
            sel.appendChild(opt);
        });
    }

    function initServerView() {
        $('#srv-start').onclick = serverStart;
        $('#srv-stop').onclick = serverStop;
        $('#srv-gen').onclick = serverGenPayload;
        $('#srv-copy').onclick = serverCopyPayload;
        $('#srv-term-send').onclick = serverSendLine;
        $('#srv-term-input').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); serverSendLine(); }
        });
        $('#srv-term-interrupt').onclick = serverTermInterrupt;
        $('#srv-term-exit').onclick = serverTermExit;
        $('#srv-term-clear').onclick = serverTermClear;
        // Reload-safe: drop stale listeners before registering so a reloaded
        // renderer never receives each listener event multiple times.
        window.api.removeListenerOutputListeners();
        window.api.removeListenerEventListeners();
        window.api.removeListenerStatusListeners();
        window.api.onListenerOutput(serverAppendOut);
        window.api.onListenerEvent(handleListenerEvent);
        window.api.onListenerStatus(handleListenerStatus);
        serverLoadShellTypes();
        updateServerUi();
    }

    // ── Init ───────────────────────────────────────────────────────────────
    function init() {
        // Navigation
        $$('.nav-item[data-view]').forEach(function (b) {
            b.addEventListener('click', function () { switchView(b.dataset.view); });
        });
        // Mode toggle (Offline/Online). The main process enforces the same
        // switch, so a run can never reach the binary with --allow-network
        // while the app is offline. Never reset a mid-run indicator.
        $$('.mode-btn').forEach(function (b) {
            b.addEventListener('click', function () {
                state.mode = b.dataset.mode;
                $$('.mode-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
                if (!state.running) setRunIndicator('idle');
                window.api.setNetworkMode(state.mode);
            });
        });
        // Command bar
        $('#btn-cmd-go').onclick = function () { handleCommand($('#cmd-bar').value); };
        $('#cmd-bar').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') handleCommand($('#cmd-bar').value);
        });
        // Suggestions
        const suggestions = [
            'identify this hash',
            'check password strength',
            'show system status',
            'list tools',
            'plan a scan of my web app',
            'start an objective',
            'show skills',
        ];
        const sugg = $('#cmd-suggestions');
        suggestions.forEach(function (s) {
            const chip = document.createElement('button');
            chip.className = 'chip';
            chip.textContent = s;
            chip.onclick = function () {
                $('#cmd-bar').value = s;
                handleCommand(s);
            };
            sugg.appendChild(chip);
        });

        // Objectives tabs
        $$('#view-objectives .tab').forEach(function (b) {
            b.addEventListener('click', function () { setObjTab(b.dataset.tab); });
        });
        // Library tabs
        $$('#view-library .tab').forEach(function (b) {
            b.addEventListener('click', function () { setLibraryTab(b.dataset.tab); });
        });
        // Objective agent buttons
        $('#btn-agent-preview').onclick = agentPreview;
        $('#btn-agent-run').onclick = agentRun;
        // Analyze
        $('#tool-search').addEventListener('input', function () { renderToolList(this.value); });
        // Home tool launcher
        const browseAll = $('#btn-browse-all');
        if (browseAll) browseAll.onclick = function () { switchView('analyze'); };
        // Engage
        $('#btn-eng-config').onclick = function () { generateConfig(); };
        $('#btn-eng-plan').onclick = engPlan;
        $('#btn-eng-run').onclick = engRun;
        $('#btn-eng-report').onclick = engReport;
        $('#btn-eng-retest').onclick = engRetest;
        // Quick tools search
        $('#quick-search').addEventListener('input', function () { renderQuickTools(this.value); });
        // Library binds
        bindBrowse('#btn-find-browse', '#find-log-path');
        bindBrowse('#btn-find-retest-browse', '#find-retest-path');
        bindBrowse('#btn-audit-browse', '#audit-path');
        bindView('#btn-find-view', '#find-log-path', ['--view-findings-db'], '#output-findings', 'Findings log');
        bindView('#btn-find-retest', '#find-retest-path', ['--schedule-retest'], '#output-findings', 'Retest schedule');
        bindView('#btn-audit-view', '#audit-path', ['--view-audit'], '#output-audit', 'Audit log');
        bindView('#btn-db-audit', '#db-audit-path', ['--view-audit-db'], '#output-dbs', 'Audit DB');
        bindView('#btn-db-findings', '#db-findings-path', ['--view-findings-db'], '#output-dbs', 'Findings DB');
        bindView('#btn-db-cal', '#db-cal-path', ['--view-calibration-db'], '#output-dbs', 'Calibration DB');
        bindView('#btn-db-reason', '#db-reason-path', ['--view-reasoning-log-db'], '#output-dbs', 'Reasoning log DB');
        bindRecordFindings();
        // LLM
        $('#btn-llm-gen').onclick = function () {
            const prompt = $('#llm-prompt').value.trim();
            const out = $('#output-llm');
            if (!prompt) {
                renderRunResult(out, { ok: false, stdout: '', stderr: 'Provide a prompt before generating.', argsLabel: 'llm generate' }, 'Generate text');
                return;
            }
            setLoading(out, 'Generating…');
            runBinary(['--llm-generate', prompt], { stream: true, label: 'generate text' }).then(function (res) {
                renderRunResult(out, res, 'Generate text');
            });
        };
        $('#btn-llm-anom').onclick = function () {
            const text = $('#llm-text').value.trim();
            const out = $('#output-llm');
            if (!text) {
                renderRunResult(out, { ok: false, stdout: '', stderr: 'Provide log text before scoring.', argsLabel: 'anomaly score' }, 'Anomaly score');
                return;
            }
            setLoading(out, 'Scoring…');
            runBinary(['--llm-perplexity', text], { stream: true, label: 'anomaly score' }).then(function (res) {
                renderRunResult(out, res, 'Anomaly score');
            });
        };
        // Guides
        $('#btn-guide').onclick = function () {
            const sec = $('#guide-section').value.trim();
            const args = ['--guide'].concat(sec ? [sec] : []);
            const out = $('#output-guides');
            setLoading(out, 'Loading guide…');
            runBinary(args, { stream: true, label: 'guide' }).then(function (res) { renderRunResult(out, res, 'Guide'); });
        };
        $('#btn-shell-guide').onclick = function () {
            const out = $('#output-guides');
            setLoading(out, 'Loading shell guide…');
            runBinary(['--shell-guide'], { stream: true, label: 'shell guide' }).then(function (res) { renderRunResult(out, res, 'Shell payload guide'); });
        };
        $('#btn-tool-help').onclick = function () {
            const input = $('#tool-help-input').value.trim();
            if (!input) { alert('Enter a command or tool name.'); return; }
            const out = $('#output-guides');
            setLoading(out, 'Loading help…');
            runBinary(['--tool-help', input], { stream: true, label: 'tool help' }).then(function (res) { renderRunResult(out, res, 'Help: ' + input); });
        };
        // Run status bar
        $('#btn-run-cancel').onclick = cancelRun;
        // Streaming chunks → current stream target (drop stale listeners first
        // so a reloaded renderer never receives each chunk multiple times).
        window.api.removeStreamListeners();
        window.api.onStreamChunk(routeChunk);

        // Boot
        state.history = loadHistory();
        renderQuickActions();
        renderHistory();
        renderCats();
        renderQuickTools('');
        renderPlaybooks('');
        initLogConsole();
        initServerView();
        setRunIndicator('idle');
        loadStatus().then(function () {
            renderToolList('');
        });
        ensureWorkspace();
    }

    document.addEventListener('DOMContentLoaded', init);
})();
