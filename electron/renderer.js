// ═══════════════════════════════════════════════════════════════════════════
// Security-Agent GUI — Renderer (UI logic)
// ═══════════════════════════════════════════════════════════════════════════

(function () {
    'use strict';

    const $ = (sel, ctx = document) => ctx.querySelector(sel);
    const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

    // ── Panel Navigation ──────────────────────────────────────────────────

    let currentPanel = 'dashboard';

    function switchPanel(panelId) {
        $$('.nav-item').forEach(btn => btn.classList.remove('active'));
        $$('.panel').forEach(p => p.classList.remove('active'));

        const navBtn = $(`.nav-item[data-panel="${panelId}"]`);
        const panel = $(`#panel-${panelId}`);
        if (navBtn) navBtn.classList.add('active');
        if (panel) {
            panel.classList.add('active');
            currentPanel = panelId;
        }
        const main = $('#main-content');
        if (main) main.scrollTop = 0;
    }

    $$('.nav-item[data-panel]').forEach(btn => {
        btn.addEventListener('click', () => switchPanel(btn.dataset.panel));
    });

    $$('.action-btn[data-panel]').forEach(btn => {
        btn.addEventListener('click', () => switchPanel(btn.dataset.panel));
    });

    // ── Output Helpers ────────────────────────────────────────────────────

    function setLoading(outputEl) {
        outputEl.innerHTML = '<span class="loading-text"><span class="spinner"></span> Running...</span>';
        outputEl.classList.remove('error');
    }

    function setResult(outputEl, data) {
        const text = (data.stdout + (data.stderr ? '\n--- stderr ---\n' + data.stderr : '')).trim();
        if (!data.ok || data.exitCode !== 0) {
            outputEl.classList.add('error');
        } else {
            outputEl.classList.remove('error');
        }
        outputEl.textContent = text || '(no output)';
    }

    function setEmpty(outputEl, msg) {
        outputEl.classList.remove('error');
        outputEl.innerHTML = '<span class="empty-state">' + msg + '</span>';
    }

    // ── Copy/Save Toolbar ─────────────────────────────────────────────────

    function ensureWrapper(outputEl) {
        let wrapper = outputEl.closest('.output-wrapper');
        if (!wrapper) {
            wrapper = document.createElement('div');
            wrapper.className = 'output-wrapper';
            outputEl.parentNode.insertBefore(wrapper, outputEl);
            wrapper.appendChild(outputEl);
        }
        return wrapper;
    }

    function addToolbar(outputEl) {
        const wrapper = ensureWrapper(outputEl);
        let toolbar = wrapper.querySelector('.output-toolbar');
        if (!toolbar) {
            toolbar = document.createElement('div');
            toolbar.className = 'output-toolbar';
            toolbar.innerHTML =
                '<button class="output-toolbar-btn" data-action="copy" title="Copy to clipboard">' +
                    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>' +
                '</button>' +
                '<button class="output-toolbar-btn" data-action="save" title="Save to file">' +
                    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>' +
                '</button>';
            wrapper.appendChild(toolbar);
        }

        var copyBtn = toolbar.querySelector('[data-action="copy"]');
        copyBtn.onclick = async function () {
            var text = outputEl.textContent || '';
            try {
                await navigator.clipboard.writeText(text);
                copyBtn.classList.add('copied');
                copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
                setTimeout(function () {
                    copyBtn.classList.remove('copied');
                    copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
                }, 1500);
            } catch (_e) {
                var textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
            }
        };

        var saveBtn = toolbar.querySelector('[data-action="save"]');
        saveBtn.onclick = async function () {
            var text = outputEl.textContent || '';
            var filePath = await window.api.saveFile({
                filters: [{ name: 'Text', extensions: ['txt'] }, { name: 'All', extensions: ['*'] }]
            });
            if (filePath) {
                await window.api.writeFile(filePath, text);
            }
        };
    }

    // ── Dashboard ─────────────────────────────────────────────────────────

    async function loadDashboard() {
        var statusEl = $('#binary-status');
        var toolsEl = $('#tools-count');
        var skillsEl = $('#skills-count');
        var coverageEl = $('#coverage-status');
        var warningEl = $('#binary-warning');

        try {
            var binPath = await window.api.getBinaryPath();
            if (binPath) {
                statusEl.textContent = 'Found';
                statusEl.style.color = 'var(--accent-green)';
                if (warningEl) warningEl.style.display = 'none';
            } else {
                statusEl.textContent = 'Not Found';
                statusEl.style.color = 'var(--accent-red)';
                if (warningEl) warningEl.style.display = 'flex';
            }
        } catch (_e) {
            statusEl.textContent = 'Error';
            statusEl.style.color = 'var(--accent-red)';
        }

        try {
            var result = await window.api.runCommand(['--offline-status']);
            if (result.ok) {
                var lines = result.stdout.split('\n');
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i];
                    if (line.startsWith('cataloged_tool_definitions=')) {
                        toolsEl.textContent = line.split('=')[1];
                    }
                    if (line.startsWith('embedded_skills=')) {
                        skillsEl.textContent = line.split('=')[1];
                    }
                    if (line.startsWith('capability_coverage=')) {
                        var val = line.split('=')[1];
                        if (val === 'ok') {
                            coverageEl.textContent = 'OK';
                            coverageEl.style.color = 'var(--accent-green)';
                        } else {
                            coverageEl.textContent = val;
                            coverageEl.style.color = 'var(--accent-orange)';
                        }
                    }
                }
            }
        } catch (_e) {
            // Dashboard shows -- values on failure
        }
    }

    // ── Online / Offline Mode Toggle ─────────────────────────────────────

    let agentMode = 'offline'; // default mode

    function setAgentMode(mode) {
        agentMode = mode;
        const offlineBtn = $('#mode-offline');
        const onlineBtn = $('#mode-online');
        if (mode === 'offline') {
            offlineBtn.classList.add('active');
            onlineBtn.classList.remove('active');
        } else {
            onlineBtn.classList.add('active');
            offlineBtn.classList.remove('active');
        }
        // Store preference
        try { localStorage.setItem('agent-mode', mode); } catch (_e) {}
        // Update subtitle
        const subtitle = $('#panel-dashboard .subtitle');
        if (subtitle) {
            subtitle.textContent = mode === 'online'
                ? 'Security-Agent orchestration overview — Online Mode'
                : 'Security-Agent orchestration overview — Offline Mode';
        }
    }

    // Restore saved preference
    try {
        const saved = localStorage.getItem('agent-mode');
        if (saved === 'online' || saved === 'offline') setAgentMode(saved);
    } catch (_e) {}

    // Wire up toggle buttons
    const modeToggle = $('#mode-toggle');
    if (modeToggle) {
        modeToggle.addEventListener('click', function (e) {
            const btn = e.target.closest('.mode-btn');
            if (btn && btn.dataset.mode) {
                setAgentMode(btn.dataset.mode);
            }
        });
    }

    // ── System Status ─────────────────────────────────────────────────────

    $('#btn-refresh-status').addEventListener('click', async function () {
        var output = $('#output-status');
        setLoading(output);
        var result = await window.api.runCommand(['--offline-status']);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Run Tool ──────────────────────────────────────────────────────────

    $('#btn-browse-tool-input').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#tool-input-path').value = file;
    });

    $('#btn-browse-tool-output').addEventListener('click', async function () {
        var file = await window.api.saveFile({ filters: [{ name: 'Text', extensions: ['txt'] }] });
        if (file) $('#tool-output-path').value = file;
    });

    $('#btn-run-tool').addEventListener('click', async function () {
        var output = $('#output-tools');
        var name = $('#tool-name').value;
        var inputPath = $('#tool-input-path').value.trim();
        var outputPath = $('#tool-output-path').value.trim();

        if (!inputPath) {
            setEmpty(output, 'Please provide an input path.');
            return;
        }

        setLoading(output);
        var args = ['--run-tool', name, inputPath];
        if (outputPath) {
            args.push('--output', outputPath);
        }
        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Skills ────────────────────────────────────────────────────────────

    var allSkills = [];

    function renderSkills(filter) {
        var listEl = $('#skill-list');
        var filtered = filter
            ? allSkills.filter(function (s) { return s.toLowerCase().includes(filter.toLowerCase()); })
            : allSkills;

        listEl.innerHTML = '';
        filtered.forEach(function (name) {
            var btn = document.createElement('button');
            btn.className = 'skill-item';
            btn.textContent = name;
            btn.addEventListener('click', async function () {
                $$('.skill-item').forEach(function (b) { b.classList.remove('active'); });
                btn.classList.add('active');
                var detailEl = $('#skill-detail');
                setLoading(detailEl);
                var res = await window.api.runCommand(['--show-skill', name]);
                setResult(detailEl, res);
                addToolbar(detailEl);
            });
            listEl.appendChild(btn);
        });

        if (filtered.length === 0) {
            setEmpty(listEl, filter ? 'No matching skills.' : 'No skills found.');
        }
    }

    $('#btn-list-skills').addEventListener('click', async function () {
        var listEl = $('#skill-list');
        setLoading(listEl);

        var result = await window.api.runCommand(['--list-skills']);
        if (!result.ok) {
            setEmpty(listEl, 'Failed to load skills.');
            return;
        }

        allSkills = result.stdout.split('\n').filter(function (s) { return s.trim(); });
        renderSkills($('#skill-search').value);
    });

    $('#skill-search').addEventListener('input', function (e) {
        renderSkills(e.target.value);
    });

    // ── External Tool ─────────────────────────────────────────────────────

    $('#btn-run-external').addEventListener('click', async function () {
        var output = $('#output-external');
        var name = $('#ext-tool-name').value.trim();
        var argsStr = $('#ext-tool-args').value.trim();
        var allowNetwork = $('#ext-allow-network').checked;

        if (!name) {
            setEmpty(output, 'Please provide a tool name.');
            return;
        }

        setLoading(output);
        var args = ['--run-external-tool'];
        if (allowNetwork) args.push('--allow-network');
        args.push(name);
        if (argsStr) {
            args.push.apply(args, argsStr.split(/\s+/));
        }
        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Plan Scan ─────────────────────────────────────────────────────────

    $('#btn-browse-plan-config').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#plan-config-path').value = file;
    });

    $('#plan-execute').addEventListener('change', function (e) {
        $('#plan-execute-options').style.display = e.target.checked ? 'block' : 'none';
    });

    $('#btn-plan-scan').addEventListener('click', async function () {
        var output = $('#output-plan-scan');
        var config = $('#plan-config-path').value.trim();

        if (!config) {
            setEmpty(output, 'Please provide an engagement config path.');
            return;
        }

        setLoading(output);
        var args = ['--plan-scan', config];

        function addOpt(id, flag) {
            var val = $(id).value.trim();
            if (val) args.push(flag, val);
        }

        addOpt('#plan-audit-log', '--audit-log');
        addOpt('#plan-audit-db', '--audit-db');
        addOpt('#plan-memory', '--memory');
        addOpt('#plan-calibration-db', '--calibration-db');

        if ($('#plan-cognitive-review').checked) args.push('--cognitive-review');
        if ($('#plan-execute').checked) {
            if ($('#plan-allow-network').checked) args.push('--allow-network');
            args.push('--execute');
            var execArgs = $('#plan-exec-args').value.trim();
            if (execArgs) args.push.apply(args, execArgs.split(/\s+/));
        }

        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Record Findings ───────────────────────────────────────────────────

    $('#btn-browse-findings-dest').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#findings-dest').value = file;
    });

    $('#btn-browse-findings-src').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#findings-src').value = file;
    });

    $('#btn-record-findings').addEventListener('click', async function () {
        var output = $('#output-findings');
        var dest = $('#findings-dest').value.trim();
        var src = $('#findings-src').value.trim();

        if (!dest || !src) {
            setEmpty(output, 'Please provide both source and destination paths.');
            return;
        }

        setLoading(output);
        var result = await window.api.runCommand(['--record-findings', dest, src]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Schedule Retest ───────────────────────────────────────────────────

    $('#btn-browse-retest').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#retest-path').value = file;
    });

    $('#btn-schedule-retest').addEventListener('click', async function () {
        var output = $('#output-retest');
        var p = $('#retest-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide a findings log path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--schedule-retest', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── View Audit Log ────────────────────────────────────────────────────

    $('#btn-browse-audit-log').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#audit-log-path').value = file;
    });

    $('#btn-view-audit').addEventListener('click', async function () {
        var output = $('#output-audit');
        var p = $('#audit-log-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide an audit log path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--view-audit', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── View Audit Database ───────────────────────────────────────────────

    $('#btn-browse-audit-db').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#audit-db-path').value = file;
    });

    $('#btn-view-audit-db').addEventListener('click', async function () {
        var output = $('#output-audit-db');
        var p = $('#audit-db-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide an audit database path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--view-audit-db', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── View Findings Database ────────────────────────────────────────────

    $('#btn-browse-findings-db').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#findings-db-path').value = file;
    });

    $('#btn-view-findings-db').addEventListener('click', async function () {
        var output = $('#output-findings-db');
        var p = $('#findings-db-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide a findings database path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--view-findings-db', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── View Calibration Database ─────────────────────────────────────────

    $('#btn-browse-calibration-db').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#calibration-db-path').value = file;
    });

    $('#btn-view-calibration-db').addEventListener('click', async function () {
        var output = $('#output-calibration-db');
        var p = $('#calibration-db-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide a calibration database path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--view-calibration-db', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── View Reasoning Log Database ───────────────────────────────────────

    $('#btn-browse-reasoning-db').addEventListener('click', async function () {
        var file = await window.api.selectFile();
        if (file) $('#reasoning-db-path').value = file;
    });

    $('#btn-view-reasoning-db').addEventListener('click', async function () {
        var output = $('#output-reasoning-db');
        var p = $('#reasoning-db-path').value.trim();
        if (!p) {
            setEmpty(output, 'Please provide a reasoning log database path.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--view-reasoning-log-db', p]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── LLM Generate ──────────────────────────────────────────────────────

    $('#btn-llm-generate').addEventListener('click', async function () {
        var output = $('#output-llm-generate');
        var prompt = $('#llm-gen-prompt').value.trim();
        if (!prompt) {
            setEmpty(output, 'Please enter a prompt.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--llm-generate', prompt]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── LLM Anomaly ──────────────────────────────────────────────────────

    $('#btn-llm-anomaly').addEventListener('click', async function () {
        var output = $('#output-llm-anomaly');
        var text = $('#llm-anomaly-text').value.trim();
        if (!text) {
            setEmpty(output, 'Please enter text to score.');
            return;
        }
        setLoading(output);
        var result = await window.api.runCommand(['--llm-perplexity', text]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Ask (NLU) with Streaming ──────────────────────────────────────────

    $('#btn-ask').addEventListener('click', async function () {
        var output = $('#output-ask');
        var input = $('#ask-input').value.trim();
        if (!input) {
            setEmpty(output, 'Please enter a question or instruction.');
            return;
        }

        setLoading(output);
        output.textContent = '';

        window.api.removeStreamListeners();
        window.api.onStreamChunk(function (chunk) {
            output.classList.remove('error');
            output.textContent += chunk;
            output.scrollTop = output.scrollHeight;
        });

        var result = await window.api.runStreaming(['--ask', input]);
        window.api.removeStreamListeners();

        if (!result.ok && result.exitCode !== 0) {
            output.classList.add('error');
            if (!output.textContent.trim()) {
                output.textContent = result.stderr || '(no output)';
            }
        }
        addToolbar(output);
    });

    // ── About ─────────────────────────────────────────────────────────────

    $('#btn-about').addEventListener('click', async function () {
        var output = $('#output-about');
        setLoading(output);
        var result = await window.api.runCommand(['--about']);
        setResult(output, result);
        addToolbar(output);
    });

    // ══════════════════════════════════════════════════════════════════════
    // Offensive Toolkit Handlers
    // ══════════════════════════════════════════════════════════════════════

    // ── Hash ID ───────────────────────────────────────────────────────────

    $('#btn-offensive-hash').addEventListener('click', async function () {
        var output = $('#output-offensive-hash');
        var hash = $('#offensive-hash-input').value.trim();
        if (!hash) { setEmpty(output, 'Enter a hash to identify.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--hash-id', hash]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Password Strength ─────────────────────────────────────────────────

    $('#btn-offensive-password').addEventListener('click', async function () {
        var output = $('#output-offensive-password');
        var pw = $('#offensive-password-input').value.trim();
        if (!pw) { setEmpty(output, 'Enter a password to analyze.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--password-strength', pw]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Gen Wordlist ──────────────────────────────────────────────────────

    $('#btn-offensive-wordlist').addEventListener('click', async function () {
        var output = $('#output-offensive-wordlist');
        var target = $('#offensive-wordlist-target').value.trim();
        if (!target) { setEmpty(output, 'Enter a target name.'); return; }
        setLoading(output);
        var args = ['--gen-wordlist', target];
        var company = $('#offensive-wordlist-company').value.trim();
        var year = $('#offensive-wordlist-year').value.trim();
        if (company) args.push('--company', company);
        if (year) args.push('--year', year);
        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Gen Shell Payload ─────────────────────────────────────────────────

    $('#btn-offensive-shell').addEventListener('click', async function () {
        var output = $('#output-offensive-shell');
        var type = $('#offensive-shell-type').value;
        var lhost = $('#offensive-shell-lhost').value.trim();
        var lport = $('#offensive-shell-lport').value.trim();
        if (!lhost || !lport) { setEmpty(output, 'Enter LHOST and LPORT.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--gen-shell', type, lhost, lport]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Analyze Payload ───────────────────────────────────────────────────

    $('#btn-offensive-payload').addEventListener('click', async function () {
        var output = $('#output-offensive-payload');
        var payload = $('#offensive-payload-input').value.trim();
        if (!payload) { setEmpty(output, 'Enter a payload to analyze.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--analyze-payload', payload]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── PS Obfuscation ───────────────────────────────────────────────────

    $('#btn-offensive-evasion').addEventListener('click', async function () {
        var output = $('#output-offensive-evasion');
        var cmd = $('#offensive-evasion-command').value.trim();
        if (!cmd) { setEmpty(output, 'Enter a PowerShell command.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--obfuscate-ps', cmd]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Wireless Audit ────────────────────────────────────────────────────

    $('#btn-offensive-wireless').addEventListener('click', async function () {
        var output = $('#output-offensive-wireless');
        var essid = $('#offensive-wifi-essid').value.trim();
        var security = $('#offensive-wifi-security').value;
        var encryption = $('#offensive-wifi-encryption').value;
        if (!essid) { setEmpty(output, 'Enter an ESSID.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--audit-wifi', essid, security, encryption]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Post-Exploit Analysis ─────────────────────────────────────────────

    $('#btn-offensive-postexploit').addEventListener('click', async function () {
        var output = $('#output-offensive-postexploit');
        var mode = $('#offensive-postexploit-mode').value;
        var input = $('#offensive-postexploit-input').value.trim();
        if (!input) { setEmpty(output, 'Provide file content or path.'); return; }
        setLoading(output);
        var flag = mode === 'passwd' ? '--analyze-passwd' : '--analyze-sudoers';
        var result = await window.api.runCommand([flag, input]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── List Tools ──────────────────────────────────────────────────────

    $('#btn-list-tools').addEventListener('click', async function () {
        var output = $('#output-list-tools');
        setLoading(output);
        var result = await window.api.runCommand(['--list-tools']);
        if (!result.ok) {
            setResult(output, result);
            addToolbar(output);
            return;
        }
        var lines = result.stdout.split('\n').filter(function (l) { return l.trim(); });
        if (lines.length === 0) {
            setEmpty(output, 'No tools found.');
            return;
        }
        var table = document.createElement('div');
        table.className = 'tools-table';
        var header = document.createElement('div');
        header.className = 'tools-row tools-header';
        header.innerHTML = '<span class="tools-cell tools-name">Tool</span>' +
            '<span class="tools-cell tools-type">Type</span>' +
            '<span class="tools-cell tools-detail">Detail</span>';
        table.appendChild(header);
        lines.forEach(function (line) {
            var parts = line.split('\t');
            var row = document.createElement('div');
            row.className = 'tools-row';
            var name = parts[0] || '';
            var type = parts[1] || '';
            var detail = parts.slice(2).join('  ');
            row.innerHTML = '<span class="tools-cell tools-name">' + name + '</span>' +
                '<span class="tools-cell tools-type">' + type + '</span>' +
                '<span class="tools-cell tools-detail">' + detail + '</span>';
            table.appendChild(row);
        });
        output.innerHTML = '';
        output.classList.remove('error');
        output.appendChild(table);
        addToolbar(output);
    });

    // ── Gen Decoys ──────────────────────────────────────────────────────

    $('#btn-offensive-decoys').addEventListener('click', async function () {
        var output = $('#output-offensive-decoys');
        var realIp = $('#offensive-decoys-real-ip').value.trim();
        if (!realIp) { setEmpty(output, 'Enter a real IP address.'); return; }
        setLoading(output);
        var args = ['--gen-decoys', realIp];
        var count = $('#offensive-decoys-count').value.trim();
        if (count) args.push(count);
        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Analyze Handshake ───────────────────────────────────────────────

    $('#btn-offensive-handshake').addEventListener('click', async function () {
        var output = $('#output-offensive-handshake');
        var framesRaw = $('#offensive-handshake-frames').value.trim();
        if (!framesRaw) { setEmpty(output, 'Paste EAPOL hex frames.'); return; }
        setLoading(output);
        var frames = framesRaw.split(/\s+/).filter(function (f) { return f.length > 0; });
        var args = ['--analyze-handshake'].concat(frames);
        var result = await window.api.runCommand(args);
        setResult(output, result);
        addToolbar(output);
    });

    // ── WPS PIN ─────────────────────────────────────────────────────────

    $('#btn-offensive-wps').addEventListener('click', async function () {
        var output = $('#output-offensive-wps');
        var pin = $('#offensive-wps-pin').value.trim();
        if (!pin) { setEmpty(output, 'Enter a WPS PIN.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--wps-pin', pin]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Analyze Keys ────────────────────────────────────────────────────

    $('#btn-offensive-keys').addEventListener('click', async function () {
        var output = $('#output-offensive-keys');
        var input = $('#offensive-keys-input').value.trim();
        if (!input) { setEmpty(output, 'Provide file content or path.'); return; }
        setLoading(output);
        var result = await window.api.runCommand(['--analyze-keys', input]);
        setResult(output, result);
        addToolbar(output);
    });

    // ── Keyboard Shortcuts ────────────────────────────────────────────────

    document.addEventListener('keydown', function (e) {
        // Escape: go back to dashboard
        if (e.key === 'Escape') {
            switchPanel('dashboard');
        }
        // Ctrl/Cmd + K: focus the active panel's first input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            var activePanel = $('.panel.active');
            if (activePanel) {
                var firstInput = activePanel.querySelector('input[type="text"], textarea');
                if (firstInput) firstInput.focus();
            }
        }
        // Ctrl/Cmd + L: focus the search bar in skills panel
        if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
            if (currentPanel === 'skills') {
                e.preventDefault();
                $('#skill-search').focus();
            }
        }
    });

    // ── Init ──────────────────────────────────────────────────────────────

    loadDashboard();
})();
