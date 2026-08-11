// Agent-mode functional test for Security-Agent GUI.
// Connects to the live app (--remote-debugging-port=9222), types goals into
// the Objectives > Agent mode prompt box, clicks Preview / Run, waits for the
// task to COMPLETE (run indicator leaves "running"), then reviews the agent's
// response — asserting it executed successfully or reporting the error.
const base = process.env.CDP_BASE || 'http://127.0.0.1:9222';

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
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
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
  await send('Page.reload', { ignoreCache: true });
  await new Promise((r) => setTimeout(r, 2500));

  async function evalJs(expr) {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { __exc: JSON.stringify(r.result.exceptionDetails).slice(0, 300) };
    return r.result ? r.result.result.value : undefined;
  }
  const out = (id) => evalJs(`(() => { const el = document.getElementById(${JSON.stringify(id)}); return el ? (el.textContent || '') : 'NO_OUTPUT_EL'; })()`);
  const outLen = (id) => evalJs(`(() => { const el = document.getElementById(${JSON.stringify(id)}); return el ? (el.textContent || '').length : -1; })()`);

  async function waitIdle(timeoutMs = 180000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const busy = await evalJs(`(() => { const d = document.getElementById('run-indicator'); return d ? d.classList.contains('running') : false; })()`);
      if (!busy) return true;
      await new Promise((r) => setTimeout(r, 500));
    }
    return false;
  }

  function runState() {
    return evalJs(`(() => {
      const d = document.getElementById('run-indicator');
      const l = document.getElementById('run-label');
      return { cls: d ? d.className : 'NO_EL', label: l ? (l.textContent || '') : 'NO_EL' };
    })()`);
  }

  // Navigate to Objectives > Agent mode.
  await evalJs(`(() => { const b = document.querySelector('.nav-item[data-view="objectives"]'); if (b) b.click(); return b ? 'ok' : 'NO_NAV'; })()`);

  async function runAgent(goal, mode, expectCmd) {
    const name = `Agent ${mode === 'run' ? 'RUN' : 'preview'}: ${goal}`;
    const setGoal = await evalJs(`(() => {
      const el = document.getElementById('agent-goal');
      if (!el) return 'NO_EL';
      el.value = ${JSON.stringify(goal)};
      el.dispatchEvent(new Event('input', { bubbles: true }));
      return 'ok';
    })()`);
    if (setGoal !== 'ok') { record(name, false, 'goal input missing'); return; }
    if (mode === 'run') {
      // Preview-only checkbox is on by default; turn it off to actually execute.
      await evalJs(`(() => { const el = document.getElementById('agent-dryrun'); if (el) el.checked = false; return 'ok'; })()`);
    }
    const beforeTxt = await out('output-agent');
    const ck = await evalJs(`(() => {
      const b = document.getElementById(${JSON.stringify(mode === 'run' ? 'btn-agent-run' : 'btn-agent-preview')});
      if (!b) return 'NO_BTN';
      b.click(); return 'ok';
    })()`);
    if (ck !== 'ok') { record(name, false, 'button missing: ' + ck); return; }
    const done = await waitIdle(180000);
    const st = await runState();
    const txt = await out('output-agent');
    const changed = txt !== beforeTxt;
    // A real plan must be present: "Plan (N step(s))" and the expected command,
    // and never the "no in-scope action" decline.
    const planned = txt.includes('Plan (') && txt.includes(expectCmd) && !txt.includes('No in-scope action matched');
    const ok = done && changed && planned && /Finished/.test(st.label || '');
    const detail = `done=${done} changed=${changed} planned=${planned} cls=${st.cls} label=${st.label}`;
    record(name, ok, detail, txt);
  }

  // ── Preview-only planning (dry run, no execution) ────────────────────────
  await runAgent('list your offensive tools', 'preview', '--list-tools');
  await runAgent('identify the hash 5f4dcc3b5aa765d61d8327deb882cf99', 'preview', '--hash-id');
  await runAgent('create a wordlist for the target acme', 'preview', '--gen-wordlist');
  await runAgent('analyze this payload bash -i', 'preview', '--analyze-payload');
  await runAgent('check the strength of this password Tr0ub4dor&3', 'preview', '--password-strength');
  await runAgent('check the wps pin 12345670', 'preview', '--wps-pin');

  // ── Real execution (offline-safe goals only; network opt-in stays off) ──
  await runAgent('list your offensive tools', 'run', '--list-tools');
  await runAgent('identify the hash 5f4dcc3b5aa765d61d8327deb882cf99', 'run', '--hash-id');
  await runAgent('create a wordlist for the target acme', 'run', '--gen-wordlist');

  // ── Summary ─────────────────────────────────────────────────────────────
  const failed = results.filter((r) => !r.ok);
  const passed = results.filter((r) => r.ok);
  console.log(`\n==== SUMMARY: ${passed.length} PASS / ${failed.length} FAIL (of ${results.length}) ====`);
  if (failed.length) {
    console.log('\n--- FAILED CASES ---');
    for (const f of failed) {
      console.log(`FAIL ${f.name}: ${f.detail}`);
      if (f.output) console.log('     output: ' + f.output.replace(/\n/g, ' | ').slice(0, 500));
    }
  }
  console.log('\n--- AGENT OUTPUTS ---');
  for (const r of results) {
    const snip = (r.output || '').replace(/\s+/g, ' ').trim();
    console.log(`[${r.name}]\n${snip.slice(0, 700)}`);
  }
  ws.close();
}

main().catch((e) => {
  console.error('TEST DRIVER FAILED:', e);
  process.exit(1);
});
