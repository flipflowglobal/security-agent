// CDP GUI functional test for Security-Agent desktop app (current v2 UI).
// Connects to the live app (--remote-debugging-port=9222), navigates the
// sidebar views + tabs, fills inputs, clicks action buttons, and asserts the
// corresponding output panel changed — covering the new Agent mode, LLM tab,
// Quick Tools, Engage, and Server surfaces.
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
  await new Promise((r) => setTimeout(r, 2500));

  async function evalJs(expr) {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { __exc: JSON.stringify(r.result.exceptionDetails).slice(0, 300) };
    return r.result ? r.result.result.value : undefined;
  }

  const navView = (name) => evalJs(`(() => {
    const b = document.querySelector('.nav-item[data-view=${JSON.stringify(name)}]');
    if (!b) return 'NO_NAV';
    b.click(); return 'ok';
  })()`);
  const switchTab = (name) => evalJs(`(() => {
    const b = [...document.querySelectorAll('.tab')].find(x => x.dataset.tab === ${JSON.stringify(name)});
    if (!b) return 'NO_TAB';
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
  const out = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    return el ? (el.textContent || '') : 'NO_OUTPUT_EL';
  })()`);
  const outLen = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    return el ? (el.textContent || '').length : -1;
  })()`);
  const clearOut = (id) => evalJs(`(() => {
    const el = document.getElementById(${JSON.stringify(id)});
    if (el) el.textContent = '';
    return 'ok';
  })()`);
  const clickCard = (selector, text) => evalJs(`(() => {
    const els = [...document.querySelectorAll(${JSON.stringify(selector)})];
    const el = els.find(x => (x.textContent || '').includes(${JSON.stringify(text)}));
    if (!el) return 'NO_CARD';
    el.click(); return 'ok';
  })()`);

  async function waitLen(id, minLen, timeoutMs = 20000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const cur = await outLen(id);
      if (cur >= minLen) return cur;
      await new Promise((r) => setTimeout(r, 250));
    }
    return await outLen(id);
  }

  // The backend runs one task at a time and refuses new ones while a task is
  // active ("Refused: another task is already running"), so every backend
  // action must wait until the run indicator leaves the "running" class.
  async function waitIdle(timeoutMs = 120000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const busy = await evalJs(`(() => {
        const d = document.getElementById('run-indicator');
        return d ? d.classList.contains('running') : false;
      })()`);
      if (!busy) return true;
      await new Promise((r) => setTimeout(r, 250));
    }
    return false;
  }

  // ── Home: status stats + quick actions ─────────────────────────────────
  await waitLen('stat-tools', 1, 15000);
  const binaryStat = await out('stat-binary');
  const toolsStat = await out('stat-tools');
  record('Home > Status stats loaded', (binaryStat || '').length > 0 && (toolsStat || '').length > 0, `binary=${binaryStat} tools=${toolsStat}`);
  const qaCount = await evalJs(`(() => { const el = document.getElementById('quick-actions'); return el ? el.children.length : -1; })()`);
  record('Home > Quick actions rendered', qaCount > 0, `count=${qaCount}`);

  // ── Objectives: Agent mode (new) ───────────────────────────────────────
  const agentTab = await evalJs(`(() => { const b = document.querySelector('.tab[data-tab="agent"]'); return b ? 'ok' : 'NO_TAB'; })()`);
  await navView('objectives');
  await clearOut('output-agent');
  const agGoal = await setIn('agent-goal', 'list your offensive tools');
  const agCk = await click('btn-agent-preview');
  const agLen = await waitLen('output-agent', 10, 30000);
  await waitIdle();
  const agTxt = await out('output-agent');
  record('Objectives > Agent mode tab present', agentTab === 'ok', agentTab);
  record('Objectives > Agent preview plan', agGoal === 'ok' && agCk === 'ok' && agLen > 10 && !/error|exception|NO_EL/i.test(agTxt || ''), `len=${agLen}`, (agTxt || '').replace(/\s+/g, ' ').slice(0, 160));

  // ── Analyze: tool catalog + detail ─────────────────────────────────────
  await navView('analyze');
  const toolItems = await evalJs(`(() => { const el = document.getElementById('tool-list'); return el ? el.querySelectorAll('.tool-item').length : -1; })()`);
  await evalJs(`(() => { const el = document.querySelector('#tool-list .tool-item'); if (el) el.click(); return el ? 'ok' : 'NO_EL'; })()`);
  const detLen = await outLen('tool-detail');
  record('Analyze > Tool list rendered', toolItems > 0, `items=${toolItems}`);
  record('Analyze > Tool detail opens', detLen > 0, `len=${detLen}`);

  // ── Engage: config generation ──────────────────────────────────────────
  await navView('engage');
  await setIn('eng-name', 'GUI test');
  await setIn('eng-auth', 'tester');
  await setIn('eng-targets', 'web1 — WebApp — https://example.test');
  await click('btn-eng-config');
  const cfgLen = await waitLen('eng-config-text', 10, 20000);
  const cfgDisp = await evalJs(`(() => { const el = document.getElementById('eng-config-preview'); return el ? el.style.display : 'NO_EL'; })()`);
  record('Engage > Generate config', cfgLen > 10 && cfgDisp !== 'none' && cfgDisp !== 'NO_EL', `cfgLen=${cfgLen} display=${cfgDisp}`);

  // ── Library: LLM (new) — Generate ──────────────────────────────────────
  const llmTab = await evalJs(`(() => { const b = document.querySelector('.tab[data-tab="llm"]'); return b ? 'ok' : 'NO_TAB'; })()`);
  await navView('library');
  await switchTab('llm');
  await clearOut('output-llm');
  await waitIdle();
  await setIn('llm-prompt', 'scan the network');
  await click('btn-llm-gen');
  const llmLen = await waitLen('output-llm', 5, 120000);
  await waitIdle(180000);
  const llmTxt = await out('output-llm');
  record('Library > LLM tab present', llmTab === 'ok', llmTab);
  record('Library > LLM Generate', llmLen > 5 && !/error|exception/i.test(llmTxt || ''), `len=${llmLen}`, (llmTxt || '').replace(/\s+/g, ' ').slice(0, 160));

  // ── Library: LLM — Anomaly score ───────────────────────────────────────
  await waitIdle();
  await clearOut('output-llm');
  await setIn('llm-text', 'The admin panel returned 403 to an unauthenticated request');
  await click('btn-llm-anom');
  const anomLen = await waitLen('output-llm', 5, 60000);
  await waitIdle(120000);
  const anomTxt = await out('output-llm');
  record('Library > LLM Anomaly score', /perplexity/i.test(anomTxt || ''), `len=${anomLen}`, (anomTxt || '').replace(/\s+/g, ' ').slice(0, 160));

  // ── Library: Quick Tools — WPS PIN ─────────────────────────────────────
  await switchTab('quick');
  await waitIdle();
  const cardCk = await clickCard('#quick-grid .quick-card', 'WPS PIN');
  let qtLen = -1;
  if (cardCk === 'ok') {
    await setIn('qt-pin', '12345670');
    await clearOut('output-quick');
    const runCk = await evalJs(`(() => { const b = document.querySelector('#quick-form .btn.primary'); if (!b) return 'NO_BTN'; b.click(); return 'ok'; })()`);
    if (runCk === 'ok') qtLen = await waitLen('output-quick', 5, 30000);
    else record('Library > Quick WPS PIN', false, 'run button failed: ' + runCk);
  }
  await waitIdle();
  record('Library > Quick Tools WPS PIN', cardCk === 'ok' && qtLen > 5, `qtLen=${qtLen} card=${cardCk}`, ((await out('output-quick')) || '').replace(/\s+/g, ' ').slice(0, 160));

  // ── Library: Guides ─────────────────────────────────────────────────────
  await switchTab('guides');
  await waitIdle();
  await clearOut('output-guides');
  await click('btn-guide');
  const guideLen = await waitLen('output-guides', 10, 20000);
  await waitIdle();
  const guideTxt = await out('output-guides');
  record('Library > Plain-language guide', guideLen > 10 && /security-agent|command|tool/i.test(guideTxt || ''), `len=${guideLen}`);

  // ── Server: reverse-shell payload generation ───────────────────────────
  await navView('server');
  const srvOpts = await evalJs(`(() => { const el = document.getElementById('srv-type'); return el ? [...el.options].map(o => o.value).filter(v => v !== '') : 'NO_EL'; })()`);
  const srvCk = await click('srv-gen');
  // genShell does not touch the run indicator; poll until the "Generating…"
  // placeholder is replaced by the real payload.
  const srvStart = Date.now();
  let srvLen = await waitLen('srv-payload', 10, 20000);
  while (Date.now() - srvStart < 15000) {
    const t = await out('srv-payload');
    if (t && t.trim() !== 'Generating…') break;
    await new Promise((r) => setTimeout(r, 250));
  }
  const srvTxt = await out('srv-payload');
  record('Server > Gen Shell payload', Array.isArray(srvOpts) && srvOpts.length > 0 && srvCk === 'ok' && srvLen > 10 && (srvTxt || '').indexOf('Payload output will appear here.') === -1 && !/Generation failed/i.test(srvTxt || ''), `types=${Array.isArray(srvOpts) ? srvOpts.length : srvOpts} len=${(srvTxt || '').length}`, (srvTxt || '').replace(/\s+/g, ' ').slice(0, 120));

  // ── Summary ─────────────────────────────────────────────────────────────
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
