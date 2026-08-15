// Smoke test: launch packaged app, verify boot, exercise core UI, check 0 errors, exit cleanly.
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
  const events = { console: [], exceptions: [], log: [] };
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    if (m.method === 'Runtime.consoleAPICalled') events.console.push(m.params);
    if (m.method === 'Runtime.exceptionThrown') events.exceptions.push(m.params);
  };
  await new Promise((res) => (ws.onopen = res));
  const send = (method, params = {}) => new Promise((res) => {
    const id = nextId++;
    pending.set(id, res);
    ws.send(JSON.stringify({ id, method, params }));
  });
  await send('Runtime.enable');
  await send('Page.enable');

  async function evalJs(expr) {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) return { __exc: JSON.stringify(r.result.exceptionDetails).slice(0, 300) };
    return r.result ? r.result.result.value : undefined;
  }

  // 1. Page booted
  await new Promise((r) => setTimeout(r, 2000));
  const title = await evalJs(`document.title`);
  const hasNav = await evalJs(`document.querySelectorAll('.nav-item').length`);
  record('Boot > Page loaded with title + nav', title.length > 0 && hasNav > 0, `title="${title}" nav=${hasNav}`);

  // 2. Home renders status (quick actions + tool chips)
  const quickActions = await evalJs(`document.querySelectorAll('#quick-actions .action-btn, #quick-actions button, #quick-actions .action-card').length`);
  const toolChips = await evalJs(`document.querySelectorAll('#tool-chip-grid .tool-chip').length`);
  const homeOutput = await evalJs(`(() => {
    const el = document.getElementById('home-output');
    return el ? el.textContent.trim() : '';
  })()`);
  record('Boot > Home quick actions + chips visible', quickActions > 0 && toolChips > 0, `quickActions=${quickActions} toolChips=${toolChips}`, homeOutput.slice(0, 60));

  // 3. Every view is reachable and has content
  const views = ['home', 'objectives', 'analyze', 'engage', 'server', 'library'];
  for (const v of views) {
    const ok = await evalJs(`(() => {
      const b = document.querySelector('.nav-item[data-view="${v}"]');
      if (!b) return 'NO_NAV';
      b.click();
      return 'ok';
    })()`);
    await new Promise((r) => setTimeout(r, 300));
    const active = await evalJs(`(() => {
      const s = document.querySelector('section.view.active, section.view[style*="display: block"], section#view-${v}');
      if (!s) return 'NO_VIEW';
      return s.id || 'unknown';
    })()`);
    record(`Views > ${v} reachable`, ok === 'ok' && active.includes(v), `active=${active}`);
  }

  // 4. Run a real tool through the Analyze view (hash-id)
  await evalJs(`(() => { const b = document.querySelector('.nav-item[data-view="analyze"]'); if (b) b.click(); return 'ok'; })()`);
  await new Promise((r) => setTimeout(r, 400));
  const toolResult = await evalJs(`(async () => {
    const input = document.querySelector('#tool-search');
    if (!input) return 'NO_INPUT';
    input.value = 'hash';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await new Promise(r => setTimeout(r, 500));
    const list = document.querySelector('#tool-list');
    const cards = list ? list.querySelectorAll('.tool-item').length : 0;
    return { cardCount: cards, htmlLen: list ? list.innerHTML.length : -1 };
  })()`);
  record('Analyze > tool search filters list', toolResult && toolResult.cardCount > 0, JSON.stringify(toolResult));

  // 5. Zero renderer errors/exceptions (allow benign noise)
  const errEvents = events.console.filter((c) => c.type === 'error');
  record('Errors > zero console errors', errEvents.length === 0, `consoleErrors=${errEvents.length}`, errEvents.slice(0, 2).map((e) => JSON.stringify(e).slice(0, 150)).join(' ; '));
  record('Errors > zero uncaught exceptions', events.exceptions.length === 0, `exceptions=${events.exceptions.length}`);

  ws.close();
  const failed = results.filter((r) => !r.ok);
  const passed = results.filter((r) => r.ok);
  console.log(`\n==== SMOKE SUMMARY: ${passed.length} PASS / ${failed.length} FAIL (of ${results.length}) ====`);
  for (const f of failed) console.log(`FAIL ${f.name}: ${f.detail} ${f.output ? '| ' + f.output : ''}`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error('SMOKE DRIVER FAILED:', e); process.exit(1); });
