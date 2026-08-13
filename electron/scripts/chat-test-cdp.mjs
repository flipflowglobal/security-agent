// Quick CDP check for the new Chat LLM view.
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

  // 1. Chat is the default view + nav present
  const activeView = await evalJs(`(() => {
    const a = document.querySelector('.view.active');
    return a ? a.id : 'NONE';
  })()`);
  const chatNav = await evalJs(`(() => {
    const b = document.querySelector('.nav-item[data-view="chat"]');
    return b ? b.classList.contains('active') : 'NO_NAV';
  })()`);
  record('Chat > default active view', activeView === 'view-chat' && chatNav === true, `active=${activeView}`);

  // 2. Layout elements present
  const layout = await evalJs(`(() => {
    const ids = ['chat-messages', 'chat-input', 'chat-send', 'chat-model', 'chat-side'];
    const missing = ids.filter(id => !document.getElementById(id));
    return missing.length ? 'MISSING:' + missing.join(',') : 'ok';
  })()`);
  record('Chat > layout elements', layout === 'ok', layout);

  // 3. Send a message → assistant bubble + run card
  await evalJs(`(() => {
    const input = document.getElementById('chat-input');
    input.value = 'list your available tools';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('chat-send').click();
    return 'ok';
  })()`);
  const start = Date.now();
  let bubbles = 0;
  while (Date.now() - start < 150000) {
    await new Promise((r) => setTimeout(r, 500));
    bubbles = await evalJs(`(() => document.querySelectorAll('.chat-msg').length)()`);
    const busy = await evalJs(`(() => {
      const d = document.getElementById('run-indicator');
      return d ? d.classList.contains('running') : false;
    })()`);
    if (!busy && bubbles >= 2) break;
  }
  const runCards = await evalJs(`(() => document.querySelectorAll('.chat-run-card').length)()`);
  const lastText = await evalJs(`(() => {
    const ms = document.querySelectorAll('.chat-msg.assistant .chat-bubble');
    return ms.length ? ms[ms.length - 1].textContent : 'NO_BUBBLE';
  })()`);
  const persisted = await evalJs(`(() => {
    try { return JSON.parse(localStorage.getItem('sa_chat_v1') || '[]').length; } catch (_e) { return -1; }
  })()`);
  const hasRealReply = (lastText || '').trim().length > 0 &&
    !/(offline model returned no reply|no reply|Tool run failed|ERROR|exception)/i.test(lastText || '');
  record('Chat > send message renders run card + reply', bubbles >= 2 && runCards >= 1 && hasRealReply, `bubbles=${bubbles} runCards=${runCards} persisted=${persisted}`, lastText.replace(/\s+/g, ' ').slice(0, 140));

  const failed = results.filter((r) => !r.ok);
  const passed = results.filter((r) => r.ok);
  console.log(`\n==== SUMMARY: ${passed.length} PASS / ${failed.length} FAIL (of ${results.length}) ====`);
  ws.close();
}

main().catch((e) => {
  console.error('CHAT TEST DRIVER FAILED:', e);
  process.exit(1);
});
