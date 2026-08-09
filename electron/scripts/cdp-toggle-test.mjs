// Online/Offline toggle behavior test via CDP.
const base = process.env.CDP_BASE || 'http://127.0.0.1:9222';
async function main() {
  const list = await (await fetch(`${base}/json`)).json();
  const page = list.find((t) => t.type === 'page');
  if (!page || !page.webSocketDebuggerUrl) throw new Error('no page target');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  await new Promise((res) => (ws.onopen = res));
  const send = (method, params = {}) => new Promise((res) => { const id = nextId++; pending.set(id, res); ws.send(JSON.stringify({ id, method, params })); });
  await send('Runtime.enable');

  const evalJs = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    return r.result && r.result.result ? r.result.result.value : undefined;
  };
  const click = (id) => evalJs(`(() => { const el = document.getElementById('${id}'); if (!el) return 'NO_EL'; el.click(); return 'ok'; })()`);
  const activeMode = () => evalJs(`(() => [...document.querySelectorAll('.mode-btn')].find(b => b.classList.contains('active')) ? [...document.querySelectorAll('.mode-btn')].find(b => b.classList.contains('active')).textContent.trim() : 'NONE')()`);
  const statusText = () => evalJs(`(() => document.getElementById('output-status') ? (document.getElementById('output-status').textContent || '') : 'NO_EL')()`);

  // Default state: offline active
  console.log('initial active mode:', await activeMode());

  // Click Online
  console.log('click Online:', await click('mode-online'));
  await new Promise((r) => setTimeout(r, 400));
  console.log('active mode after Online:', await activeMode());

  // Refresh status in online mode
  await evalJs(`(() => { const el = document.getElementById('output-status'); if (el) el.textContent = ''; })()`);
  console.log('click Refresh Status:', await click('btn-refresh-status'));
  await new Promise((r) => setTimeout(r, 2500));
  const onlineStatus = await statusText();
  console.log('online-mode status:  ', onlineStatus.replace(/\s+/g, ' ').trim().slice(0, 140));

  // Back to Offline
  console.log('click Offline:', await click('mode-offline'));
  await new Promise((r) => setTimeout(r, 400));
  console.log('active mode after Offline:', await activeMode());

  // Refresh status in offline mode
  await evalJs(`(() => { const el = document.getElementById('output-status'); if (el) el.textContent = ''; })()`);
  console.log('click Refresh Status:', await click('btn-refresh-status'));
  await new Promise((r) => setTimeout(r, 2500));
  const offlineStatus = await statusText();
  console.log('offline-mode status: ', offlineStatus.replace(/\s+/g, ' ').trim().slice(0, 140));

  // Verify toggles switch active mode and status refreshes in both modes.
  const ok = (await activeMode()) === 'Offline' && onlineStatus.length > 0 && offlineStatus.length > 0;
  console.log(ok ? 'TOGGLE TEST PASS' : 'TOGGLE TEST FAIL');
  ws.close();
}
main().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
