// Online/Offline toggle behavior test via CDP (v2 UI).
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
  const activeMode = () => evalJs(`(() => { const b = [...document.querySelectorAll('.mode-btn')].find(x => x.classList.contains('active')); return b ? b.textContent.trim() : 'NONE'; })()`);
  const clickSystemStatus = () => evalJs(`(() => { const b = [...document.querySelectorAll('.action-btn')].find(x => x.textContent.includes('System status')); if (!b) return 'NO_EL'; b.click(); return 'ok'; })()`);
  const homeOutput = () => evalJs(`(() => document.getElementById('home-output') ? (document.getElementById('home-output').textContent || '') : 'NO_EL')()`);
  const statMode = () => evalJs(`(() => document.getElementById('stat-mode') ? document.getElementById('stat-mode').textContent : 'NO_EL')()`);

  // Default state: offline active
  const initial = await activeMode();
  console.log('initial active mode:', initial);

  // Click Online
  console.log('click Online:', await click('mode-online'));
  await new Promise((r) => setTimeout(r, 400));
  const afterOnline = await activeMode();
  console.log('active mode after Online:', afterOnline);

  // Back to Offline
  console.log('click Offline:', await click('mode-offline'));
  await new Promise((r) => setTimeout(r, 400));
  const afterOffline = await activeMode();
  console.log('active mode after Offline:', afterOffline);

  // Status refresh in offline mode (Home "System status" quick action)
  await evalJs(`(() => { const el = document.getElementById('home-output'); if (el) el.textContent = ''; })()`);
  console.log('click System status:', await clickSystemStatus());
  await new Promise((r) => setTimeout(r, 4000));
  const output = await homeOutput();
  const modeStat = await statMode();
  console.log('home-output:  ', output.replace(/\s+/g, ' ').trim().slice(0, 120));
  console.log('stat-mode:    ', modeStat);

  const ok =
    initial === 'Offline' &&
    afterOnline === 'Online' &&
    afterOffline === 'Offline' &&
    output.trim() !== '' && output !== 'NO_EL' && modeStat === 'Offline';
  console.log(ok ? 'TOGGLE TEST PASS' : 'TOGGLE TEST FAIL');
  if (!ok) process.exitCode = 1;
  ws.close();
}
main().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
