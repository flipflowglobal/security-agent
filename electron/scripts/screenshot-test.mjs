// Capture screenshots of the Chat view and Home view for visual verification.
const base = process.env.CDP_BASE || 'http://127.0.0.1:9222';
import fs from 'node:fs';

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
  await send('Page.enable');
  await new Promise((r) => setTimeout(r, 800));

  async function shot(file) {
    const r = await send('Page.captureScreenshot', { format: 'png' });
    if (r.result && r.result.data) {
      fs.writeFileSync(file, Buffer.from(r.result.data, 'base64'));
      console.log('saved ' + file);
    } else {
      console.log('capture failed for ' + file);
    }
  }

  await shot('C:/Users/david/AppData/Local/Temp/opencode/gui-test/chat-default.png');
  await send('Runtime.evaluate', { expression: `document.querySelector('.nav-item[data-view="home"]').click()` });
  await new Promise((r) => setTimeout(r, 1200));
  await shot('C:/Users/david/AppData/Local/Temp/opencode/gui-test/home.png');
  ws.close();
}

main().catch((e) => { console.error('SHOT FAILED:', e); process.exit(1); });
