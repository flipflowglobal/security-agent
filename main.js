const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, execFile } = require('child_process');

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 880,
    minWidth: 1080,
    minHeight: 720,
    title: 'Security Agent — Autonomous Operations Console',
    backgroundColor: '#090d16',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile('index.html');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function runSaCommand(args) {
  return new Promise((resolve) => {
    const saPath = path.join(__dirname, 'sa');
    const proc = spawn(saPath, args, { cwd: __dirname });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('cmd-output', { stream: 'stdout', data: data.toString() });
      }
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('cmd-output', { stream: 'stderr', data: data.toString() });
      }
    });

    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });

    proc.on('error', (err) => {
      resolve({ code: -1, stdout, stderr: err.message });
    });
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handlers
ipcMain.handle('get-offline-status', async () => {
  const result = await runSaCommand(['--offline-status']);
  const metrics = {};
  if (result.stdout) {
    result.stdout.split('\n').forEach(line => {
      const parts = line.split('=');
      if (parts.length === 2) {
        metrics[parts[0].trim()] = parts[1].trim();
      }
    });
  }
  return { success: result.code === 0, metrics, raw: result.stdout };
});

ipcMain.handle('list-skills', async () => {
  const result = await runSaCommand(['--list-skills']);
  const skills = result.stdout ? result.stdout.split('\n').filter(s => s.trim().length > 0) : [];
  return { success: result.code === 0, skills };
});

ipcMain.handle('show-skill', async (event, name) => {
  const result = await runSaCommand(['--show-skill', name]);
  return { success: result.code === 0, content: result.stdout || result.stderr };
});

ipcMain.handle('list-tools', async () => {
  const result = await runSaCommand(['--list-tools']);
  const tools = [];
  if (result.stdout) {
    result.stdout.split('\n').forEach(line => {
      if (line.trim()) {
        const parts = line.split('\t');
        tools.push({
          name: parts[0],
          type: parts[1] || '',
          details: parts.slice(2).join(' ')
        });
      }
    });
  }
  return { success: result.code === 0, tools };
});

ipcMain.handle('ask-agent', async (event, query) => {
  const result = await runSaCommand(['--ask', query]);
  return { success: result.code === 0, response: result.stdout || result.stderr };
});

ipcMain.handle('plan-scan', async (event, configPath) => {
  const result = await runSaCommand(['--plan-scan', configPath]);
  return { success: result.code === 0, output: result.stdout || result.stderr };
});

ipcMain.handle('run-custom-cmd', async (event, argsString) => {
  const argsArr = argsString.trim().split(/\s+/);
  const result = await runSaCommand(argsArr);
  return { success: result.code === 0, output: result.stdout || result.stderr };
});
