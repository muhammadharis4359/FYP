#!/usr/bin/env bash
# ==============================================================================
# AI Exploit Chain Mapper - Native WebSocket PTY Bridge Installer (Approach 2)
# Target Host: 213.199.43.129 (Ubuntu VPS)
# ==============================================================================

set -e

echo "=========================================================================="
echo " [*] Deploying Native WebSocket PTY Bridge with Persistent Report Logging..."
echo "=========================================================================="

# 1. Install System Build Dependencies & Node.js 20 LTS
echo "[*] Checking and installing system dependencies (build-essential, python3, nodejs)..."
apt-get update -y
apt-get install -y curl build-essential python3 make g++

if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d'.' -f1 | tr -d 'v')" -lt 18 ]; then
    echo "[*] Installing Node.js 20 LTS via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

echo "[+] Node.js version: $(node -v)"
echo "[+] NPM version: $(npm -v)"

# 2. Setup Application Directory
APP_DIR="/opt/terminal-bridge"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# 3. Write package.json
cat << 'EOF' > "$APP_DIR/package.json"
{
  "name": "vps-terminal-bridge",
  "version": "1.0.0",
  "description": "Native WebSocket PTY Bridge with xterm.js support and persistent session report logging",
  "main": "server.js",
  "dependencies": {
    "cors": "^2.8.5",
    "express": "^4.19.2",
    "node-pty": "^1.0.2",
    "uuid": "^9.0.1",
    "ws": "^8.17.0"
  }
}
EOF

# 4. Write server.js
cat << 'EOF' > "$APP_DIR/server.js"
const http = require('http');
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const { WebSocketServer } = require('ws');
const pty = require('node-pty');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 7682;
const HOST = process.env.HOST || '0.0.0.0';
const DEFAULT_SHELL = process.env.SHELL || '/bin/bash';
const REPORT_DIR = process.env.REPORT_DIR || '/var/log/dashboard-reports';

if (!fs.existsSync(REPORT_DIR)) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
}

const app = express();
app.use(cors());
app.use(express.json());

// API: Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VPS Native WebSocket PTY Terminal Bridge',
    reports_dir: REPORT_DIR,
    timestamp: new Date().toISOString()
  });
});

// API: List generated reports
app.get('/api/reports', (req, res) => {
  try {
    if (!fs.existsSync(REPORT_DIR)) return res.json([]);
    const files = fs.readdirSync(REPORT_DIR);
    const jsonFiles = files.filter(f => f.startsWith('session-') && f.endsWith('.json'));
    const reports = jsonFiles.map(f => {
      try { return JSON.parse(fs.readFileSync(path.join(REPORT_DIR, f), 'utf8')); } catch (e) { return null; }
    }).filter(Boolean);
    reports.sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0));
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve reports', details: err.message });
  }
});

// API: Get specific report details
app.get('/api/reports/:id', (req, res) => {
  try {
    const reportFile = path.join(REPORT_DIR, `session-${req.params.id}.json`);
    if (!fs.existsSync(reportFile)) return res.status(404).json({ error: 'Report not found' });
    res.json(JSON.parse(fs.readFileSync(reportFile, 'utf8')));
  } catch (err) {
    res.status(500).json({ error: 'Failed to read report', details: err.message });
  }
});

// API: Get raw text log
app.get('/api/reports/:id/raw', (req, res) => {
  try {
    const logFile = path.join(REPORT_DIR, `session-${req.params.id}.log`);
    if (!fs.existsSync(logFile)) return res.status(404).json({ error: 'Log not found' });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    fs.createReadStream(logFile).pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read log', details: err.message });
  }
});

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (request, socket, head) => {
  const { pathname } = new URL(request.url, `http://${request.headers.host}`);
  if (pathname === '/ws/terminal' || pathname === '/ws/terminal/') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws, req) => {
  const sessionId = uuidv4().slice(0, 8);
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const startTime = new Date();
  
  const logFilePath = path.join(REPORT_DIR, `session-${sessionId}.log`);
  const reportFilePath = path.join(REPORT_DIR, `session-${sessionId}.json`);
  
  console.log(`[PTY Bridge] [+] Client connected: Session #${sessionId} from ${clientIp}`);

  const logStream = fs.createWriteStream(logFilePath, { flags: 'a', encoding: 'utf8' });
  logStream.write(`=== SESSION ${sessionId} START [${startTime.toISOString()}] (Client: ${clientIp}) ===\n\n`);

  let totalBytesStreamed = 0;
  let commandHistory = [];
  let currentInputBuffer = '';

  let ptyProcess;
  try {
    ptyProcess = pty.spawn(DEFAULT_SHELL, [], {
      name: 'xterm-256color',
      cols: 100,
      rows: 30,
      cwd: '/root',
      env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' }
    });
  } catch (err) {
    console.error(`[PTY Bridge] Failed to spawn shell:`, err.message);
    ws.send(`\r\n\x1b[31m[Bridge Error] Failed to spawn shell: ${err.message}\x1b[0m\r\n`);
    ws.close();
    return;
  }

  ptyProcess.onData((data) => {
    totalBytesStreamed += Buffer.byteLength(data, 'utf8');
    try { logStream.write(data); } catch (e) {}
    if (ws.readyState === ws.OPEN) ws.send(data);
  });

  ws.on('message', (message) => {
    let text = message.toString();

    if (text.startsWith('{') && text.endsWith('}')) {
      try {
        const payload = JSON.parse(text);
        if (payload.type === 'resize' && payload.cols && payload.rows) {
          const cols = Math.max(10, Math.min(parseInt(payload.cols), 400));
          const rows = Math.max(5, Math.min(parseInt(payload.rows), 200));
          ptyProcess.resize(cols, rows);
          return;
        }
        if (payload.type === 'input' && typeof payload.data === 'string') {
          text = payload.data;
        }
      } catch (e) {}
    }

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (char === '\r' || char === '\n') {
        const cleanCmd = currentInputBuffer.trim();
        if (cleanCmd.length > 0) {
          commandHistory.push({ timestamp: new Date().toISOString(), command: cleanCmd });
        }
        currentInputBuffer = '';
      } else if (char === '\x7f' || char === '\b') {
        currentInputBuffer = currentInputBuffer.slice(0, -1);
      } else if (char.charCodeAt(0) >= 32) {
        currentInputBuffer += char;
      }
    }

    try { ptyProcess.write(text); } catch (err) {}
  });

  const cleanupSession = (exitCode = 0) => {
    const endTime = new Date();
    const durationSec = Math.round((endTime - startTime) / 1000);

    logStream.write(`\n\n=== SESSION ${sessionId} CLOSED [${endTime.toISOString()}] (Exit: ${exitCode}, Duration: ${durationSec}s) ===\n`);
    logStream.end();

    const reportData = {
      id: sessionId,
      clientIp: clientIp,
      status: 'completed',
      exitCode: exitCode,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      durationSeconds: durationSec,
      totalBytes: totalBytesStreamed,
      commandsCount: commandHistory.length,
      commands: commandHistory,
      logFile: logFilePath,
      summary: `Terminal session completed (${durationSec}s duration, ${commandHistory.length} commands recorded).`
    };

    try {
      fs.writeFileSync(reportFilePath, JSON.stringify(reportData, null, 2), 'utf8');
      console.log(`[PTY Bridge] [✓] Saved report: ${reportFilePath}`);
    } catch (err) {}

    if (ptyProcess) {
      try {
        ptyProcess.kill('SIGTERM');
        setTimeout(() => { try { ptyProcess.kill('SIGKILL'); } catch (e) {} }, 1000);
      } catch (e) {}
    }
  };

  ptyProcess.onExit(({ exitCode }) => {
    cleanupSession(exitCode);
    if (ws.readyState === ws.OPEN) ws.close();
  });

  ws.on('close', () => cleanupSession(0));
  ws.on('error', (err) => console.warn(`[PTY Bridge] Socket error #${sessionId}:`, err.message));
});

server.listen(PORT, HOST, () => {
  console.log(`[✓] VPS WebSocket PTY Bridge listening on http://${HOST}:${PORT}`);
});
EOF

# 5. Install Node Dependencies (Compiling node-pty C++ addons)
echo "[*] Installing NPM dependencies & compiling node-pty..."
npm install --production

# 6. Setup Logging Directory
mkdir -p /var/log/dashboard-reports
chmod 755 /var/log/dashboard-reports

# 7. Create Systemd Service
echo "[*] Creating /etc/systemd/system/terminal-bridge.service..."
NODE_BIN=$(which node)
cat << EOF > /etc/systemd/system/terminal-bridge.service
[Unit]
Description=VPS Native WebSocket PTY Terminal Bridge & Report Logger
Documentation=https://github.com/muhammadharis4359/FYP
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/terminal-bridge
ExecStart=${NODE_BIN} /opt/terminal-bridge/server.js
Restart=always
RestartSec=3s
Environment=NODE_ENV=production
Environment=PORT=7682
Environment=HOST=0.0.0.0
Environment=REPORT_DIR=/var/log/dashboard-reports
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 8. Reload & Start Service
echo "[*] Reloading systemd and enabling terminal-bridge..."
systemctl daemon-reload
systemctl enable terminal-bridge.service
systemctl restart terminal-bridge.service

# 9. Open Firewall Port 7682 if UFW active
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo "[*] Allowing port 7682/tcp through UFW..."
        ufw allow 7682/tcp comment "VPS WebSocket Terminal Bridge"
    fi
fi

echo "=========================================================================="
echo " [✓] SUCCESS: Native WebSocket PTY Bridge is running on port 7682!"
echo "=========================================================================="
echo " -> HTTP API: http://213.199.43.129:7682/api/reports"
echo " -> WebSocket: ws://213.199.43.129:7682/ws/terminal"
echo " -> Reports:   /var/log/dashboard-reports/"
echo " -> Check status: sudo systemctl status terminal-bridge.service"
echo "=========================================================================="
