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
const DEFAULT_SHELL = process.platform === 'win32' ? 'powershell.exe' : (process.env.SHELL || '/bin/bash');

// Setup persistent log directory
const REPORT_DIR = process.env.REPORT_DIR || (
  process.platform === 'win32'
    ? path.join(__dirname, 'logs', 'reports')
    : '/var/log/dashboard-reports'
);

try {
  if (!fs.existsSync(REPORT_DIR)) {
    fs.mkdirSync(REPORT_DIR, { recursive: true });
  }
} catch (err) {
  console.error(`[Error] Failed to initialize report directory at ${REPORT_DIR}:`, err.message);
}

const app = express();
app.use(cors());
app.use(express.json());

// -----------------------------------------------------------------------------
// REST API ENDPOINTS
// -----------------------------------------------------------------------------

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VPS Native WebSocket PTY Terminal Bridge',
    reports_dir: REPORT_DIR,
    timestamp: new Date().toISOString()
  });
});

// List all generated session reports
app.get('/api/reports', (req, res) => {
  try {
    if (!fs.existsSync(REPORT_DIR)) {
      return res.json([]);
    }

    const files = fs.readdirSync(REPORT_DIR);
    const jsonFiles = files.filter(f => f.startsWith('session-') && f.endsWith('.json'));

    const reports = jsonFiles.map(file => {
      try {
        const content = fs.readFileSync(path.join(REPORT_DIR, file), 'utf8');
        return JSON.parse(content);
      } catch (e) {
        return null;
      }
    }).filter(Boolean);

    // Sort newest first
    reports.sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0));
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve reports', details: err.message });
  }
});

// Get specific report JSON metadata
app.get('/api/reports/:id', (req, res) => {
  try {
    const reportFile = path.join(REPORT_DIR, `session-${req.params.id}.json`);
    if (!fs.existsSync(reportFile)) {
      return res.status(404).json({ error: 'Report not found' });
    }
    const data = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read report', details: err.message });
  }
});

// Get raw log content for report
app.get('/api/reports/:id/raw', (req, res) => {
  try {
    const logFile = path.join(REPORT_DIR, `session-${req.params.id}.log`);
    if (!fs.existsSync(logFile)) {
      return res.status(404).json({ error: 'Log file not found' });
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    fs.createReadStream(logFile).pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read raw log', details: err.message });
  }
});

// -----------------------------------------------------------------------------
// HTTP & WEBSOCKET SERVER SETUP
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// PTY PROCESS SPAWNING & DUAL-PIPING ENGINE
// -----------------------------------------------------------------------------

wss.on('connection', (ws, req) => {
  const sessionId = uuidv4().slice(0, 8);
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const startTime = new Date();
  
  const logFilePath = path.join(REPORT_DIR, `session-${sessionId}.log`);
  const reportFilePath = path.join(REPORT_DIR, `session-${sessionId}.json`);
  
  console.log(`[PTY Bridge] [+] Client connected: Session #${sessionId} from ${clientIp}`);

  // Create write stream for session log
  const logStream = fs.createWriteStream(logFilePath, { flags: 'a', encoding: 'utf8' });
  logStream.write(`=== SESSION ${sessionId} START [${startTime.toISOString()}] (Client: ${clientIp}) ===\n\n`);

  let totalBytesStreamed = 0;
  let commandHistory = [];
  let currentInputBuffer = '';

  // Spawn isolated pseudo-terminal instance
  let ptyProcess;
  try {
    ptyProcess = pty.spawn(DEFAULT_SHELL, [], {
      name: 'xterm-256color',
      cols: 100,
      rows: 30,
      cwd: process.env.HOME || (process.platform === 'win32' ? process.cwd() : '/root'),
      env: {
        ...process.env,
        TERM: 'xterm-256color',
        COLORTERM: 'truecolor'
      }
    });
  } catch (err) {
    console.error(`[PTY Bridge] Failed to spawn shell '${DEFAULT_SHELL}':`, err.message);
    ws.send(`\r\n\x1b[31m[Bridge Error] Failed to spawn shell: ${err.message}\x1b[0m\r\n`);
    ws.close();
    return;
  }

  // 1. PTY stdout -> WebSocket client & Persistent Log File
  ptyProcess.onData((data) => {
    totalBytesStreamed += Buffer.byteLength(data, 'utf8');
    
    // Write to persistent log file
    try {
      logStream.write(data);
    } catch (e) {}

    // Stream to client
    if (ws.readyState === ws.OPEN) {
      ws.send(data);
    }
  });

  // 2. WebSocket client stdin -> PTY & Command Logger
  ws.on('message', (message) => {
    let text = message.toString();

    // Check if message is a JSON control payload (e.g. resize event)
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
      } catch (e) {
        // Not JSON, continue treating as raw keystroke text
      }
    }

    // Command line activity tracker for report extraction
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (char === '\r' || char === '\n') {
        const cleanCmd = currentInputBuffer.trim();
        if (cleanCmd.length > 0) {
          commandHistory.push({
            timestamp: new Date().toISOString(),
            command: cleanCmd
          });
        }
        currentInputBuffer = '';
      } else if (char === '\x7f' || char === '\b') {
        currentInputBuffer = currentInputBuffer.slice(0, -1);
      } else if (char.charCodeAt(0) >= 32) {
        currentInputBuffer += char;
      }
    }

    try {
      ptyProcess.write(text);
    } catch (err) {
      console.warn(`[PTY Bridge] Error writing to PTY #${sessionId}:`, err.message);
    }
  });

  // 3. Finalize report and clean up on disconnect or shell exit
  const cleanupSession = (exitCode = 0) => {
    const endTime = new Date();
    const durationSec = Math.round((endTime - startTime) / 1000);

    logStream.write(`\n\n=== SESSION ${sessionId} CLOSED [${endTime.toISOString()}] (Exit: ${exitCode}, Duration: ${durationSec}s) ===\n`);
    logStream.end();

    // Generate structured report JSON
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
      console.log(`[PTY Bridge] [✓] Generated session report: ${reportFilePath}`);
    } catch (err) {
      console.error(`[PTY Bridge] Failed to save session report:`, err.message);
    }

    // Kill PTY process safely
    if (ptyProcess) {
      try {
        ptyProcess.kill('SIGTERM');
        setTimeout(() => {
          try { ptyProcess.kill('SIGKILL'); } catch (e) {}
        }, 1000);
      } catch (e) {}
    }
  };

  ptyProcess.onExit(({ exitCode, signal }) => {
    console.log(`[PTY Bridge] PTY #${sessionId} exited with code ${exitCode}, signal ${signal}`);
    cleanupSession(exitCode);
    if (ws.readyState === ws.OPEN) {
      ws.close();
    }
  });

  ws.on('close', () => {
    console.log(`[PTY Bridge] [-] WebSocket closed for Session #${sessionId}`);
    cleanupSession(0);
  });

  ws.on('error', (err) => {
    console.warn(`[PTY Bridge] WebSocket error on #${sessionId}:`, err.message);
  });
});

// -----------------------------------------------------------------------------
// START SERVER
// -----------------------------------------------------------------------------

server.listen(PORT, HOST, () => {
  console.log(`===================================================================`);
  console.log(` [✓] VPS WebSocket PTY Terminal Bridge is actively listening`);
  console.log(`     HTTP API : http://${HOST}:${PORT}/api/reports`);
  console.log(`     WebSocket: ws://${HOST}:${PORT}/ws/terminal`);
  console.log(`     Reports  : ${REPORT_DIR}`);
  console.log(`===================================================================`);
});
