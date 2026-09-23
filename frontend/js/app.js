/**
 * AI Exploit Chain Mapper — Cyber Dashboard Client Logic
 * Theme: Deep Obsidian & Electric Cyber Green (PDF Spec Alignment)
 */

// Global State
const savedApiUrl = localStorage.getItem('recon_api_url');
const savedVpsWsUrl = localStorage.getItem('vps_terminal_ws_url');
const state = {
  apiBaseUrl: savedApiUrl || ((window.location.protocol.startsWith('http') && window.location.port === '8000') 
    ? window.location.origin 
    : 'http://127.0.0.1:8000'),
  vpsTerminalWsUrl: savedVpsWsUrl || 'ws://213.199.43.129:7682/ws/terminal',
  term: null,
  fitAddon: null,
  termSocket: null,
  reports: [],
  isOnline: false,
  targets: [],
  selectedTargetId: null,
  scans: [],
  activeScanId: null,
  activeScan: null,
  subdomains: [],
  liveHosts: [],
  endpoints: [],
  findings: [],
  chains: [],
  stats: null,
  pollTimer: null,
  isPolling: false,
  soundEnabled: true,
  terminalLogs: [],
  cy: null,
  charts: {
    severity: null,
    sources: null,
    exploitability: null,
  },
  activeTab: 'overview',
};

// Web Audio API Sound Synthesizer
class CyberAudio {
  constructor() {
    this.ctx = null;
  }

  init() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
  }

  playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.03) {
    if (!state.soundEnabled) return;
    try {
      this.init();
      if (!this.ctx) return;
      if (this.ctx.state === 'suspended') this.ctx.resume();

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch (e) {}
  }

  blip() { this.playTone(880, 'sine', 0.06, 0.04); }
  click() { this.playTone(1200, 'triangle', 0.03, 0.02); }
  scanAlert() {
    this.playTone(440, 'sawtooth', 0.12, 0.05);
    setTimeout(() => this.playTone(880, 'sawtooth', 0.15, 0.05), 100);
  }
}

const cyberAudio = new CyberAudio();

// Configure API URL Helper
window.configureApiUrl = () => {
  const current = state.apiBaseUrl;
  const input = prompt('Configure Backend API Host URL:', current);
  if (input !== null) {
    const formatted = input.trim().replace(/\/+$/, '');
    if (formatted) {
      state.apiBaseUrl = formatted;
      localStorage.setItem('recon_api_url', formatted);
      logTerminal(`API Base URL updated to: ${formatted}`, 'info');
      checkApiHealth().then(online => {
        if (online) loadInitialData();
      });
    }
  }
};

// API Helper
async function apiCall(endpoint, options = {}) {
  const url = `${state.apiBaseUrl}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(options.headers || {}),
      },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP Error ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.warn(`API Error [${endpoint}]:`, err.message);
    throw err;
  }
}

function logTerminal(message, type = 'info') {
  const time = new Date().toLocaleTimeString();
  const entry = { time, message, type };
  state.terminalLogs.push(entry);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// App Initialization
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  const isOnline = await checkApiHealth();
  if (isOnline) {
    await loadInitialData();
  }
  startPolling();
});

// Event Listeners
function setupEventListeners() {
  // Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      switchTab(tabId);
      cyberAudio.click();
    });
  });

  // Target Select
  document.getElementById('target-select')?.addEventListener('change', (e) => {
    const targetId = parseInt(e.target.value);
    if (targetId) {
      state.selectedTargetId = targetId;
      loadScansForTarget(targetId);
    }
  });

  // Action Buttons
  document.getElementById('btn-new-target')?.addEventListener('click', () => {
    openModal('modal-new-target');
    cyberAudio.click();
  });

  document.getElementById('btn-start-scan')?.addEventListener('click', () => {
    openModal('modal-new-scan');
    cyberAudio.click();
  });

  document.getElementById('btn-demo-flight')?.addEventListener('click', async () => {
    cyberAudio.click();
    await triggerDemoFlight();
  });

  // Modals Close
  document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', () => {
      closeAllModals();
      cyberAudio.click();
    });
  });

  // Form Submit: New Target
  document.getElementById('form-create-target')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domainInput = document.getElementById('input-target-domain');
    const domain = domainInput.value.trim().toLowerCase();
    if (!domain) return;
    try {
      const target = await apiCall('/targets', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      });
      closeAllModals();
      domainInput.value = '';
      await loadTargets();
      state.selectedTargetId = target.id;
      document.getElementById('target-select').value = target.id;
      loadScansForTarget(target.id);
    } catch (err) {
      alert(`Failed to create target: ${err.message}`);
    }
  });

  // Form Submit: New Scan
  document.getElementById('form-launch-scan')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.selectedTargetId) {
      alert('Please select or create a target first.');
      return;
    }
    const isDemo = document.getElementById('input-scan-mode')?.value === 'demo';
    try {
      const endpoint = isDemo ? '/scans/demo' : '/scans';
      const scan = await apiCall(endpoint, {
        method: 'POST',
        body: JSON.stringify({ target_id: state.selectedTargetId }),
      });
      cyberAudio.scanAlert();
      closeAllModals();
      state.activeScanId = scan.id;
      await refreshAllData();
    } catch (err) {
      alert(`Failed to start scan: ${err.message}`);
    }
  });

  // Audio Toggle
  document.getElementById('btn-audio-toggle')?.addEventListener('click', () => {
    state.soundEnabled = !state.soundEnabled;
    const icon = document.getElementById('audio-icon');
    if (icon) {
      icon.innerHTML = state.soundEnabled
        ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path></svg>`
        : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg>`;
    }
  });

  // Floating Chat Widget
  const chatDrawer = document.getElementById('chat-window-drawer');
  document.getElementById('btn-chat-trigger')?.addEventListener('click', () => {
    chatDrawer.classList.toggle('open');
    cyberAudio.click();
  });
  document.getElementById('btn-close-chat')?.addEventListener('click', () => {
    chatDrawer.classList.remove('open');
    cyberAudio.click();
  });

  document.getElementById('btn-send-chat')?.addEventListener('click', sendChatMessage);
  document.getElementById('input-chat-msg')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendChatMessage();
  });

  // Search Filter
  document.getElementById('filter-findings')?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    const container = document.getElementById('findings-container');
    if (!container) return;
    for (let card of container.children) {
      card.style.display = card.textContent.toLowerCase().includes(query) ? '' : 'none';
    }
  });

  // Reports
  document.getElementById('btn-export-markdown')?.addEventListener('click', exportReportMarkdown);
  document.getElementById('btn-export-json')?.addEventListener('click', exportReportJson);

  // Live VPS Terminal Controls
  initVpsTerminal();
}

// Switch Tab
function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });

  if (tabId === 'attack-paths') {
    setTimeout(renderCytoscapeAttackGraph, 100);
  } else if (tabId === 'terminal') {
    ensureTerminalLoaded();
  }
}

// Live VPS Terminal Integration (xterm.js + Native WebSocket PTY)
function initVpsTerminal() {
  const container = document.getElementById('xterm-container');
  if (!container) return;

  // Initialize xterm.js instance
  if (!state.term && typeof Terminal !== 'undefined') {
    state.term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontSize: 13,
      lineHeight: 1.2,
      fontFamily: '"Fira Code", "JetBrains Mono", Consolas, monospace',
      theme: {
        background: '#020503',
        foreground: '#e2fded',
        cursor: '#00ff66',
        cursorAccent: '#000000',
        selectionBackground: 'rgba(0, 255, 102, 0.3)',
        black: '#0a110c',
        red: '#ff0055',
        green: '#00ff66',
        yellow: '#facc15',
        blue: '#00f0ff',
        magenta: '#c084fc',
        cyan: '#00f0ff',
        white: '#ffffff',
        brightBlack: '#4ade80',
        brightGreen: '#39ff14',
      }
    });

    if (typeof FitAddon !== 'undefined' && FitAddon.FitAddon) {
      state.fitAddon = new FitAddon.FitAddon();
      state.term.loadAddon(state.fitAddon);
    }

    state.term.open(container);
    if (state.fitAddon) {
      setTimeout(() => state.fitAddon.fit(), 100);
    }

    // Keyboard stroke routing -> WebSocket
    state.term.onData(data => {
      if (state.termSocket && state.termSocket.readyState === WebSocket.OPEN) {
        state.termSocket.send(data);
      }
    });

    // Dynamic resize observer
    const wrapper = document.getElementById('terminal-xterm-wrapper');
    if (wrapper && window.ResizeObserver) {
      const ro = new ResizeObserver(() => {
        if (state.fitAddon && state.term) {
          state.fitAddon.fit();
          if (state.termSocket && state.termSocket.readyState === WebSocket.OPEN) {
            state.termSocket.send(JSON.stringify({
              type: 'resize',
              cols: state.term.cols,
              rows: state.term.rows
            }));
          }
        }
      });
      ro.observe(wrapper);
    }
  }

  // Connect WebSocket Bridge
  connectTerminalWebSocket();

  // Route Preset Selector
  const routeSelect = document.getElementById('terminal-route-preset');
  routeSelect?.addEventListener('change', (e) => {
    cyberAudio.click();
    const val = e.target.value;
    const isHttps = window.location.protocol === 'https:';
    const wsProto = isHttps ? 'wss:' : 'ws:';
    
    if (val === 'direct') {
      setTerminalWsUrl('ws://213.199.43.129:7682/ws/terminal');
    } else if (val === 'nginx') {
      const host = window.location.host;
      setTerminalWsUrl(`${wsProto}//${host}/ws/terminal`);
    } else if (val === 'local') {
      setTerminalWsUrl('ws://127.0.0.1:7682/ws/terminal');
    } else if (val === 'custom') {
      configureTerminalWsUrl();
    }
  });

  // Action Buttons
  document.getElementById('btn-config-terminal')?.addEventListener('click', () => {
    cyberAudio.click();
    configureTerminalWsUrl();
  });

  document.getElementById('btn-reload-terminal')?.addEventListener('click', () => {
    cyberAudio.click();
    connectTerminalWebSocket(true);
  });

  document.getElementById('btn-clear-terminal')?.addEventListener('click', () => {
    cyberAudio.click();
    if (state.term) state.term.clear();
  });

  document.getElementById('btn-view-reports')?.addEventListener('click', () => {
    cyberAudio.click();
    openReportsModal();
  });

  document.getElementById('btn-refresh-reports-list')?.addEventListener('click', () => {
    cyberAudio.click();
    loadTerminalReports();
  });

  document.getElementById('btn-fullscreen-terminal')?.addEventListener('click', () => {
    cyberAudio.click();
    toggleTerminalFullscreen();
  });

  // Quick Command Buttons -> write directly to WebSocket
  const sendQuickCmd = (cmd) => {
    if (state.termSocket && state.termSocket.readyState === WebSocket.OPEN) {
      state.termSocket.send(cmd + '\r');
      cyberAudio.click();
    } else {
      alert('Terminal WebSocket is not connected.');
    }
  };

  document.getElementById('qcmd-reports')?.addEventListener('click', () => sendQuickCmd('ls -la /var/log/dashboard-reports'));
  document.getElementById('qcmd-htop')?.addEventListener('click', () => sendQuickCmd('htop'));
  document.getElementById('qcmd-port')?.addEventListener('click', () => sendQuickCmd('ss -tulpn | grep 7682'));
  document.getElementById('qcmd-restart')?.addEventListener('click', () => sendQuickCmd('systemctl status terminal-bridge'));

  // Preload reports count badge
  loadTerminalReports();
}

function connectTerminalWebSocket(forceReconnect = false) {
  if (state.termSocket && (state.termSocket.readyState === WebSocket.OPEN || state.termSocket.readyState === WebSocket.CONNECTING)) {
    if (!forceReconnect) return;
    state.termSocket.close();
  }

  const dot = document.getElementById('terminal-socket-dot');
  const urlLabel = document.getElementById('terminal-current-url-label');
  const hostPill = document.getElementById('terminal-host-pill');

  if (urlLabel) urlLabel.textContent = `Target: ${state.vpsTerminalWsUrl}`;
  if (hostPill) {
    try {
      const u = new URL(state.vpsTerminalWsUrl);
      hostPill.textContent = u.host || state.vpsTerminalWsUrl;
    } catch (e) {
      hostPill.textContent = state.vpsTerminalWsUrl;
    }
  }

  if (state.term) {
    state.term.writeln(`\r\n\x1b[36m[*] Connecting to VPS WebSocket: ${state.vpsTerminalWsUrl} ...\x1b[0m`);
  }

  try {
    state.termSocket = new WebSocket(state.vpsTerminalWsUrl);
    
    state.termSocket.onopen = () => {
      dot?.classList.remove('offline');
      if (state.term) {
        state.term.writeln(`\x1b[32m[+] WebSocket Bridge Connected. Spawning interactive PTY session...\x1b[0m\r\n`);
        if (state.fitAddon) {
          state.fitAddon.fit();
          state.termSocket.send(JSON.stringify({
            type: 'resize',
            cols: state.term.cols,
            rows: state.term.rows
          }));
        }
      }
    };

    state.termSocket.onmessage = (event) => {
      if (state.term) {
        state.term.write(event.data);
      }
    };

    state.termSocket.onclose = () => {
      dot?.classList.add('offline');
      if (state.term) {
        state.term.writeln(`\r\n\x1b[33m[-] Terminal session closed / disconnected.\x1b[0m`);
      }
      loadTerminalReports();
    };

    state.termSocket.onerror = (err) => {
      dot?.classList.add('offline');
      if (state.term) {
        state.term.writeln(`\r\n\x1b[31m[!] WebSocket Connection Error. Check if node-pty bridge is running on port 7682.\x1b[0m`);
      }
    };
  } catch (e) {
    dot?.classList.add('offline');
    if (state.term) {
      state.term.writeln(`\r\n\x1b[31m[!] Connection failed: ${e.message}\x1b[0m`);
    }
  }
}

function ensureTerminalLoaded() {
  if (!state.term) {
    initVpsTerminal();
  } else if (state.fitAddon) {
    setTimeout(() => state.fitAddon.fit(), 100);
  }
}

function setTerminalWsUrl(url) {
  state.vpsTerminalWsUrl = url;
  localStorage.setItem('vps_terminal_ws_url', url);
  connectTerminalWebSocket(true);
}

function configureTerminalWsUrl() {
  const current = state.vpsTerminalWsUrl || 'ws://213.199.43.129:7682/ws/terminal';
  const custom = prompt('Enter VPS Terminal WebSocket URL (e.g. ws://213.199.43.129:7682/ws/terminal or /ws/terminal):', current);
  if (custom !== null && custom.trim()) {
    setTerminalWsUrl(custom.trim());
  }
}

function toggleTerminalFullscreen() {
  const panel = document.querySelector('.terminal-panel-card');
  const btn = document.getElementById('btn-fullscreen-terminal');
  if (panel) {
    panel.classList.toggle('fullscreen');
    const isFs = panel.classList.contains('fullscreen');
    if (btn) btn.textContent = isFs ? '✕ Exit Fullscreen' : '⛶ Fullscreen';
    if (state.fitAddon) {
      setTimeout(() => state.fitAddon.fit(), 150);
    }
  }
}

// Session Reports API integration
async function loadTerminalReports() {
  const badge = document.getElementById('reports-count-badge');
  try {
    let httpBase = state.vpsTerminalWsUrl.replace(/^ws:\/\//, 'http://').replace(/^wss:\/\//, 'https://').replace(/\/ws\/terminal\/?$/, '');
    if (!httpBase.startsWith('http')) httpBase = `${window.location.origin}`;
    
    const res = await fetch(`${httpBase}/api/reports`, { headers: { 'Accept': 'application/json' } });
    if (res.ok) {
      const reports = await res.json();
      state.reports = reports || [];
      if (badge) badge.textContent = state.reports.length;
      renderReportsList(state.reports);
      return;
    }
  } catch (e) {}

  if (badge) badge.textContent = state.reports.length || '0';
}

function openReportsModal() {
  openModal('modal-terminal-reports');
  loadTerminalReports();
}

function renderReportsList(reports) {
  const container = document.getElementById('terminal-reports-list-container');
  if (!container) return;

  if (!reports || reports.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--text-dim); padding: 30px;">
        No persistent terminal session reports recorded yet.
      </div>
    `;
    return;
  }

  container.innerHTML = reports.map(r => `
    <div class="report-item-card">
      <div>
        <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 700; color: var(--neon-green);">
          Session #${r.id} <span style="font-size: 11px; color: var(--text-muted); font-weight: 400;">· ${new Date(r.startTime).toLocaleString()}</span>
        </div>
        <div style="font-size: 11px; color: var(--text-main); margin-top: 4px;">
          <strong>Duration:</strong> ${r.durationSeconds}s · <strong>Commands Run:</strong> ${r.commandsCount || (r.commands ? r.commands.length : 0)} · <strong>Total Bytes:</strong> ${r.totalBytes}
        </div>
        ${r.commands && r.commands.length > 0 ? `
          <div style="font-family: var(--font-mono); font-size: 10px; color: var(--cyber-cyan); margin-top: 4px;">
            Last: <code>${escapeHtml(r.commands[r.commands.length - 1].command)}</code>
          </div>
        ` : ''}
      </div>
      <div>
        <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="viewReportDetails('${r.id}')">View Details</button>
      </div>
    </div>
  `).join('');
}

window.viewReportDetails = (id) => {
  const rep = state.reports.find(r => r.id === id);
  if (!rep) return;
  alert(`Session #${rep.id} Details:\n\nStart: ${rep.startTime}\nEnd: ${rep.endTime}\nDuration: ${rep.durationSeconds}s\nCommands:\n${(rep.commands || []).map(c => ` - [${c.timestamp.slice(11, 19)}] ${c.command}`).join('\n') || 'None'}`);
};

window.copyToClipboard = (text) => {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      cyberAudio.click();
      alert(`Copied to clipboard:\n${text}`);
    }).catch(() => fallbackCopyText(text));
  } else {
    fallbackCopyText(text);
  }
};

function fallbackCopyText(text) {
  const tempInput = document.createElement('textarea');
  tempInput.value = text;
  document.body.appendChild(tempInput);
  tempInput.select();
  document.execCommand('copy');
  document.body.removeChild(tempInput);
  alert(`Copied to clipboard:\n${text}`);
}

// Health Check
async function checkApiHealth() {
  const dot = document.getElementById('api-status-dot');
  const text = document.getElementById('api-status-text');

  const candidates = [];
  if (state.apiBaseUrl) candidates.push(state.apiBaseUrl);
  if (window.location.protocol.startsWith('http')) {
    candidates.push(window.location.origin);
  }
  if (!candidates.includes('http://127.0.0.1:8000')) candidates.push('http://127.0.0.1:8000');
  if (!candidates.includes('http://localhost:8000')) candidates.push('http://localhost:8000');

  for (const host of candidates) {
    try {
      const res = await fetch(`${host}/api/health`, { method: 'GET', headers: { 'Accept': 'application/json' } });
      if (res.ok) {
        const data = await res.json().catch(() => null);
        if (data && data.status === 'ok') {
          const wasOffline = !state.isOnline;
          state.apiBaseUrl = host;
          state.isOnline = true;
          dot?.classList.remove('offline');
          if (text) text.textContent = `API ONLINE (${host.replace(/http:\/\//, '')})`;
          if (wasOffline) {
            await loadInitialData();
          }
          return true;
        }
      }
    } catch (e) {}
  }

  state.isOnline = false;
  dot?.classList.add('offline');
  if (text) text.textContent = 'BACKEND OFFLINE';
  return false;
}

// Load Initial Data
async function loadInitialData() {
  await loadTargets();
  await loadStatsSummary();
  await loadToolsStatus();
  await loadScansList();
}

async function loadTargets() {
  try {
    const targets = await apiCall('/targets');
    state.targets = targets || [];
    const select = document.getElementById('target-select');
    if (!select) return;

    select.innerHTML = '';
    if (state.targets.length === 0) {
      select.innerHTML = '<option value="">-- No Targets Configured --</option>';
      state.selectedTargetId = null;
      return;
    }

    state.targets.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = `${t.domain} (#${t.id})`;
      select.appendChild(opt);
    });

    if (!state.selectedTargetId && state.targets.length > 0) {
      state.selectedTargetId = state.targets[0].id;
    }
    select.value = state.selectedTargetId;
  } catch (e) {}
}

async function loadScansList() {
  try {
    const scans = await apiCall('/scans');
    state.scans = scans || [];
    renderRecentScansTable(state.scans);

    if (state.scans.length > 0) {
      if (!state.activeScanId || !state.scans.some(s => s.id === state.activeScanId)) {
        state.activeScanId = state.scans[0].id;
      }
      await loadScanDetails(state.activeScanId);
    }
  } catch (e) {}
}

async function loadScansForTarget(targetId) {
  const targetScans = state.scans.filter(s => s.target_id === targetId);
  if (targetScans.length > 0) {
    state.activeScanId = targetScans[0].id;
    await loadScanDetails(state.activeScanId);
  }
}

async function loadScanDetails(scanId) {
  if (!scanId) return;
  try {
    const scan = await apiCall(`/scans/${scanId}`);
    state.activeScan = scan;
    state.activeScanId = scan.id;

    const [subs, hosts, eps, findings, chains] = await Promise.all([
      apiCall(`/scans/${scanId}/subdomains`).catch(() => []),
      apiCall(`/scans/${scanId}/live-hosts`).catch(() => []),
      apiCall(`/scans/${scanId}/endpoints`).catch(() => []),
      apiCall(`/scans/${scanId}/findings`).catch(() => []),
      apiCall(`/scans/${scanId}/chains`).catch(() => []),
    ]);

    state.subdomains = subs || [];
    state.liveHosts = hosts || [];
    state.endpoints = eps || [];
    state.findings = findings || [];
    state.chains = chains || [];

    renderActiveScanHeader(scan);
    renderMetricsCards();
    renderExploitChains();
    renderFindingsList();
    renderAssetsAndEndpoints();
    renderCharts();

    if (state.activeTab === 'attack-paths') {
      renderCytoscapeAttackGraph();
    }
  } catch (err) {
    console.error(`Error loading scan #${scanId}:`, err);
  }
}

async function loadStatsSummary() {
  try {
    const stats = await apiCall('/stats/summary');
    state.stats = stats;
  } catch (e) {}
}

async function loadToolsStatus() {
  try {
    const tools = await apiCall('/api/tools/status');
    const container = document.getElementById('tools-status-list');
    if (!container || !tools) return;

    const cli = tools.cli_tools || {};
    const hasAnyCli = Object.values(cli).some(Boolean);
    const cliBadges = Object.entries(cli).map(([name, installed]) => 
      `<span style="color: ${installed ? 'var(--neon-green)' : 'var(--text-dim)'}; font-size: 10px;">${name}:${installed ? 'OK' : 'Native'}</span>`
    ).join(' · ');

    container.innerHTML = `
      <div>• <strong>Subdomain Recon:</strong> <span style="color: var(--neon-green);">Passive CT (crt.sh) + Socket DNS ${cli.subfinder ? '+ Subfinder' : ''}</span></div>
      <div>• <strong>Live Host Prober:</strong> <span style="color: var(--neon-green);">Concurrent SSL/TLS & Tech Detect ${cli.httpx ? '+ HTTPX' : ''}</span></div>
      <div>• <strong>Endpoint Discovery:</strong> <span style="color: var(--neon-green);">Wayback Machine CDX API ${cli.gau ? '+ GAU' : ''}</span></div>
      <div>• <strong>4-Scanner Layer:</strong> <span style="color: var(--neon-green);">Content + Secrets + CORS ${cli.nuclei ? '+ Nuclei CLI' : '+ Nuclei Templates'}</span></div>
      <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border-green); font-size: 10px; color: var(--text-dim);">
        <div>Status: <span style="color: var(--cyber-cyan); font-weight: 600;">Hybrid Dual-Engine Active</span></div>
        <div style="margin-top: 3px;">Binaries: ${cliBadges}</div>
      </div>
    `;
  } catch (e) {}
}

async function triggerDemoFlight() {
  try {
    let target = state.targets.find(t => t.domain === 'demo-target.cybersec.io');
    if (!target) {
      target = await apiCall('/targets', {
        method: 'POST',
        body: JSON.stringify({ domain: 'demo-target.cybersec.io' }),
      });
      await loadTargets();
    }

    state.selectedTargetId = target.id;
    document.getElementById('target-select').value = target.id;

    const scan = await apiCall('/scans/demo', {
      method: 'POST',
      body: JSON.stringify({ target_id: target.id }),
    });

    state.activeScanId = scan.id;
    cyberAudio.scanAlert();
    await refreshAllData();
  } catch (err) {
    alert(`Demo flight failed: ${err.message}`);
  }
}

function startPolling() {
  if (state.isPolling) return;
  state.isPolling = true;

  state.pollTimer = setInterval(async () => {
    const isOnline = await checkApiHealth();
    if (!isOnline) return;

    if (state.activeScan && ['queued', 'recon_running', 'scan_running'].includes(state.activeScan.status)) {
      await refreshAllData();
      cyberAudio.blip();
    } else {
      await loadStatsSummary();
      await loadScansList();
    }
  }, 2500);
}

async function refreshAllData() {
  await loadStatsSummary();
  await loadToolsStatus();
  await loadScansList();
  if (state.activeScanId) {
    await loadScanDetails(state.activeScanId);
  }
}

// ==========================================================================
// RENDERERS (PDF Specifications)
// ==========================================================================

function renderActiveScanHeader(scan) {
  const target = state.targets.find(t => t.id === scan.target_id);
  const domain = target ? target.domain : (scan.target_domain || `Target #${scan.target_id}`);

  document.getElementById('active-domain-name').textContent = domain;
  document.getElementById('active-target-id').textContent = `#${scan.target_id}`;
  document.getElementById('active-scan-id').textContent = `Scan #${scan.id}`;

  const riskVal = scan.overall_risk_score != null ? scan.overall_risk_score.toFixed(1) : '0.0';
  document.getElementById('risk-score-val').textContent = riskVal;

  const priBadge = document.getElementById('target-priority-badge');
  const pri = scan.priority || 'P4';
  if (priBadge) {
    priBadge.className = `priority-pill ${pri}`;
    priBadge.textContent = `${pri} PRIORITY`;
  }

  document.getElementById('risk-breakdown-text').textContent = 
    `${scan.actionable_count || 0} Actionable Findings · ${state.chains.length} Inferred Exploit Chains`;

  const statusBadge = document.getElementById('scan-status-badge');
  if (statusBadge) {
    statusBadge.className = `scan-status-badge ${scan.status === 'completed' ? 'completed' : 'running'}`;
    statusBadge.textContent = (scan.status || 'IDLE').replace('_', ' ');
  }
}

function renderMetricsCards() {
  document.getElementById('stat-subdomains-count').textContent = state.subdomains.length;
  document.getElementById('stat-hosts-count').textContent = state.liveHosts.length;
  document.getElementById('stat-endpoints-count').textContent = state.endpoints.length;
  document.getElementById('stat-findings-count').textContent = state.findings.length;
  document.getElementById('stat-chains-count').textContent = state.chains.length;

  document.getElementById('tab-badge-chains').textContent = state.chains.length;
  document.getElementById('tab-badge-findings').textContent = state.findings.length;
  document.getElementById('tab-badge-assets').textContent = state.liveHosts.length + state.endpoints.length;

  const actionable = state.findings.filter(f => f.validity !== 'informational').length;
  const informational = state.findings.length - actionable;
  document.getElementById('overview-actionable-badge').textContent = `${actionable} Actionable Issues`;
  document.getElementById('overview-informational-badge').textContent = `${informational} Informational Noise`;
}

// 15 Inferred Exploit Chains (PDF §6.1 & §7.2)
function renderExploitChains() {
  const container = document.getElementById('exploit-chains-list');
  const label = document.getElementById('chains-count-label');
  if (!container) return;
  if (label) label.textContent = state.chains.length;

  if (state.chains.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 40px; color: var(--text-dim); font-family: var(--font-mono);">
        No multi-step exploit chains could be inferred from current findings.
      </div>
    `;
    return;
  }

  container.innerHTML = state.chains.map(c => {
    let steps = [];
    try { steps = JSON.parse(c.steps_json); } catch (e) {}

    const stepsHtml = steps.map((s, idx) => `
      <div class="chain-step-node ${s.type || 'weakness'}">
        <div style="font-weight: 700; color: var(--text-pure); margin-bottom: 2px;">Step ${s.step || idx+1}: ${escapeHtml(s.title)}</div>
        <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(s.desc || '')}</div>
      </div>
      ${idx < steps.length - 1 ? '<span class="chain-arrow">→</span>' : ''}
    `).join('');

    return `
      <div class="exploit-chain-card" id="chain-card-${c.id}">
        <div class="chain-card-header">
          <div class="chain-card-title">
            <span class="badge-sev ${c.severity}">${c.severity}</span>
            <span>${escapeHtml(c.name)}</span>
          </div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <span class="mono" style="font-size: 11px; background: var(--bg-void); border: 1px solid var(--border-green); padding: 3px 8px; border-radius: 4px;">
              CVSS: <strong>${c.cvss_score.toFixed(1)}</strong>
            </span>
            <span class="mono" style="font-size: 11px; color: var(--neon-green); background: rgba(0,255,102,0.1); border: 1px solid var(--neon-green); padding: 3px 8px; border-radius: 4px;">
              ${c.confidence}% Confidence
            </span>
            <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="highlightChainPath('${escapeHtml(c.name)}')">Highlight Path</button>
          </div>
        </div>

        <div class="chain-steps-flow">${stepsHtml}</div>

        <div style="font-size: 12px; color: var(--text-main); margin-top: 10px; line-height: 1.6;">
          <div><strong style="color: var(--sev-critical);">Impact:</strong> ${escapeHtml(c.impact)}</div>
          <div style="margin-top: 4px;"><strong style="color: var(--neon-green);">Remediation:</strong> ${escapeHtml(c.remediation)}</div>
        </div>
      </div>
    `;
  }).join('');
}

// Cytoscape.js Attack Graph (Target -> Subdomains -> Services -> Weaknesses -> Impact)
function renderCytoscapeAttackGraph() {
  const container = document.getElementById('cy-attack-graph');
  if (!container || typeof cytoscape === 'undefined') return;

  const target = state.targets.find(t => t.id === (state.activeScan ? state.activeScan.target_id : state.selectedTargetId));
  const rootDomain = target ? target.domain : 'Target Scope';

  const elements = [];

  // Root Node
  elements.push({
    data: { id: 'root', label: rootDomain, type: 'root', bg: '#00ff66', size: 50 }
  });

  // Subdomains
  state.subdomains.slice(0, 8).forEach((s, idx) => {
    const subId = `sub_${idx}`;
    elements.push({ data: { id: subId, label: s.subdomain, type: 'subdomain', bg: '#00f0ff', size: 36 } });
    elements.push({ data: { source: 'root', target: subId, label: 'dns' } });
  });

  // Live Hosts
  state.liveHosts.slice(0, 6).forEach((h, idx) => {
    const hostId = `host_${idx}`;
    const cleanUrl = h.url.replace('https://', '').replace('http://', '');
    elements.push({ data: { id: hostId, label: cleanUrl, type: 'host', bg: '#10b981', size: 32 } });
    const parentSub = elements.find(e => e.data.type === 'subdomain' && cleanUrl.includes(e.data.label));
    elements.push({ data: { source: parentSub ? parentSub.data.id : 'root', target: hostId, label: 'http' } });
  });

  // Vulnerability Findings
  state.findings.slice(0, 8).forEach((f, idx) => {
    const findId = `vuln_${idx}`;
    const sevColor = f.severity === 'critical' ? '#ff0055' : (f.severity === 'high' ? '#ff7700' : '#ffaa00');
    elements.push({ data: { id: findId, label: f.template_id, type: 'vuln', bg: sevColor, size: 28 } });
    const parentHost = elements.find(e => e.data.type === 'host' && f.matched_url.includes(e.data.label));
    elements.push({ data: { source: parentHost ? parentHost.data.id : 'root', target: findId, label: 'exploit' } });
  });

  // Exploit Chain Target Nodes
  state.chains.slice(0, 4).forEach((c, idx) => {
    const chainId = `chain_${idx}`;
    elements.push({ data: { id: chainId, label: c.category, type: 'impact', bg: '#ff0055', size: 40 } });
    elements.push({ data: { source: elements[elements.length - 2]?.data.id || 'root', target: chainId, label: 'chain-impact' } });
  });

  state.cy = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(bg)',
          'label': 'data(label)',
          'color': '#e2fded',
          'font-family': 'Fira Code, monospace',
          'font-size': '11px',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'width': 'data(size)',
          'height': 'data(size)',
          'border-width': 2,
          'border-color': '#030604',
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'rgba(34, 197, 94, 0.4)',
          'target-arrow-color': 'rgba(34, 197, 94, 0.6)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
        }
      },
      {
        selector: '.highlighted',
        style: {
          'line-color': '#00f0ff',
          'target-arrow-color': '#00f0ff',
          'width': 4,
          'shadow-blur': 15,
          'shadow-color': '#00f0ff',
        }
      }
    ],
    layout: {
      name: 'breadthfirst',
      directed: true,
      padding: 30,
      spacingFactor: 1.25,
    }
  });
}

window.fitCytoscapeGraph = () => {
  if (state.cy) state.cy.fit();
};

window.highlightChainPath = (chainName) => {
  if (!state.cy) return;
  state.cy.edges().removeClass('highlighted');
  state.cy.edges().addClass('highlighted');
  cyberAudio.scanAlert();
};

// Findings Catalog (PDF §7.3)
function renderFindingsList() {
  const container = document.getElementById('findings-container');
  if (!container) return;

  if (state.findings.length === 0) {
    container.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--text-dim);">No vulnerability findings recorded.</div>`;
    return;
  }

  container.innerHTML = state.findings.map(f => {
    const sev = (f.severity || 'info').toLowerCase();
    const source = f.source || 'nuclei';
    const validity = f.validity || 'actionable';
    const exploitability = f.exploitability || 'medium';
    const priority = f.priority || 'P3';

    return `
      <div class="finding-item-card" style="background: var(--bg-card); border: 1px solid var(--border-glass); border-radius: 8px; padding: 16px; margin-bottom: 12px;">
        <div class="finding-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="badge-sev ${sev}">${sev}</span>
            <span class="badge-source ${source}">${source}</span>
            <span class="badge-validity ${validity}">${validity}</span>
            <span class="priority-pill ${priority}" style="font-size: 10px; padding: 2px 6px;">${priority}</span>
            <strong style="font-size: 14px; color: var(--text-pure); margin-left: 6px;">${escapeHtml(f.name || f.template_id)}</strong>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="mono" style="font-size: 11px; color: var(--cyber-cyan);">Exploitability: <strong>${exploitability.toUpperCase()}</strong></span>
            <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="showSafeTestCase('${escapeHtml(f.name)}', '${escapeHtml(f.safe_payload_test || 'curl -s -I ' + f.matched_url)}')">Safe Test-Case</button>
          </div>
        </div>

        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">${escapeHtml(f.description || 'No description available.')}</p>

        <div style="background: var(--bg-void); border: 1px solid var(--border-green); border-radius: 4px; padding: 8px 12px; font-family: var(--font-mono); font-size: 11px; color: var(--neon-green);">
          Matched URL: <strong>${escapeHtml(f.matched_url)}</strong>
        </div>
      </div>
    `;
  }).join('');
}

window.showSafeTestCase = (title, testContent) => {
  document.getElementById('modal-testcase-title').textContent = `SAFE TEST CASE: ${title}`;
  document.getElementById('modal-testcase-content').textContent = testContent;
  openModal('modal-safe-testcase');
  cyberAudio.click();
};

// Assets & Endpoints
function renderAssetsAndEndpoints() {
  // Hosts
  const hostsTbody = document.getElementById('table-hosts-body');
  if (hostsTbody) {
    hostsTbody.innerHTML = state.liveHosts.map((h, i) => `
      <tr>
        <td class="mono" style="color: var(--text-dim); width: 40px;">#${i + 1}</td>
        <td><a href="${escapeHtml(h.url)}" target="_blank" style="color: var(--neon-green); font-family: var(--font-mono);">${escapeHtml(h.url)} ↗</a></td>
        <td><span class="pill pill-status-200">${h.status_code || 200}</span></td>
        <td style="font-size: 12px;">${escapeHtml(h.title || 'Untitled')}</td>
        <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(h.tech_stack || 'None')}</td>
      </tr>
    `).join('');
  }

  // Endpoints
  const epsTbody = document.getElementById('table-endpoints-body');
  if (epsTbody) {
    epsTbody.innerHTML = state.endpoints.map((ep, i) => `
      <tr>
        <td class="mono" style="color: var(--text-dim); width: 40px;">#${i + 1}</td>
        <td class="mono" style="font-size: 12px;">${escapeHtml(ep.url)}</td>
        <td><span class="pill pill-tool">${escapeHtml(ep.category || 'api')}</span></td>
        <td class="mono" style="color: var(--text-muted);">${escapeHtml(ep.source)}</td>
        <td style="text-align: right;"><button class="btn btn-icon" title="Copy URL" onclick="copyText('${escapeHtml(ep.url)}')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></td>
      </tr>
    `).join('');
  }
}

// Charts
function renderCharts() {
  if (typeof Chart === 'undefined') return;

  // Severity Chart
  const sevCanvas = document.getElementById('chart-severity');
  if (sevCanvas) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    state.findings.forEach(f => {
      const s = (f.severity || 'info').toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
    });

    if (state.charts.severity) state.charts.severity.destroy();
    state.charts.severity = new Chart(sevCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [counts.critical, counts.high, counts.medium, counts.low, counts.info],
          backgroundColor: ['#ff0055', '#ff5500', '#ffaa00', '#00bbff', '#00ffaa'],
          borderColor: '#060a08',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#86efac', font: { family: 'Fira Code', size: 10 } } } },
        cutout: '68%',
      }
    });
  }

  // Scanner Sources Chart
  const sourcesCanvas = document.getElementById('chart-sources');
  if (sourcesCanvas) {
    const sources = { nuclei: 0, content_discovery: 0, gitleaks: 0, secrets_regex: 0 };
    state.findings.forEach(f => {
      const src = f.source || 'nuclei';
      if (sources[src] !== undefined) sources[src]++;
    });

    if (state.charts.sources) state.charts.sources.destroy();
    state.charts.sources = new Chart(sourcesCanvas, {
      type: 'bar',
      data: {
        labels: ['Nuclei', 'Content Disc', 'GitLeaks', 'Regex'],
        datasets: [{
          label: 'Findings',
          data: [sources.nuclei, sources.content_discovery, sources.gitleaks, sources.secrets_regex],
          backgroundColor: ['#00ff66', '#00f0ff', '#c084fc', '#facc15'],
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#86efac', font: { family: 'Fira Code', size: 10 } }, grid: { display: false } },
          y: { ticks: { color: '#86efac', font: { family: 'Fira Code', size: 10 } }, grid: { color: 'rgba(20, 83, 45, 0.3)' } },
        }
      }
    });
  }
}

// Recent Scans Table
function renderRecentScansTable(scans) {
  const tbody = document.getElementById('table-recent-scans-body');
  if (!tbody) return;

  tbody.innerHTML = scans.map(s => `
    <tr style="${s.id === state.activeScanId ? 'background: rgba(0,255,102,0.08);' : ''}">
      <td class="mono" style="font-weight: 700; color: var(--neon-green);">#${s.id}</td>
      <td class="mono" style="font-weight: 600;">${escapeHtml(s.target_domain || `Target #${s.target_id}`)}</td>
      <td><span class="scan-status-badge ${s.status === 'completed' ? 'completed' : 'running'}">${s.status}</span></td>
      <td><span class="priority-pill ${s.priority || 'P4'}" style="font-size: 10px;">${s.priority || 'P4'}</span></td>
      <td class="mono" style="font-weight: 700;">${s.overall_risk_score != null ? s.overall_risk_score.toFixed(1) : '0.0'}</td>
      <td class="mono" style="color: var(--cyber-cyan); font-weight: 700;">${s.chains_count || 0}</td>
      <td class="mono" style="color: var(--sev-critical); font-weight: 700;">${s.findings_count || 0}</td>
      <td style="text-align: right;">
        <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="selectScan(${s.id})">Inspect</button>
        <button class="btn btn-icon" style="color: var(--cyber-red); margin-left: 4px;" title="Delete Scan" onclick="deleteScan(${s.id})"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
      </td>
    </tr>
  `).join('');
}

window.selectScan = async (scanId) => {
  state.activeScanId = scanId;
  await loadScanDetails(scanId);
  renderRecentScansTable(state.scans);
  cyberAudio.click();
};

window.deleteScan = async (scanId) => {
  if (!confirm(`Delete scan #${scanId}?`)) return;
  try {
    await apiCall(`/scans/${scanId}`, { method: 'DELETE' });
    await refreshAllData();
  } catch (e) { alert(e.message); }
};

// AI Security Assistant Chat (PDF §6.5)
async function sendChatMessage() {
  const input = document.getElementById('input-chat-msg');
  const msg = input.value.trim();
  if (!msg) return;

  const messagesBody = document.getElementById('chat-messages-body');
  
  // Append user message
  const userDiv = document.createElement('div');
  userDiv.className = 'chat-msg user';
  userDiv.textContent = msg;
  messagesBody.appendChild(userDiv);
  input.value = '';
  messagesBody.scrollTop = messagesBody.scrollHeight;
  cyberAudio.click();

  // Call /api/chat
  try {
    const res = await apiCall('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ message: msg, scan_id: state.activeScanId }),
    });

    const botDiv = document.createElement('div');
    botDiv.className = 'chat-msg bot';
    botDiv.innerHTML = escapeHtml(res.response).replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    messagesBody.appendChild(botDiv);
    messagesBody.scrollTop = messagesBody.scrollHeight;
  } catch (err) {
    const botDiv = document.createElement('div');
    botDiv.className = 'chat-msg bot';
    botDiv.textContent = 'Error connecting to local AI assistant service.';
    messagesBody.appendChild(botDiv);
  }
}

// Export Reports (PDF §8)
function exportReportMarkdown() {
  const target = state.targets.find(t => t.id === (state.activeScan ? state.activeScan.target_id : state.selectedTargetId));
  const domain = target ? target.domain : 'Target';
  const scan = state.activeScan || {};

  let md = `# AI Exploit Chain Mapper — Security Assessment Report\n\n`;
  md += `**Target Domain:** ${domain}\n`;
  md += `**Scan ID:** #${scan.id || 'N/A'}\n`;
  md += `**Overall Risk Score:** ${scan.overall_risk_score || 0.0} / 100 (Priority: ${scan.priority || 'P4'})\n`;
  md += `**Date:** ${new Date().toUTCString()}\n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `- **Subdomains Discovered:** ${state.subdomains.length}\n`;
  md += `- **Live HTTP Hosts:** ${state.liveHosts.length}\n`;
  md += `- **Categorized Endpoints:** ${state.endpoints.length}\n`;
  md += `- **Multi-Scanner Findings:** ${state.findings.length}\n`;
  md += `- **Inferred Exploit Chains:** ${state.chains.length}\n\n`;

  md += `## 2. Inferred Multi-Step Exploit Chains\n\n`;
  state.chains.forEach((c, idx) => {
    md += `### ${idx + 1}. [${c.severity.toUpperCase()}] ${c.name} (CVSS: ${c.cvss_score})\n`;
    md += `- **Category:** ${c.category}\n`;
    md += `- **Confidence:** ${c.confidence}%\n`;
    md += `- **Impact:** ${c.impact}\n`;
    md += `- **Remediation Action:** ${c.remediation}\n\n`;
  });

  md += `## 3. Findings Catalog\n\n`;
  state.findings.forEach((f, idx) => {
    md += `### ${idx + 1}. [${(f.severity || 'INFO').toUpperCase()}] ${f.name} (${f.source})\n`;
    md += `- **Matched URL:** \`${f.matched_url}\`\n`;
    md += `- **Template ID:** \`${f.template_id}\`\n`;
    md += `- **Safe Test-Case:** \`${f.safe_payload_test || 'N/A'}\`\n\n`;
  });

  downloadFile(`${domain}-exploit-chain-report.md`, md, 'text/markdown');
}

function exportReportJson() {
  const data = {
    target: state.targets.find(t => t.id === (state.activeScan ? state.activeScan.target_id : state.selectedTargetId)),
    scan: state.activeScan,
    chains: state.chains,
    findings: state.findings,
    live_hosts: state.liveHosts,
    endpoints: state.endpoints,
    subdomains: state.subdomains,
  };
  downloadFile(`exploit-chains-${state.activeScanId || 'all'}.json`, JSON.stringify(data, null, 2), 'application/json');
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

window.copyText = (text) => {
  navigator.clipboard.writeText(text);
  cyberAudio.click();
};

function openModal(id) {
  closeAllModals();
  document.getElementById(id)?.classList.add('active');
}

function closeAllModals() {
  document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
}
