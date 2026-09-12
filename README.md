# AI Recon & Exploit Chain Mapper

An advanced cybersecurity reconnaissance, vulnerability scanning, and automated attack-graph mapping platform built with a **FastAPI** backend, **Real Dual-Engine Hybrid Scanners**, an **Interactive Telemetry Web Dashboard**, and a **Live Cyber Terminal Monitor**.

---

## Key Features

- **Automated Reconnaissance (Phase 3)**:
  - Multi-source passive subdomain enumeration (Certificate Transparency via `crt.sh`, AlienVault OTX, `subfinder`, `amass`).
  - Concurrent DNS socket resolution & host verification.
  - Active HTTP/HTTPS probing with technology fingerprinting (`httpx`).
  - Historical endpoint discovery via Wayback Machine CDX API and passive archive extraction (`gau`).

- **Multi-Scanner Vulnerability Detection (Phase 4)**:
  - Real Nuclei CLI template scanning integration.
  - Active content and sensitive directory/backup discovery (25+ security-focused paths).
  - Client-side JavaScript secret, token, and API key scraper.
  - CORS misconfiguration and security headers auditor.

- **AI Exploit Chain Inference & Attack Graph (Phase 5 & 6)**:
  - Correlation engine inferring multi-hop attack vectors and exploit chains from raw findings.
  - CVSS scoring, confidence metrics, and prioritized target risk ranking (P1 to P5).

- **Interactive Cyber Telemetry Dashboard**:
  - Live target monitoring, visual attack path graph, scan history, real-time stage progress, and findings inventory.

- **Dedicated Live Terminal Stream**:
  - Standalone console window streaming colorized, real-time tool execution logs, discovered hosts, vulnerability alerts, and exploit chains.

---

## Architecture Overview

```
recon-exploit-mapper/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application entry point
│   │   ├── config.py               # Settings and environment configuration
│   │   ├── database.py             # SQLAlchemy session & SQLite database setup
│   │   ├── models.py               # Database schemas (Target, Scan, Finding, ExploitChain, etc.)
│   │   ├── telemetry_logger.py     # Real-time console and file telemetry logger
│   │   ├── modules/
│   │   │   ├── recon.py            # Hybrid reconnaissance engine (crt.sh, DNS, httpx, subfinder)
│   │   │   ├── scanners.py         # 4-scanner vulnerability detection layer (Nuclei, JS secrets, etc.)
│   │   │   ├── chains.py           # Attack chain inference & target risk calculator
│   │   │   └── pipeline.py         # 6-stage end-to-end scanning pipeline
│   │   └── routers/
│   │       ├── targets.py          # Target CRUD endpoints
│   │       ├── scans.py            # Scan launch, stage polling & findings endpoints
│   │       └── chains.py           # Exploit chain API endpoints
│   ├── live_monitor.py             # Standalone real-time cyber terminal log streamer
│   ├── install_tools.bat           # 1-click Windows CLI binary downloader
│   ├── requirements.txt            # Python dependencies
│   └── run.bat                     # Backend server launcher
├── frontend/
│   ├── index.html                  # Cyber telemetry dashboard UI
│   ├── css/
│   │   └── styles.css              # Dark-mode dashboard styling
│   └── js/
│       └── app.js                  # Frontend state management, charts, and API client
├── start_dashboard.bat             # Starts backend API & dashboard server
├── live_terminal.bat               # Starts standalone live tool execution monitor
├── start_with_terminal.bat         # Launches server + live terminal monitor side-by-side
└── install_tools.bat               # Root wrapper for CLI tool installer
```

---

## Quick Start (Windows)

### 1. Launch Server & Live Terminal Together
Double-click:
```bat
start_with_terminal.bat
```
- **Window 1**: FastAPI Backend Server running at `http://127.0.0.1:8000`
- **Window 2**: Real-time Cyber Terminal streaming live tool actions & discoveries
- **Web Dashboard**: Open `http://127.0.0.1:8000` in your browser.

### 2. (Optional) Install Standalone CLI Binaries
The engine runs 100% natively using built-in Python socket resolvers, HTTP probers, and archive extractors. To add official 64-bit releases of `subfinder`, `httpx`, and `nuclei`:
```bat
install_tools.bat
```

---

## Manual Setup

```bash
# 1. Navigate to backend and create virtual environment
cd backend
python -m venv venv
venv\Scripts\activate       # On Linux/macOS: source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
copy .env.example .env      # On Linux/macOS: cp .env.example .env

# 4. Start backend server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Interactive API Docs**: `http://127.0.0.1:8000/docs`
- **Dashboard**: `http://127.0.0.1:8000`

---

## Disclaimer

> **Important**: This software is intended strictly for authorized security assessments, educational purposes, and bug bounty programs within explicit scope. Scanning targets without prior authorization is illegal.
