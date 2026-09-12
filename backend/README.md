# Recon & Exploit Mapper — Backend (Phase 3 + Phase 4)

This is the first working slice of the platform: **Automated Reconnaissance**
(Phase 3) chained directly into the **Vulnerability Scanning Engine** (Phase 4).
Submit a domain, and the pipeline runs subdomain enumeration → live-host
detection → endpoint discovery → Nuclei vulnerability scanning, storing every
stage's output in the database as it goes.

No hosting required — clone it, install the tools below, and run it locally.

> ⚠️ **Only scan targets you own or are explicitly authorized to test**
> (e.g. your own lab environment, or a domain in scope for a bug bounty
> program you're enrolled in). Running this against domains you don't have
> permission to test is not okay — treat it the same as any other offensive
> security tool.

---

## 1. Prerequisites

- **Python 3.10+**
- **Go 1.21+** (needed to install the recon/scan tools below)
- Make sure `$HOME/go/bin` is on your `PATH` after installing Go tools.

## 2. Install the recon & scanning tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Nuclei needs its template library pulled once before first use:
nuclei -update-templates
```

Verify each one is on your PATH:

```bash
subfinder -version && amass -version && httpx -version && gau -h && nuclei -version
```

If a tool isn't installed, the pipeline **won't crash** — it logs a warning
and skips that source, so you can test the API immediately and add tools
one at a time.

## 3. Set up the Python backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # defaults are fine to start
```

## 4. Run it

```bash
uvicorn app.main:app --reload
```

The API is now at `http://127.0.0.1:8000` — interactive docs at
`http://127.0.0.1:8000/docs`.

## 5. Try it

```bash
# 1. Register a target
curl -X POST http://127.0.0.1:8000/targets \
  -H "Content-Type: application/json" \
  -d '{"domain": "your-authorized-target.com"}'
# -> {"id": 1, "domain": "your-authorized-target.com", ...}

# 2. Start a scan (runs recon + scan in the background)
curl -X POST http://127.0.0.1:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1}'
# -> {"id": 1, "status": "queued", ...}

# 3. Poll status
curl http://127.0.0.1:8000/scans/1
# status moves: queued -> recon_running -> scan_running -> completed

# 4. Once completed, pull results
curl http://127.0.0.1:8000/scans/1/subdomains
curl http://127.0.0.1:8000/scans/1/live-hosts
curl http://127.0.0.1:8000/scans/1/endpoints
curl http://127.0.0.1:8000/scans/1/findings
```

## 6. Run the mocked pipeline test (no tools required)

Before installing anything, you can verify the orchestration logic itself
is correct using mocked tool output:

```bash
python tests/test_pipeline_mock.py
```

This proves the recon → scan hand-off, database writes, and failure
handling all work, independent of whether Amass/Nuclei are installed yet.

---

## What's in this slice

| File | Role |
|---|---|
| `app/modules/recon.py` | Phase 3 — Subfinder, Amass, httpx, gau wrappers |
| `app/modules/scanner.py` | Phase 4 — Nuclei wrapper + JSON parsing |
| `app/modules/pipeline.py` | Chains Phase 3 output directly into Phase 4 input |
| `app/models.py` | Target, Scan, Subdomain, LiveHost, Endpoint, Finding tables |
| `app/routers/scans.py` | REST API: create targets, start scans, poll status, fetch results |
| `tests/test_pipeline_mock.py` | End-to-end pipeline test with mocked tool output |

## Known simplification (flagged on purpose)

Background scanning currently uses FastAPI's built-in `BackgroundTasks`,
not Celery + Redis. This is fine for the scale this project targets
(a couple of concurrent scans during dev/demo) and means **no extra
services to install right now**. The SRS's longer-term plan is Celery +
Redis for real retry/concurrency behavior — when that's needed, only
`app/routers/scans.py`'s `_run_pipeline_in_background` function needs to
change; the pipeline and module code underneath it doesn't.

## Next phases (not in this slice)

- **Phase 5**: AI false-positive filtering on `Finding` rows
- **Phase 6**: exploit chaining (`exploit_chains` table) + attack-path graph
- **Dashboard**: React frontend consuming this API
