from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
from typing import Optional, Any
import json
import time
import re

from app.database import get_db, SessionLocal
from app import models, schemas
from app.modules.pipeline import run_full_pipeline
from app.modules.chains import infer_exploit_chains, calculate_target_risk, generate_safe_payload_suggestion, CHAIN_PATTERNS

router = APIRouter()



# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

@router.post("/targets", response_model=schemas.TargetOut)
def create_target(payload: schemas.TargetCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Target).filter(models.Target.domain == payload.domain.strip()).first()
    if existing:
        return existing
    target = models.Target(domain=payload.domain.strip())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets", response_model=list[schemas.TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return db.query(models.Target).order_by(models.Target.id.desc()).all()


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(models.Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return {"status": "ok", "message": f"Target {target_id} deleted"}


# ---------------------------------------------------------------------------
# Scans & Pipeline Execution
# ---------------------------------------------------------------------------

def _run_pipeline_in_background(scan_id: int, domain: str):
    db = SessionLocal()
    try:
        run_full_pipeline(scan_id, domain, db)
    finally:
        db.close()


def _run_demo_pipeline_in_background(scan_id: int, domain: str):
    """Simulates the complete 4-scanner detection + 15-pattern exploit chain inference."""
    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        if not scan:
            return
        scan.status = "recon_running"
        scan.current_stage = "subdomain_enumeration"
        scan.started_at = datetime.utcnow()
        db.commit()
        time.sleep(1.0)

        # 1. Subdomains (subfinder + amass + assetfinder)
        subs = [
            (f"api.{domain}", "subfinder"),
            (f"dev.{domain}", "subfinder"),
            (f"admin.{domain}", "amass"),
            (f"staging.{domain}", "amass"),
            (f"vpn.{domain}", "subfinder"),
            (f"auth.{domain}", "amass"),
            (f"cdn.{domain}", "subfinder"),
            (f"mail.{domain}", "assetfinder"),
            (f"portal.{domain}", "assetfinder"),
            (f"internal-docs.{domain}", "amass"),
        ]
        for sub, tool in subs:
            db.add(models.Subdomain(scan_id=scan_id, subdomain=sub, source_tool=tool))
        db.commit()

        # 2. Live Hosts (httpx + tech fingerprint)
        scan.current_stage = "live_host_detection"
        db.commit()
        time.sleep(1.0)

        hosts = [
            {"url": f"https://{domain}", "status_code": 200, "title": f"Home - {domain}", "tech_stack": "Nginx 1.22, Cloudflare, React, Next.js"},
            {"url": f"https://api.{domain}", "status_code": 200, "title": "REST API Gateway v2.4", "tech_stack": "Express, Node.js 18, Docker, Swagger"},
            {"url": f"https://dev.{domain}", "status_code": 403, "title": "403 Forbidden - Dev Portal", "tech_stack": "Apache/2.4.52, PHP/8.1"},
            {"url": f"https://admin.{domain}", "status_code": 200, "title": "Admin Dashboard Login", "tech_stack": "Grafana 9.4, Linux, OpenSSL"},
            {"url": f"https://staging.{domain}", "status_code": 500, "title": "Internal Server Error (Debug Mode Active)", "tech_stack": "Django 3.2, Python 3.9, SQLite"},
            {"url": f"https://vpn.{domain}", "status_code": 200, "title": "Pulse Secure SSL VPN", "tech_stack": "Pulse Connect Secure, OpenSSL"},
            {"url": f"https://auth.{domain}", "status_code": 200, "title": "Keycloak Auth SSO", "tech_stack": "Keycloak 21.0, WildFly, Java 17"},
            {"url": f"https://portal.{domain}", "status_code": 200, "title": "Customer Portal", "tech_stack": "Vue.js 3, TailwindCSS, Express"},
        ]
        for h in hosts:
            db.add(models.LiveHost(
                scan_id=scan_id,
                url=h["url"],
                status_code=h["status_code"],
                title=h["title"],
                tech_stack=h["tech_stack"],
            ))
        db.commit()

        # 3. Categorized Endpoints (gau + waybackurls)
        scan.current_stage = "endpoint_discovery"
        db.commit()
        time.sleep(1.0)

        endpoints = [
            (f"https://{domain}/api/v1/users?id=101", "gau", "api"),
            (f"https://{domain}/.env", "gau", "sensitive"),
            (f"https://{domain}/.git/config", "gau", "sensitive"),
            (f"https://{domain}/graphql", "gau", "api"),
            (f"https://{domain}/oauth/authorize?redirect_uri=https://evil.com", "gau", "auth"),
            (f"https://{domain}/config.json", "gau", "sensitive"),
            (f"https://api.{domain}/swagger/v1/swagger.json", "gau", "api"),
            (f"https://dev.{domain}/phpinfo.php", "gau", "sensitive"),
            (f"https://dev.{domain}/upload.php", "gau", "upload"),
            (f"https://admin.{domain}/actuator/heapdump", "gau", "admin"),
            (f"https://admin.{domain}/actuator/env", "gau", "admin"),
            (f"https://staging.{domain}/debug/vars", "gau", "api"),
            (f"https://auth.{domain}/oauth2/token", "gau", "auth"),
            (f"https://{domain}/backup_2024.zip", "gau", "sensitive"),
            (f"https://portal.{domain}/profile/avatar/upload", "gau", "upload"),
        ]
        for ep_url, src, cat in endpoints:
            db.add(models.Endpoint(scan_id=scan_id, url=ep_url, source=src, category=cat))
        db.commit()

        # 4. Multi-Scanner Detection (Nuclei + Content Discovery + GitLeaks + Secrets)
        scan.status = "scan_running"
        scan.current_stage = "vulnerability_scanning"
        db.commit()
        time.sleep(1.5)

        raw_findings = [
            {
                "matched_url": f"https://{domain}/oauth/authorize?redirect_uri=https://evil.com",
                "template_id": "open-redirect-oauth",
                "name": "OAuth Open Redirect Parameter",
                "severity": "medium",
                "chain_aware_severity": "critical",
                "cvss_score": 9.1,
                "source": "nuclei",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 9.2,
                "priority": "P1",
                "description": "Unvalidated redirect_uri parameter allows stealing OAuth authorization codes.",
            },
            {
                "matched_url": f"https://{domain}/.env",
                "template_id": "env-file-exposure",
                "name": "Exposed Environment Configuration (.env)",
                "severity": "critical",
                "chain_aware_severity": "critical",
                "cvss_score": 9.8,
                "source": "content_discovery",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 9.8,
                "priority": "P1",
                "description": "Production .env file contains PostgreSQL credentials and AWS root secret keys.",
            },
            {
                "matched_url": f"https://{domain}/bundle.js",
                "template_id": "gitleaks-aws-key",
                "name": "Leaked AWS Access Key in Client Bundle",
                "severity": "critical",
                "chain_aware_severity": "critical",
                "cvss_score": 9.5,
                "source": "gitleaks",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 9.5,
                "priority": "P1",
                "description": "Hardcoded AWS Access Key ID (AKIA...) detected in bundled frontend scripts.",
            },
            {
                "matched_url": f"https://admin.{domain}/actuator/heapdump",
                "template_id": "springboot-actuator-heapdump",
                "name": "Spring Boot Actuator Heapdump Disclosure",
                "severity": "high",
                "chain_aware_severity": "critical",
                "cvss_score": 8.2,
                "source": "content_discovery",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 8.5,
                "priority": "P1",
                "description": "Memory heapdump accessible without authentication exposing database passwords.",
            },
            {
                "matched_url": f"https://dev.{domain}/upload.php",
                "template_id": "unrestricted-file-upload",
                "name": "Unrestricted File Upload Vulnerability",
                "severity": "high",
                "chain_aware_severity": "critical",
                "cvss_score": 9.4,
                "source": "nuclei",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 9.0,
                "priority": "P1",
                "description": "Form accepts arbitrary executable files (.phtml/.php) without validation.",
            },
            {
                "matched_url": f"https://dev.{domain}/phpinfo.php",
                "template_id": "phpinfo-disclosure",
                "name": "PHPInfo System Environment Disclosure",
                "severity": "medium",
                "chain_aware_severity": "high",
                "cvss_score": 5.3,
                "source": "content_discovery",
                "validity": "actionable",
                "exploitability": "medium",
                "risk_score": 5.5,
                "priority": "P2",
                "description": "PHP diagnostic script outputs server document root, internal IPs, and loaded modules.",
            },
            {
                "matched_url": f"https://{domain}/graphql",
                "template_id": "graphql-introspection-enabled",
                "name": "GraphQL Schema Introspection Enabled",
                "severity": "low",
                "chain_aware_severity": "high",
                "cvss_score": 7.8,
                "source": "nuclei",
                "validity": "actionable",
                "exploitability": "medium",
                "risk_score": 6.0,
                "priority": "P2",
                "description": "Introspection enabled exposing hidden mutations (updateUserRole, deleteTenant).",
            },
            {
                "matched_url": f"https://{domain}/api/v1/users?id=101",
                "template_id": "idor-user-enumeration",
                "name": "Insecure Direct Object Reference (IDOR)",
                "severity": "high",
                "chain_aware_severity": "high",
                "cvss_score": 7.7,
                "source": "nuclei",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 7.5,
                "priority": "P2",
                "description": "Sequential user IDs allow unauthenticated retrieval of sensitive profile PII.",
            },
            {
                "matched_url": f"https://portal.{domain}/comments",
                "template_id": "stored-xss",
                "name": "Stored Cross-Site Scripting (XSS)",
                "severity": "high",
                "chain_aware_severity": "high",
                "cvss_score": 8.0,
                "source": "nuclei",
                "validity": "actionable",
                "exploitability": "high",
                "risk_score": 8.0,
                "priority": "P2",
                "description": "Unsanitized user comment renders arbitrary JavaScript in admin reviewer session.",
            },
            {
                "matched_url": f"https://{domain}/",
                "template_id": "missing-security-headers",
                "name": "Missing Security Headers (HSTS, CSP, X-Frame)",
                "severity": "info",
                "chain_aware_severity": "low",
                "cvss_score": 0.0,
                "source": "nuclei",
                "validity": "informational",
                "exploitability": "low",
                "risk_score": 1.0,
                "priority": "P4",
                "description": "Standard defensive HTTP security headers are missing from base web response.",
            },
        ]

        for f in raw_findings:
            db.add(models.Finding(
                scan_id=scan_id,
                matched_url=f["matched_url"],
                template_id=f["template_id"],
                name=f["name"],
                severity=f["severity"],
                chain_aware_severity=f.get("chain_aware_severity", f["severity"]),
                cvss_score=f["cvss_score"],
                source=f.get("source", "nuclei"),
                validity=f.get("validity", "actionable"),
                exploitability=f.get("exploitability", "medium"),
                risk_score=f.get("risk_score", 5.0),
                priority=f.get("priority", "P3"),
                safe_payload_test=generate_safe_payload_suggestion(f["name"], f["template_id"], f["matched_url"]),
                description=f["description"],
                raw_output="{}",
            ))
        db.commit()

        # 5. Exploit Chains Inference (Phase 6 / PDF Spec)
        scan.current_stage = "exploit_chain_inference"
        db.commit()
        time.sleep(1.0)

        # Store inferred exploit chains in database
        inferred = infer_exploit_chains(raw_findings, [{"url": ep[0]} for ep in endpoints])
        for c in inferred:
            db.add(models.ExploitChain(
                scan_id=scan_id,
                name=c["name"],
                category=c["category"],
                severity=c["severity"],
                cvss_score=c["cvss_score"],
                confidence=c["confidence"],
                steps_json=c["steps_json"],
                impact=c["impact"],
                remediation=c["remediation"],
                findings_ids_json=c["findings_ids_json"],
            ))
        db.commit()

        # 6. Overall Risk Scoring
        risk_metrics = calculate_target_risk(raw_findings, inferred)
        scan.overall_risk_score = risk_metrics["overall_risk_score"]
        scan.priority = risk_metrics["priority"]
        scan.actionable_count = risk_metrics["actionable_count"]
        scan.informational_count = risk_metrics["informational_count"]
        scan.chains_count = risk_metrics["chains_count"]
        scan.status = "completed"
        scan.current_stage = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan = db.get(models.Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.current_stage = "failed"
            scan.error_message = str(e)
            db.commit()
    finally:
        db.close()


@router.post("/scans", response_model=schemas.ScanOut)
def start_scan(payload: schemas.ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(models.Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_pipeline_in_background, scan.id, target.domain)
    return scan


@router.post("/scans/demo", response_model=schemas.ScanOut)
def start_demo_scan(payload: schemas.ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(models.Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_demo_pipeline_in_background, scan.id, target.domain)
    return scan


@router.get("/scans", response_model=list[schemas.ScanListItemOut])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.id.desc()).all()
    results = []
    for s in scans:
        results.append(schemas.ScanListItemOut(
            id=s.id,
            target_id=s.target_id,
            target_domain=s.target.domain if s.target else None,
            status=s.status,
            current_stage=s.current_stage,
            error_message=s.error_message,
            started_at=s.started_at,
            completed_at=s.completed_at,
            overall_risk_score=s.overall_risk_score or 0.0,
            priority=s.priority or "P4",
            subdomains_count=len(s.subdomains) if s.subdomains else 0,
            live_hosts_count=len(s.live_hosts) if s.live_hosts else 0,
            endpoints_count=len(s.endpoints) if s.endpoints else 0,
            findings_count=len(s.findings) if s.findings else 0,
            chains_count=len(s.exploit_chains) if s.exploit_chains else 0,
        ))
    return results


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "ok", "message": f"Scan {scan_id} deleted"}


@router.get("/scans/{scan_id}/subdomains", response_model=list[schemas.SubdomainOut])
def get_subdomains(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.Subdomain).filter(models.Subdomain.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/live-hosts", response_model=list[schemas.LiveHostOut])
def get_live_hosts(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.LiveHost).filter(models.LiveHost.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/endpoints", response_model=list[schemas.EndpointOut])
def get_endpoints(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.Endpoint).filter(models.Endpoint.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingOut])
def get_findings(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/chains", response_model=list[schemas.ExploitChainOut])
def get_chains(scan_id: int, db: Session = Depends(get_db)):
    return db.query(models.ExploitChain).filter(models.ExploitChain.scan_id == scan_id).all()


# ---------------------------------------------------------------------------
# Telemetry Ingestion Helpers & Endpoints (Approach B & Approach C)
# ---------------------------------------------------------------------------

ANSI_REGEX = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _clean_ansi(text: str) -> str:
    return ANSI_REGEX.sub('', text) if text else ""


def _parse_raw_lines_or_json(raw_text: str) -> list[Any]:
    cleaned = _clean_ansi(raw_text).strip()
    if not cleaned:
        return []
    
    # Try as full JSON document
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            if "chains" in parsed and isinstance(parsed["chains"], list):
                return parsed["chains"]
            if "findings" in parsed and isinstance(parsed["findings"], list):
                return parsed["findings"]
            if "hosts" in parsed and isinstance(parsed["hosts"], list):
                return parsed["hosts"]
            if "subdomains" in parsed and isinstance(parsed["subdomains"], list):
                return parsed["subdomains"]
            return [parsed]
    except Exception:
        pass
    
    # Try line-by-line JSONL or plain strings
    results = []
    for line in cleaned.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "===", "[*]", "[-]")):
            continue
        try:
            results.append(json.loads(line))
        except Exception:
            results.append(line)
    return results


def _categorize_endpoint_url(url: str) -> str:
    low = url.lower()
    if any(k in low for k in ["login", "token", "oauth", "auth", "signin", "password"]):
        return "auth"
    if any(k in low for k in ["admin", "actuator", "dashboard", "manage", "root", "cpanel"]):
        return "admin"
    if any(k in low for k in ["upload", "file", "avatar", "attachment", "import"]):
        return "upload"
    if any(k in low for k in [".env", ".git", ".bak", ".zip", "backup", "secret", "config", "debug"]):
        return "sensitive"
    return "api"


@router.get("/api/scans/active", response_model=schemas.ScanOut)
@router.get("/scans/active", response_model=schemas.ScanOut)
def get_active_scan(domain: Optional[str] = None, auto_create: bool = False, db: Session = Depends(get_db)):
    """Finds the most recent active scan (or newest scan) so VPS hook knows which scan to attach to."""
    query = db.query(models.Scan).join(models.Target)
    if domain:
        query = query.filter(models.Target.domain == domain.strip().lower())
    
    active = query.filter(models.Scan.status.in_(["queued", "recon_running", "scan_running", "analyzing"])).order_by(models.Scan.id.desc()).first()
    if not active:
        active = query.order_by(models.Scan.id.desc()).first()
    
    if not active:
        if auto_create and domain:
            target = db.query(models.Target).filter(models.Target.domain == domain.strip().lower()).first()
            if not target:
                target = models.Target(domain=domain.strip().lower())
                db.add(target)
                db.commit()
                db.refresh(target)
            active = models.Scan(target_id=target.id, status="scan_running", current_stage="vulnerability_scanning", started_at=datetime.utcnow())
            db.add(active)
            db.commit()
            db.refresh(active)
        else:
            raise HTTPException(status_code=404, detail="No active or recent scan found")
            
    return active


@router.post("/api/scans/{scan_id}/ingest/telemetry", response_model=schemas.TelemetryIngestResponse)
@router.post("/scans/{scan_id}/ingest/telemetry", response_model=schemas.TelemetryIngestResponse)
def ingest_scan_telemetry(scan_id: int, payload: schemas.TelemetryIngestRequest, db: Session = Depends(get_db)):
    """
    Universal Smart Ingestion Engine for Tool-Native JSON & Agent-Structured Output (Approach B & C).
    Accepts raw CLI outputs or structured dictionaries, auto-identifies record types, deduplicates,
    and updates database records and live risk scores.
    """
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_domain = scan.target.domain if scan.target else "target"

    # Extract records
    records: list[Any] = []
    if payload.records is not None:
        records = payload.records
    elif payload.raw_output:
        records = _parse_raw_lines_or_json(payload.raw_output)
    elif payload.chains is not None:
        records = payload.chains

    cmd = (payload.command or "").lower()
    data_type = payload.data_type or "auto"

    # Auto-detect data type based on command or payload
    if data_type == "auto":
        if payload.chains is not None:
            data_type = "exploit_chains"
        elif any(t in cmd for t in ["subfinder", "amass", "assetfinder"]):
            data_type = "subdomains"
        elif "httpx" in cmd:
            data_type = "live_hosts"
        elif any(t in cmd for t in ["nuclei", "gitleaks"]):
            data_type = "findings"
        elif any(t in cmd for t in ["gau", "wayback", "katana"]):
            data_type = "endpoints"
        elif records:
            first = records[0]
            if isinstance(first, dict):
                if any(k in first for k in ["template-id", "template_id"]) or ("info" in first and "severity" in first.get("info", {})):
                    data_type = "findings"
                elif any(k in first for k in ["status_code", "status-code", "tech", "technologies"]):
                    data_type = "live_hosts"
                elif any(k in first for k in ["steps", "steps_json", "confidence"]):
                    data_type = "exploit_chains"
                elif "host" in first or "subdomain" in first:
                    data_type = "subdomains"
                elif "url" in first:
                    data_type = "endpoints"
            elif isinstance(first, str):
                if first.startswith("http://") or first.startswith("https://"):
                    data_type = "endpoints"
                else:
                    data_type = "subdomains"

    ingested_counts = {
        "subdomains": 0,
        "live_hosts": 0,
        "endpoints": 0,
        "findings": 0,
        "exploit_chains": 0
    }

    # Ingestion processors
    if data_type == "subdomains":
        for r in records:
            sub = (r.get("host") or r.get("subdomain")) if isinstance(r, dict) else str(r)
            sub = sub.strip().lower()
            if not sub or len(sub) < 3 or " " in sub:
                continue
            sub = re.sub(r'^https?://', '', sub).split('/')[0].split(':')[0]
            if "." not in sub:
                continue
            
            existing = db.query(models.Subdomain).filter(
                models.Subdomain.scan_id == scan_id,
                models.Subdomain.subdomain == sub
            ).first()
            if not existing:
                tool = payload.source_tool or ("amass" if "amass" in cmd else "subfinder")
                db.add(models.Subdomain(scan_id=scan_id, subdomain=sub, source_tool=tool))
                ingested_counts["subdomains"] += 1

    elif data_type == "live_hosts":
        for r in records:
            if not isinstance(r, dict):
                continue
            url = r.get("url") or r.get("input")
            if not url or not str(url).startswith("http"):
                continue
            url = str(url).strip()
            status_code = r.get("status_code") or r.get("status-code")
            title = r.get("title")
            tech = r.get("tech") or r.get("technologies") or r.get("tech_stack")
            if isinstance(tech, list):
                tech_stack = ", ".join(str(t) for t in tech)
            elif tech:
                tech_stack = str(tech)
            else:
                tech_stack = None

            existing = db.query(models.LiveHost).filter(
                models.LiveHost.scan_id == scan_id,
                models.LiveHost.url == url
            ).first()
            if not existing:
                db.add(models.LiveHost(scan_id=scan_id, url=url, status_code=status_code, title=title, tech_stack=tech_stack))
                ingested_counts["live_hosts"] += 1
            else:
                if status_code: existing.status_code = status_code
                if title: existing.title = title
                if tech_stack: existing.tech_stack = tech_stack

    elif data_type == "endpoints":
        for r in records:
            url = (r.get("url") if isinstance(r, dict) else str(r)).strip()
            if not url or not url.startswith("http"):
                continue
            cat = _categorize_endpoint_url(url)
            src = payload.source_tool or ("waybackurls" if "wayback" in cmd else "gau")
            existing = db.query(models.Endpoint).filter(
                models.Endpoint.scan_id == scan_id,
                models.Endpoint.url == url
            ).first()
            if not existing:
                db.add(models.Endpoint(scan_id=scan_id, url=url, source=src, category=cat))
                ingested_counts["endpoints"] += 1

    elif data_type == "findings":
        for r in records:
            if not isinstance(r, dict):
                continue
            template_id = r.get("template-id") or r.get("template_id") or "vuln-detected"
            matched_url = r.get("matched-at") or r.get("matched_at") or r.get("url") or r.get("matched_url")
            if not matched_url:
                continue
            matched_url = str(matched_url).strip()
            info = r.get("info") if isinstance(r.get("info"), dict) else {}
            name = info.get("name") or r.get("name") or template_id
            severity = (info.get("severity") or r.get("severity") or "medium").lower()
            
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            cvss = classification.get("cvss-score") or r.get("cvss_score")
            if cvss is None:
                sev_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}
                cvss = sev_map.get(severity, 5.0)
            else:
                try: cvss = float(cvss)
                except Exception: cvss = 5.0

            src = payload.source_tool or ("gitleaks" if "gitleaks" in cmd else "nuclei")
            validity = "informational" if severity in ["info", "unknown"] else "actionable"
            exploitability = "high" if severity in ["critical", "high"] else ("medium" if severity == "medium" else "low")
            priority = "P1" if severity == "critical" else ("P2" if severity == "high" else ("P3" if severity == "medium" else "P4"))
            desc = info.get("description") or r.get("description") or f"Detected via {template_id}"
            safe_test = generate_safe_payload_suggestion(name, template_id, matched_url)

            existing = db.query(models.Finding).filter(
                models.Finding.scan_id == scan_id,
                models.Finding.template_id == template_id,
                models.Finding.matched_url == matched_url
            ).first()
            if existing:
                existing.duplicate_count = (existing.duplicate_count or 1) + 1
            else:
                db.add(models.Finding(
                    scan_id=scan_id,
                    matched_url=matched_url,
                    template_id=template_id,
                    name=name,
                    severity=severity,
                    chain_aware_severity=severity,
                    cvss_score=round(cvss, 1),
                    source=src,
                    validity=validity,
                    exploitability=exploitability,
                    risk_score=round(cvss, 1),
                    priority=priority,
                    safe_payload_test=safe_test,
                    duplicate_count=1,
                    description=desc,
                    raw_output=json.dumps(r)
                ))
                ingested_counts["findings"] += 1

    elif data_type == "exploit_chains":
        for c in records:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            if not name:
                continue
            category = c.get("category", "General")
            severity = (c.get("severity", "medium")).lower()
            try: cvss = float(c.get("cvss_score", 8.5))
            except Exception: cvss = 8.5
            try: confidence = int(c.get("confidence", 85))
            except Exception: confidence = 85
            steps = c.get("steps") or c.get("steps_json") or []
            steps_json = steps if isinstance(steps, str) else json.dumps(steps)
            impact = c.get("impact", "Multi-stage attack path resulting in system compromise.")
            remediation = c.get("remediation", "Apply validation filters and patch affected services.")
            finding_ids = c.get("findings_ids") or c.get("findings_ids_json")
            findings_ids_json = finding_ids if isinstance(finding_ids, str) else (json.dumps(finding_ids) if finding_ids else None)

            existing = db.query(models.ExploitChain).filter(
                models.ExploitChain.scan_id == scan_id,
                models.ExploitChain.name == name
            ).first()
            if not existing:
                db.add(models.ExploitChain(
                    scan_id=scan_id,
                    name=name,
                    category=category,
                    severity=severity,
                    cvss_score=cvss,
                    confidence=confidence,
                    steps_json=steps_json,
                    impact=impact,
                    remediation=remediation,
                    findings_ids_json=findings_ids_json
                ))
                ingested_counts["exploit_chains"] += 1

    # Auto-infer exploit chains if findings were ingested but no chains passed
    if ingested_counts["findings"] > 0 and ingested_counts["exploit_chains"] == 0:
        existing_chains_count = db.query(models.ExploitChain).filter(models.ExploitChain.scan_id == scan_id).count()
        if existing_chains_count == 0:
            current_findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
            current_eps = db.query(models.Endpoint).filter(models.Endpoint.scan_id == scan_id).all()
            f_dicts = [{"template_id": f.template_id, "name": f.name, "severity": f.severity, "matched_url": f.matched_url} for f in current_findings]
            ep_dicts = [{"url": ep.url} for ep in current_eps]
            auto_inferred = infer_exploit_chains(f_dicts, ep_dicts)
            for ch in auto_inferred:
                db.add(models.ExploitChain(
                    scan_id=scan_id,
                    name=ch["name"],
                    category=ch["category"],
                    severity=ch["severity"],
                    cvss_score=ch["cvss_score"],
                    confidence=ch["confidence"],
                    steps_json=ch["steps_json"],
                    impact=ch["impact"],
                    remediation=ch["remediation"],
                    findings_ids_json=ch["findings_ids_json"]
                ))
                ingested_counts["exploit_chains"] += 1

    # Recalculate Scan Metrics & Risk
    db.flush()
    all_findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    all_chains = db.query(models.ExploitChain).filter(models.ExploitChain.scan_id == scan_id).all()


    if payload.overall_risk_score is not None:
        scan.overall_risk_score = float(payload.overall_risk_score)
        if payload.priority:
            scan.priority = payload.priority
    else:
        findings_dicts = [{"severity": f.severity, "validity": f.validity} for f in all_findings]
        chains_dicts = [{"severity": c.severity, "confidence": c.confidence} for c in all_chains]
        metrics = calculate_target_risk(findings_dicts, chains_dicts)
        scan.overall_risk_score = metrics["overall_risk_score"]
        scan.priority = metrics["priority"]

    scan.actionable_count = sum(1 for f in all_findings if (f.validity or "").lower() == "actionable")
    scan.informational_count = sum(1 for f in all_findings if (f.validity or "").lower() == "informational")
    scan.chains_count = len(all_chains)

    if scan.status in ["queued", "recon_running"]:
        if ingested_counts["findings"] > 0:
            scan.status = "scan_running"
            scan.current_stage = "vulnerability_scanning"
        elif ingested_counts["live_hosts"] > 0:
            scan.status = "recon_running"
            scan.current_stage = "live_host_detection"

    db.commit()
    db.refresh(scan)

    return schemas.TelemetryIngestResponse(
        status="ok",
        scan_id=scan.id,
        target_domain=target_domain,
        ingested=ingested_counts,
        overall_risk_score=scan.overall_risk_score or 0.0,
        priority=scan.priority or "P4",
        message=f"Successfully ingested telemetry for Scan #{scan.id}"
    )


# ---------------------------------------------------------------------------
# Direct Batch Ingestion Endpoints (Convenience)
# ---------------------------------------------------------------------------

@router.post("/scans/{scan_id}/subdomains", response_model=schemas.TelemetryIngestResponse)
def bulk_create_subdomains(scan_id: int, payload: schemas.SubdomainsBulkCreate, db: Session = Depends(get_db)):
    req = schemas.TelemetryIngestRequest(data_type="subdomains", source_tool=payload.source_tool, records=[{"host": s} for s in payload.subdomains])
    return ingest_scan_telemetry(scan_id, req, db)


@router.post("/scans/{scan_id}/live-hosts", response_model=schemas.TelemetryIngestResponse)
def bulk_create_live_hosts(scan_id: int, payload: schemas.LiveHostsBulkCreate, db: Session = Depends(get_db)):
    req = schemas.TelemetryIngestRequest(data_type="live_hosts", records=payload.hosts)
    return ingest_scan_telemetry(scan_id, req, db)


@router.post("/scans/{scan_id}/endpoints", response_model=schemas.TelemetryIngestResponse)
def bulk_create_endpoints(scan_id: int, payload: schemas.EndpointsBulkCreate, db: Session = Depends(get_db)):
    req = schemas.TelemetryIngestRequest(data_type="endpoints", source_tool=payload.source, records=payload.endpoints)
    return ingest_scan_telemetry(scan_id, req, db)


@router.post("/scans/{scan_id}/findings", response_model=schemas.TelemetryIngestResponse)
def bulk_create_findings(scan_id: int, payload: schemas.FindingsBulkCreate, db: Session = Depends(get_db)):
    req = schemas.TelemetryIngestRequest(data_type="findings", records=payload.findings)
    return ingest_scan_telemetry(scan_id, req, db)


@router.post("/scans/{scan_id}/chains", response_model=schemas.TelemetryIngestResponse)
def bulk_create_chains(scan_id: int, payload: schemas.ChainsBulkCreate, db: Session = Depends(get_db)):
    req = schemas.TelemetryIngestRequest(data_type="exploit_chains", chains=payload.chains, overall_risk_score=payload.overall_risk_score, priority=payload.priority)
    return ingest_scan_telemetry(scan_id, req, db)



# ---------------------------------------------------------------------------
# AI Security Assistant (Chat Grounded in Scan Data - PDF Section 6.5)
# ---------------------------------------------------------------------------

@router.post("/api/chat", response_model=schemas.ChatResponse)
def security_chat(payload: schemas.ChatRequest, db: Session = Depends(get_db)):
    """Conversational AI security assistant grounded in active scan findings and exploit chains."""
    msg = payload.message.lower().strip()
    scan_id = payload.scan_id

    # Retrieve context
    findings = []
    chains = []
    target_domain = "target"
    if scan_id:
        scan = db.get(models.Scan, scan_id)
        if scan and scan.target:
            target_domain = scan.target.domain
        findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
        chains = db.query(models.ExploitChain).filter(models.ExploitChain.scan_id == scan_id).all()

    # Rule & Context grounded response builder
    critical_findings = [f for f in findings if (f.severity or "").lower() == "critical"]
    high_findings = [f for f in findings if (f.severity or "").lower() == "high"]
    
    if "serious" in msg or "critical" in msg or "worst" in msg or "priority" in msg:
        if critical_findings or chains:
            resp = f"**Critical Security Risks for {target_domain}:**\n\n"
            if chains:
                top_chain = chains[0]
                resp += f"1. **Worst Exploit Chain**: {top_chain.name} (CVSS: {top_chain.cvss_score}, Confidence: {top_chain.confidence}%)\n"
                resp += f"   - **Impact**: {top_chain.impact}\n"
                resp += f"   - **Remediation**: {top_chain.remediation}\n\n"
            if critical_findings:
                resp += "2. **Key Actionable Findings:**\n"
                for cf in critical_findings[:3]:
                    resp += f"   - **{cf.name}** (`{cf.matched_url}`)\n"
            return schemas.ChatResponse(
                response=resp,
                sources_cited=[c.name for c in chains[:2]] + [f.name for f in critical_findings[:2]],
            )
        else:
            return schemas.ChatResponse(
                response=f"No critical vulnerabilities or severe exploit chains have been detected for {target_domain}.",
                sources_cited=[],
            )

    if "fix" in msg or "remediat" in msg or "patch" in msg:
        if chains:
            resp = "**Priority Remediation Action Plan:**\n\n"
            for i, c in enumerate(chains[:3], 1):
                resp += f"**{i}. Fix for {c.name}:**\n"
                resp += f"   {c.remediation}\n\n"
            return schemas.ChatResponse(
                response=resp,
                sources_cited=[c.name for c in chains[:3]],
            )
        else:
            return schemas.ChatResponse(
                response="Enforce standard security hygiene: remove exposed dotfiles (.env/.git), enforce strict OAuth redirect URI whitelisting, and deploy security headers.",
                sources_cited=[],
            )

    if "chain" in msg or "path" in msg or "graph" in msg:
        if chains:
            resp = f"**Inferred Exploit Attack Paths ({len(chains)} chains detected):**\n\n"
            for i, c in enumerate(chains[:4], 1):
                resp += f"{i}. **{c.name}** [Severity: {c.severity.upper()} | CVSS {c.cvss_score}]\n"
                resp += f"   - *Category*: {c.category}\n"
            return schemas.ChatResponse(
                response=resp,
                sources_cited=[c.name for c in chains[:4]],
            )
        else:
            return schemas.ChatResponse(
                response="No multi-step exploit chains could be inferred from current findings.",
                sources_cited=[],
            )

    # General grounded security assistant response
    resp = f"I am your local AI Security Assistant for **{target_domain}** (Scan #{scan_id or 'Active'}).\n\n"
    resp += f"- **Target Risk Score:** {scan.overall_risk_score if scan_id and scan else 0.0}/100 (Priority: {scan.priority if scan_id and scan else 'P4'})\n"
    resp += f"- **Actionable Findings:** {len(critical_findings) + len(high_findings)} High/Critical issues\n"
    resp += f"- **Inferred Exploit Chains:** {len(chains)} active attack paths\n\n"
    resp += "You can ask me:\n"
    resp += "• *'What is the most serious finding?'*\n"
    resp += "• *'How do I remediate the critical exploit chains?'*\n"
    resp += "• *'Explain the OAuth account takeover path.'*"

    return schemas.ChatResponse(
        response=resp,
        sources_cited=[c.name for c in chains[:2]],
    )


# ---------------------------------------------------------------------------
# Stats Summary
# ---------------------------------------------------------------------------

@router.get("/stats/summary", response_model=schemas.StatsSummaryOut)
def get_stats_summary(db: Session = Depends(get_db)):
    total_targets = db.query(models.Target).count()
    total_scans = db.query(models.Scan).count()
    active_scans = db.query(models.Scan).filter(models.Scan.status.in_(["queued", "recon_running", "scan_running"])).count()
    completed_scans = db.query(models.Scan).filter(models.Scan.status == "completed").count()

    total_subdomains = db.query(models.Subdomain).count()
    total_live_hosts = db.query(models.LiveHost).count()
    total_endpoints = db.query(models.Endpoint).count()
    total_findings = db.query(models.Finding).count()
    total_chains = db.query(models.ExploitChain).count()

    actionable_count = db.query(models.Finding).filter(models.Finding.validity == "actionable").count()
    informational_count = db.query(models.Finding).filter(models.Finding.validity == "informational").count()

    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = db.query(models.Finding).filter(func.lower(models.Finding.severity) == sev).count()
        severity_counts[sev] = count

    source_counts = {}
    for src in ["nuclei", "content_discovery", "gitleaks", "secrets_regex"]:
        count = db.query(models.Finding).filter(models.Finding.source == src).count()
        source_counts[src] = count

    return schemas.StatsSummaryOut(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        completed_scans=completed_scans,
        total_subdomains=total_subdomains,
        total_live_hosts=total_live_hosts,
        total_endpoints=total_endpoints,
        total_findings=total_findings,
        total_chains=total_chains,
        findings_by_severity=severity_counts,
        findings_by_source=source_counts,
        actionable_findings=actionable_count,
        informational_findings=informational_count,
    )


# ---------------------------------------------------------------------------
# Integrated Tools & Engines Status
# ---------------------------------------------------------------------------

@router.get("/api/tools/status", tags=["system"])
def get_tools_status():
    """Returns the operational status of all CLI and native scanning engines."""
    from app.modules import recon

    cli_tools = {
        "subfinder": bool(recon._tool_path("subfinder")),
        "amass": bool(recon._tool_path("amass")),
        "httpx": bool(recon._tool_path("httpx")),
        "gau": bool(recon._tool_path("gau")),
        "nuclei": bool(recon._tool_path("nuclei")),
    }

    native_engines = {
        "passive_crtsh": "active (Certificate Transparency + OTX)",
        "dns_resolver": "active (Multi-threaded Socket DNS)",
        "http_prober": "active (Concurrent SSL/TLS & Tech Fingerprinter)",
        "wayback_cdx": "active (Internet Archive CDX API)",
        "content_discovery": "active (25+ Sensitive Path Checkers)",
        "secret_scanner": "active (Live Client JS Regex Matcher)",
        "cors_headers_auditor": "active (Live Origin Reflection & Security Headers)",
        "exploit_chain_mapper": "active (15 Multi-Step Attack Patterns)",
    }

    return {
        "status": "ready",
        "cli_tools": cli_tools,
        "native_engines": native_engines,
        "mode": "hybrid_dual_engine"
    }
