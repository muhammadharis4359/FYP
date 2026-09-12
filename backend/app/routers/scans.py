from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
import json
import time

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
