"""
Orchestrates Phase 3 (recon) into Phase 4 (scanning) as one pipeline.

This is the "alignment" point between the two phases: the scan stage
never re-discovers hosts on its own -- it only ever scans the live_hosts
rows that the recon stage already wrote to the database. That's the
hand-off contract between the two modules.
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.modules import recon, scanner, scanners
from app.modules.chains import infer_exploit_chains, calculate_target_risk, generate_safe_payload_suggestion
from app.models import Scan, Subdomain, LiveHost, Endpoint, Finding, ExploitChain
from app.telemetry_logger import (
    log_scan_start,
    log_stage,
    log_tool_activity,
    log_host_found,
    log_finding_found,
    log_chain_inferred,
    log_scan_complete,
    log_scan_error,
)

logger = logging.getLogger("pipeline")


def execute_recon_stage(scan_id: int, domain: str, db: Session) -> None:
    """Phase 3: subdomain enum -> live host detection -> endpoint discovery."""
    scan = db.get(Scan, scan_id)
    scan.status = "recon_running"
    scan.current_stage = "subdomain_enumeration"
    scan.started_at = datetime.utcnow()
    db.commit()

    # --- 1. Subdomain Enumeration ---
    log_stage(1, f"Subdomain Enumeration for {domain}")
    subdomain_pairs = recon.merge_subdomains(domain)
    for sub, source in subdomain_pairs:
        db.add(Subdomain(scan_id=scan_id, subdomain=sub, source_tool=source))
    db.commit()
    log_tool_activity("Subdomain Recon", f"Discovered {len(subdomain_pairs)} unique subdomains: {[s for s, _ in subdomain_pairs[:5]]}")

    # --- 2. Live Host Detection ---
    scan.current_stage = "live_host_detection"
    db.commit()
    log_stage(2, "Live Host Detection & Tech Fingerprinting")

    all_hosts = [domain] + [sub for sub, _ in subdomain_pairs]
    live_host_records = recon.run_httpx(all_hosts)
    for record in live_host_records:
        db.add(LiveHost(
            scan_id=scan_id,
            url=record["url"],
            status_code=record["status_code"],
            title=record["title"],
            tech_stack=record["tech_stack"],
        ))
        log_host_found(record["url"], record["status_code"], record["title"], record["tech_stack"])
    db.commit()
    log_tool_activity("Host Prober", f"Confirmed {len(live_host_records)} reachable live HTTP/HTTPS hosts")

    # --- 3. Endpoint Discovery ---
    scan.current_stage = "endpoint_discovery"
    db.commit()
    log_stage(3, "Endpoint Discovery & Historical Archive")

    endpoint_urls = recon.run_gau(domain)
    for url in endpoint_urls:
        db.add(Endpoint(scan_id=scan_id, url=url, source="gau", category="api"))
    db.commit()
    log_tool_activity("Endpoint Engine", f"Extracted {len(endpoint_urls)} endpoints via archive & live crawler")

    scan.current_stage = "recon_complete"
    db.commit()


def execute_scan_stage(scan_id: int, db: Session, severity: str | None = None) -> None:
    """Phase 4, 5 & 6: run 4-scanner detection layer against live hosts, then infer exploit chains."""
    scan = db.get(Scan, scan_id)
    scan.status = "scan_running"
    scan.current_stage = "vulnerability_scanning"
    db.commit()

    live_hosts = db.query(LiveHost).filter(LiveHost.scan_id == scan_id).all()
    urls = [h.url for h in live_hosts]
    if not urls:
        target_domain = scan.target_domain or (scan.target.domain if scan.target else None)
        if target_domain:
            urls = [f"https://{target_domain}", f"http://{target_domain}"]

    log_stage(4, f"Multi-Scanner Vulnerability Detection Layer (Scanning {len(urls)} live targets)")
    raw_findings_dict_list = scanners.run_multi_scanner_detection(urls)
    
    for f_dict in raw_findings_dict_list:
        db.add(Finding(
            scan_id=scan_id,
            matched_url=f_dict["matched_url"],
            template_id=f_dict["template_id"],
            name=f_dict["name"],
            severity=f_dict["severity"],
            chain_aware_severity=f_dict.get("chain_aware_severity", f_dict["severity"]),
            cvss_score=f_dict.get("cvss_score", 5.0),
            source=f_dict.get("source", "nuclei"),
            validity=f_dict.get("validity", "actionable"),
            exploitability=f_dict.get("exploitability", "medium"),
            risk_score=f_dict.get("risk_score", 5.0),
            priority=f_dict.get("priority", "P3"),
            safe_payload_test=f_dict.get("safe_payload_test") or generate_safe_payload_suggestion(f_dict["name"], f_dict["template_id"], f_dict["matched_url"]),
            description=f_dict.get("description"),
            raw_output=f_dict.get("raw_output", "{}"),
        ))
        log_finding_found(f_dict["severity"], f_dict["name"], f_dict["matched_url"], f_dict.get("source", "scanner"))
    db.commit()
    log_tool_activity("Multi-Scanner", f"Consolidated {len(raw_findings_dict_list)} total actionable & informational findings")

    # --- 5. Exploit Chain Inference ---
    scan.current_stage = "exploit_chain_inference"
    db.commit()
    log_stage(5, "Exploit Chain Inference & Attack Graph Mapping")

    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    inferred_chains = infer_exploit_chains(raw_findings_dict_list, [{"url": ep.url} for ep in endpoints])
    
    for c in inferred_chains:
        db.add(ExploitChain(
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
        log_chain_inferred(c["name"], c["severity"], c["cvss_score"], c["confidence"])
    db.commit()

    # --- Target Risk Metrics ---
    risk_metrics = calculate_target_risk(raw_findings_dict_list, inferred_chains)
    scan.overall_risk_score = risk_metrics["overall_risk_score"]
    scan.priority = risk_metrics["priority"]
    scan.actionable_count = risk_metrics["actionable_count"]
    scan.informational_count = risk_metrics["informational_count"]
    scan.chains_count = risk_metrics["chains_count"]
    scan.status = "completed"
    scan.current_stage = "completed"
    scan.completed_at = datetime.utcnow()
    db.commit()

    target_domain = scan.target.domain if scan.target else f"Target #{scan.target_id}"
    log_scan_complete(
        scan_id=scan.id,
        domain=target_domain,
        risk=scan.overall_risk_score,
        priority=scan.priority,
        findings_cnt=len(raw_findings_dict_list),
        chains_cnt=len(inferred_chains),
    )


def run_full_pipeline(scan_id: int, domain: str, db: Session) -> None:
    """Entry point used by the API layer -- runs both phases back-to-back."""
    log_scan_start(scan_id, domain)
    try:
        execute_recon_stage(scan_id, domain, db)
        execute_scan_stage(scan_id, db)
    except Exception as e:
        logger.exception("scan %s failed", scan_id)
        log_scan_error(scan_id, str(e))
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.current_stage = "failed"
            scan.error_message = str(e)[:1000]
            db.commit()


