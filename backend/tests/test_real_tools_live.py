"""
Live integration test for real reconnaissance and multi-scanner engines.
Tests live DNS, HTTP probing, Wayback CDX, content discovery, and exploit chains.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models
from app.modules import recon, scanners, pipeline

engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestSession = sessionmaker(bind=engine)


def test_real_recon_and_scanning_live():
    print("\n[TEST] Running live reconnaissance on 'scanme.nmap.org'...")
    Base.metadata.create_all(bind=engine)
    db = TestSession()

    target = models.Target(domain="scanme.nmap.org")
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Execute full real pipeline
    pipeline.run_full_pipeline(scan.id, target.domain, db)
    db.refresh(scan)

    print(f"[RESULT] Scan Status: {scan.status}")
    print(f"[RESULT] Overall Risk: {scan.overall_risk_score} (Priority: {scan.priority})")

    subdomains = db.query(models.Subdomain).filter_by(scan_id=scan.id).all()
    print(f"[RESULT] Subdomains discovered: {len(subdomains)} -> {[s.subdomain for s in subdomains]}")

    live_hosts = db.query(models.LiveHost).filter_by(scan_id=scan.id).all()
    print(f"[RESULT] Live hosts confirmed: {len(live_hosts)} -> {[h.url for h in live_hosts]}")
    for h in live_hosts:
        print(f"         - Host: {h.url} | Status: {h.status_code} | Title: {h.title} | Tech: {h.tech_stack}")

    endpoints = db.query(models.Endpoint).filter_by(scan_id=scan.id).all()
    print(f"[RESULT] Endpoints discovered: {len(endpoints)}")

    findings = db.query(models.Finding).filter_by(scan_id=scan.id).all()
    print(f"[RESULT] Multi-scanner findings: {len(findings)}")
    for f in findings:
        print(f"         - Finding: [{f.severity.upper()}] {f.name} ({f.source}) -> {f.matched_url}")

    chains = db.query(models.ExploitChain).filter_by(scan_id=scan.id).all()
    print(f"[RESULT] Inferred Exploit Chains: {len(chains)}")
    for c in chains:
        chain_name_safe = c.name.encode("ascii", errors="replace").decode("ascii")
        print(f"         - Chain: [{c.severity.upper()}] {chain_name_safe} (CVSS: {c.cvss_score}, Conf: {c.confidence}%)")

    assert scan.status == "completed", f"Scan failed: {scan.error_message}"
    assert len(live_hosts) >= 1, "Expected at least 1 live host confirmed"
    print("\n[SUCCESS] Real tools integrated and working end-to-end!")


if __name__ == "__main__":
    test_real_recon_and_scanning_live()
