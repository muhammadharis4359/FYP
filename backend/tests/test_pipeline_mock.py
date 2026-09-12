"""
Verifies the Phase 3 -> Phase 4 pipeline logic (data flow, DB writes, stage
transitions) WITHOUT needing Amass/Subfinder/httpx/gau/Nuclei installed.

This is what you should run first, before installing any of the actual
CLI tools -- it proves the orchestration code itself is correct. Once this
passes, install the real tools (see README) and run against a real target.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import models
from app.modules import pipeline

# Isolated in-memory DB for the test -- never touches recon_mapper.db
engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestSession = sessionmaker(bind=engine)


def make_db():
    Base.metadata.create_all(bind=engine)
    return TestSession()


FAKE_SUBFINDER = ["api.example.com", "dev.example.com"]
FAKE_AMASS = ["dev.example.com", "staging.example.com"]  # overlaps with subfinder on purpose

FAKE_HTTPX = [
    {"url": "https://api.example.com", "status_code": 200, "title": "API", "tech_stack": "nginx"},
    {"url": "https://dev.example.com", "status_code": 403, "title": "Forbidden", "tech_stack": None},
]

FAKE_GAU = [
    "https://example.com/old-login.php",
    "https://example.com/api/v1/users?id=1",
]

FAKE_NUCLEI = [
    {
        "matched_url": "https://api.example.com",
        "template_id": "exposed-panel",
        "name": "Exposed Admin Panel",
        "severity": "medium",
        "description": "An administrative panel was found exposed.",
        "raw_output": "{}",
    }
]


def test_pipeline_end_to_end():
    db = make_db()

    target = models.Target(domain="example.com")
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with patch("app.modules.recon.run_subfinder", return_value=FAKE_SUBFINDER), \
         patch("app.modules.recon.run_amass", return_value=FAKE_AMASS), \
         patch("app.modules.recon.run_passive_crtsh", return_value=[]), \
         patch("app.modules.recon.run_dns_bruteforce", return_value=[]), \
         patch("app.modules.recon.run_httpx", return_value=FAKE_HTTPX), \
         patch("app.modules.recon.run_gau", return_value=FAKE_GAU), \
         patch("app.modules.scanners.run_content_discovery_scanner", return_value=[]), \
         patch("app.modules.scanners.run_secret_scanner", return_value=[]), \
         patch("app.modules.scanners.run_cors_and_headers_scanner", return_value=[]), \
         patch("app.modules.scanner.run_nuclei", return_value=FAKE_NUCLEI):

        pipeline.run_full_pipeline(scan.id, target.domain, db)

    db.refresh(scan)

    # --- assertions ---
    assert scan.status == "completed", f"scan ended in status={scan.status}, error={scan.error_message}"

    subdomains = db.query(models.Subdomain).filter_by(scan_id=scan.id).all()
    assert len(subdomains) == 3, "expected 3 unique subdomains (dev.example.com deduped)"

    live_hosts = db.query(models.LiveHost).filter_by(scan_id=scan.id).all()
    assert len(live_hosts) == 2

    endpoints = db.query(models.Endpoint).filter_by(scan_id=scan.id).all()
    assert len(endpoints) == 2

    findings = db.query(models.Finding).filter_by(scan_id=scan.id).all()
    assert len(findings) == 1
    assert findings[0].template_id == "exposed-panel"
    assert findings[0].severity == "medium"

    print("ALL ASSERTIONS PASSED")
    print(f"  subdomains: {[s.subdomain for s in subdomains]}")
    print(f"  live_hosts: {[h.url for h in live_hosts]}")
    print(f"  endpoints:  {len(endpoints)} found")
    print(f"  findings:   {[f.template_id for f in findings]}")


def test_pipeline_handles_tool_failure_gracefully():
    """If a tool crashes mid-recon, the scan should be marked failed --
    not silently swallow the error or leave the scan stuck 'running'."""
    db = make_db()

    target = models.Target(domain="broken-target.com")
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    with patch("app.modules.recon.run_subfinder", side_effect=RuntimeError("simulated crash")):
        pipeline.run_full_pipeline(scan.id, target.domain, db)

    db.refresh(scan)
    assert scan.status == "failed"
    assert "simulated crash" in scan.error_message
    print("ALL ASSERTIONS PASSED (failure path)")


if __name__ == "__main__":
    test_pipeline_end_to_end()
    test_pipeline_handles_tool_failure_gracefully()
    print("\n2/2 tests passed.")
