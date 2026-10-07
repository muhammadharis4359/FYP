"""
Comprehensive Test for Telemetry Ingestion (Approach B & Approach C)
Tests real-time sync of Subfinder, httpx, Nuclei, gau, and Agent Exploit Chains.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import Base, engine, SessionLocal
from app import models, schemas

Base.metadata.create_all(bind=engine)

from app.routers.scans import (
    ingest_scan_telemetry,
    get_active_scan,
    get_subdomains,
    get_live_hosts,
    get_endpoints,
    get_findings,
    get_chains,
    get_scan,
)


def test_telemetry_ingestion_end_to_end():
    db = SessionLocal()
    try:
        # 1. Setup a clean test target and scan
        target = db.query(models.Target).filter(models.Target.domain == "telemetry-test.io").first()
        if not target:
            target = models.Target(domain="telemetry-test.io")
            db.add(target)
            db.commit()
            db.refresh(target)

        scan = models.Scan(target_id=target.id, status="queued", current_stage="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
        print(f"\n[+] Created Test Target {target.domain} with Scan #{scan_id}")

        # 2. Test active scan lookup
        active_scan = get_active_scan(domain=target.domain, auto_create=False, db=db)
        assert active_scan.id == scan_id
        print("[OK] Active scan lookup verified")

        # 3. Test Subfinder Output Ingestion (Approach B - plain lines)
        subfinder_raw = """
        api.telemetry-test.io
        dev.telemetry-test.io
        admin.telemetry-test.io
        vpn.telemetry-test.io
        """
        req_subs = schemas.TelemetryIngestRequest(
            command="subfinder -d telemetry-test.io -silent",
            raw_output=subfinder_raw,
            source_tool="subfinder",
        )
        res_subs = ingest_scan_telemetry(scan_id=scan_id, payload=req_subs, db=db)
        assert res_subs.ingested["subdomains"] == 4
        print(f"[OK] Ingested {res_subs.ingested['subdomains']} subdomains")

        # 4. Test httpx JSONL Ingestion (Approach B)
        httpx_raw = """
        {"url":"https://api.telemetry-test.io","status_code":200,"title":"REST API Gateway","tech":["Express","Node.js","Docker"]}
        {"url":"https://admin.telemetry-test.io","status_code":200,"title":"Grafana Admin Panel","tech":["Grafana","Linux"]}
        {"url":"https://dev.telemetry-test.io","status_code":403,"title":"403 Forbidden","tech":["Apache/2.4.52","PHP/8.1"]}
        """
        req_hosts = schemas.TelemetryIngestRequest(
            command="httpx -l /tmp/hosts.txt -silent -json -tech-detect",
            raw_output=httpx_raw,
        )
        res_hosts = ingest_scan_telemetry(scan_id=scan_id, payload=req_hosts, db=db)
        assert res_hosts.ingested["live_hosts"] == 3
        print(f"[OK] Ingested {res_hosts.ingested['live_hosts']} live hosts with tech stacks")

        # 5. Test Endpoint Archive Ingestion (Approach B - gau)
        gau_raw = """
        https://api.telemetry-test.io/v1/auth/login
        https://admin.telemetry-test.io/actuator/heapdump
        https://telemetry-test.io/.env
        https://dev.telemetry-test.io/upload/avatar
        """
        req_eps = schemas.TelemetryIngestRequest(
            command="gau telemetry-test.io",
            raw_output=gau_raw,
            source_tool="gau",
        )
        res_eps = ingest_scan_telemetry(scan_id=scan_id, payload=req_eps, db=db)
        assert res_eps.ingested["endpoints"] == 4
        print(f"[OK] Ingested {res_eps.ingested['endpoints']} categorized endpoints")

        # 6. Test Nuclei Vulnerability Ingestion (Approach B - JSONL)
        nuclei_raw = """
        {"template-id":"env-file-exposure","info":{"name":"Exposed Environment File (.env)","severity":"critical","description":"Production .env file contains PostgreSQL credentials and AWS root secret keys."},"matched-at":"https://telemetry-test.io/.env"}
        {"template-id":"springboot-actuator-heapdump","info":{"name":"Spring Boot Actuator Heapdump Disclosure","severity":"high","description":"Memory heapdump accessible without authentication exposing database passwords."},"matched-at":"https://admin.telemetry-test.io/actuator/heapdump"}
        {"template-id":"open-redirect-oauth","info":{"name":"OAuth Open Redirect Parameter","severity":"medium","description":"Unvalidated redirect_uri parameter allows stealing OAuth authorization codes."},"matched-at":"https://api.telemetry-test.io/v1/auth/login?redirect=https://evil.com"}
        """
        req_nuclei = schemas.TelemetryIngestRequest(
            command="nuclei -u https://telemetry-test.io -silent -jsonl",
            raw_output=nuclei_raw,
        )
        res_nuclei = ingest_scan_telemetry(scan_id=scan_id, payload=req_nuclei, db=db)
        assert res_nuclei.ingested["findings"] == 3
        print(f"[OK] Ingested {res_nuclei.ingested['findings']} Nuclei findings (Risk: {res_nuclei.overall_risk_score}, Priority: {res_nuclei.priority})")

        # 7. Test Agent-Structured Exploit Chains (Approach C - AI Reasoning Payload)
        agent_chains_payload = {
            "type": "exploit_chains_payload",
            "overall_risk_score": 92.5,
            "priority": "P1",
            "chains": [
                {
                    "name": "Exposed .env -> AWS Secret Key -> S3 Data Dump -> Account Takeover",
                    "category": "Cloud Compromise",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "confidence": 95,
                    "steps": [
                        "Identified publicly accessible .env file on web root",
                        "Extracted AWS_SECRET_ACCESS_KEY and AWS_ACCESS_KEY_ID",
                        "Authenticated to AWS IAM and dumped multi-tenant S3 database backups",
                    ],
                    "impact": "Complete exfiltration of customer database backups and AWS root takeover",
                    "remediation": "Block access to dotfiles in Nginx/Apache configuration and rotate AWS root credentials immediately",
                },
                {
                    "name": "OAuth Redirect -> Token Theft -> Admin Account Takeover",
                    "category": "Account Takeover",
                    "severity": "high",
                    "cvss_score": 8.9,
                    "confidence": 90,
                    "steps": [
                        "Unvalidated redirect_uri parameter discovered on OAuth authorization endpoint",
                        "Attacker crafts malicious URL sending auth code to evil.com",
                        "Attacker exchanges auth code for admin bearer token",
                    ],
                    "impact": "Administrative account takeover without brute-force",
                    "remediation": "Enforce strict URI whitelist on OAuth authorization server",
                },
            ],
        }
        req_chains = schemas.TelemetryIngestRequest(**agent_chains_payload)
        res_chains = ingest_scan_telemetry(scan_id=scan_id, payload=req_chains, db=db)
        assert res_chains.ingested["exploit_chains"] == 2
        assert res_chains.overall_risk_score == 92.5
        assert res_chains.priority == "P1"
        print(f"[OK] Ingested {res_chains.ingested['exploit_chains']} AI Exploit Chains (Risk Score: {res_chains.overall_risk_score}, Priority: {res_chains.priority})")

        # 8. Verify the Scan detail endpoints return all records properly for Frontend
        scan_detail = get_scan(scan_id=scan_id, db=db)
        assert scan_detail.overall_risk_score == 92.5
        assert scan_detail.priority == "P1"

        subs = get_subdomains(scan_id=scan_id, db=db)
        assert len(subs) == 4

        hosts = get_live_hosts(scan_id=scan_id, db=db)
        assert len(hosts) == 3

        eps = get_endpoints(scan_id=scan_id, db=db)
        assert len(eps) == 4

        findings = get_findings(scan_id=scan_id, db=db)
        assert len(findings) == 3

        chains = get_chains(scan_id=scan_id, db=db)
        assert len(chains) >= 2

        print("\n=======================================================")
        print(" [ALL TESTS PASSED] Hybrid B+C Telemetry Sync Verified!")
        print("=======================================================\n")

    finally:
        db.close()


if __name__ == "__main__":
    test_telemetry_ingestion_end_to_end()
