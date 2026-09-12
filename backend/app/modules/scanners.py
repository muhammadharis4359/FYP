"""
Multi-Scanner Detection Layer (PDF Section 5 & Phase 4 Alignment).

Orchestrates 4 distinct security scanning engines:
1. nuclei: CVE & Vulnerability Templates (CLI wrapper when installed)
2. content-discovery: High-speed concurrent checking of sensitive files, panels, backups, actuator endpoints
3. gitleaks / secret-scanner: Live scraping and scanning of client HTML/JS files for leaked API keys & tokens
4. cors & header auditor: Insecure CORS reflections and missing defensive HTTP security headers
"""

import concurrent.futures
import json
import logging
import re
import ssl
import urllib.parse
import urllib.request
from typing import Any, Optional

from app.modules import scanner
from app.modules.chains import generate_safe_payload_suggestion

logger = logging.getLogger("scanners")

# Curated content discovery paths & verification rules
CONTENT_PATHS = [
    {
        "path": "/.env",
        "template_id": "exposed-env-file",
        "name": "Exposed .env Configuration File",
        "severity": "critical",
        "cvss": 9.5,
        "keywords": ["DB_", "APP_", "SECRET", "PASSWORD", "KEY=", "AWS_"],
        "desc": "Sensitive environment file is publicly exposed, disclosing database and API credentials."
    },
    {
        "path": "/.git/HEAD",
        "template_id": "exposed-git-repository",
        "name": "Exposed Git Version Control Repository",
        "severity": "critical",
        "cvss": 9.1,
        "keywords": ["ref: refs/"],
        "desc": "Publicly accessible .git/HEAD allows attackers to reconstruct source code repository history."
    },
    {
        "path": "/.git/config",
        "template_id": "exposed-git-config",
        "name": "Exposed .git/config File",
        "severity": "high",
        "cvss": 8.2,
        "keywords": ["[core]", "[remote"],
        "desc": "Git configuration file disclosed, revealing remote repository URLs and branches."
    },
    {
        "path": "/actuator/heapdump",
        "template_id": "spring-actuator-heapdump",
        "name": "Spring Boot Actuator Heapdump Disclosure",
        "severity": "critical",
        "cvss": 9.8,
        "content_types": ["application/octet-stream", "application/gzip"],
        "desc": "Spring Boot Actuator /heapdump exposed, allowing full in-memory secret extraction."
    },
    {
        "path": "/actuator/env",
        "template_id": "spring-actuator-env",
        "name": "Spring Boot Actuator Environment Disclosure",
        "severity": "high",
        "cvss": 8.6,
        "keywords": ["propertySources", "server.port", "profiles"],
        "desc": "Spring Boot Actuator /env endpoint exposed, revealing application configuration and environment variables."
    },
    {
        "path": "/actuator/health",
        "template_id": "spring-actuator-health",
        "name": "Spring Boot Actuator Health Status",
        "severity": "info",
        "cvss": 0.0,
        "keywords": ['"status":"UP"', '"status":"UNKNOWN"'],
        "desc": "Spring Boot Actuator /health status endpoint publicly reachable."
    },
    {
        "path": "/phpinfo.php",
        "template_id": "phpinfo-exposure",
        "name": "PHPInfo Configuration File Exposure",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ["PHP Version", "Configuration File (php.ini)", "System"],
        "desc": "PHPInfo diagnostic script exposed, revealing absolute system paths, PHP modules, and server environment."
    },
    {
        "path": "/info.php",
        "template_id": "phpinfo-exposure",
        "name": "PHPInfo Configuration File Exposure",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ["PHP Version", "Configuration File (php.ini)"],
        "desc": "PHPInfo diagnostic script exposed."
    },
    {
        "path": "/swagger/v1/swagger.json",
        "template_id": "swagger-api-introspection",
        "name": "Exposed Swagger/OpenAPI Specification",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ['"swagger"', '"openapi"', '"paths"'],
        "desc": "Publicly accessible Swagger JSON schema exposes hidden internal API routes and schemas."
    },
    {
        "path": "/api/v1/swagger.json",
        "template_id": "swagger-api-introspection",
        "name": "Exposed Swagger/OpenAPI Specification",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ['"swagger"', '"openapi"', '"paths"'],
        "desc": "Publicly accessible Swagger API specification exposes endpoints."
    },
    {
        "path": "/openapi.json",
        "template_id": "openapi-spec-disclosure",
        "name": "Exposed OpenAPI Specification",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ['"openapi"', '"paths"'],
        "desc": "OpenAPI documentation schema publicly accessible."
    },
    {
        "path": "/graphql",
        "template_id": "graphql-introspection-enabled",
        "name": "GraphQL Endpoint Accessible",
        "severity": "low",
        "cvss": 3.7,
        "keywords": ["GraphQL", "Must provide query string", "GET query missing"],
        "desc": "GraphQL API endpoint detected on live host."
    },
    {
        "path": "/admin",
        "template_id": "exposed-admin-panel",
        "name": "Exposed Administrative Dashboard / Panel",
        "severity": "medium",
        "cvss": 6.5,
        "keywords": ["admin", "login", "password", "dashboard"],
        "desc": "Administrative interface or login page discovered on public surface."
    },
    {
        "path": "/admin/login",
        "template_id": "exposed-admin-panel",
        "name": "Exposed Administrative Login Portal",
        "severity": "medium",
        "cvss": 6.5,
        "keywords": ["admin", "login", "password"],
        "desc": "Administrative login portal accessible on target host."
    },
    {
        "path": "/server-status",
        "template_id": "apache-server-status",
        "name": "Apache Server-Status Diagnostic Exposure",
        "severity": "medium",
        "cvss": 5.3,
        "keywords": ["Apache Server Status", "Server Version:"],
        "desc": "Apache mod_status page publicly exposed, revealing client IP addresses and active URLs."
    },
    {
        "path": "/.aws/credentials",
        "template_id": "exposed-aws-credentials",
        "name": "Exposed AWS Credentials File",
        "severity": "critical",
        "cvss": 9.9,
        "keywords": ["aws_access_key_id", "[default]"],
        "desc": "AWS credentials file publicly accessible, granting full cloud API access."
    },
    {
        "path": "/backup.zip",
        "template_id": "exposed-backup-archive",
        "name": "Exposed Application Backup Zip File",
        "severity": "high",
        "cvss": 8.5,
        "content_types": ["application/zip", "application/x-zip-compressed"],
        "desc": "Application backup zip archive exposed on web root."
    },
    {
        "path": "/backup.sql",
        "template_id": "exposed-database-backup",
        "name": "Exposed SQL Database Dump",
        "severity": "critical",
        "cvss": 9.5,
        "keywords": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump"],
        "desc": "Full SQL database dump exposed, leaking tables and records."
    },
    {
        "path": "/db.sqlite3",
        "template_id": "exposed-sqlite-database",
        "name": "Exposed SQLite Database File",
        "severity": "critical",
        "cvss": 9.5,
        "keywords": ["SQLite format 3"],
        "desc": "SQLite database file directly downloadable from web surface."
    },
    {
        "path": "/docker-compose.yml",
        "template_id": "exposed-docker-compose",
        "name": "Exposed Docker Compose File",
        "severity": "high",
        "cvss": 7.8,
        "keywords": ["version:", "services:", "image:"],
        "desc": "Docker compose configuration file exposed, revealing backend architecture and container credentials."
    },
    {
        "path": "/id_rsa",
        "template_id": "exposed-ssh-private-key",
        "name": "Exposed SSH Private Key",
        "severity": "critical",
        "cvss": 10.0,
        "keywords": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"],
        "desc": "SSH private key file exposed on server root, allowing unauthorized server shell access."
    }
]

# High-precision client-side secret patterns
SECRET_REGEXES = [
    (r"AKIA[0-9A-Z]{16}", "aws-access-key-id", "AWS Access Key ID Leaked in Client Code", "critical", 9.8),
    (r"ghp_[0-9a-zA-Z]{36}", "github-personal-access-token", "GitHub Personal Access Token Leaked", "critical", 9.5),
    (r"sk_live_[0-9a-zA-Z]{24}", "stripe-live-secret-key", "Stripe Live Secret API Key Leaked", "critical", 9.9),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "slack-bot-or-user-token", "Slack Bot/User Token Leaked", "high", 8.5),
    (r"AIza[0-9A-Za-z\-_]{35}", "google-api-key", "Google Cloud API Key Leaked", "medium", 6.5),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private-key-leak", "RSA/SSH Private Key Leaked in Code", "critical", 10.0),
    (r"(?:api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{24,64})['\"]", "generic-api-secret", "High-Entropy API Secret / Token Exposed", "high", 8.0),
]


def _format_finding(matched_url: str, template_id: str, name: str, severity: str,
                    cvss: float, source: str, desc: str, raw_output: str = "{}") -> dict:
    sev = (severity or "info").lower()
    priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}
    prio = priority_map.get(sev, "P4")
    validity = "informational" if sev == "info" else "actionable"

    return {
        "matched_url": matched_url,
        "template_id": template_id,
        "name": name,
        "severity": sev,
        "chain_aware_severity": sev,
        "cvss_score": cvss,
        "source": source,
        "validity": validity,
        "exploitability": "high" if sev in ["critical", "high"] else "medium",
        "risk_score": cvss,
        "priority": prio,
        "safe_payload_test": generate_safe_payload_suggestion(name, template_id, matched_url),
        "description": desc,
        "raw_output": raw_output,
    }


# ---------------------------------------------------------------------------
# 1. Scanner: Content Discovery (Exposed Files, Actuator, Backups)
# ---------------------------------------------------------------------------

def _probe_content_path(base_url: str, item: dict) -> Optional[dict]:
    clean_base = base_url.rstrip("/")
    probe_url = f"{clean_base}{item['path']}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        probe_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            status = resp.status
            if status not in [200, 206]:
                return None

            content_type = resp.headers.get("Content-Type", "").lower()
            body_bytes = resp.read(32768)
            body_text = body_bytes.decode("utf-8", errors="ignore")

            # Validate positive signals
            verified = False
            expected_types = item.get("content_types")
            if expected_types:
                if any(t in content_type for t in expected_types):
                    verified = True

            keywords = item.get("keywords")
            if keywords:
                if any(kw in body_text for kw in keywords):
                    verified = True

            # If no specific keyword required and status 200 on non-HTML if expecting binary
            if not keywords and not expected_types and status == 200:
                verified = True

            if verified:
                return _format_finding(
                    matched_url=probe_url,
                    template_id=item["template_id"],
                    name=item["name"],
                    severity=item["severity"],
                    cvss=item["cvss"],
                    source="content_discovery",
                    desc=item["desc"],
                    raw_output=json.dumps({"status": status, "content_type": content_type, "length": len(body_bytes)}),
                )
    except urllib.error.HTTPError as e:
        # Check GraphQL 400 with valid error body
        if e.code == 400 and item["template_id"] == "graphql-introspection-enabled":
            body = e.read(4096).decode("utf-8", errors="ignore")
            if "GraphQL" in body or "query" in body:
                return _format_finding(
                    matched_url=probe_url,
                    template_id=item["template_id"],
                    name=item["name"],
                    severity="low",
                    cvss=3.7,
                    source="content_discovery",
                    desc="GraphQL API endpoint active on server.",
                    raw_output=json.dumps({"status": e.code, "body": body[:200]}),
                )
    except Exception:
        pass
    return None


def run_content_discovery_scanner(urls: list[str]) -> list[dict]:
    """Runs concurrent content path discovery across live hosts."""
    findings = []
    if not urls:
        return findings

    probe_targets = []
    for u in urls:
        for item in CONTENT_PATHS:
            probe_targets.append((u, item))

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = [executor.submit(_probe_content_path, u, item) for u, item in probe_targets]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                findings.append(res)

    return findings


# ---------------------------------------------------------------------------
# 2. Scanner: Client-Side JS Secret & Leaked Credential Scanner
# ---------------------------------------------------------------------------

def _scan_text_for_secrets(text: str, source_url: str) -> list[dict]:
    findings = []
    seen_matches = set()

    for pattern, template_id, name, severity, cvss in SECRET_REGEXES:
        matches = re.finditer(pattern, text)
        for m in matches:
            matched_val = m.group(0)
            if matched_val in seen_matches:
                continue
            seen_matches.add(matched_val)

            # Mask secret for safe output
            masked = matched_val[:4] + "*" * max(4, len(matched_val) - 8) + matched_val[-4:] if len(matched_val) > 8 else "****"

            findings.append(_format_finding(
                matched_url=source_url,
                template_id=template_id,
                name=name,
                severity=severity,
                cvss=cvss,
                source="gitleaks",
                desc=f"Hardcoded sensitive secret or API key ({masked}) identified in client code.",
                raw_output=json.dumps({"secret_type": template_id, "masked_evidence": masked}),
            ))
    return findings


def run_secret_scanner(urls: list[str]) -> list[dict]:
    """Fetches HTML and linked JS files from target hosts to scan for exposed secrets."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for base_url in urls[:8]:
        try:
            req = urllib.request.Request(
                base_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                html = resp.read(131072).decode("utf-8", errors="ignore")

            # Scan HTML directly
            findings.extend(_scan_text_for_secrets(html, base_url))

            # Extract script URLs
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for src in script_srcs[:5]:
                js_url = urllib.parse.urljoin(base_url, src)
                if not js_url.startswith("http"):
                    continue
                try:
                    js_req = urllib.request.Request(
                        js_url,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
                    )
                    with urllib.request.urlopen(js_req, timeout=4, context=ctx) as js_resp:
                        js_code = js_resp.read(262144).decode("utf-8", errors="ignore")
                        findings.extend(_scan_text_for_secrets(js_code, js_url))
                except Exception:
                    continue
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# 3. Scanner: CORS Misconfiguration & Security Headers Auditor
# ---------------------------------------------------------------------------

def run_cors_and_headers_scanner(urls: list[str]) -> list[dict]:
    """Audits CORS origins and HTTP defensive headers on live hosts."""
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for base_url in urls[:10]:
        try:
            test_origin = "https://evil-attacker.corp"
            req = urllib.request.Request(
                base_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0",
                    "Origin": test_origin,
                }
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # CORS Analysis
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower() == "true"

                if test_origin in acao:
                    findings.append(_format_finding(
                        matched_url=base_url,
                        template_id="cors-arbitrary-origin-reflection",
                        name="CORS Misconfiguration: Arbitrary Origin Reflection",
                        severity="high" if acac else "medium",
                        cvss=7.5 if acac else 5.3,
                        source="nuclei",
                        desc=f"Server reflects arbitrary Origin header '{test_origin}' (Credentials: {acac}), enabling cross-origin authenticated data theft.",
                        raw_output=json.dumps({"ACAO": acao, "ACAC": acac}),
                    ))
                elif acao == "*" and acac:
                    findings.append(_format_finding(
                        matched_url=base_url,
                        template_id="cors-wildcard-with-credentials",
                        name="CORS Misconfiguration: Wildcard with Credentials",
                        severity="high",
                        cvss=7.5,
                        source="nuclei",
                        desc="Server allows wildcard '*' CORS origin with credentials enabled.",
                        raw_output=json.dumps({"ACAO": acao, "ACAC": acac}),
                    ))

                # Security Header Analysis
                if "x-frame-options" not in headers and "content-security-policy" not in headers:
                    findings.append(_format_finding(
                        matched_url=base_url,
                        template_id="missing-clickjacking-protection",
                        name="Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
                        severity="low",
                        cvss=3.4,
                        source="nuclei",
                        desc="Target web page lacks X-Frame-Options or CSP frame-ancestors headers, allowing UI redress clickjacking.",
                        raw_output=json.dumps({"headers": list(headers.keys())}),
                    ))

                if base_url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append(_format_finding(
                        matched_url=base_url,
                        template_id="missing-hsts-header",
                        name="Missing HTTP Strict Transport Security (HSTS)",
                        severity="info",
                        cvss=0.0,
                        source="nuclei",
                        desc="HTTPS endpoint does not advertise Strict-Transport-Security header.",
                        raw_output=json.dumps({"headers": list(headers.keys())}),
                    ))
        except Exception:
            continue

    return findings


# ---------------------------------------------------------------------------
# Consolidated Multi-Scanner Entrypoint (PDF §5 & Phase 4/6)
# ---------------------------------------------------------------------------

def run_multi_scanner_detection(urls: list[str]) -> list[dict]:
    """Runs all 4 scanners in parallel / sequence and returns consolidated,
    source-tagged findings without duplication."""
    all_findings = []
    seen = set()

    # 1. Nuclei Scanner (CLI if installed)
    try:
        nuclei_results = scanner.run_nuclei(urls)
        for f in nuclei_results:
            key = (f["matched_url"], f["template_id"])
            if key not in seen:
                seen.add(key)
                all_findings.append(_format_finding(
                    matched_url=f["matched_url"],
                    template_id=f["template_id"],
                    name=f.get("name") or f["template_id"],
                    severity=f.get("severity") or "info",
                    cvss=f.get("cvss_score", 5.0),
                    source="nuclei",
                    desc=f.get("description") or "Vulnerability template matched.",
                    raw_output=f.get("raw_output", "{}"),
                ))
    except Exception as e:
        logger.info("Nuclei execution note: %s", e)

    # 2. Content & Path Discovery Scanner
    try:
        content_findings = run_content_discovery_scanner(urls)
        for f in content_findings:
            key = (f["matched_url"], f["template_id"])
            if key not in seen:
                seen.add(key)
                all_findings.append(f)
    except Exception as e:
        logger.warning("Content discovery scanner error: %s", e)

    # 3. Client-Side Secret / JS Scanner
    try:
        secret_findings = run_secret_scanner(urls)
        for f in secret_findings:
            key = (f["matched_url"], f["template_id"])
            if key not in seen:
                seen.add(key)
                all_findings.append(f)
    except Exception as e:
        logger.warning("Secret scanner error: %s", e)

    # 4. CORS & Security Headers Auditor
    try:
        cors_findings = run_cors_and_headers_scanner(urls)
        for f in cors_findings:
            key = (f["matched_url"], f["template_id"])
            if key not in seen:
                seen.add(key)
                all_findings.append(f)
    except Exception as e:
        logger.warning("CORS and headers scanner error: %s", e)

    logger.info("Multi-scanner detection completed: %d total consolidated findings", len(all_findings))
    return all_findings

