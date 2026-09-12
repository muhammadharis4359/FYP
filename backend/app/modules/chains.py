"""
Exploit Chain Inference & Intelligence Layer (Phase 6 / PDF Spec)
Implements 15 hand-written chain patterns, capability mapping,
chain-aware severity re-ranking, and confidence-weighted risk scoring.
"""

import json
from typing import Any


CHAIN_PATTERNS = [
    {
        "id": "chain-01-open-redirect-ato",
        "name": "Open Redirect → OAuth Token Theft → Account Takeover",
        "category": "Account Takeover",
        "severity": "critical",
        "cvss_score": 9.1,
        "base_confidence": 90,
        "triggers": ["open-redirect", "oauth", "redirect"],
        "steps": [
            {"step": 1, "title": "Open Redirect Identified", "type": "weakness", "desc": "Unvalidated redirect parameter on authorization redirect handler."},
            {"step": 2, "title": "OAuth Authorization Flow Manipulated", "type": "pivot", "desc": "Victim redirected to attacker endpoint with sensitive OAuth access code."},
            {"step": 3, "title": "Account Takeover Completed", "type": "impact", "desc": "Full session hijacking and unauthorized user account takeover."},
        ],
        "impact": "Attacker steals OAuth authorization codes to impersonate legitimate users and take over their accounts.",
        "remediation": "Strictly whitelist allowed redirect URLs on OAuth clients and disable wildcards on OAuth redirect_uri parameters.",
    },
    {
        "id": "chain-02-ssrf-metadata-rce",
        "name": "SSRF → Cloud Metadata (169.254.169.254) → IAM Key Compromise / RCE",
        "category": "Cloud Compromise",
        "severity": "critical",
        "cvss_score": 9.8,
        "base_confidence": 95,
        "triggers": ["ssrf", "metadata", "aws-metadata", "169.254.169.254"],
        "steps": [
            {"step": 1, "title": "Server-Side Request Forgery", "type": "weakness", "desc": "Backend proxy endpoint allows forging HTTP requests to internal networks."},
            {"step": 2, "title": "Instance Metadata Queried", "type": "pivot", "desc": "Accessing 169.254.169.254 extracts temporary EC2/GCP IAM credentials and role tokens."},
            {"step": 3, "title": "Cloud Infrastructure Control", "type": "impact", "desc": "Pivot to cloud management APIs with privileged role permissions."},
        ],
        "impact": "Full compromise of cloud infrastructure, database access, and potential remote execution via cloud compute agents.",
        "remediation": "Enforce IMDSv2 with token hops restricted to 1, and block outbound RFC1918/link-local IP addresses at the application layer.",
    },
    {
        "id": "chain-03-env-git-leak-compromise",
        "name": "Exposed .env / .git → Secret Extraction → Database & API Compromise",
        "category": "Data Exfiltration",
        "severity": "critical",
        "cvss_score": 9.6,
        "base_confidence": 95,
        "triggers": ["env-file", "git-folder", "config-leak", "database_password", "aws_secret"],
        "steps": [
            {"step": 1, "title": "Configuration File Exposure", "type": "weakness", "desc": "Publicly accessible .env or .git folder exposed on web root."},
            {"step": 2, "title": "Credential Harvest", "type": "pivot", "desc": "Extraction of production database connection strings, JWT secret keys, and AWS access keys."},
            {"step": 3, "title": "Direct Database / Cloud Access", "type": "impact", "desc": "Unauthenticated access to backend data stores and external third-party integrations."},
        ],
        "impact": "Immediate data exfiltration, database dumping, and infrastructure compromise without requiring authentication.",
        "remediation": "Block access to dotfiles (.env, .git) in web server configuration (Nginx/Apache) and rotate all leaked credentials immediately.",
    },
    {
        "id": "chain-04-fileupload-webshell-rce",
        "name": "Unrestricted File Upload → Webshell Deployment → Remote Code Execution",
        "category": "Remote Code Execution",
        "severity": "critical",
        "cvss_score": 9.8,
        "base_confidence": 90,
        "triggers": ["file-upload", "webshell", "upload", "php-upload"],
        "steps": [
            {"step": 1, "title": "File Upload Extension Bypass", "type": "weakness", "desc": "Upload form allows executable extensions (.php5, .phtml, .jsp) or content-type bypass."},
            {"step": 2, "title": "Webshell Stored in Public Directory", "type": "pivot", "desc": "File is written to publicly accessible web path without execution restrictions."},
            {"step": 3, "title": "Remote Code Execution", "type": "impact", "desc": "Executing uploaded script grants command execution with web server privileges."},
        ],
        "impact": "Total server compromise, persistent backdoor placement, and lateral network traversal.",
        "remediation": "Store uploads in dedicated object storage (e.g. S3), randomize file names, and disable script execution in upload directories.",
    },
    {
        "id": "chain-05-xss-session-ato",
        "name": "Stored XSS → Session Hijacking → Admin Account Takeover",
        "category": "Account Takeover",
        "severity": "high",
        "cvss_score": 8.6,
        "base_confidence": 85,
        "triggers": ["xss", "cross-site-scripting", "stored-xss", "session-cookie"],
        "steps": [
            {"step": 1, "title": "Cross-Site Scripting Injection", "type": "weakness", "desc": "Unsanitized input rendered without contextual HTML encoding."},
            {"step": 2, "title": "Session Token Exfiltration", "type": "pivot", "desc": "JavaScript payload steals non-HttpOnly admin session cookies or localStorage bearer tokens."},
            {"step": 3, "title": "Administrative Impersonation", "type": "impact", "desc": "Attacker assumes admin role, modifying application state and user permissions."},
        ],
        "impact": "Unauthorized access to administrative capabilities and full data visibility across users.",
        "remediation": "Apply strict Content-Security-Policy (CSP), set HttpOnly & SameSite flags on all authentication cookies, and sanitize rendered output.",
    },
    {
        "id": "chain-06-actuator-heapdump-privilege",
        "name": "Spring Boot Actuator → Heapdump Disclosure → Secret Extraction",
        "category": "Privilege Escalation",
        "severity": "high",
        "cvss_score": 8.2,
        "base_confidence": 90,
        "triggers": ["actuator", "heapdump", "springboot", "env-actuator"],
        "steps": [
            {"step": 1, "title": "Actuator Endpoints Exposed", "type": "weakness", "desc": "Unauthenticated access to /actuator/heapdump or /actuator/env."},
            {"step": 2, "title": "Memory Dump Parsing", "type": "pivot", "desc": "Extraction of plaintext passwords, active API tokens, and encryption keys from memory heap."},
            {"step": 3, "title": "Privilege Escalation", "type": "impact", "desc": "Leverage discovered service tokens to authenticate into protected internal APIs."},
        ],
        "impact": "Exposure of sensitive runtime memory state leading to full lateral credential reuse.",
        "remediation": "Restrict management.endpoints.web.exposure.include to 'health,info' and require authentication on all actuator endpoints.",
    },
    {
        "id": "chain-07-graphql-introspection-bola",
        "name": "GraphQL Introspection → Hidden Mutation Discovery → BOLA / IDOR",
        "category": "Broken Access Control",
        "severity": "high",
        "cvss_score": 7.8,
        "base_confidence": 80,
        "triggers": ["graphql", "introspection", "bola", "idor"],
        "steps": [
            {"step": 1, "title": "Schema Introspection Enabled", "type": "weakness", "desc": "GraphQL __schema endpoint responds with full application schema and unlisted types."},
            {"step": 2, "title": "Unprotected Mutation Enumeration", "type": "pivot", "desc": "Discovery of sensitive administrative mutations (e.g. updateUserRole, deleteTenant)."},
            {"step": 3, "title": "Broken Object Authorization", "type": "impact", "desc": "Invoking mutations directly bypasses UI checks and mutates target records."},
        ],
        "impact": "Unauthorized modification of tenant data and user privilege escalation via unadvertised GraphQL endpoints.",
        "remediation": "Disable GraphQL schema introspection in production environments and enforce object-level authorization on all resolvers.",
    },
    {
        "id": "chain-08-admin-panel-default-creds",
        "name": "Exposed Admin Panel → Default Credentials → Full Panel Compromise",
        "category": "Administrative Takeover",
        "severity": "high",
        "cvss_score": 8.0,
        "base_confidence": 85,
        "triggers": ["admin-panel", "login-panel", "default-login", "grafana", "phpmyadmin"],
        "steps": [
            {"step": 1, "title": "Admin Dashboard Exposed", "type": "weakness", "desc": "Management console exposed to public internet without IP allowlisting."},
            {"step": 2, "title": "Default Credentials Accepted", "type": "pivot", "desc": "System accepts default vendor credentials (admin:admin, admin:password)."},
            {"step": 3, "title": "Administrative Access Granted", "type": "impact", "desc": "Attacker gains administrative dashboard access to manage system configuration."},
        ],
        "impact": "Full control over underlying application configuration, metrics, and internal resources.",
        "remediation": "Enforce mandatory password reset on initial setup, require multi-factor authentication (MFA), and place admin interfaces behind a VPN.",
    },
    {
        "id": "chain-09-cors-misconfig-data-theft",
        "name": "CORS Wildcard / Origin Reflection → Sensitive API Read → User Data Theft",
        "category": "Data Exfiltration",
        "severity": "medium",
        "cvss_score": 6.8,
        "base_confidence": 80,
        "triggers": ["cors", "access-control-allow-origin", "credentials-cors"],
        "steps": [
            {"step": 1, "title": "Overly Permissive CORS Policy", "type": "weakness", "desc": "Server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true."},
            {"step": 2, "title": "Cross-Origin Fetch Executed", "type": "pivot", "desc": "Attacker page induces victim browser to query private authenticated API endpoints."},
            {"step": 3, "title": "Sensitive Data Exfiltration", "type": "impact", "desc": "Private profile information and API keys sent directly to attacker origin."},
        ],
        "impact": "Cross-origin reading of confidential authenticated user data by malicious third-party websites.",
        "remediation": "Do not reflect arbitrary Origin headers. Maintain an explicit whitelist of trusted origins.",
    },
    {
        "id": "chain-10-lfi-traversal-info-leak",
        "name": "Path Traversal / LFI → Sensitive File Read → System Reconnaissance",
        "category": "Information Disclosure",
        "severity": "high",
        "cvss_score": 7.5,
        "base_confidence": 85,
        "triggers": ["lfi", "path-traversal", "directory-traversal", "passwd"],
        "steps": [
            {"step": 1, "title": "Path Traversal Parameter", "type": "weakness", "desc": "File viewer parameter fails to sanitize '../' dot-dot-slash sequence."},
            {"step": 2, "title": "System Configuration Read", "type": "pivot", "desc": "Retrieval of /etc/passwd, /etc/hosts, or application source files."},
            {"step": 3, "title": "Credential / Architecture Recon", "type": "impact", "desc": "Exposes local usernames, system paths, and embedded database connection strings."},
        ],
        "impact": "Deep internal architecture disclosure enabling subsequent exploit chaining.",
        "remediation": "Validate input using a strict whitelist or resolve absolute paths and verify they reside within the intended directory.",
    },
    {
        "id": "chain-11-gitleaks-cloud-key-compromise",
        "name": "GitLeaks Client Secret → AWS / Cloud Key Leak → Cloud Takeover",
        "category": "Cloud Compromise",
        "severity": "critical",
        "cvss_score": 9.4,
        "base_confidence": 95,
        "triggers": ["gitleaks", "aws-key", "stripe-key", "github-token", "slack-webhook"],
        "steps": [
            {"step": 1, "title": "Hardcoded API Key in JavaScript", "type": "weakness", "desc": "High-entropy API key or service token discovered in client-side bundle."},
            {"step": 2, "title": "Token Privileges Validated", "type": "pivot", "desc": "Key used to authenticate against Cloud provider or SaaS APIs."},
            {"step": 3, "title": "Cloud Resource Hijacking", "type": "impact", "desc": "Direct manipulation of S3 buckets, serverless functions, or financial payment gateways."},
        ],
        "impact": "Direct abuse of cloud infrastructure, financial API manipulation, and database access.",
        "remediation": "Revoke and rotate the exposed secret immediately, remove secrets from client code, and use secret scanning in CI/CD.",
    },
    {
        "id": "chain-12-phpinfo-path-leak-exploit",
        "name": "PHPInfo Exposure → Absolute Path & Module Leak → Targeted Exploitation",
        "category": "Information Disclosure",
        "severity": "medium",
        "cvss_score": 5.8,
        "base_confidence": 75,
        "triggers": ["phpinfo", "php-exposure", "server-info"],
        "steps": [
            {"step": 1, "title": "phpinfo() File Left in Production", "type": "weakness", "desc": "Diagnostic script outputs full PHP environment parameters."},
            {"step": 2, "title": "Environment Analysis", "type": "pivot", "desc": "Attacker identifies exact server document root, loaded modules, and internal IPs."},
            {"step": 3, "title": "Precision Exploitation", "type": "impact", "desc": "Unlocks exact target paths required for LFI, session file inclusion, or deserialization."},
        ],
        "impact": "Assists attackers in tailoring exploits specifically to the host operating system and module layout.",
        "remediation": "Remove all test and diagnostic scripts (phpinfo.php, test.php) from production web servers.",
    },
    {
        "id": "chain-13-subdomain-takeover-cookie-theft",
        "name": "Subdomain Takeover → Dangling CNAME Hijack → Cookie Poisoning",
        "category": "Infrastructure Hijack",
        "severity": "high",
        "cvss_score": 8.3,
        "base_confidence": 90,
        "triggers": ["subdomain-takeover", "dangling-cname", "s3-takeover", "github-pages"],
        "steps": [
            {"step": 1, "title": "Dangling DNS Record", "type": "weakness", "desc": "Subdomain points to unclaimed cloud provider service (e.g. AWS S3, GitHub Pages)."},
            {"step": 2, "title": "Subdomain Claimed by Attacker", "type": "pivot", "desc": "Attacker claims the target domain in the cloud service and serves malicious content."},
            {"step": 3, "title": "Cookie Forgery & Credential Phishing", "type": "impact", "desc": "Reads wildcard session cookies (*.domain.com) and conducts trusted phishing attacks."},
        ],
        "impact": "Loss of brand reputation, credential harvesting, and interception of wildcard session cookies.",
        "remediation": "Audit DNS records and immediately delete CNAME records pointing to decommissioned external resources.",
    },
    {
        "id": "chain-14-missing-headers-clickjacking",
        "name": "Missing Security Headers + Sensitive Action → Clickjacking / CSRF",
        "category": "Client-Side Attack",
        "severity": "low",
        "cvss_score": 4.3,
        "base_confidence": 70,
        "triggers": ["missing-security-headers", "x-frame-options", "clickjacking", "csp-missing"],
        "steps": [
            {"step": 1, "title": "Missing X-Frame-Options Header", "type": "weakness", "desc": "Application allows being framed inside an arbitrary IFRAME."},
            {"step": 2, "title": "Invisible Overlay Constructed", "type": "pivot", "desc": "Attacker overlays tempting buttons over the sensitive authenticated UI."},
            {"step": 3, "title": "Inadvertent User Action", "type": "impact", "desc": "Victim unknowingly clicks sensitive actions (e.g. 1-click password change, transfer funds)."},
        ],
        "impact": "Unintentional execution of state-changing transactions by authenticated users.",
        "remediation": "Configure 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none'' across all authenticated pages.",
    },
    {
        "id": "chain-15-idor-api-enumeration",
        "name": "IDOR on User API → Mass Data Scraping → Privacy Breach",
        "category": "Broken Access Control",
        "severity": "high",
        "cvss_score": 7.7,
        "base_confidence": 85,
        "triggers": ["idor", "user-id", "api-users", "unauthorized-access"],
        "steps": [
            {"step": 1, "title": "Predictable ID Parameter", "type": "weakness", "desc": "API endpoints reference customer records using sequential integer IDs (?id=101)."},
            {"step": 2, "title": "Automated ID Iteration", "type": "pivot", "desc": "Sequential requests iterate across all integer ID spaces without ownership verification."},
            {"step": 3, "title": "Mass PII Extraction", "type": "impact", "desc": "Complete dump of user names, emails, phone numbers, and private orders."},
        ],
        "impact": "Large-scale customer data privacy leak and GDPR/regulatory compliance violation.",
        "remediation": "Implement strict session-to-object ownership checks and replace sequential IDs with random UUIDv4 identifiers.",
    },
]


def infer_exploit_chains(findings: list[dict], endpoints: list[dict] = None) -> list[dict]:
    """Infers ordered exploit chains by matching findings and endpoint signals
    against the 15 expert-system rules.
    """
    inferred_chains = []
    findings = findings or []
    endpoints = endpoints or []

    # Build lookup text for findings
    finding_texts = []
    for f in findings:
        text = f"{f.get('template_id', '')} {f.get('name', '')} {f.get('description', '')} {f.get('matched_url', '')}".lower()
        finding_texts.append((f, text))

    endpoint_urls = [ep.get("url", "").lower() for ep in endpoints]

    for pattern in CHAIN_PATTERNS:
        matched_findings = []
        is_triggered = False

        for trigger in pattern["triggers"]:
            for f, text in finding_texts:
                if trigger in text or trigger in f.get("template_id", "").lower():
                    if f.get("id") not in [mf.get("id") for mf in matched_findings]:
                        matched_findings.append(f)
                    is_triggered = True

            # Also check endpoints
            for ep_url in endpoint_urls:
                if trigger in ep_url:
                    is_triggered = True

        if is_triggered:
            # Calculate adjusted confidence
            confidence = pattern["base_confidence"]
            if len(matched_findings) > 1:
                confidence = min(98, confidence + 5)

            inferred_chains.append({
                "name": pattern["name"],
                "category": pattern["category"],
                "severity": pattern["severity"],
                "cvss_score": pattern["cvss_score"],
                "confidence": confidence,
                "steps_json": json.dumps(pattern["steps"]),
                "impact": pattern["impact"],
                "remediation": pattern["remediation"],
                "findings_ids_json": json.dumps([f.get("id") for f in matched_findings if f.get("id")]),
            })

    return inferred_chains


def calculate_target_risk(findings: list[dict], chains: list[dict]) -> dict:
    """Calculates overall target risk (0-100), Priority (P1-P4), and actionability split."""
    if not findings and not chains:
        return {
            "overall_risk_score": 0.0,
            "priority": "P4",
            "actionable_count": 0,
            "informational_count": 0,
            "chains_count": 0,
        }

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    actionable_count = 0
    informational_count = 0

    for f in findings:
        sev = (f.get("severity") or "info").lower()
        validity = f.get("validity", "actionable")
        if validity == "informational" or sev == "info":
            informational_count += 1
            info_count += 1
        else:
            actionable_count += 1
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                medium_count += 1
            elif sev == "low":
                low_count += 1

    # Base score from findings
    score = (critical_count * 25.0) + (high_count * 15.0) + (medium_count * 6.0) + (low_count * 2.0)
    
    # Chain impact boost (confidence-weighted)
    for c in chains:
        sev = c.get("severity", "medium").lower()
        conf = c.get("confidence", 80) / 100.0
        if sev == "critical":
            score += 20.0 * conf
        elif sev == "high":
            score += 12.0 * conf
        elif sev == "medium":
            score += 5.0 * conf

    # Normalize to 0-100
    overall_score = min(100.0, max(0.0, round(score, 1)))

    # Priority mapping
    if overall_score >= 75.0 or critical_count > 0:
        priority = "P1"
    elif overall_score >= 45.0 or high_count > 0:
        priority = "P2"
    elif overall_score >= 20.0 or medium_count > 0:
        priority = "P3"
    else:
        priority = "P4"

    return {
        "overall_risk_score": overall_score,
        "priority": priority,
        "actionable_count": actionable_count,
        "informational_count": informational_count,
        "chains_count": len(chains),
    }


def generate_safe_payload_suggestion(finding_name: str, template_id: str, url: str) -> str:
    """Generates non-destructive, safe validation test cases per finding (PDF §6.6)."""
    t_id = (template_id or "").lower()
    name = (finding_name or "").lower()

    if "env" in t_id or "env" in name:
        return f"curl -s -I '{url}' | head -n 1\n# Non-destructive: verify HTTP 200 and Content-Type text/plain without downloading credentials."
    if "redirect" in t_id or "redirect" in name:
        return f"curl -s -I '{url}?url=https://example.com' | grep -i 'Location:'\n# Verify redirect header points to benign external domain example.com."
    if "heapdump" in t_id or "actuator" in t_id:
        return f"curl -s -I '{url}' | head -n 5\n# Verify endpoint returns application/octet-stream without pulling full multi-megabyte heap memory."
    if "graphql" in t_id or "introspection" in name:
        return f"curl -s -X POST '{url}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__typename}}\"}}'\n# Safe schema probe checking GraphQL endpoint response."
    if "phpinfo" in t_id:
        return f"curl -s '{url}' | grep -o -i '<title>phpinfo().*</title>'\n# Safe check for PHP configuration title tag."
    if "cors" in t_id:
        return f"curl -s -I -H 'Origin: https://evil-test.com' '{url}' | grep -i 'Access-Control-Allow-Origin'\n# Safe CORS reflection test."
    
    return f"curl -s -I '{url}'\n# Inspect HTTP response headers and status code for safe validation."
