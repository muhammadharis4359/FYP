#!/usr/bin/env python3
"""
AI Exploit Chain Mapper — Claude Code PostToolUse Telemetry Hook
Runs deterministically after every Bash tool call in Claude Code.
Silently intercepts tool-native outputs (Subfinder, httpx, Nuclei, gau)
and Agent-structured Exploit Chain JSON, forwarding them to the FastAPI
Backend to update Dashboard tabs in real time.
"""

import sys
import json
import re
import urllib.request
import urllib.error
from typing import Optional

API_BASE_URL = "http://127.0.0.1:8000"
LOG_FILE = "/tmp/sync_hook.log"
CURRENT_SCAN_FILE = "/tmp/current_scan.json"

TARGET_TOOLS = [
    "subfinder",
    "amass",
    "assetfinder",
    "httpx",
    "nuclei",
    "gau",
    "waybackurls",
    "gitleaks",
    "katana",
]

def log_debug(msg: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[*] {msg}\n")
    except Exception:
        pass


def extract_domain(command: str) -> Optional[str]:
    """Extracts target domain from CLI arguments or URLs."""
    # Match -d domain.com or -target domain.com
    m = re.search(r'(?:-d|-domain|-target)\s+([a-zA-Z0-9\.\-]+)', command, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    
    # Match URL https://api.domain.com
    m = re.search(r'https?://([a-zA-Z0-9\.\-]+)', command, re.IGNORECASE)
    if m:
        host = m.group(1).strip()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
        
    return None


def get_active_scan_id(domain: Optional[str] = None) -> Optional[int]:
    """Retrieves active scan ID from session state file or backend API."""
    # 1. Check local session file
    try:
        with open(CURRENT_SCAN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "scan_id" in data:
                return int(data["scan_id"])
    except Exception:
        pass

    # 2. Query Backend API
    try:
        url = f"{API_BASE_URL}/api/scans/active"
        if domain:
            url += f"?domain={domain}&auto_create=true"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                res_data = json.loads(resp.read().decode("utf-8"))
                return res_data.get("id")
    except Exception as e:
        log_debug(f"Failed to lookup active scan from {API_BASE_URL}: {e}")

    return None


def main():
    try:
        # Read hook payload from STDIN
        raw_stdin = sys.stdin.read().strip()
        if not raw_stdin:
            sys.exit(0)

        try:
            event = json.loads(raw_stdin)
        except Exception:
            sys.exit(0)

        # Inspect tool and command
        tool_name = event.get("tool_name") or event.get("tool") or ""
        tool_input = event.get("tool_input") or event.get("input") or {}
        command = tool_input.get("command") or ""

        # Extract tool output (Claude Code uses tool_response or tool_output)
        output = event.get("tool_response") or event.get("tool_output") or event.get("output") or ""
        if isinstance(output, dict):
            output = json.dumps(output)
        elif not isinstance(output, str):
            output = str(output)

        output = output.strip()
        if not output:
            sys.exit(0)

        cmd_lower = command.lower()

        # Check if output is an Agent-Structured Exploit Chain payload (Approach C)
        is_chain_payload = (
            "exploit_chains_payload" in output
            or ("chains" in output and "cvss_score" in output and "remediation" in output)
        )

        # Check if command is one of our target security tools (Approach B)
        is_recon_tool = any(t in cmd_lower for t in TARGET_TOOLS)

        if not is_recon_tool and not is_chain_payload:
            # Not a relevant security tool or reasoning payload
            sys.exit(0)

        domain = extract_domain(command)
        scan_id = get_active_scan_id(domain)
        if not scan_id:
            log_debug(f"No active scan found for command: {command[:50]}")
            sys.exit(0)

        # Build Telemetry Ingest Request
        payload = {
            "command": command,
            "raw_output": output,
            "domain": domain
        }

        # If it's pure exploit chains JSON, parse directly
        if is_chain_payload:
            try:
                parsed_json = json.loads(output)
                if isinstance(parsed_json, dict) and "chains" in parsed_json:
                    payload["chains"] = parsed_json["chains"]
                    payload["overall_risk_score"] = parsed_json.get("overall_risk_score")
                    payload["priority"] = parsed_json.get("priority")
            except Exception:
                pass

        # POST to FastAPI Backend Ingestion API
        ingest_url = f"{API_BASE_URL}/api/scans/{scan_id}/ingest/telemetry"
        json_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            ingest_url,
            data=json_data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=2.5) as resp:
            log_debug(f"Ingested telemetry to Scan #{scan_id} (HTTP {resp.status})")

    except Exception as e:
        log_debug(f"Hook exception: {e}")
    finally:
        # Non-blocking: Claude Code must NEVER be stalled or halted by the hook
        sys.exit(0)


if __name__ == "__main__":
    main()
