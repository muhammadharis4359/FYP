"""
Cyber Terminal & Live File Telemetry Logger.
Streams rich, real-time tool execution, reconnaissance discovery, and vulnerability
signals to both the backend console and a dedicated live log file (backend/logs/scanner_live.log).
"""

import sys
import os
import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "scanner_live.log"

# ANSI Color codes for Windows/Linux terminals
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[38;5;46m"
CYAN = "\033[38;5;51m"
YELLOW = "\033[38;5;226m"
RED = "\033[38;5;196m"
MAGENTA = "\033[38;5;201m"
WHITE = "\033[38;5;255m"


def _write_log(colored_msg: str, raw_msg: str):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    formatted_console = f"{DIM}[{timestamp}]{RESET} {colored_msg}"
    formatted_raw = f"[{timestamp}] {raw_msg}"

    # 1. Print to console stdout
    try:
        sys.stdout.write(formatted_console + "\n")
        sys.stdout.flush()
    except Exception:
        pass

    # 2. Append to live log file
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_raw + "\n")
    except Exception:
        pass


def log_scan_start(scan_id: int, domain: str):
    banner_raw = "=" * 70
    _write_log(
        f"\n{CYAN}{BOLD}{'=' * 70}\n[*] [SCAN #{scan_id}] LAUNCHED REAL PIPELINE -> TARGET: {domain}\n{'=' * 70}{RESET}",
        f"\n{banner_raw}\n[*] [SCAN #{scan_id}] LAUNCHED REAL PIPELINE -> TARGET: {domain}\n{banner_raw}"
    )


def log_stage(stage_num: int, stage_name: str):
    _write_log(
        f"{YELLOW}{BOLD}[*] [STAGE {stage_num}] {stage_name.upper()}{RESET}",
        f"[*] [STAGE {stage_num}] {stage_name.upper()}"
    )


def log_tool_activity(tool_name: str, message: str):
    _write_log(
        f"    {GREEN}[+] [{tool_name}]{RESET} {message}",
        f"    [+] [{tool_name}] {message}"
    )


def log_host_found(url: str, status: int, title: str, tech: str):
    title_str = f' - "{title}"' if title else ""
    tech_str = f" ({tech})" if tech else ""
    _write_log(
        f"        {GREEN}--> Host Verified:{RESET} {BOLD}{url}{RESET} [{CYAN}{status}{RESET}]{tech_str}{title_str}",
        f"        --> Host Verified: {url} [{status}]{tech_str}{title_str}"
    )


def log_finding_found(sev: str, name: str, matched_url: str, source: str):
    sev_upper = (sev or "INFO").upper()
    color = RED if sev_upper == "CRITICAL" else (YELLOW if sev_upper == "HIGH" else CYAN)
    _write_log(
        f"        {color}{BOLD}[!] {sev_upper}:{RESET} {WHITE}{name}{RESET} ({source})\n            {DIM}--> Matched: {matched_url}{RESET}",
        f"        [!] {sev_upper}: {name} ({source})\n            --> Matched: {matched_url}"
    )


def log_chain_inferred(name: str, sev: str, cvss: float, conf: int):
    sev_upper = (sev or "HIGH").upper()
    color = RED if sev_upper in ["CRITICAL", "HIGH"] else YELLOW
    _write_log(
        f"    {color}{BOLD}==> INFERRED ATTACK CHAIN:{RESET} {WHITE}{name}{RESET} [CVSS: {cvss} | Confidence: {conf}%]",
        f"    ==> INFERRED ATTACK CHAIN: {name} [CVSS: {cvss} | Confidence: {conf}%]"
    )


def log_scan_complete(scan_id: int, domain: str, risk: float, priority: str, findings_cnt: int, chains_cnt: int):
    banner_raw = "=" * 70
    _write_log(
        f"{GREEN}{BOLD}{'=' * 70}\n[+] [SCAN #{scan_id}] COMPLETED for {domain}\n    Risk Score: {risk}/100 [{priority} Priority] | Findings: {findings_cnt} | Exploit Chains: {chains_cnt}\n{'=' * 70}{RESET}\n",
        f"{banner_raw}\n[+] [SCAN #{scan_id}] COMPLETED for {domain}\n    Risk Score: {risk}/100 [{priority} Priority] | Findings: {findings_cnt} | Exploit Chains: {chains_cnt}\n{banner_raw}\n"
    )


def log_scan_error(scan_id: int, error_msg: str):
    _write_log(
        f"{RED}{BOLD}[-] [SCAN #{scan_id}] PIPELINE ERROR: {error_msg}{RESET}",
        f"[-] [SCAN #{scan_id}] PIPELINE ERROR: {error_msg}"
    )
