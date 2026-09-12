"""
Phase 4 -- Vulnerability Scanning Engine.

Wraps Nuclei to run its template library against the live hosts that
Phase 3's recon module already confirmed are reachable. Kept deliberately
simple for this stage: no AI filtering yet (that's Phase 5), this module's
only job is to run the scan and hand back clean, parsed findings.
"""

import os
import json
import shutil
import subprocess
import tempfile
import logging

from app.config import settings

from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent.parent.parent / "bin"


def _tool_path(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    local_bin = BIN_DIR / f"{name}.exe"
    if local_bin.exists():
        return str(local_bin)
    local_bin_no_ext = BIN_DIR / name
    if local_bin_no_ext.exists():
        return str(local_bin_no_ext)
    return None


def run_nuclei(urls: list[str], severity: str | None = None) -> list[dict]:
    """Run Nuclei against a list of live host URLs and return parsed findings.

    Args:
        urls: live host URLs from httpx (Phase 3 output).
        severity: optional Nuclei -severity filter, e.g. "medium,high,critical"
                  to skip informational noise during early testing.
    """
    if not urls:
        return []
    if not _tool_path("nuclei"):
        logger.warning("nuclei not installed -- skipping vulnerability scan")
        return []

    # Nuclei reads targets from a file more reliably than stdin for large lists.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        target_file = f.name

    cmd = ["nuclei", "-l", target_file, "-silent", "-jsonl"]
    if severity:
        cmd += ["-severity", severity]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.NUCLEI_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        logger.warning("nuclei timed out after %ss: %s", settings.NUCLEI_TIMEOUT, e)
        return []
    finally:
        try:
            os.remove(target_file)
        except OSError:
            pass

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append(_parse_nuclei_record(record))
    return findings


def _parse_nuclei_record(record: dict) -> dict:
    """Flatten a raw Nuclei JSON line into the fields our Finding model needs."""
    info = record.get("info", {}) or {}
    return {
        "matched_url": record.get("matched-at") or record.get("host", ""),
        "template_id": record.get("template-id", "unknown"),
        "name": info.get("name"),
        "severity": info.get("severity"),
        "description": info.get("description"),
        "raw_output": json.dumps(record),
    }
