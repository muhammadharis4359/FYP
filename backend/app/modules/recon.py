"""
Phase 3 -- Automated Reconnaissance Module (Hybrid Dual-Engine).

Orchestrates:
1. Subdomain Enumeration:
   - CLI: Subfinder & Amass (if installed)
   - Native: Live Certificate Transparency logs (crt.sh & AlienVault)
   - Native: Live high-speed socket DNS resolution & dictionary enumeration
2. Live Host Detection & Tech Fingerprinting:
   - CLI: ProjectDiscovery httpx (if installed)
   - Native: Concurrent HTTP/HTTPS prober (ports 80/443), status code, title, and tech stack signatures
3. Endpoint Discovery:
   - CLI: gau (if installed)
   - Native: Wayback Machine CDX API + live HTML/JS endpoint extractor
"""

import concurrent.futures
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request
from typing import Optional

from app.config import settings

logger = logging.getLogger("recon")

# Common high-priority subdomains for fast DNS brute-forcing
COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "stage", "admin", "app", "auth",
    "portal", "test", "dashboard", "cdn", "assets", "static", "login",
    "internal", "corp", "sso", "vpn", "gateway", "server", "remote", "blog",
    "docs", "support", "beta", "demo", "secure", "m", "shop", "status",
    "graphql", "swagger", "k8s", "grafana", "prometheus", "jenkins", "gitlab"
]

BIN_DIR = Path(__file__).resolve().parent.parent.parent / "bin"


def _tool_path(name: str) -> Optional[str]:
    """Finds a tool on system PATH or in backend/bin."""
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


def _run(cmd: list[str], timeout: int) -> str:
    """Run a CLI command and return its stdout, or raise on failure/timeout."""
    tool_bin = _tool_path(cmd[0])
    if tool_bin:
        cmd[0] = tool_bin

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(
            f"Command failed ({' '.join(cmd)}): {result.stderr.strip()[:500]}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# 1. Subdomain Enumeration (CLI + Native Passive CT + Native DNS)
# ---------------------------------------------------------------------------

def run_subfinder(domain: str) -> list[str]:
    """Fast, passive-only subdomain enumeration via Subfinder CLI."""
    if not _tool_path("subfinder"):
        return []
    try:
        out = _run(["subfinder", "-d", domain, "-silent"], settings.SUBFINDER_TIMEOUT)
        return [line.strip().lower() for line in out.splitlines() if line.strip()]
    except Exception as e:
        logger.warning("subfinder CLI failed for %s: %s", domain, e)
        return []


def run_amass(domain: str) -> list[str]:
    """Deeper passive enumeration via Amass CLI."""
    if not _tool_path("amass"):
        return []
    try:
        out = _run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", str(max(1, settings.AMASS_TIMEOUT // 60))],
            settings.AMASS_TIMEOUT,
        )
        return [line.strip().lower() for line in out.splitlines() if line.strip()]
    except Exception as e:
        logger.warning("amass CLI failed for %s: %s", domain, e)
        return []


def run_passive_crtsh(domain: str) -> list[str]:
    """Native live Certificate Transparency log query via crt.sh and AlienVault."""
    subdomains = set()
    clean_domain = domain.strip().lower()

    # 1. crt.sh Certificate Transparency
    try:
        url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
                for item in data:
                    name_value = item.get("name_value", "")
                    for entry in name_value.split("\n"):
                        entry = entry.strip().lower()
                        if entry.startswith("*."):
                            entry = entry[2:]
                        if entry and (entry == clean_domain or entry.endswith(f".{clean_domain}")) and "@" not in entry:
                            subdomains.add(entry)
    except Exception as e:
        logger.info("crt.sh CT query completed: %s", e)

    # 2. AlienVault OTX Passive DNS Fallback
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_domain}/passive_dns"
        req = urllib.request.Request(
            otx_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
                for entry in data.get("passive_dns", []):
                    host = entry.get("hostname", "").strip().lower()
                    if host and (host == clean_domain or host.endswith(f".{clean_domain}")):
                        subdomains.add(host)
    except Exception:
        pass

    return list(subdomains)


def run_dns_bruteforce(domain: str) -> list[str]:
    """Native concurrent socket DNS resolution for high-frequency subdomains."""
    found = set()
    clean_domain = domain.strip().lower()

    def resolve_sub(prefix: str):
        candidate = f"{prefix}.{clean_domain}"
        try:
            # Quick DNS socket resolution
            socket.gethostbyname(candidate)
            return candidate
        except (socket.gaierror, socket.herror, TimeoutError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found.add(res)

    return list(found)


def merge_subdomains(domain: str) -> list[tuple[str, str]]:
    """Runs all subdomain sources (Subfinder, Amass, CRT.sh, DNS Brute) and returns
    de-duplicated (subdomain, source_tool) pairs."""
    clean_domain = domain.strip().lower()
    seen: dict[str, str] = {}

    # 1. CLI Tools (if installed)
    for sub in run_subfinder(clean_domain):
        if sub != clean_domain:
            seen.setdefault(sub, "subfinder")

    for sub in run_amass(clean_domain):
        if sub != clean_domain:
            seen.setdefault(sub, "amass")

    # 2. Native Passive Certificate Transparency Engine
    for sub in run_passive_crtsh(clean_domain):
        if sub != clean_domain:
            seen.setdefault(sub, "crt.sh")

    # 3. Native Active DNS Resolution
    for sub in run_dns_bruteforce(clean_domain):
        if sub != clean_domain:
            seen.setdefault(sub, "dns_resolver")

    return list(seen.items())


# ---------------------------------------------------------------------------
# 2. Live Host Detection & Tech Fingerprinting (CLI + Native HTTP Prober)
# ---------------------------------------------------------------------------

def _extract_page_title(html: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()
        return title[:120] if title else None
    return None


def _detect_tech_stack(headers: dict, html: str) -> Optional[str]:
    tech = []
    server = headers.get("Server") or headers.get("server")
    if server:
        tech.append(server.strip())

    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
    if powered_by:
        tech.append(powered_by.strip())

    if "cf-ray" in headers or "cloudflare" in str(server).lower():
        tech.append("Cloudflare")
    if "x-varnish" in headers:
        tech.append("Varnish Cache")
    if "x-amz-cf-id" in headers:
        tech.append("AWS CloudFront")

    html_lower = html.lower()
    if "wp-content" in html_lower or "wordpress" in html_lower:
        tech.append("WordPress")
    if "react" in html_lower or "reactdom" in html_lower or "__next" in html_lower:
        tech.append("React/Next.js")
    if "vue" in html_lower or "__vue__" in html_lower:
        tech.append("Vue.js")
    if "bootstrap" in html_lower:
        tech.append("Bootstrap")

    # Deduplicate while preserving order
    unique_tech = list(dict.fromkeys(tech))
    return ", ".join(unique_tech) if unique_tech else None


def _probe_single_host(host_or_url: str) -> Optional[dict]:
    """Probes a single host on HTTPS (and HTTP fallback) with status, title, tech stack."""
    clean_host = host_or_url.replace("https://", "").replace("http://", "").strip().rstrip("/")
    if not clean_host:
        return None

    # Check HTTPS first, then HTTP
    protocols = ["https", "http"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for proto in protocols:
        url = f"{proto}://{clean_host}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                status_code = resp.status
                headers_dict = dict(resp.headers)
                body = resp.read(65536).decode("utf-8", errors="ignore")
                title = _extract_page_title(body)
                tech = _detect_tech_stack(headers_dict, body)
                return {
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "tech_stack": tech,
                }
        except urllib.error.HTTPError as e:
            headers_dict = dict(e.headers)
            body = e.read(16384).decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
            title = _extract_page_title(body)
            tech = _detect_tech_stack(headers_dict, body)
            return {
                "url": url,
                "status_code": e.code,
                "title": title or f"HTTP {e.code}",
                "tech_stack": tech,
            }
        except Exception:
            continue
    return None


def run_httpx(subdomains: list[str]) -> list[dict]:
    """Probes subdomains to confirm which are live, status codes, page titles, and tech stack."""
    if not subdomains:
        return []

    # If httpx CLI is available, run it
    if _tool_path("httpx"):
        input_text = "\n".join(subdomains)
        try:
            result = subprocess.run(
                ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect", "-timeout", "5"],
                input=input_text,
                capture_output=True,
                text=True,
                timeout=settings.HTTPX_TIMEOUT,
            )
            live_hosts = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    live_hosts.append({
                        "url": record.get("url", ""),
                        "status_code": record.get("status_code"),
                        "title": record.get("title"),
                        "tech_stack": ", ".join(record.get("tech", [])) if record.get("tech") else None,
                    })
                except json.JSONDecodeError:
                    continue
            if live_hosts:
                return live_hosts
        except Exception as e:
            logger.info("httpx CLI error, falling back to native prober: %s", e)

    # Native concurrent HTTP/HTTPS prober
    live_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_probe_single_host, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                live_hosts.append(res)

    return live_hosts


# ---------------------------------------------------------------------------
# 3. Endpoint Discovery (CLI + Native Wayback Machine & HTML Scraper)
# ---------------------------------------------------------------------------

def run_archive_endpoints(domain: str) -> list[str]:
    """Native endpoint extraction via Wayback Machine CDX API."""
    clean_domain = domain.strip().lower()
    endpoints = set()

    # 1. Wayback Machine CDX API query
    try:
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
        req = urllib.request.Request(
            cdx_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=12, context=ctx) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
                # first item is header row
                for item in data[1:]:
                    if item and isinstance(item, list) and item[0]:
                        url = item[0].strip()
                        if url.startswith("http://") or url.startswith("https://"):
                            endpoints.add(url)
    except Exception as e:
        logger.info("Wayback CDX endpoint query completed: %s", e)

    # 2. Live root page links scraper
    try:
        for proto in ["https", "http"]:
            root_url = f"{proto}://{clean_domain}"
            req = urllib.request.Request(
                root_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconMapper/1.0"}
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    html = resp.read(65536).decode("utf-8", errors="ignore")
                    # Extract href and src paths
                    links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.IGNORECASE)
                    for link in links:
                        link = link.strip()
                        if link.startswith("/") and not link.startswith("//"):
                            endpoints.add(f"{proto}://{clean_domain}{link}")
                        elif link.startswith("http://") or link.startswith("https://"):
                            if clean_domain in link:
                                endpoints.add(link)
                break
            except Exception:
                continue
    except Exception:
        pass

    return list(endpoints)


def run_gau(domain: str) -> list[str]:
    """Pull historical URLs for the domain from gau's archive sources or native CDX engine."""
    clean_domain = domain.strip().lower()

    if _tool_path("gau"):
        try:
            out = _run(["gau", "--subs", clean_domain], settings.GAU_TIMEOUT)
            urls = [line.strip() for line in out.splitlines() if line.strip()]
            if urls:
                return list(dict.fromkeys(urls))
        except Exception as e:
            logger.info("gau CLI error, falling back to native engine: %s", e)

    return run_archive_endpoints(clean_domain)

