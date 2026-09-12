from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text, Float
)
from sqlalchemy.orm import relationship

from app.database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)

    # queued -> recon_running -> recon_complete -> scan_running -> analyzing -> completed | failed
    status = Column(String, default="queued")
    current_stage = Column(String, default="queued")
    error_message = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # AI & Risk Scoring metrics
    overall_risk_score = Column(Float, default=0.0)  # 0 to 100
    priority = Column(String, default="P4")  # P1, P2, P3, P4
    actionable_count = Column(Integer, default=0)
    informational_count = Column(Integer, default=0)
    chains_count = Column(Integer, default=0)

    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    live_hosts = relationship("LiveHost", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    exploit_chains = relationship("ExploitChain", back_populates="scan", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    subdomain = Column(String, nullable=False, index=True)
    source_tool = Column(String, nullable=False)  # "amass" | "subfinder" | "assetfinder"

    scan = relationship("Scan", back_populates="subdomains")


class LiveHost(Base):
    __tablename__ = "live_hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(String, nullable=False, index=True)
    status_code = Column(Integer, nullable=True)
    title = Column(String, nullable=True)
    tech_stack = Column(String, nullable=True)  # comma-separated, from httpx -tech-detect

    scan = relationship("Scan", back_populates="live_hosts")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(String, nullable=False)
    source = Column(String, nullable=False)  # "gau" | "waybackurls"
    category = Column(String, default="api")  # "auth" | "api" | "admin" | "upload" | "sensitive"

    scan = relationship("Scan", back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    matched_url = Column(String, nullable=False)
    template_id = Column(String, nullable=False)
    name = Column(String, nullable=True)
    severity = Column(String, nullable=True)  # info | low | medium | high | critical
    chain_aware_severity = Column(String, nullable=True)  # uplifted severity based on chain context
    cvss_score = Column(Float, nullable=True)
    source = Column(String, default="nuclei")  # "nuclei" | "content_discovery" | "gitleaks" | "secrets_regex"
    validity = Column(String, default="actionable")  # "actionable" | "informational"
    exploitability = Column(String, default="medium")  # "low" | "medium" | "high"
    risk_score = Column(Float, default=5.0)  # 0 - 10 risk rating
    priority = Column(String, default="P3")  # P1 | P2 | P3 | P4
    safe_payload_test = Column(Text, nullable=True)  # safe, class-aware non-destructive test case
    duplicate_count = Column(Integer, default=1)
    description = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class ExploitChain(Base):
    __tablename__ = "exploit_chains"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String, nullable=False)  # e.g. "Open Redirect -> OAuth Token Theft -> Account Takeover"
    category = Column(String, nullable=False)  # "Account Takeover" | "RCE" | "Data Exfiltration" | "Privilege Escalation"
    severity = Column(String, nullable=False)  # "critical" | "high" | "medium"
    cvss_score = Column(Float, default=8.5)
    confidence = Column(Integer, default=85)  # 0 to 100 percentage
    steps_json = Column(Text, nullable=False)  # JSON array of ordered step strings / node objects
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    findings_ids_json = Column(Text, nullable=True)  # JSON array of related finding IDs

    scan = relationship("Scan", back_populates="exploit_chains")

