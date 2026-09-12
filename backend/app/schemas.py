from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class TargetCreate(BaseModel):
    domain: str


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    domain: str
    created_at: datetime


class ScanCreate(BaseModel):
    target_id: int


class ExploitChainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    name: str
    category: str
    severity: str
    cvss_score: float
    confidence: int
    steps_json: str
    impact: str
    remediation: str
    findings_ids_json: Optional[str] = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: Optional[int] = None
    matched_url: str
    template_id: str
    name: Optional[str] = None
    severity: Optional[str] = None
    chain_aware_severity: Optional[str] = None
    cvss_score: Optional[float] = None
    source: Optional[str] = "nuclei"
    validity: Optional[str] = "actionable"
    exploitability: Optional[str] = "medium"
    risk_score: Optional[float] = 5.0
    priority: Optional[str] = "P3"
    safe_payload_test: Optional[str] = None
    duplicate_count: Optional[int] = 1
    description: Optional[str] = None


class SubdomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    subdomain: str
    source_tool: str


class LiveHostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech_stack: Optional[str] = None


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    url: str
    source: str
    category: Optional[str] = "api"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    status: str
    current_stage: str
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_risk_score: Optional[float] = 0.0
    priority: Optional[str] = "P4"
    actionable_count: Optional[int] = 0
    informational_count: Optional[int] = 0
    chains_count: Optional[int] = 0


class ScanListItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    target_domain: Optional[str] = None
    status: str
    current_stage: str
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_risk_score: Optional[float] = 0.0
    priority: Optional[str] = "P4"
    subdomains_count: int = 0
    live_hosts_count: int = 0
    endpoints_count: int = 0
    findings_count: int = 0
    chains_count: int = 0


class StatsSummaryOut(BaseModel):
    total_targets: int = 0
    total_scans: int = 0
    active_scans: int = 0
    completed_scans: int = 0
    total_subdomains: int = 0
    total_live_hosts: int = 0
    total_endpoints: int = 0
    total_findings: int = 0
    total_chains: int = 0
    findings_by_severity: dict[str, int] = {}
    findings_by_source: dict[str, int] = {}
    actionable_findings: int = 0
    informational_findings: int = 0


class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[int] = None


class ChatResponse(BaseModel):
    response: str
    sources_cited: list[str] = []


