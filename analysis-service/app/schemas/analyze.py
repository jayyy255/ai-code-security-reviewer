from pydantic import BaseModel, Field, field_validator
from uuid import UUID
from typing import Any

class Finding(BaseModel):
    scanner: str
    rule_id: str
    file_path: str = "snippet"
    line: int | None = None
    column: int | None = None
    severity: str = "LOW"
    category: str = "security"
    message: str = ""
    source: str = "semgrep"
    confidence: str | None = "HIGH"

    owasp: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    vulnerability_class: list[str] = Field(default_factory=list)

    likelihood: str | None = None
    impact: str | None = None
    explanation: str | None = None
    risk: str | None = None
    remediation: list[str] = Field(default_factory=list)
    fixed_code: str | None = None
    requires_verification: bool = False

class AnalyzeSummary(BaseModel):
    security_score: float
    critical: int
    high: int
    medium: int
    low: int
    total_findings: int = 0

class ScannerStatusInfo(BaseModel):
    scanner_name: str
    available: bool
    version: str | None = None
    rules_loaded: int = 0
    capabilities: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status_message: str = "Operational"

class MalwareStatusInfo(BaseModel):
    status: str # "clean", "suspicious", "infected", "unavailable", "failed"
    engine: str = "ClamAV"
    engine_available: bool = False
    details: str = ""
    threat_name: str | None = None
    files_scanned: int = 0
    infected_files: list[str] = Field(default_factory=list)

class PrivacyMetadataInfo(BaseModel):
    raw_code_stored: bool = False
    ephemeral_scan: bool = False
    ai_context_isolated: bool = True
    snippets_only_to_ai: bool = True
    storage_type: str = "none"

class AnalyzeRequest(BaseModel):
    code: str
    language: str | None = Field(default=None, description="Programming language or extension")
    file_name: str | None = Field(default="snippet", description="Optional file name")
    ephemeral: bool = Field(default=False, description="Whether to run scan in-memory without persistence")

    @field_validator("code")
    def validate_code(cls, value):
        if not value.strip():
            raise ValueError("Code cannot be empty or whitespace.")
        return value

class BatchScanRequest(BaseModel):
    files: list[dict] # [{"filename": "...", "content": "...", "language": "..."}]
    ephemeral: bool = False

class CommitScanRequest(BaseModel):
    repository_url: str
    commit_sha: str | None = None
    branch: str | None = None
    strategy: str = "auto" # "auto", "full", "incremental"
    baseline_findings: list[dict] = Field(default_factory=list)
    ephemeral: bool = False

class AnalyzeResponse(BaseModel):
    analysis_id: UUID
    scan_type: str = "paste" # "paste", "upload", "commit"
    language: str | None = None
    summary: AnalyzeSummary
    findings: list[Finding]
    files_analyzed: list[str] = Field(default_factory=list)
    files_skipped: list[str] = Field(default_factory=list)
    scanner_status: list[ScannerStatusInfo] = Field(default_factory=list)
    malware_status: MalwareStatusInfo | None = None
    privacy_metadata: PrivacyMetadataInfo = Field(default_factory=PrivacyMetadataInfo)
    
    # Commit scan specific fields
    repository_url: str | None = None
    commit_sha: str | None = None
    parent_sha: str | None = None
    changed_files: dict[str, list[str]] = Field(default_factory=dict)
    new_findings: list[Finding] = Field(default_factory=list)
    fixed_findings: list[Finding] = Field(default_factory=list)
    persistent_findings: list[Finding] = Field(default_factory=list)