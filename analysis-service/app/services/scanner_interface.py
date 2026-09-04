from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field

class FindingModel(BaseModel):
    scanner: str
    rule_id: str
    file_path: str = "snippet"
    line: int | None = None
    column: int | None = None
    severity: str = "LOW"
    category: str = "security"
    message: str = ""
    source: str = "static_scanner"
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

class ScannerStatusModel(BaseModel):
    scanner_name: str
    available: bool
    version: str | None = None
    rules_loaded: int = 0
    capabilities: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status_message: str = "Operational"

class BaseScanner(ABC):
    @abstractmethod
    def scan_code(self, code: str, language: str | None = None, file_name: str = "snippet") -> list[dict]:
        """Scan raw code snippet in memory."""
        pass

    @abstractmethod
    def scan_path(self, target_path: str) -> list[dict]:
        """Scan a file or directory path."""
        pass

    @abstractmethod
    def get_status(self) -> ScannerStatusModel:
        """Get scanner availability, loaded rules, capabilities, and limitations."""
        pass
