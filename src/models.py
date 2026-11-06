from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, Field


class PermissionTier(StrEnum):
    READ_ONLY = "read_only"
    SANDBOX_WRITE = "sandbox_write"
    PROD_MUTATE = "prod_mutate"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GuardrailInput(BaseModel):
    action: str = "check"
    tier: PermissionTier = PermissionTier.SANDBOX_WRITE
    target_path: str = "unspecified"
    payload: str
    human_override_token: str | None = None


class GuardrailVerdict(BaseModel):
    allowed: bool
    reason: str
    latency_path: Literal["HOT_PATH_CPU", "COLD_PATH_ASYNC"] = "HOT_PATH_CPU"
    audit_id: str


class Violation(BaseModel):
    file: str
    line: int
    severity: Severity = Severity.HIGH
    category: str
    rule: str
    snippet: str
    remediation: str


class ScanReport(BaseModel):
    scanned_path: str
    total_files_scanned: int = 0
    violations: list[Violation] = Field(default_factory=list)
    protected_paths_found: list[str] = Field(default_factory=list)
    guardrails_active: bool = True
    clean: bool = True
    scan_duration_ms: float = 0.0
    summary: dict[str, int] = Field(default_factory=dict)

