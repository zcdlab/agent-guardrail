from enum import StrEnum
from typing import Literal
from pydantic import BaseModel


class PermissionTier(StrEnum):
    READ_ONLY = "read_only"
    SANDBOX_WRITE = "sandbox_write"
    PROD_MUTATE = "prod_mutate"


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
