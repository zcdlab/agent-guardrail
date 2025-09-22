import ast
import hashlib
from pathlib import Path
import re
from src.models import GuardrailInput, GuardrailVerdict, PermissionTier

INJECTION_SIGS = (
    "SYSTEM_PROMPT_OVERRIDE",
    "IGNORE_ALL_INSTRUCTIONS",
    "IGNORE_PREVIOUS_INSTRUCTIONS",
    "<|im_start|>",
    "<|im_end|>",
    "[INST]",
    "<<SYS>>",
    "DAN_MODE",
    "<!-- SYSTEM:",
)

CYBERSEC_SIGS = (
    "sk_live_",
    "AKIA",
    "ghp_",
    "-----BEGIN OPENSSH",
    "-----BEGIN RSA",
    "os.system(",
    "subprocess.Popen(",
    "subprocess.call(",
    "rm -rf /",
    "eval(",
    "exec(",
    "pickle.loads(",
    "/etc/passwd",
    "/etc/shadow",
    "169.254.169.254",
)

AI_SAFETY_SIGS = ("git push --force", "DROP TABLE", "DROP DATABASE")
ALL_FORBIDDEN = INJECTION_SIGS + CYBERSEC_SIGS + AI_SAFETY_SIGS
PROTECTED_PATHS = ("infra/prod/", "security/", ".agent-policy.yaml", ".github/workflows/", ".env")


def inspect_hot_path(req: GuardrailInput) -> GuardrailVerdict:
    audit_id = f"audit-{hashlib.sha256(f'{req.action}:{req.target_path}:{req.payload}'.encode()).hexdigest()[:12]}"
    for sig in ALL_FORBIDDEN:
        if sig in req.payload:
            category = "Prompt Injection" if sig in INJECTION_SIGS else ("Cyber Security / Secret leak" if sig in CYBERSEC_SIGS else "AI Safety policy breach")
            return GuardrailVerdict(allowed=False, reason=f"{category} detected: {sig}", latency_path="HOT_PATH_CPU", audit_id=audit_id)
    is_protected = any(req.target_path.startswith(p) or req.target_path == p for p in PROTECTED_PATHS)
    if is_protected and not req.human_override_token:
        return GuardrailVerdict(allowed=False, reason=f"Protected path {req.target_path} requires human override token", latency_path="HOT_PATH_CPU", audit_id=audit_id)
    if req.tier == PermissionTier.PROD_MUTATE and not req.human_override_token:
        return GuardrailVerdict(allowed=False, reason="PROD_MUTATE requires human override token", latency_path="HOT_PATH_CPU", audit_id=audit_id)
    return GuardrailVerdict(allowed=True, reason="Action allowed by hot-path policy", latency_path="HOT_PATH_CPU", audit_id=audit_id)


def verify_retry_storm_math(timeout_ms: int, max_retries: int, backoff_ms: int, caller_deadline_ms: int) -> tuple[bool, str]:
    worst_case_ms = timeout_ms * (max_retries + 1) + (backoff_ms * max_retries)
    if worst_case_ms <= caller_deadline_ms:
        return True, f"Budget valid: {worst_case_ms}ms <= {caller_deadline_ms}ms"
    return False, f"Retry storm risk: worst-case budget {worst_case_ms}ms exceeds deadline {caller_deadline_ms}ms"


def synthesize_safe_patch(diff: str) -> tuple[str, bool]:
    lines = [line[1:] if line.startswith("+") and not line.startswith("+++") else line for line in diff.splitlines() if not line.startswith(("-", "---", "@@"))]
    code = "\n".join(lines).replace("while True:", "for _attempt in range(3):")
    code = re.sub(r"time\.sleep\([^)]*\)", "await asyncio.sleep(0.1)", code)
    is_valid = False
    for candidate in (code, "async def _patch_wrapper():\n" + "\n".join(f"    {line}" for line in code.splitlines())):
        try:
            ast.parse(candidate)
            is_valid = True
            break
        except SyntaxError:
            pass
    return code, is_valid
    return code, is_valid


def scan_directory(dir_path: Path) -> dict:
    found = [p for p in PROTECTED_PATHS if (dir_path / p.rstrip("/")).exists()]
    return {"scanned_path": str(dir_path), "protected_paths_found": found, "guardrails_active": True}
