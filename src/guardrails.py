import ast
import hashlib
from pathlib import Path
import re
import time
from typing import Any

from src.models import (
    GuardrailInput,
    GuardrailVerdict,
    PermissionTier,
    ScanReport,
    Severity,
    Violation,
)
from src.policy import load_policy

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

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".agent",
    "htmlcov",
}

SCANNABLE_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".bash",
    ".toml",
    ".sql",
    ".tf",
    ".env",
    ".cfg",
    ".ini",
}


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


def scan_file(file_path: Path, repo_root: Path) -> list[Violation]:
    """Scan a single file for prompt injections, secrets, exploits, and AST safety."""
    violations: list[Violation] = []
    rel_path = str(file_path.relative_to(repo_root))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return violations

    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        # 1. Prompt Injection checks (match highest priority signature per line)
        matched_inj = [sig for sig in INJECTION_SIGS if sig in line]
        if matched_inj:
            best_sig = max(matched_inj, key=len)
            violations.append(
                Violation(
                    file=rel_path,
                    line=idx,
                    severity=Severity.CRITICAL,
                    category="Prompt Injection",
                    rule=best_sig,
                    snippet=line.strip()[:140],
                    remediation="Quarantine untrusted input. Strip system prompt overrides, HTML comments, and ChatML delimiters before LLM inference.",
                )
            )

        # 2. Cyber Security & Secrets checks (match highest priority signature per line)
        matched_cyber = [sig for sig in CYBERSEC_SIGS if sig in line]
        if matched_cyber:
            best_sig = max(matched_cyber, key=len)
            is_secret = any(k in best_sig for k in ("sk_live_", "AKIA", "ghp_", "BEGIN OPENSSH", "BEGIN RSA"))
            violations.append(
                Violation(
                    file=rel_path,
                    line=idx,
                    severity=Severity.CRITICAL if is_secret else Severity.HIGH,
                    category="Hardcoded Secret" if is_secret else "Cyber Security Exploit",
                    rule=best_sig,
                    snippet=line.strip()[:140],
                    remediation="Redact hardcoded credential to environment variable or replace raw shell/eval execution with safe parameterized APIs.",
                )
            )

        # 3. AI Safety checks
        matched_safety = [sig for sig in AI_SAFETY_SIGS if sig in line]
        if matched_safety:
            best_sig = max(matched_safety, key=len)
            violations.append(
                Violation(
                    file=rel_path,
                    line=idx,
                    severity=Severity.HIGH,
                    category="AI Safety Violation",
                    rule=best_sig,
                    snippet=line.strip()[:140],
                    remediation="Block high blast-radius force-push or destructive SQL table drops without explicit cryptographic human approval.",
                )
            )

    # 4. AST concurrency check on Python files
    if file_path.suffix == ".py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Check for time.sleep inside async def
                if isinstance(node, ast.AsyncFunctionDef):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                            if getattr(sub.func.value, "id", None) == "time" and sub.func.attr == "sleep":
                                violations.append(
                                    Violation(
                                        file=rel_path,
                                        line=getattr(sub, "lineno", 1),
                                        severity=Severity.MEDIUM,
                                        category="Concurrency Invariant",
                                        rule="time.sleep inside async def",
                                        snippet="time.sleep(...) inside async function",
                                        remediation="Replace synchronous time.sleep with non-blocking await asyncio.sleep to prevent thread starvation.",
                                    )
                                )
        except SyntaxError:
            pass

    return violations


def scan_directory(
    dir_path: Path | str,
    max_files: int = 5000,
    ignore_dirs: set[str] | None = None,
) -> dict[str, Any]:
    """Recursively scan a repository directory for security and guardrail violations.
    Returns a comprehensive dict compatible with ScanReport and existing tests.
    """
    t0 = time.perf_counter()
    p = Path(dir_path).resolve()
    policy = load_policy(p)

    ignored = set(IGNORED_DIRS)
    if ignore_dirs:
        ignored.update(ignore_dirs)

    # Combine default and policy protected paths
    registered_protected = set(PROTECTED_PATHS)
    for path_str in policy.get("protected_paths", []):
        registered_protected.add(path_str.rstrip("/"))

    found_protected = [
        str(prot)
        for prot in registered_protected
        if (p / prot.rstrip("/")).exists()
    ]

    all_violations: list[Violation] = []
    scanned_count = 0

    if p.is_dir():
        for root_dir, dirs, files in p.walk():
            dirs[:] = [d for d in dirs if d not in ignored and not d.startswith(".")]

            for fname in files:
                if scanned_count >= max_files:
                    break

                fpath = root_dir / fname
                ext = fpath.suffix.lower()

                # Check scannable extensions or dotfiles like .env
                if ext in SCANNABLE_EXTS or fname.startswith(".env"):
                    # Skip huge files (> 2MB) to keep scan sub-millisecond per file
                    try:
                        if fpath.stat().st_size > 2 * 1024 * 1024:
                            continue
                    except OSError:
                        continue

                    scanned_count += 1
                    file_violations = scan_file(fpath, p)
                    all_violations.extend(file_violations)

            if scanned_count >= max_files:
                break

    duration_ms = round((time.perf_counter() - t0) * 1000, 2)

    cat_summary: dict[str, int] = {}
    for v in all_violations:
        cat_summary[v.category] = cat_summary.get(v.category, 0) + 1
    cat_summary["total"] = len(all_violations)

    return {
        "scanned_path": str(p),
        "protected_paths_found": sorted(found_protected),
        "guardrails_active": True,
        "total_files_scanned": scanned_count,
        "violations": [v.model_dump() for v in all_violations],
        "clean": len(all_violations) == 0,
        "summary": cat_summary,
        "scan_duration_ms": duration_ms,
    }
