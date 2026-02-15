from pathlib import Path
from fastmcp import FastMCP
from src.guardrails import ALL_FORBIDDEN, PROTECTED_PATHS, inspect_hot_path, scan_directory, verify_retry_storm_math
from src.models import GuardrailInput

mcp = FastMCP("agent-guardrail")


@mcp.resource("policy://active")
def get_active_policy() -> dict:
    return {"protected_paths": list(PROTECTED_PATHS), "forbidden_signatures_count": len(ALL_FORBIDDEN)}


@mcp.tool()
def inspect_guardrail(payload: str, target_path: str = "src/code.py", action: str = "check") -> dict:
    req = GuardrailInput(action=action, target_path=target_path, payload=payload)
    return inspect_hot_path(req).model_dump()


@mcp.tool()
def check_retry_budget(timeout_ms: int, max_retries: int, backoff_ms: int, caller_deadline_ms: int) -> dict:
    ok, hint = verify_retry_storm_math(timeout_ms, max_retries, backoff_ms, caller_deadline_ms)
    return {"allowed": ok, "details": hint}


@mcp.tool()
def scan_project(path: str = ".") -> dict:
    return scan_directory(Path(path))


if __name__ == "__main__":
    mcp.run()
