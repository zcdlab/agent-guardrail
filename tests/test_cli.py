from src.cli import main as cli_main
from src.mcp_server import get_active_policy, inspect_guardrail, check_retry_budget, scan_project


def test_cli_math_command():
    assert cli_main(["math", "--timeout", "600", "--retries", "2", "--backoff", "100", "--deadline", "2000"]) == 0
    assert cli_main(["math", "--timeout", "1000", "--retries", "1", "--backoff", "1", "--deadline", "2000"]) == 0


def test_cli_check_command():
    assert cli_main(["check", "--payload", "clean python code"]) == 0
    assert cli_main(["check", "--payload", "os.system('rm -rf /')"]) == 0


def test_cli_scan_command():
    assert cli_main(["scan", "."]) == 0


def test_mcp_endpoints():
    policy = get_active_policy()
    assert isinstance(policy, dict)
    assert "protected_paths" in policy

    res = inspect_guardrail(payload="clean code")
    assert res["allowed"] is True

    blocked = inspect_guardrail(payload="os.system('ls')")
    assert blocked["allowed"] is False

    budget = check_retry_budget(timeout_ms=500, max_retries=2, backoff_ms=100, caller_deadline_ms=2000)
    assert budget["allowed"] is True

    scan = scan_project(".")
    assert scan["guardrails_active"] is True
