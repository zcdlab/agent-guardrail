import argparse
from pathlib import Path
import sys
import webbrowser
from src.guardrails import inspect_hot_path, scan_directory, verify_retry_storm_math
from src.llm import synthesize_patch_with_llm
from src.models import GuardrailInput


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrail", description="High-Assurance AI Agent Guardrail CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_check = sub.add_parser("check", help="Inspect payload for prompt injection, secrets, and exploits")
    p_check.add_argument("--file", default="input.txt")
    p_check.add_argument("--payload", default="")

    p_math = sub.add_parser("math", help="Verify retry-storm deadline budget")
    p_math.add_argument("--timeout", type=int, default=600)
    p_math.add_argument("--retries", type=int, default=2)
    p_math.add_argument("--backoff", type=int, default=100)
    p_math.add_argument("--deadline", type=int, default=2000)

    p_scan = sub.add_parser("scan", help="Scan repository for protected paths and policy status")
    p_scan.add_argument("path", nargs="?", default=".")

    p_patch = sub.add_parser("patch", help="Synthesize safe patch from unsafe diff")
    p_patch.add_argument("--diff", default="while True:\n    time.sleep(1)")
    p_patch.add_argument("--llm", action="store_true", help="Call LLM for real-time synthesis")

    sub.add_parser("ui", help="Open Control Plane Web UI")
    sub.add_parser("serve", help="Start FastMCP server")

    args = parser.parse_args(argv)
    if args.cmd == "check":
        v = inspect_hot_path(GuardrailInput(action="cli_check", target_path=args.file, payload=args.payload))
        print(f"Verdict: {'ALLOWED' if v.allowed else 'BLOCKED'}\nReason: {v.reason}\nAudit ID: {v.audit_id}")
    elif args.cmd == "math":
        ok, hint = verify_retry_storm_math(args.timeout, args.retries, args.backoff, args.deadline)
        print(f"{'PASS' if ok else 'FAIL'}: {hint}")
    elif args.cmd == "scan":
        res = scan_directory(Path(args.path))
        print(f"Scan complete: {len(res['protected_paths_found'])} protected paths found | Guardrails Active")
    elif args.cmd == "patch":
        code, ok, engine = synthesize_patch_with_llm(args.diff, force_llm=args.llm)
        print(f"Synthesized Safe Patch [Engine: {engine}] (Valid AST: {ok}):\n{code}")
    elif args.cmd == "ui":
        ui_path = Path(__file__).resolve().parent.parent / "docs" / "index.html"
        webbrowser.open(f"file://{ui_path}")
        print(f"Control Plane UI: file://{ui_path}")
    elif args.cmd == "serve":
        from src.mcp_server import mcp

        mcp.run()
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
