import argparse
import json
from pathlib import Path
import sys
import webbrowser
from src.guardrails import inspect_hot_path, scan_directory, verify_retry_storm_math
from src.llm import synthesize_patch_with_llm
from src.models import GuardrailInput
from src.policy import init_policy, load_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="High-Assurance AI Agent Guardrail Engine & Policy CLI",
    )
    sub = parser.add_subparsers(dest="cmd")

    # check
    p_check = sub.add_parser("check", help="Inspect payload or file for prompt injection, secrets, and exploits")
    p_check.add_argument("--file", default="")
    p_check.add_argument("--payload", default="")
    p_check.add_argument("--strict", action="store_true", help="Exit with code 1 if blocked")

    # scan
    p_scan = sub.add_parser("scan", help="Recursively scan repository for security threats and guardrail violations")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_scan.add_argument("--strict", action="store_true", help="Exit with non-zero exit code if violations found")
    p_scan.add_argument("--max-files", type=int, default=5000, help="Maximum number of files to scan")

    # init
    p_init = sub.add_parser("init", help="Initialize .agent-policy.yaml zero-trust contract in target repository")
    p_init.add_argument("path", nargs="?", default=".")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing .agent-policy.yaml")

    # policy
    p_pol = sub.add_parser("policy", help="Display active guardrail policy contract")
    p_pol.add_argument("path", nargs="?", default=".")
    p_pol.add_argument("--json", action="store_true", help="Output policy as JSON")

    # math
    p_math = sub.add_parser("math", help="Verify retry-storm deadline budget")
    p_math.add_argument("--timeout", type=int, default=600)
    p_math.add_argument("--retries", type=int, default=2)
    p_math.add_argument("--backoff", type=int, default=100)
    p_math.add_argument("--deadline", type=int, default=2000)

    # patch
    p_patch = sub.add_parser("patch", help="Synthesize safe patch from unsafe diff")
    p_patch.add_argument("--diff", default="while True:\n    time.sleep(1)")
    p_patch.add_argument("--llm", action="store_true", help="Call LLM for real-time synthesis")

    # ui & serve
    sub.add_parser("ui", help="Open Control Plane Web UI")
    sub.add_parser("serve", help="Start FastMCP server")

    args = parser.parse_args(argv)

    if args.cmd == "check":
        payload = args.payload
        target_path = args.file or "input.txt"
        if args.file and Path(args.file).exists():
            try:
                payload = Path(args.file).read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                print(f"Error reading {args.file}: {e}", file=sys.stderr)
                return 1

        v = inspect_hot_path(GuardrailInput(action="cli_check", target_path=target_path, payload=payload))
        verdict_str = "ALLOWED" if v.allowed else "BLOCKED"
        print(f"Verdict: {verdict_str}\nReason: {v.reason}\nAudit ID: {v.audit_id}")
        if args.strict and not v.allowed:
            return 1

    elif args.cmd == "scan":
        target = Path(args.path).resolve()
        res = scan_directory(target, max_files=args.max_files)

        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"\n🛡️  AgentGuardrail Scan Report")
            print(f"📦 Target: {target}")
            print(f"⚡ Scanned: {res['total_files_scanned']} files in {res['scan_duration_ms']} ms")
            if res["protected_paths_found"]:
                print(f"🔒 Protected Paths Active: {', '.join(res['protected_paths_found'])}")

            violations = res.get("violations", [])
            if not violations:
                print("✓ Clean: 0 violations detected — Repository Guardrails Passing\n")
            else:
                print(f"\n✕ {len(violations)} Violation(s) Detected:")
                for vi in violations:
                    print(f"  [{vi['severity']}] {vi['category']} — {vi['file']}:{vi['line']}")
                    print(f"    Rule: {vi['rule']}")
                    print(f"    Snippet: {vi['snippet']}")
                    print(f"    Remediation: {vi['remediation']}\n")

        if args.strict and not res.get("clean", True):
            return 1

    elif args.cmd == "init":
        target = Path(args.path).resolve()
        policy_path, created = init_policy(target, force=args.force)
        if created:
            print(f"✨ Initialized .agent-policy.yaml at {policy_path}")
        else:
            print(f"ℹ️  .agent-policy.yaml already exists at {policy_path} (use --force to overwrite)")

    elif args.cmd == "policy":
        target = Path(args.path).resolve()
        pol = load_policy(target)
        if args.json:
            print(json.dumps(pol, indent=2))
        else:
            print(f"\n🛡️  Active Guardrail Policy for {target}:")
            print(f"  Version: {pol.get('version')}")
            print(f"  Permission Tier: {pol.get('permission_tier')}")
            print(f"  Enforcement: {pol.get('enforcement')}")
            print(f"  Protected Paths: {', '.join(pol.get('protected_paths', []))}")
            banned = pol.get("command_rules", {}).get("banned", [])
            print(f"  Banned Commands: {', '.join(banned)}\n")

    elif args.cmd == "math":
        ok, hint = verify_retry_storm_math(args.timeout, args.retries, args.backoff, args.deadline)
        print(f"{'PASS' if ok else 'FAIL'}: {hint}")

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
