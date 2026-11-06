from pathlib import Path
from typing import Any
import yaml

DEFAULT_POLICY_DICT: dict[str, Any] = {
    "version": "1.0",
    "permission_tier": "sandbox_write",
    "enforcement": "strict",
    "protected_paths": [
        "infra/prod/",
        "security/",
        ".agent-policy.yaml",
        ".github/workflows/",
        ".env*",
        "secrets/",
        "credentials/",
    ],
    "command_rules": {
        "banned": [
            "rm -rf*",
            "*curl*|*sh*",
            "git push --force*",
            "git push -f*",
            "DROP TABLE*",
            "DROP DATABASE*",
        ],
        "require_override": [
            "terraform apply*",
            "kubectl apply*",
            "docker push*",
        ],
    },
    "allowed_tools": [
        "file_read",
        "file_edit",
        "run_command",
    ],
    "verification_hooks": {
        "pre_commit_gate": "pytest -v tests/",
    },
    "custom_forbidden_patterns": [],
}

DEFAULT_POLICY_YAML = """# Zero-Trust AI Agent Policy Contract
version: '1.0'
permission_tier: sandbox_write
enforcement: strict

# High blast-radius directories locked against autonomous mutations
protected_paths:
  - infra/prod/
  - security/
  - .agent-policy.yaml
  - .github/workflows/
  - .env*
  - secrets/
  - credentials/

# Command execution boundary rules
command_rules:
  banned:
    - 'rm -rf*'
    - '*curl*|*sh*'
    - 'git push --force*'
    - 'git push -f*'
    - 'DROP TABLE*'
    - 'DROP DATABASE*'
  require_override:
    - 'terraform apply*'
    - 'kubectl apply*'
    - 'docker push*'

# Sandboxed capabilities granted to agent
allowed_tools:
  - file_read
  - file_edit
  - run_command

# Mandatory deterministic test gates before committing or claiming completion
verification_hooks:
  pre_commit_gate: 'pytest -v tests/'

# Optional repository-specific forbidden regex or string patterns
custom_forbidden_patterns: []
"""


def load_policy(repo_path: Path | str) -> dict[str, Any]:
    """Load .agent-policy.yaml from the target repository, or return DEFAULT_POLICY_DICT."""
    p = Path(repo_path).resolve()
    if p.is_file():
        p = p.parent
    policy_file = p / ".agent-policy.yaml"
    if policy_file.exists():
        try:
            loaded = yaml.safe_load(policy_file.read_text())
            if isinstance(loaded, dict):
                merged = dict(DEFAULT_POLICY_DICT)
                merged.update(loaded)
                return merged
        except Exception:
            pass
    return dict(DEFAULT_POLICY_DICT)


def init_policy(repo_path: Path | str, force: bool = False) -> tuple[Path, bool]:
    """Initialize .agent-policy.yaml in the target repository.
    Returns (policy_path, created_bool).
    """
    p = Path(repo_path).resolve()
    if p.is_file():
        p = p.parent
    p.mkdir(parents=True, exist_ok=True)
    target = p / ".agent-policy.yaml"
    if target.exists() and not force:
        return target, False
    target.write_text(DEFAULT_POLICY_YAML)
    return target, True


def validate_policy(policy_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a parsed policy dictionary against minimum schema requirements."""
    errors = []
    if "version" not in policy_data:
        errors.append("Missing required field: 'version'")
    if "protected_paths" not in policy_data:
        errors.append("Missing required field: 'protected_paths'")
    elif not isinstance(policy_data["protected_paths"], list):
        errors.append("'protected_paths' must be a list of path strings")
    return len(errors) == 0, errors
