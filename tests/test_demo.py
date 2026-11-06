import re
from pathlib import Path
import pytest


def test_demo_index_html_exists_and_contains_core_elements():
    doc = Path("docs/index.html")
    assert doc.exists()
    content = doc.read_text()
    assert "agent-guardrail" in content
    assert "Prompt Injection" in content
    assert "Cyber Security" in content
    assert "AI Safety" in content
    assert "Interactive Guardrail CLI Simulator" in content
    assert "Evaluate Guardrail Engine" in content


def test_demo_javascript_syntax_and_integrity():
    doc = Path("docs/index.html")
    content = doc.read_text()

    # Extract javascript
    m = re.search(r"<script>(.*?)</script>", content, re.DOTALL)
    assert m is not None, "Missing inline script in docs/index.html"
    code = m.group(1)

    # Validate delimiter balance
    assert code.count("{") == code.count("}"), "Unbalanced braces in docs/index.html script"
    assert code.count("[") == code.count("]"), "Unbalanced brackets in docs/index.html script"

    # Validate depth never drops below zero outside backticks
    depth = 0
    in_backtick = False
    for line in code.splitlines():
        for ch in line:
            if ch == "`":
                in_backtick = not in_backtick
            elif not in_backtick:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    assert depth >= 0, f"Negative brace depth encountered: {line}"
    assert depth == 0

    # Ensure all interactive functions are declared
    required_fns = [
        "switchTab", "loadPromptCase", "evaluatePromptGuardrail",
        "autoSanitizePrompt", "loadCyberCase", "evaluateCyberGuardrail",
        "autoSanitizeCyber", "loadSafetyCase", "toggleAstSynthesis",
        "updateMathLive", "runCliDemo"
    ]
    for fn in required_fns:
        assert f"function {fn}" in code, f"Missing function {fn} in docs/index.html"
