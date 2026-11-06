import ast
import json
import os
import re
import urllib.request
from src.guardrails import synthesize_safe_patch


def is_demo_mode() -> bool:
    return os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")


def get_api_key() -> tuple[str | None, str]:
    if is_demo_mode():
        return None, "demo"
    for provider, key_name in (("openai", "OPENAI_API_KEY"), ("gemini", "GEMINI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")):
        val = os.getenv(key_name)
        if val:
            return val, provider
    return None, "none"


def call_llm(prompt: str, system: str = "") -> str | None:
    api_key, _ = get_api_key()
    if not api_key:
        return None
    url = os.getenv("LLM_API_BASE", "https://api.openai.com/v1/chat/completions")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system or "You are an AI code and security synthesizer."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except Exception:
        return None


def synthesize_patch_with_llm(diff: str, force_llm: bool = False) -> tuple[str, bool, str]:
    if force_llm or (not is_demo_mode() and get_api_key()[0]):
        sys_prompt = "You are a secure code synthesizer. Convert unsafe diffs into safe async python code with loop bounds and sleep limits. Return valid code only."
        llm_out = call_llm(f"Synthesize safe patch for this diff:\n{diff}", system=sys_prompt)
        if llm_out:
            code = re.sub(r"^```python\s*|^```\s*|```$", "", llm_out.strip(), flags=re.MULTILINE).strip()
            try:
                ast.parse(code)
                return code, True, "llm_synthesized"
            except SyntaxError:
                pass
    code, ok = synthesize_safe_patch(diff)
    return code, ok, "precalculated_ast_heuristic"

