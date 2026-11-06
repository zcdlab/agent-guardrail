import json
from pathlib import Path
from src.guardrails import inspect_hot_path, verify_retry_storm_math, synthesize_safe_patch
from src.models import GuardrailInput


def test_guardrail_golden_cases_integrity():
    eval_file = Path("evals/golden_cases.json")
    assert eval_file.exists()
    data = json.loads(eval_file.read_text())
    assert "prompt_injection" in data["cases"]
    assert "cyber_security" in data["cases"]

    for case in data["cases"]["prompt_injection"]:
        v = inspect_hot_path(GuardrailInput(action="test", target_path="input.txt", payload=case["payload"]))
        assert not v.allowed
        assert case["category"] in v.reason

    for case in data["cases"]["cyber_security"]:
        v = inspect_hot_path(GuardrailInput(action="test", target_path="input.txt", payload=case["payload"]))
        assert not v.allowed
        assert case["category"] in v.reason
