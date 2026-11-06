from unittest.mock import patch
from src.cli import main as cli_main
from src.llm import call_llm, synthesize_patch_with_llm, is_demo_mode


def test_is_demo_mode(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    assert not is_demo_mode()
    monkeypatch.setenv("DEMO_MODE", "true")
    assert is_demo_mode()


def test_synthesize_patch_precalculated_fallback(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    diff = "+while True:\n+    time.sleep(1)"
    code, ok, engine = synthesize_patch_with_llm(diff)
    assert ok is True
    assert engine == "precalculated_ast_heuristic"
    assert "for _attempt in range(3):" in code
    assert "await asyncio.sleep(0.1)" in code


def test_synthesize_patch_with_mocked_llm(monkeypatch):
    mock_response = "```python\nfor _i in range(5):\n    print('safe')\n```"
    with patch("src.llm.call_llm", return_value=mock_response):
        code, ok, engine = synthesize_patch_with_llm("+unsafe", force_llm=True)
        assert ok is True
        assert engine == "llm_synthesized"
        assert "print('safe')" in code


def test_cli_patch_command():
    assert cli_main(["patch", "--diff", "+while True:\n+    time.sleep(1)"]) == 0
