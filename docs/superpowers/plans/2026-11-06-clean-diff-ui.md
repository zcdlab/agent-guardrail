# Clean Unified Diff UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the payload viewers in `agent-guardrail` into a clean GitHub-style unified diff display while eliminating noise banners and redundant telemetry tables.

**Architecture:** Introduce a lightweight, zero-dependency `computeUnifiedDiff` JavaScript helper that contrasts original and sanitized payloads, generating visual rows with red deletion markers (`-`) and green addition markers (`+`). Remove extraneous marketing/architecture banners and repetitive audit metadata from the DOM, creating a streamlined focus on the diff view and enforce action.

**Tech Stack:** Vanilla JavaScript (ES6+), HTML5, Tailwind CSS, Python / pytest for syntax and delimiter verification.

**Spec:** [`docs/superpowers/specs/2026-11-06-clean-diff-ui-design.md`](file:///Users/zcd/.gemini/antigravity/scratch/agent-platform-core/docs/superpowers/specs/2026-11-06-clean-diff-ui-design.md)

## Global Constraints

- Preserve all existing required functions in `docs/index.html`: `switchTab`, `loadPromptCase`, `evaluatePromptGuardrail`, `autoSanitizePrompt`, `loadCyberCase`, `evaluateCyberGuardrail`, `autoSanitizeCyber`, `loadSafetyCase`, `toggleAstSynthesis`, `updateMathLive`, `runCliDemo`.
- Maintain balanced JavaScript delimiter counts (`{` matching `}`, `[` matching `]`).
- Do not introduce external npm dependencies or heavy third-party libraries (keep pure Tailwind CSS classes).
- Core Python files in `src/` must remain untouched and pass all unit tests (`pytest -v`).

## Review Focus

1. **Benign payload with no malicious signatures**: Ensure that a clean input (e.g. `benign` case) renders without false-positive red `-` deletion markers and displays the green `✓ APPROVED (200)` badge.
2. **Multi-line prompt injection comments**: Ensure multi-line HTML comments or multi-line ChatML blocks are correctly broken down into individual diff rows with appropriate line numbering.
3. **Re-clicking Enforce / Revert toggle**: Ensure cycling between "Enforce Guardrail" and "Revert to Injected Payload" cleanly transitions the diff view between quarantined state (`-` lines highlighted) and sanitized state (`-` and `+` diff shown).
4. **Randomized 1–4s LLM spinner during Enforce**: Ensure button spinner transitions correctly without getting stuck or throwing uncaught ReferenceErrors during the async timeout.
5. **Mobile / narrow viewport responsiveness**: Ensure code line numbers and diff rows wrap or scroll horizontally with `overflow-x-auto` without breaking page container layout.

---

### Task 1: Diff Computation and Formatting Utility in `docs/index.html`

**Files:**
- Modify: `docs/index.html`
- Test: `tests/test_demo.py`

**Interfaces:**
- Produces: `computeUnifiedDiff(originalText, sanitizedText, isSanitized, signatures) -> Array<{type: 'neutral'|'del'|'add', lineNum: string, text: string}>`
- Produces: `renderDiffTable(rows) -> string` (HTML string)

- [ ] **Step 1: Write the failing test in `tests/test_demo.py`**

Add assertion to `tests/test_demo.py` checking that `computeUnifiedDiff` and `renderDiffTable` are defined in the inline script of `docs/index.html`.

```python
def test_demo_diff_renderer_functions_declared():
    doc = Path("docs/index.html")
    content = doc.read_text()
    assert "function computeUnifiedDiff" in content
    assert "function renderDiffTable" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_demo.py::test_demo_diff_renderer_functions_declared -v`
Expected: FAIL with "Missing function computeUnifiedDiff"

- [ ] **Step 3: Implement `computeUnifiedDiff` and `renderDiffTable` in `docs/index.html`**

Add pure JavaScript diff generator in `<script>`:
- Compares line arrays of `originalText` and `sanitizedText`.
- If `!isSanitized`, marks any lines containing signatures with `type: 'del'` and other lines as `type: 'neutral'`.
- If `isSanitized`, generates unified diff showing deleted lines with `type: 'del'` and inserted replacement lines with `type: 'add'`.
- `renderDiffTable` outputs a table with line number columns, `+`/`-`/` ` indicator column, and syntax-highlighted code column with Tailwind classes (`bg-red-50 text-red-700` for deletions, `bg-emerald-50 text-emerald-800` for additions).

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_demo.py -v`
Expected: PASS with delimiter balance preserved.

- [ ] **Step 5: Commit**

```bash
git add tests/test_demo.py docs/index.html
git commit -m "feat(ui): add unified diff computation and rendering utility" --author="zcdlab <zcdlab@users.noreply.github.com>"
```

---

### Task 2: Streamline Tab 1 (Prompt Injections) with Unified Diff Viewer

**Files:**
- Modify: `docs/index.html:50-200, 580-775`
- Test: `tests/test_demo.py`

**Interfaces:**
- Consumes: `computeUnifiedDiff`, `renderDiffTable`
- Modifies: `#tab-prompt` DOM structure and `renderPromptDiff()` logic

- [ ] **Step 1: Write the test asserting Tab 1 clean diff elements in `tests/test_demo.py`**

Add test asserting that `#prompt-diff-container` exists and outdated verbose boxes (`prompt-remediation-box` step logs) are pruned.

```python
def test_demo_tab1_diff_container_present():
    content = Path("docs/index.html").read_text()
    assert 'id="prompt-diff-container"' in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_demo.py::test_demo_tab1_diff_container_present -v`
Expected: FAIL

- [ ] **Step 3: Streamline Tab 1 DOM and update `loadPromptCase` / `autoSanitizePrompt`**

- Remove top "Architecture Info Callout" from `<main>`.
- Remove Tab 1 "When to use this guardrail" callout card.
- Replace two-column layout in Tab 1 with a streamlined card:
  - Header: Filename (`#prompt-file-name`), vector badge, and status pill (`#prompt-verdict-pill`: `✕ BLOCKED (0.019 ms)` or `✓ APPROVED & SANITIZED (200)`).
  - Body: `#prompt-diff-container` containing the rendered unified diff.
  - Footer: Single enforce button `#btn-prompt-action` and latency badge.
- Update `loadPromptCase()` and `autoSanitizePrompt()` to call `renderPromptDiff()`.

- [ ] **Step 4: Run tests to verify delimiter balance and syntax**

Run: `.venv/bin/pytest -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add docs/index.html tests/test_demo.py
git commit -m "feat(ui): streamline Tab 1 prompt injection viewer into clean diff" --author="zcdlab <zcdlab@users.noreply.github.com>"
```

---

### Task 3: Streamline Tab 2 (Cybersecurity & Code) with Unified Diff Viewer

**Files:**
- Modify: `docs/index.html:200-350, 890-1050`
- Test: `tests/test_demo.py`

**Interfaces:**
- Consumes: `computeUnifiedDiff`, `renderDiffTable`
- Modifies: `#tab-cyber` DOM structure and `renderCyberDiff()` logic

- [ ] **Step 1: Write the test asserting Tab 2 clean diff elements in `tests/test_demo.py`**

Add test asserting `#cyber-diff-container` exists:

```python
def test_demo_tab2_diff_container_present():
    content = Path("docs/index.html").read_text()
    assert 'id="cyber-diff-container"' in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_demo.py::test_demo_tab2_diff_container_present -v`
Expected: FAIL

- [ ] **Step 3: Streamline Tab 2 DOM and update `loadCyberCase` / `autoSanitizeCyber`**

- Remove Tab 2 "When to use this guardrail" card.
- Replace two-column layout with the unified diff card:
  - Header: Filename (`#cyber-file-name`), threat tag, and status pill (`#cyber-verdict-pill`).
  - Body: `#cyber-diff-container` containing the rendered unified diff.
  - Footer: `#btn-cyber-action` auto-remediate button.
- Update `loadCyberCase()` and `autoSanitizeCyber()` to call `renderCyberDiff()`.

- [ ] **Step 4: Run tests to verify delimiter balance and syntax**

Run: `.venv/bin/pytest -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add docs/index.html tests/test_demo.py
git commit -m "feat(ui): streamline Tab 2 cyber security viewer into clean diff" --author="zcdlab <zcdlab@users.noreply.github.com>"
```

---

### Task 4: Sync Artifacts, Verify Full Suite, and Deploy to Remote

**Files:**
- Sync: `docs/index.html` -> `index.html`
- Sync: `docs/index.html` -> `/Users/zcd/.gemini/antigravity/brain/a9b74abc-c0f8-41ed-8eae-fb80a7a5a177/guardrail_demo.html`
- Branch: `gh-pages`

- [ ] **Step 1: Copy `docs/index.html` to root `index.html` and brain artifact**

```bash
cp docs/index.html index.html
cp docs/index.html /Users/zcd/.gemini/antigravity/brain/a9b74abc-c0f8-41ed-8eae-fb80a7a5a177/guardrail_demo.html
```

- [ ] **Step 2: Run complete pytest suite**

Run: `.venv/bin/pytest -v`
Expected: 50+ passed, 0 failed.

- [ ] **Step 3: Commit and update `gh-pages`**

```bash
git add index.html
git commit -m "deploy: update root demo with clean diff UI" --author="zcdlab <zcdlab@users.noreply.github.com>"
git checkout gh-pages
git checkout main -- docs/index.html index.html
git add docs/index.html index.html
git commit -m "deploy: update gh-pages with clean diff UI" --author="zcdlab <zcdlab@users.noreply.github.com>"
git checkout main
```

- [ ] **Step 4: Push to origin**

Run: `git push origin main gh-pages` (with BypassSandbox: true and toolSummary "Push branches to remote")

- [ ] **Step 5: Verify live endpoint**

Run: `curl -sI "https://zcdlab.github.io/agent-guardrail/"`
Expected: HTTP 200.

