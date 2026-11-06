# Short Design Doc: Clean Diff UI for Agent Guardrail

## Intent & The Why
The user reported that the current UI contains too much visual noise (callout banners, telemetry tables, simulated terminal logs) and requested a clean unified diff view showing exact additions (`+` in green) and deletions (`-` in red) when guardrails detect and strip malicious payloads, rather than raw text replacement.

## Goals
- **Unified Diff View**: Replace the plain textarea payload viewer with a GitHub/VS Code-style unified diff display.
  - Shows line numbers and diff indicators (`-` in red background/text for malicious tokens, `+` in green background/text for safe sanitized replacements).
  - When in quarantined state: shows the malicious line clearly flagged with `-` (red).
  - When enforce/sanitize is clicked: transitions (after the 1–4s simulated LLM latency) to show the clean diff with the stripped lines (`-`) and clean sanitized lines (`+`), or purely clean code with a clear `✓ APPROVED` badge.
- **De-clutter & Noise Reduction**:
  - Remove verbose architecture and "When to use" explanatory banners.
  - Remove dense 4-row audit reference tables (`Audit Reference`, `Action`, etc.) and multi-step simulated logging boxes.
  - Retain only high-signal controls: Preset selector pills, the Unified Diff viewer, status pill (`Blocked` / `Approved`), latency indicator, and the single Enforce Action button.
- **Applies to Key Tabs**: Tab 1 (Prompt Injections & Jailbreaks) and Tab 2 (Cybersecurity & Code Execution).
- **Zero Regressions**: Maintain all 48 existing unit tests (`pytest -v`), delimiter matching, and hot-path execution speed.

## Non-Goals & Anti-Goals
- **Non-Goals**: No changes to core Python guardrails (`src/`), CLI subcommands, or `evals/golden_cases.json`.
- **Anti-Goals**: No heavy third-party diff libraries or npm dependencies (keep pure lightweight Tailwind CSS + vanilla JS). No multi-pane layouts that create horizontal scrolling.

## Approaches Considered
- **Approach 1 (Inline Unified Diff with Minimal Chrome) — Selected**: Single unified diff viewer displaying red `-` deletions and green `+` additions with minimal header/footer chrome. Highest readability, least noise, responsive on mobile and desktop.
- **Approach 2 (Side-by-Side Diff + Tabbed Views) — Rejected**: Requires split panes that squeeze code on small/medium screens and adds extra view toggle controls.

## Design Details
1. **Header / Chrome**:
   - Clean minimalist top nav.
   - Clean preset button group (active tab with subtle border/ring, no clutter).
2. **Diff Viewer Component**:
   - Standard code container (`bg-slate-900` or `bg-white` with clean borders).
   - Each line rendered as a row:
     - Neutral line: neutral text, neutral line number.
     - Deleted line (`-`): `bg-red-50 text-red-700` (or dark variant), red line number and `-` prefix.
     - Added/sanitized line (`+`): `bg-emerald-50 text-emerald-800`, green line number and `+` prefix.
3. **Status & Action Footer**:
   - Status badge: `BLOCKED (403)` / `APPROVED (200)` with CPU latency tag (e.g., `0.02ms`).
   - Action button: `Enforce Guardrail & Strip Injection` / `Revert to Injected Payload`.
