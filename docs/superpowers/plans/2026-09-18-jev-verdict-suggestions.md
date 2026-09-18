# Jev Verdict Suggestions Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit optional command that produces non-authoritative Jev verdict suggestions for unreviewed Semgrep findings.

**Architecture:** A standalone Python script filters a normalized report, submits one narrow Choice judgment per eligible finding through the official TypeSafe SDK, and atomically writes a separate suggestions artifact. Pure filtering and result-building functions accept an injected client so unit tests require neither network access nor the optional SDK.

**Tech Stack:** Python 3.10+, `unittest`, optional `typesafe-sdk`, TypeSafe System One API (`jev-latest`).

---

## Chunk 1: Script, tests, and documentation

### Task 1: Define suggestion behavior test-first

**Files:**
- Create: `tests/test_suggest_verdicts.py`
- Create: `scripts/suggest_verdicts.py`

- [ ] Write a failing unit test proving only unreviewed Semgrep code findings with snippets are submitted, and that reviewed/non-code/no-snippet findings are recorded as skipped.
- [ ] Run `python3 -m unittest tests.test_suggest_verdicts -v`; expect import failure because the script does not exist.
- [ ] Implement the minimal pure filtering and suggestion code. Send normalized finding metadata plus the existing redacted snippet, use a three-option raw Choice question, and parse `response.raw_http_response.json()`.
- [ ] Run the focused test; expect PASS.
- [ ] Write failing tests for malformed reports/responses and atomic JSON output behavior.
- [ ] Implement minimal validation, timestamp metadata, output-directory handling, and temporary-file replacement.
- [ ] Run `python3 -m unittest tests.test_suggest_verdicts -v`; expect PASS.

### Task 2: Add the optional CLI boundary

**Files:**
- Modify: `tests/test_suggest_verdicts.py`
- Modify: `scripts/suggest_verdicts.py`

- [ ] Write failing tests for argument parsing and the missing-SDK error path.
- [ ] Run the focused test and confirm the expected failures.
- [ ] Add `REPORT`, required `--out`, optional `--model` defaulting to `jev-latest`, lazy `typesafe_sdk` import, `TYPESAFE_API_KEY` check, and non-zero CLI errors without exposing credentials.
- [ ] Run the focused test; expect PASS.

### Task 3: Document and verify

**Files:**
- Modify: `README.md`
- Modify: `SKILL.md`

- [ ] Document manual `typesafe-sdk` installation, explicit invocation, transmitted fields, output separation, and mandatory human evidence review.
- [ ] Run `python3 -m unittest discover -s tests -v`; expect all tests PASS.
- [ ] Run `python3 -m compileall -q scripts tests && git diff --check`; expect exit 0.
- [ ] Review the diff against `docs/superpowers/specs/2026-09-18-jev-verdict-suggestions-design.md` and remove any unrequested behavior.
