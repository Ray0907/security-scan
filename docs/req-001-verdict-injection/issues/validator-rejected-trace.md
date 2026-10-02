# Validator: rejected verdicts need a file:line trace

Requirements: R1, R2, R3, R4

## Goal

`scripts/validate_report.py` deterministically rejects a report in which a `rejected` verdict has
no file:line evidence in `verdict_evidence.trace`, so a verdict written under prompt injection
cannot hide a finding.

## Scope

- Add a semantic check to `scripts/validate_report.py` that runs after schema validation, over
  every element of `findings`. Apply it only to findings whose `verdict` is `rejected`, including
  ones with `verdict_carried_forward: true`.
- A finding fails when `verdict_evidence` is absent, or `verdict_evidence.trace` is absent, null,
  empty or whitespace only, or contains no file:line reference.
- file:line reference: compile once at module level as
  `re.compile(r"[^\s:]*[A-Za-z][^\s:]*:[1-9][0-9]*(?![0-9])")` and use `search`.
- Error line format, one per failing finding, printed to stderr like existing errors:
  `/findings/<index>/verdict_evidence/trace: rejected verdict requires a file:line reference`.
- Exit code 1 when schema errors or semantic errors exist; 0 otherwise; 2 unchanged for unreadable
  input. Schema errors and semantic errors are both printed when both exist.
- Keep `validateDocument` a generic schema validator; put the new check in its own function (for
  example `validateVerdicts(document) -> list[str]`) called from `runMain`. If the document is not
  an object or `findings` is not a list, the semantic check returns no errors (schema errors already
  cover that).
- Tests in `tests/test_validate_report.py`:
  - Unit-level: rejected with trace null, `""`, `"   "`, `"looks safe"`, `"10:30"`, missing
    `verdict_evidence`, and carried-forward rejected with trace null each produce exactly the
    expected pointer error. Rejected with `"api/view.py:12"`, `"Dockerfile:3"`,
    `"entry.py:10 -> sink.py:42"` produce none. `confirmed` and `needs_validation` with trace null
    produce none.
  - End-to-end (R4): build an evidence directory from the real `tests/fixtures/semgrep/findings.json`
    the same way existing normalize tests do, run `scripts/normalize_findings.py` as a subprocess
    with `--verdicts` pointing at a verdicts file keyed by a real fingerprint from that report, then
    run `scripts/validate_report.py` as a subprocess on the output. Cases: trace null exits 1;
    trace `"comment says verified false positive"` exits 1; trace naming the finding's own
    `location:line` exits 0. Assert the stderr pointer line on the failing cases.

## Acceptance criteria

- `python3 -m unittest discover -s tests` passes, including all pre-existing tests unchanged.
- `python3 -m compileall -q scripts` succeeds.
- A report produced by `normalize_findings.py` with no verdicts validates with exit 0, as before.
- The end-to-end test runs the real CLIs (subprocess), not imported functions only.

## Out of scope

- Opening the scanned repository to check whether cited lines are comments (no `--root` option).
- Changing `schema/security-findings.schema.json` or adding fields such as `control`.
- Changing `normalize_findings.py` behavior; it may still merge weak verdicts, the validator is
  the gate.
- Any edit to `SKILL.md`, `references/`, or `CHANGELOG.md` (separate feature).
