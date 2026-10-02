# SARIF output refuses rejected verdicts without a file:line trace

Requirements: R7

## Goal

`normalize_findings.py --format sarif` turns rejected verdicts into SARIF suppressions, which hide
findings in GitHub code scanning. It must apply the same rule as `validate_report.py`, so the SARIF
path cannot bypass the validator.

## Scope

- Depends on `scripts/verdict_rules.py` from validator-rejected-trace. Import `validateVerdicts`
  in `scripts/normalize_findings.py` with the existing `try: from scripts.... except ImportError`
  pattern used for `redaction`.
- In `runMain`, when `args_output.format == "sarif"`, call `validateVerdicts(data_report)` before
  building output. If it returns errors: print each to stderr, prefixed exactly as returned (no
  extra prefix), write nothing to `--out` or stdout, and exit 1. An existing `--out` file is left
  untouched.
- JSON and markdown formats behave exactly as before, including with weak rejected verdicts.
- Tests in `tests/test_normalize_findings.py`, driving the real CLI as a subprocess on the real
  `tests/fixtures/semgrep/findings.json` evidence with a `--verdicts` file keyed by a real
  fingerprint:
  - `--format sarif`, rejected verdict with trace null: exit 1, stdout empty, stderr has the
    `/findings/<index>/verdict_evidence/trace:` line; with `--out`, the out file is not created.
  - `--format sarif`, rejected verdict with trace `"<location>:<line>"` of that finding: exit 0 and
    the SARIF result carries a suppression.
  - default JSON format with the weak rejected verdict: exit 0 and output unchanged from before.

## Acceptance criteria

- `python3 -m unittest discover -s tests` passes, including all pre-existing tests unchanged.
- `python3 -m compileall -q scripts` succeeds.
- The regex and rule exist only in `scripts/verdict_rules.py`; no copy in `normalize_findings.py`.

## Out of scope

- Changing `toSarif` mapping or suppression format.
- Gating JSON or markdown output.
- Any doc, schema, or changelog edit.
