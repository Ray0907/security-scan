# Report Correctness Fixes

Six verified defects in the runner and normalizer. Each fix is small. Order is by severity.

## Rules for the implementer

- For each item: write the failing test first in the existing `tests/test_*.py` file, run it red,
  then change code until green. Stdlib `unittest` only, no new dependencies.
- Match existing style: tabs, `camelCase` functions, `noun_qualifier` variable names.
- Do not commit or push. Do not change fingerprint composition beyond item 1.
- Done gate, all must pass:
  - `python3 -m unittest discover -s tests`
  - `python3 -m compileall -q scripts`
  - `npx --yes markdownlint-cli2@0.23.2 "**/*.md"`
  - The item 1 acceptance repro prints `4 4`.

## 1. Fingerprint collision across projects (high)

Dependency parsers hard-code `location` to a lockfile name (`scripts/normalize_findings.py:159`,
`:238`, `:304`, `:333`). Two projects at `p1/` and `p2/` with the same vulnerable package produce
identical fingerprints. Verdicts and baseline diffs then merge unrelated findings.

Fix once in `normalizeEvidence` (`scripts/normalize_findings.py:580`), not per parser: when
`meta_record["path"] != "."` and a finding's `location` is relative, set
`location = f"{path}/{location}"` and recompute `fingerprint` with the same formula as
`makeFinding` (extract a small `getFingerprint(finding)` helper and use it in both places).
Leave absolute locations alone.

After normalization, raise `ValueError` if fingerprints are not unique, so a future parser
collision fails loudly.

Acceptance repro:

```bash
D=$(mktemp -d)
for i in 1 2; do
  mkdir "$D/0$i-python-p$i"
  cp tests/fixtures/pip-audit/findings.json "$D/0$i-python-p$i/stdout.txt"
done
cat > "$D/run.json" <<'E'
{"plan_root":"/x","records":[
{"plan_index":1,"kind":"python","path":"p1","tool":"pip-audit","state":"ran"},
{"plan_index":2,"kind":"python","path":"p2","tool":"pip-audit","state":"ran"}]}
E
python3 scripts/normalize_findings.py "$D" | python3 -c \
  "import json,sys;f=[x['fingerprint'] for x in json.load(sys.stdin)['findings']];print(len(f),len(set(f)))"
```

Before the fix it prints `4 2`. After the fix it must print `4 4`.

Add a `CHANGELOG.md` entry: fingerprints change for findings in subdirectory projects, so existing
baselines and verdict files will report those findings as new once.

## 2. `--force` deletes any directory (high, data loss)

`prepareOutput` (`scripts/run_plan.py:74`) runs `shutil.rmtree` on any non-empty `--out`.
`--out . --force` wipes the repository.

Fix: with `--force`, only remove the directory when it contains `run.json`. Otherwise raise
`ValueError("refusing to remove non-evidence directory: ...")`. Test both paths.

## 3. Coverage computed after filtering (medium)

`getCoverage` (`scripts/normalize_findings.py:657`) receives the list already filtered by
`--severity` / `--owasp`. A category whose findings were filtered out shows as
`automated-covered`. Compute coverage from the unfiltered findings list. Keep `finding_count`
reflecting the filtered list.

## 4. `--only` / `--skip` drop records silently (medium)

`scripts/run_plan.py:125` uses `continue`, so excluded kinds never appear in `run.json` or the
report. The README promises missing scanners show as incomplete coverage, never clean.

Fix: write the record with `state: "skipped"` and `reason: "excluded by --only"` or
`"excluded by --skip"`, no command execution. Confirm `normalizeEvidence` renders it as `skipped`.

## 5. SARIF `kind` / `level` violate spec (medium)

SARIF 2.1.0 §3.27.9: "If level has any value other than 'none' and kind is present, then kind
SHALL have the value 'fail'." `toSarif` (`scripts/normalize_findings.py:686`) emits `review` or
`notApplicable` together with `error` / `warning` / `note`.

Fix:

- All results: `kind: "fail"` and the existing severity-based `level`.
- Rejected findings: add
  `"suppressions": [{"kind": "external", "status": "accepted", "justification": <verdict_evidence>}]`.
- Update the mapping table at `references/REPORTING.md:121` to match.

## 6. Markdown table breaks on `|` or newline (low)

`toMarkdown` (`scripts/normalize_findings.py:732`, `:742`) interpolates `summary` raw. Add one
`getMarkdownRow(finding)` helper used by both loops that escapes `|` as `\|` and replaces
newlines with a space.

## 7. Wrong version for cargo-audit (low)

`getToolVersion(command_scan[0])` (`scripts/run_plan.py:149`) runs `cargo --version`, so the
report records cargo's version as cargo-audit's. Pass `["cargo", "audit", "--version"]` when
`name_tool == "cargo-audit"`, otherwise `[command_scan[0], "--version"]`.

## Out of scope

- Parallel scanner execution.
- Validating the plan against `schema/scan-plan.schema.json` in `run_plan.py`.
- Removing `line` from the fingerprint. Open design question for the maintainer.
