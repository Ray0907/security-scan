# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.11.0] - 2026-11-11

### Added in 1.11.0

- The planner marks Yarn, Cargo, and rustup records `inconclusive` with no command when a
  repository config in the project or an ancestor up to the scan root could run repository code
  (`yarnPath`, `plugins`, `yarn-path`, Cargo `audit` aliases or `include`, `rust-toolchain`
  `path`) or cannot be proven plain. See `references/SCANNERS.md` for the rules and limits.
- Gitleaks, Trivy, and Semgrep ignore or config files in the repository are recorded in the plan
  `note` and `evidence`, carried into `run.json` and the report's scanner entry (new optional
  `note` field), and listed in the Markdown report.

### Changed in 1.11.0

- `composer audit` runs with `--no-plugins --no-scripts`.
- Tool version probes run in the system temporary directory instead of the current directory.
- Some Yarn Berry projects that commit `yarnPath` become `inconclusive` instead of scanned.

### Fixed in 1.11.0

- Secrets written with a JSON-escaped quote (`password = \"value\"`) are redacted in saved
  evidence, and keyword redaction no longer corrupts valid scanner JSON in those cases.
- Private-key redaction runs in linear time on output with many unterminated `BEGIN` headers.

## [1.10.0] - 2026-11-11

### Fixed in 1.10.0

- SARIF omits scanners without a tool and null driver versions, and uses the first available
  tool version across scanner records.
- OSV locations inside the scan root become root-relative before fingerprinting, without
  double-prefixing subprojects or rewriting paths outside the root. **Baseline-affecting:**
  existing OSV findings with these absolute locations get new fingerprints once.
- License planning marks pnpm, yarn, bun, uv, poetry, pipenv, and pylock lockfiles
  `inconclusive` without a command; npm, Cargo, and `requirements*.txt` remain supported.

## [1.9.0] - 2026-11-08

### Added in 1.9.0

- The Markdown report adds a `Reason` column to the scanner table and a `Not Covered` section
  listing skipped, inconclusive, and failed scanners and OWASP categories without coverage.

### Changed in 1.9.0

- Breaking: `validate_report.py` and `normalize_findings.py --format sarif` now reject a
  `confirmed` verdict without a non-empty `verdict_evidence.trace`, and any reviewed finding whose
  `reason`, `reviewer`, or `reviewed_at` is blank. Reports with such verdicts that passed before
  now fail. Add the missing evidence to the verdict and normalize again.

### Fixed

- Each scanner reports only its own `finding_count`, so a clean project no longer inherits
  the total of another project that runs the same tool.
- SARIF output emits one run per tool instead of repeating every finding in each run of a tool
  that scanned several projects.
- A non-UTF-8 `requirements*.txt` marks its license record `inconclusive` instead of crashing
  the planner.
- A string `cwe` value is kept as one entry instead of being split into characters.

## [1.8.0] - 2026-10-27

### Added in 1.8.0

- Runtime-version check for Node.js and PHP (`kind: runtime`, `scripts/check_runtime.py`). It
  matches exact pins against the `nodejs/security-wg` advisory feed, flags end-of-life lines, and
  flags PHP pins that are older than a security release of their branch. Ranges, floating tags,
  and unresolvable values stay `inconclusive`. Coverage is declared-version-only.
- The findings schema accepts finding type `runtime`; the plan schema accepts kind `runtime`.

## [1.7.0] - 2026-10-20

### Added in 1.7.0

- Severity calibration anchors, a "Not covered" report section, guidance-vs-scan mode, and an
  anti-pattern list.

### Changed in 1.7.0

- A `needs_validation` verdict now requires a non-empty `verdict_evidence.unresolved_fact`;
  `validate_report.py` fails reports without it. Existing verdict files that leave it null must
  be updated.

## [1.6.0] - 2026-10-07

### Added in 1.6.0

- Read-only OSV license-compliance scans for Node, Python, and Rust lockfiles with SPDX-expression
  severity classification, local-package provenance filtering, and explicit inconclusive coverage.
- `run_plan.py --jobs N` runs scanners for distinct tools concurrently. Records sharing a tool
  stay sequential as a precaution against cache/advisory-database lock conflicts (e.g. Trivy,
  cargo-audit); see `references/SCANNERS.md` for what was and was not confirmed in testing.

### Changed in 1.6.0

- Findings in subdirectory projects now include the project path in their fingerprint. Existing
  baselines and verdict files will report those findings as new once.

### Removed in 1.6.0

- Optional TypeSafe Jev verdict suggestions (`suggest_verdicts.py`). Reviewing agents already
  verify each finding with evidence, so snippet-only suggestions added an external dependency and
  code transmission without replacing that review.

## [1.5.0] - 2026-10-02

### Changed in 1.5.0

- `validate_report.py` fails reports and `normalize_findings.py --format sarif` refuses SARIF
  output when a rejected verdict lacks a file:line reference in `verdict_evidence.trace`.
  This is breaking for such reports, including verdicts carried forward from older baselines.
- `SKILL.md` treats scanned repository content as data, never instructions; claims that a finding
  is safe, reviewed, or a false positive are never evidence. Reviewers must verify that cited lines
  are real non-comment code showing the control or unreachability; no script checks this.

## [1.4.0] - 2026-09-16

### Added in 1.4.0

- Evidence-backed `confirmed`, `needs_validation`, and `rejected` finding verdicts with baseline
  carry-forward, Markdown grouping, and SARIF review states.
- Published schemas for findings reports, scan plans, and evidence runs, plus a stdlib validator and
  automatic normalized-report validation.
- Guidance for using deterministic scanner evidence before a complementary logic-level audit.

## [1.3.1] - 2026-09-16

### Fixed in 1.3.1

- Verified all scanner parsers against real output and replaced synthetic fixtures with trimmed
  real finding and clean runs.
- Corrected govulncheck JSON-stream parsing, Composer and bundler-audit schemas, OSV severity and
  fix extraction, package versions, and zizmor source locations.
- Added runner-managed Semgrep evidence and corrected pip-audit and Gitleaks planner commands.

## [1.3.0] - 2026-09-16

### Added in 1.3.0

- Bun planning, OSV-Scanner lockfile fallbacks, IaC detection, filesystem secret scanning, and
  offline GitHub Actions audits in planner schema v2.
- A read-only plan runner with execution metadata, timeout and scope controls, and evidence
  redaction before persistence.
- A fixture-tested findings normalizer with JSON, SARIF, and Markdown output, OWASP mapping,
  severity normalization, stable fingerprints, and baseline diffs.
- End-to-end planner, runner, normalizer, evidence layout, baseline, and SARIF documentation.
- A validated Claude Code plugin manifest for skills-directory installations.

## [1.2.0] - 2026-09-16

### Added

- Repeatable planner exclusions with `--exclude`.
- Containerfile detection alongside Dockerfile detection.
- Actionable export guidance for uv and Poetry lockfiles.
- Installation and report examples plus a private vulnerability reporting policy.
- Python 3.10, 3.12, and 3.13 CI coverage and weekly GitHub Actions dependency updates.

## [1.1.0] - 2026-08-22

### Changed

- Deterministic monorepo and package-manager detection through `scripts/scan_plan.py`.
- Correct separation of scanner findings from tool failures and skipped coverage.
- Consistent OWASP Top 10:2025 normalization, including legacy Semgrep labels.
- Mandatory secret redaction and reproducible report metadata.
- Structured false-positive review instead of conversation-only memory.
- Cross-client instructions without Claude-specific `Task` or settings paths.

## [1.0.0] - 2026-01-18

- Initial release.

[Unreleased]: https://github.com/Ray0907/security-scan/compare/v1.11.0...HEAD
[1.11.0]: https://github.com/Ray0907/security-scan/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/Ray0907/security-scan/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/Ray0907/security-scan/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/Ray0907/security-scan/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/Ray0907/security-scan/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Ray0907/security-scan/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Ray0907/security-scan/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Ray0907/security-scan/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Ray0907/security-scan/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Ray0907/security-scan/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Ray0907/security-scan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Ray0907/security-scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Ray0907/security-scan/releases/tag/v1.0.0
