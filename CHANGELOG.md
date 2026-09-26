# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added in Unreleased

- Read-only OSV license-compliance scans for Node, Python, and Rust lockfiles with SPDX-expression
  severity classification, local-package provenance filtering, and explicit inconclusive coverage.
- `run_plan.py --jobs N` runs scanners for distinct tools concurrently. Records sharing a tool
  stay sequential as a precaution against cache/advisory-database lock conflicts (e.g. Trivy,
  cargo-audit); see `references/SCANNERS.md` for what was and was not confirmed in testing.

### Changed in Unreleased

- Findings in subdirectory projects now include the project path in their fingerprint. Existing
  baselines and verdict files will report those findings as new once.

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

[Unreleased]: https://github.com/Ray0907/security-scan/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/Ray0907/security-scan/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Ray0907/security-scan/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Ray0907/security-scan/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Ray0907/security-scan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Ray0907/security-scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Ray0907/security-scan/releases/tag/v1.0.0
