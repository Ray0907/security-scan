# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for 1.3.0

- Bun planning, OSV-Scanner lockfile fallbacks, IaC detection, filesystem secret scanning, and
  offline GitHub Actions audits in planner schema v2.

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

[Unreleased]: https://github.com/Ray0907/security-scan/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Ray0907/security-scan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Ray0907/security-scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Ray0907/security-scan/releases/tag/v1.0.0
