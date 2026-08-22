# Security Scan

[![Agent Skills compatible](https://img.shields.io/badge/Agent%20Skills-compatible-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An [Agent Skills](https://agentskills.io/specification) security workflow for dependency audits,
Semgrep code-pattern scanning, OWASP Top 10:2025 mapping, and reviewable findings.

## What Changed in 1.1

- Deterministic monorepo and package-manager detection through `scripts/scan_plan.py`.
- Correct separation of scanner findings from tool failures and skipped coverage.
- Consistent OWASP Top 10:2025 normalization, including legacy Semgrep labels.
- Mandatory secret redaction and reproducible report metadata.
- Structured false-positive review instead of conversation-only memory.
- Cross-client instructions without Claude-specific `Task` or settings paths.

## Safety Model

Scanning is read-only by default. The skill does not install tools, update dependencies, execute
project scripts, build images, or change global agent settings without explicit approval. Missing
or failed scanners are reported as incomplete coverage, never as a clean result.

## Installation

Clone or copy this directory into the skills location documented by your Agent Skills-compatible
client. The Agent Skills standard defines the package format, but each client chooses its install
location and invocation UI.

Code scanning requires Python 3.10 or newer and Semgrep. Officially recommended Semgrep installs:

```bash
pipx install semgrep
# or
uv tool install semgrep
```

Dependency tools are needed only for ecosystems detected in the target repository. See
[`references/SCANNERS.md`](references/SCANNERS.md) for commands and limitations.

## Usage

Ask naturally or use slash-command-style arguments if the client supports them:

```text
Scan this repository for security issues.
/security-scan
/security-scan --deps-only
/security-scan --code-only
/security-scan --owasp A05
/security-scan --severity critical,high
/security-scan --export-bypass
```

`--deps-only` and `--code-only` are mutually exclusive. Persistent reminders are client-specific;
the skill will not claim `--auto-remind` is active until a supported hook or automation is chosen.

## Supported Dependency Evidence

| Ecosystem | Primary evidence | Tool |
| --- | --- | --- |
| Node.js | pnpm, Yarn, or npm lockfile | Matching package manager audit |
| Python | Requirements or `pylock.*.toml` | `pip-audit` |
| Go | `go.mod` | `govulncheck` |
| Rust | `Cargo.lock` | `cargo-audit` |
| PHP | `composer.lock` | Composer audit |
| Ruby | `Gemfile.lock` | `bundler-audit` |
| Java | Maven or Gradle manifest | Trivy filesystem fallback |
| Dockerfile | `Dockerfile*` | Trivy misconfiguration scan |

A Dockerfile alone is not an image vulnerability inventory. Image scanning requires an existing
image supplied by the user; this skill does not build untrusted repositories during a scan.

## How It Works

1. `scripts/scan_plan.py` recursively inventories supported projects and emits a JSON execution
   plan without running a scanner.
2. Each planned dependency command runs independently from its project directory.
3. Semgrep runs with `p/owasp-top-ten` and metrics disabled for code-pattern coverage.
4. Findings retain native advisory IDs and are normalized to OWASP 2025 only when supported.
5. Reports list every scanner as `clean`, `findings`, `failed`, `skipped`, or `inconclusive`.

Detailed contracts:

- [`references/SCANNERS.md`](references/SCANNERS.md): commands, exit handling, and NVD enrichment.
- [`references/OWASP.md`](references/OWASP.md): 2025 categories and legacy-label translation.
- [`references/REPORTING.md`](references/REPORTING.md): redaction, report schema, and false positives.

## Development

Run the deterministic tests and official format validator:

```bash
python3 -m unittest discover -s tests -v
uvx --from skills-ref agentskills validate "$(pwd)"
```

Validate the external Semgrep ruleset separately:

```bash
semgrep scan --config p/owasp-top-ten --validate --metrics=off
```

## Structure

```text
security-scan/
├── .github/workflows/validate.yml
├── scripts/scan_plan.py
├── tests/test_scan_plan.py
├── references/
│   ├── OWASP.md
│   ├── REPORTING.md
│   └── SCANNERS.md
├── SKILL.md
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome. Include a regression test for planner behavior and run all validation
commands before opening a pull request.

## License

[MIT](LICENSE)
