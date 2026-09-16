# Security Scan

[![Agent Skills compatible](https://img.shields.io/badge/Agent%20Skills-compatible-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An [Agent Skills](https://agentskills.io/specification) security workflow for dependency audits,
Semgrep code-pattern scanning, OWASP Top 10:2025 mapping, and reviewable findings.

See the [changelog](CHANGELOG.md) for release history.

## Safety Model

Scanning is read-only by default. The skill does not install tools, update dependencies, execute
project scripts, build images, or change global agent settings without explicit approval. Missing
or failed scanners are reported as incomplete coverage, never as a clean result.

## Installation

For Claude Code:

```bash
git clone https://github.com/Ray0907/security-scan.git ~/.claude/skills/security-scan
```

Restart Claude Code, open `/plugin`, and verify `security-scan@skills-dir` is enabled. The bundled
Claude Code plugin manifest points its skill directory at this repository root.

Other clients use their own skills directory. Consult the client's documentation for its install
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

The local three-command pipeline is:

```bash
python3 scripts/scan_plan.py . --pretty > plan.json
python3 scripts/run_plan.py plan.json --out scan-evidence
python3 scripts/normalize_findings.py scan-evidence --out security-findings.json
```

Add `--baseline security-findings.json` on repeat scans, or `--format sarif` when preparing output
for GitHub code scanning.

## Example

For a monorepo with a pnpm app, a Python API with a Dockerfile, and an unlocked Rust crate:

```bash
python3 scripts/scan_plan.py /work/app --exclude web/fixtures --pretty
```

```json
{
  "excluded": ["web/fixtures"],
  "projects": [
    {
      "kind": "rust",
      "path": ".",
      "status": "needs-lockfile",
      "tool": "cargo-audit",
      "command": null,
      "reason": "Cargo.toml exists without Cargo.lock"
    },
    {
      "kind": "container",
      "path": "api",
      "status": "ready",
      "tool": "trivy",
      "coverage": "misconfiguration-only",
      "command": ["trivy", "fs", "--format", "json", "--scanners", "misconfig", "."]
    },
    {
      "kind": "python",
      "path": "api",
      "status": "ready",
      "tool": "pip-audit",
      "command": ["pip-audit", "--format", "json", "-r", "requirements.txt"]
    },
    {
      "kind": "node",
      "path": "web",
      "status": "ready",
      "tool": "pnpm",
      "command": ["pnpm", "audit", "--json"]
    }
  ],
  "root": "/work/app",
  "schema_version": 1
}
```

A completed report records every scanner state explicitly:

| Scanner | Status | Example detail |
| --- | --- | --- |
| npm audit | `clean` | No advisories found |
| pip-audit | `findings` | 2 advisories found |
| Semgrep | `failed` | Ruleset download timed out |
| cargo-audit | `skipped` | Tool unavailable |
| Trivy | `inconclusive` | No supported lockfile |

## Supported Dependency Evidence

| Ecosystem | Primary evidence | Tool |
| --- | --- | --- |
| Node.js | pnpm, Yarn, npm, or Bun lockfile | Matching package manager audit |
| Python | Requirements or `pylock.*.toml` | `pip-audit` |
| Fallback ecosystems | uv, Poetry, Pipenv, Dart, Elixir, Swift, .NET, Deno lockfile | OSV-Scanner |
| Go | `go.mod` | `govulncheck` |
| Rust | `Cargo.lock` | `cargo-audit` |
| PHP | `composer.lock` | Composer audit |
| Ruby | `Gemfile.lock` | `bundler-audit` |
| Java | Maven or Gradle manifest | Trivy filesystem fallback |
| Container | `Dockerfile*`, `Containerfile*` | Trivy misconfiguration scan |
| Infrastructure as code | Terraform, Compose, Kubernetes YAML | Trivy misconfiguration scan |
| Secrets | Repository filesystem | Gitleaks |
| CI workflows | GitHub Actions YAML | Zizmor offline audits |

A Dockerfile or Containerfile alone is not an image vulnerability inventory. Image scanning
requires an existing image supplied by the user; this skill does not build untrusted repositories
during a scan.

## How It Works

1. `scripts/scan_plan.py` recursively inventories supported projects and emits a JSON execution
   plan without running a scanner.
2. `scripts/run_plan.py` executes ready records without a shell and stores redacted evidence.
3. `scripts/normalize_findings.py` parses scanner output, applies baselines and filters, and emits
   JSON, SARIF, or Markdown.
4. Semgrep runs with `p/owasp-top-ten` and metrics disabled for code-pattern coverage.
5. Findings retain native advisory IDs and are normalized to OWASP 2025 only when supported.
6. Reports list every scanner as `clean`, `findings`, `failed`, `skipped`, or `inconclusive`.

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
├── .claude-plugin/plugin.json
├── .github/workflows/validate.yml
├── docs/                       # Design documents
├── scripts/
│   ├── normalize_findings.py
│   ├── redaction.py
│   ├── run_plan.py
│   └── scan_plan.py
├── tests/
│   ├── fixtures/               # Minimal scanner output samples
│   ├── test_normalize_findings.py
│   ├── test_run_plan.py
│   └── test_scan_plan.py
├── references/
│   ├── OWASP.md
│   ├── REPORTING.md
│   └── SCANNERS.md
├── CHANGELOG.md
├── SECURITY.md
├── SKILL.md
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome. Include a regression test for planner behavior and run all validation
commands before opening a pull request.

## License

[MIT](LICENSE)
