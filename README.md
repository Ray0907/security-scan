# Security Scan

[![Agent Skills compatible](https://img.shields.io/badge/Agent%20Skills-compatible-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Ray0907/security-scan)](https://github.com/Ray0907/security-scan/releases)
[![Validate](https://github.com/Ray0907/security-scan/actions/workflows/validate.yml/badge.svg)](https://github.com/Ray0907/security-scan/actions/workflows/validate.yml)

An [Agent Skills](https://agentskills.io/specification) security workflow for AI coding agents.
It plans and runs read-only dependency audits, Semgrep code-pattern scans, infrastructure
misconfiguration checks, secret detection, and GitHub Actions audits, then normalizes everything
into one OWASP Top 10:2025 mapped report with fingerprints, baseline diffs, and SARIF output.

See the [changelog](CHANGELOG.md) for release history.

## When to use this skill

- Use this skill for a deterministic scanner baseline with reproducible evidence and normalized
  findings.
- Use Cloudflare's complementary
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) for a logic-level
  source audit.
- For both, run this skill first and provide `security-findings.json` to the audit as prior evidence.

## Safety Model

Scanning is read-only by default. The skill does not install tools, update dependencies, execute
project scripts, build images, or change global agent settings without explicit approval. Missing
or failed scanners are reported as incomplete coverage, never as a clean result.

## Installation

With the [Skills CLI](https://skills.sh), which installs into any supported coding agent:

```bash
npx skills add Ray0907/security-scan
# user-level instead of project-level
npx skills add Ray0907/security-scan --global
```

For Claude Code without the CLI:

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

The local pipeline is:

```bash
python3 scripts/scan_plan.py . --pretty > plan.json
python3 scripts/run_plan.py plan.json --out scan-evidence --semgrep
python3 scripts/normalize_findings.py scan-evidence --out security-findings.unreviewed.json
# Review findings and write verdicts.json keyed by fingerprint.
python3 scripts/normalize_findings.py scan-evidence --verdicts verdicts.json \
  --out security-findings.json
python3 scripts/validate_report.py security-findings.json
```

Unreviewed code findings must remain labeled unreviewed. Add `--baseline security-findings.json` on
repeat scans, or `--format sarif` when preparing output for GitHub code scanning.

## Example

A monorepo with a Bun app, an npm app, an `infra/` directory holding a Dockerfile and a Kubernetes
manifest, and a GitHub Actions workflow:

```bash
python3 scripts/scan_plan.py /work/app --exclude infra/legacy --pretty
```

```json
{
  "excluded": ["infra/legacy"],
  "projects": [
    {
      "kind": "ci",
      "path": ".",
      "status": "ready",
      "tool": "zizmor",
      "coverage": "offline-audits-only",
      "command": ["zizmor", "--format", "json", "--offline", ".github/workflows"]
    },
    {
      "kind": "secrets",
      "path": ".",
      "status": "ready",
      "tool": "gitleaks",
      "coverage": "filesystem-only",
      "command": ["gitleaks", "dir", ".", "--no-banner", "--redact", "--report-format", "json", "--report-path", "-"]
    },
    {
      "kind": "node",
      "path": "bunapp",
      "status": "ready",
      "tool": "bun",
      "command": ["bun", "audit", "--json"]
    },
    {
      "kind": "container",
      "path": "infra",
      "status": "ready",
      "tool": "trivy",
      "coverage": "misconfiguration-only",
      "evidence": ["pod.yaml"],
      "command": ["trivy", "fs", "--format", "json", "--scanners", "misconfig", "."]
    },
    {
      "kind": "node",
      "path": "npmapp",
      "status": "ready",
      "tool": "npm",
      "command": ["npm", "audit", "--json"]
    }
  ],
  "root": "/work/app",
  "schema_version": 2
}
```

After normalization and review, each finding keeps its native identity and adds normalized fields
and an evidence-backed verdict:

```json
{
  "aliases": ["1097678"],
  "confidence": "unknown",
  "cwe": ["CWE-1321"],
  "fingerprint": "26011568e34bedbe",
  "fixed_versions": [],
  "id": "GHSA-xvch-5gv4-984h",
  "installed_version": null,
  "line": null,
  "location": "bun.lock",
  "native_severity": "critical",
  "normalized_severity": "critical",
  "owasp_2025": ["A03"],
  "package": "minimist",
  "references": ["https://github.com/advisories/GHSA-xvch-5gv4-984h"],
  "rule_id": null,
  "source": "bun",
  "summary": "Prototype Pollution in minimist",
  "type": "dependency",
  "verdict": "confirmed",
  "verdict_evidence": {
    "reason": "bun audit reports the locked minimist release in the vulnerable range and no fixed release is locked.",
    "reviewed_at": "2026-09-16T00:00:00+00:00",
    "reviewer": "security-reviewer",
    "trace": "minimist -> bun.lock",
    "unresolved_fact": null
  }
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

## Supported Scanners

| Target | Evidence | Tool |
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
4. Review assigns `confirmed`, `needs_validation`, or `rejected` verdicts with evidence; omitted
   verdicts remain unreviewed.
5. The normalizer and `scripts/validate_report.py` enforce the published JSON report schema.
6. Semgrep runs with `p/owasp-top-ten` and metrics disabled for code-pattern coverage.
7. Findings retain native advisory IDs and are normalized to OWASP 2025 only when supported.
8. Reports list every scanner as `clean`, `findings`, `failed`, `skipped`, or `inconclusive`.

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
├── schema/
│   ├── run.schema.json
│   ├── scan-plan.schema.json
│   └── security-findings.schema.json
├── scripts/
│   ├── normalize_findings.py
│   ├── redaction.py
│   ├── run_plan.py
│   ├── scan_plan.py
│   └── validate_report.py
├── tests/
│   ├── fixtures/               # Minimal scanner output samples
│   ├── test_normalize_findings.py
│   ├── test_run_plan.py
│   ├── test_scan_plan.py
│   └── test_validate_report.py
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

Contributions are welcome. Include a regression test for planner or runner behavior, and add a
minimal fixture under `tests/fixtures/<tool>/` for any new or changed scanner parser. Run all
validation commands before opening a pull request.

## License

[MIT](LICENSE)
