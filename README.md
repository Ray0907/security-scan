# Security Scan

[![agentskills.io](https://img.shields.io/badge/agentskills.io-compatible-blue)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Comprehensive security scanning skill following [agentskills.io](https://agentskills.io) specification. Combines CVE vulnerability detection, OWASP Top 10 (2025) code pattern analysis, and dependency audits.

## Compatibility

This skill follows the [Agent Skills Specification](https://agentskills.io/specification) and works with:

- **Claude Code** (Anthropic)
- **Codex CLI** (OpenAI)
- **Gemini CLI** (Google)
- Any AI coding agent supporting agentskills.io format

## Features

- **Dependency Scanning** - Detect known CVE vulnerabilities in project dependencies
- **OWASP Top 10** - Scan code for common security anti-patterns
- **Multi-language** - Auto-detect project type and use appropriate tools
- **Parallel Execution** - Subagent architecture for faster scanning
- **Detailed Reports** - CLI summary + Markdown report
- **False Positive Export** - Generate DOCX report for audit/compliance

## Installation

### Required

```bash
# Semgrep (OWASP code pattern scanning)
npm install -g semgrep
# or
pip install semgrep
# or
brew install semgrep
```

### Language-Specific (auto-installed prompt)

The skill will detect your project type and prompt for missing tools:

```bash
# Python
pip install pip-audit

# Go
go install golang.org/x/vuln/cmd/govulncheck@latest

# Rust
cargo install cargo-audit

# Multi-language / Container fallback
brew install trivy
```

**Node.js:** `npm audit` / `yarn audit` / `pnpm audit` are built-in.

### For Report Export (Optional)

Uses existing skills for document generation:
- **DOCX**: https://github.com/anthropics/skills/tree/main/skills/docx
- **PDF**: https://github.com/anthropics/skills/tree/main/skills/pdf

## Usage

```bash
# Full scan (dependencies + OWASP code patterns)
/security-scan

# Dependencies only
/security-scan --deps-only

# Code patterns only (OWASP)
/security-scan --code-only

# Specific OWASP category
/security-scan --owasp A03

# Filter by severity
/security-scan --severity critical,high

# Auto-remind settings (default: off)
/security-scan --auto-remind on
/security-scan --auto-remind off

# Export false positive report (after review)
/security-scan --export-bypass           # DOCX (default)
/security-scan --export-bypass --pdf     # PDF format
/security-scan --export-bypass --template ./template.docx  # Custom DOCX template
/security-scan --export-bypass --pdf --template ./template.pdf  # Custom PDF template
```

## Supported Languages

| Language | Detection File | Scan Tool |
|----------|---------------|-----------|
| Node.js | package.json, yarn.lock, pnpm-lock.yaml | npm/yarn/pnpm audit |
| Python | requirements.txt, Pipfile.lock, pyproject.toml | pip-audit |
| Go | go.mod | govulncheck |
| Rust | Cargo.toml | cargo audit |
| PHP | composer.json | composer audit |
| Ruby | Gemfile.lock | bundler-audit |
| Java | pom.xml, build.gradle | trivy |
| Container | Dockerfile | trivy |

## OWASP Top 10 Coverage (2025)

Source: https://owasp.org/Top10/2025/

| Code | Category | Examples |
|------|----------|----------|
| A01 | Broken Access Control | Missing auth checks, IDOR |
| A02 | Security Misconfiguration | Debug enabled, default credentials |
| A03 | Software Supply Chain | Vulnerable dependencies, typosquatting |
| A04 | Cryptographic Failures | Weak encryption, hardcoded secrets |
| A05 | Injection | SQL injection, XSS, command injection |
| A06 | Insecure Design | Missing rate limits, business logic flaws |
| A07 | Authentication Failures | Weak passwords, session fixation |
| A08 | Integrity Failures | Insecure deserialization, unsigned JWTs |
| A09 | Logging & Alerting Failures | Missing audit logs, no alerting |
| A10 | Exceptional Conditions | Fail-open errors, unhandled exceptions |

## Output

### CLI Summary

```
Security Scan Results
=====================

Scanned: Node.js (npm)
Duration: 8.2s

CRITICAL  1   [!!] Immediate action required
HIGH      3   [!]  Fix soon
MEDIUM    5   [ ]  Review recommended
LOW       2   [ ]  Minor issues

Top Issues:
-------------------------------------------------------------
[CRITICAL] CVE-2024-1234 - Prototype pollution in lodash
           Package: lodash@4.17.20 -> Fix: upgrade to 4.17.21
           OWASP: A05 Injection

[HIGH] A05-Injection - SQL Injection detected
       File: src/db/users.ts:45
       Code: `db.query(\`SELECT * FROM users WHERE id = ${id}\`)`
-------------------------------------------------------------

Full report: ./security-report.md
```

### Markdown Report

Generates `security-report.md` with:
- Summary table (severity counts)
- OWASP Top 10 coverage status
- Dependency vulnerabilities (grouped by severity)
- Code vulnerabilities (grouped by OWASP category)
- Remediation recommendations

## Architecture

```
/security-scan (Main Agent)
         |
         v
    Codebase Detection
         |
    +----+----+
    v         v
Subagent 1  Subagent 2    (parallel)
Dependency  OWASP/Code
Scanner     Scanner
    +----+----+
         |
         v
    Subagent 3             (sequential)
    CVE Enrichment
    (NVD API)
         |
         v
    Report Generator
    - CLI summary
    - security-report.md
```

## APIs Used

- **NVD API** - https://services.nvd.nist.gov/rest/json/cves/2.0
  - Free, rate limit: 5 req/30s (no key), 50 req/30s (with key)
- **Semgrep Registry** - `p/owasp-top-ten` ruleset

## Auto-Remind Feature

Disabled by default. When enabled, prompts before:
- Git commit
- Adding new dependencies
- Modifying sensitive files (auth, db, api)

```bash
# Enable
/security-scan --auto-remind on

# Disable
/security-scan --auto-remind off
```

## False Positive Report

For audit and compliance purposes, you can document false positives in a DOCX report.

### Workflow

1. Run `/security-scan` to get scan results
2. Review results and tell Claude which items are false positives with reasons
3. Run `/security-scan --export-bypass` to generate DOCX report

### Example

```
You: "CVE-2024-1234 is a false positive - we don't use the affected function"
Claude: "Noted. CVE-2024-1234 marked as false positive."

You: "The SQL injection in src/db.ts:45 is safe, id is validated internally"
Claude: "Noted. A03-Injection in src/db.ts:45 marked as false positive."

You: "/security-scan --export-bypass"
Claude: [Generates false-positive-report.docx]
```

### Output

Generates `false-positive-report.docx` (or `.pdf` with `--pdf` flag) containing:
- Scan date and project info
- Each false positive with:
  - Vulnerability ID (CVE or OWASP rule)
  - File location
  - Severity
  - User-provided reason

### Custom Template (Optional)

Provide your own branded template with placeholders:

| Placeholder | Description |
|-------------|-------------|
| `{{scan_date}}` | Scan date |
| `{{project_name}}` | Project name |
| `{{scope}}` | Scanned languages/tools |
| `{{false_positives}}` | List of items |
| `{{item.id}}` | CVE/OWASP rule |
| `{{item.severity}}` | Severity level |
| `{{item.reason}}` | False positive reason |

## Skill Structure

Following [agentskills.io specification](https://agentskills.io/specification):

```
security-scan/
├── SKILL.md              # Main skill instructions
├── README.md             # Documentation
├── references/
│   └── OWASP.md          # OWASP Top 10 2025 detailed reference
├── scripts/              # Executable scripts (future)
└── assets/               # Templates and static resources (future)
```

## Related Files

- `SKILL.md` - Skill instructions (loaded by AI agent)
- `references/OWASP.md` - Detailed OWASP 2025 reference (on-demand)
- `./security-report.md` - Generated report (per project)
- `./false-positive-report.docx` - False positive report (when exported)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Author

**Ray Tien** - [@Ray0907](https://github.com/Ray0907)

## License

MIT
