---
name: security-scan
description: Use when a user asks to scan a repository for dependency vulnerabilities, insecure code patterns, CVEs, or OWASP Top 10 risks.
license: MIT
metadata:
  author: Ray Tien
  version: "1.3.1"
---

# Security Scan

Produce an evidence-backed security assessment without changing application code or dependencies.

## Boundaries

- Treat scanning as read-only. Do not install tools, update advisory databases, build images,
  run project scripts, or modify global client settings without explicit approval.
- Never report a clean scan when a tool failed, was missing, or could not cover the target.
- Never copy secret values into chat or reports. Follow
  [the reporting and redaction contract](references/REPORTING.md).
- Scan every detected project in a monorepo, not only the repository root.

## Interpret the Request

Default to dependency and code scanning. Apply these modes before running tools:

- `--deps-only`: skip Semgrep.
- `--code-only`: skip dependency scanners.
- `--owasp A01` through `A10`: retain only findings mapped to that 2025 category.
- `--severity critical,high`: filter after normalizing scanner output.
- `--export-bypass`: read the reporting reference and export reviewed false positives only.
- `--auto-remind`: explain that reminders are client-specific. Do not claim they are enabled or
  write client configuration until the user chooses a supported hook or automation.

Reject incompatible `--deps-only` and `--code-only` requests instead of guessing.

## Workflow

1. Record the repository path, Git commit, requested modes, scope, and exclusions.
2. Read [the scanner contract](references/SCANNERS.md). Build the dependency plan, repeating
   `--exclude` for each user-requested relative path:

   ```bash
   python3 <skill-root>/scripts/scan_plan.py <project-root> \
     [--exclude <relative-path>] --pretty
   ```

3. Review schema v2 `fallback`, `note`, and `evidence` fields, including root secrets and CI
   records. Run ready records into a new evidence directory:

   ```bash
   python3 <skill-root>/scripts/run_plan.py plan.json --out scan-evidence [--semgrep]
   ```

   Never chain package managers with `||`; a non-zero exit may mean findings, not tool failure.
4. Normalize the evidence before interpreting results:

   ```bash
   python3 <skill-root>/scripts/normalize_findings.py scan-evidence --out security-findings.json
   ```

   For repeat scans, pass `--baseline security-findings.json`. Use `--format sarif` for a GitHub
   code-scanning upload. Read every normalized scanner state and reason; normalization does not
   replace the completion gate for `failed`, `skipped`, or `inconclusive` coverage.
5. Do not run planner records marked `inconclusive`; their command is null because project evidence
   is ambiguous. Preserve the planner's reason and report the affected scope as incomplete. Mark
   `needs-lockfile`, `needs-export`, and missing-tool entries as `inconclusive` or `skipped`. Offer
   installation or preparation instructions, but do not perform them without approval.
6. Unless code scanning was disabled, pass `--semgrep` to the evidence runner. It appends this
   root-level command as a code-scanning evidence record:

   ```bash
   semgrep scan --config p/owasp-top-ten --json --metrics=off .
   ```

   Parse the JSON even when the command exits non-zero. Treat Semgrep as pattern coverage, not
   proof that all OWASP risks were tested.
7. Read [the OWASP 2025 mapping](references/OWASP.md). Do not trust legacy 2017 or 2021 labels
   without translating them. Dependency findings map primarily to A03:2025.
8. Enrich actual CVE identifiers only when useful. Batch up to 100 IDs with the NVD `cveIds`
   parameter, honor rate limits, and preserve the scanner result if enrichment fails. Do not
   invent CVEs for GHSA, RUSTSEC, PYSEC, or other advisory identifiers.
9. Generate the result using [the reporting contract](references/REPORTING.md). Unless the user
   requested files, summarize in chat. Never overwrite an existing report without confirmation.

## Completion Gate

Report every scanner as `clean`, `findings`, `failed`, `skipped`, or `inconclusive`. Include tool
versions and uncovered scope. A scan is complete only when all planned scanners have a recorded
state and every displayed snippet has passed redaction.
