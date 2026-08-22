# Reporting Contract

Use this reference when presenting scan results, saving report files, or documenting reviewed false
positives.

## Required Scan Metadata

Record enough evidence to reproduce and interpret the result:

- project path, project name, Git commit, branch, and dirty-worktree state;
- scan date, requested mode, included paths, excluded paths, and detected ecosystems;
- every scanner's command, working directory, version, duration, and final state;
- ruleset or advisory database identity and freshness when available;
- failures, skipped tools, inconclusive projects, and manual-review gaps.

Use exactly these scanner states: `clean`, `findings`, `failed`, `skipped`, and `inconclusive`.
`Clean` applies only to the named tool and recorded scope; it never means the application is secure.

## Finding Schema

Keep the native identifier and severity alongside normalized values:

```json
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "aliases": ["CVE-YYYY-NNNN"],
  "source": "pnpm",
  "type": "dependency",
  "package": "example",
  "installed_version": "1.0.0",
  "fixed_versions": ["1.0.1"],
  "native_severity": "high",
  "normalized_severity": "high",
  "owasp_2025": ["A03"],
  "location": "pnpm-lock.yaml",
  "summary": "Redacted summary",
  "references": []
}
```

For code findings, add the rule ID, file, line, CWE, confidence, and a redacted snippet. Do not
invent a normalized severity when the scanner provides no defensible mapping; use `unknown`.

## Secret Redaction

Reports and chat must not contain credentials, tokens, private keys, passwords, connection strings,
or sensitive personal data.

- Replace the value with `[REDACTED]`; retain only the variable name and location.
- Do not preserve prefixes, suffixes, or "last four" characters of a secret.
- Build fingerprints from stable metadata such as rule ID, path, and line—not the secret value.
- Redact stdout and stderr before saving raw scanner evidence.
- If reliable redaction is uncertain, omit the snippet and explain why.

## Markdown Report

Use this order:

1. Executive summary and severity counts.
2. Scope and reproducibility metadata.
3. Scanner status table, including failures and skipped coverage.
4. Findings ordered by normalized severity, confidence, then stable identifier.
5. OWASP 2025 coverage table with automated and manual-review status.
6. Prioritized remediation with fixed versions where verified.
7. Reviewed false positives and accepted risks.
8. Limitations and incomplete enrichment.

When NVD data is included, add this notice:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Do not overwrite `security-report.md` or `security-findings.json` without confirmation. A chat-only
request does not require writing either file.

## False Positive Records

A user assertion alone is not technical verification. Record each reviewed item as structured data:

| Field | Requirement |
| --- | --- |
| Finding identity | Native advisory or rule ID plus fingerprint |
| Scope | Commit SHA, file and line, package version, or dependency path |
| Reason | Specific reason the vulnerable condition is unreachable or controlled |
| Evidence | Validation, call path, configuration, test, or compensating control |
| Decision | False positive, accepted risk, deferred, or fixed |
| Owner | Person or team accepting the decision |
| Dates | Review date and expiration or next-review date |
| Scanner | Tool, version, and ruleset or advisory database |

Do not call a finding false positive merely because input is "internal." Verify the trust boundary,
validation, authorization, and failure behavior. If evidence is incomplete, classify it as accepted
risk or pending review instead.

Export DOCX or PDF only when explicitly requested and a compatible document tool is available.
Otherwise preserve the structured Markdown/JSON record and state that the requested export was not
generated.
