# OWASP Top 10:2025 Mapping

Use this reference when normalizing scanner output or reporting OWASP coverage. The authoritative
source is the [OWASP Top 10:2025](https://owasp.org/Top10/).

OWASP Top 10 is an awareness document, not a promise that ten automated checks can prove an
application secure. Report pattern coverage and manual-review gaps separately.

## Categories

| Code | Official 2025 category | Typical evidence | Automation limit |
| --- | --- | --- | --- |
| A01 | Broken Access Control | Authorization paths, IDOR, SSRF | SAST plus manual authorization review |
| A02 | Security Misconfiguration | Headers, debug settings, cloud and server config | Configuration-dependent |
| A03 | Software Supply Chain Failures | Lockfiles, advisories, provenance, CI controls | SCA covers only known advisories |
| A04 | Cryptographic Failures | Algorithms, key handling, transport settings | Context and key lifecycle need review |
| A05 | Injection | SQL, command, template, XSS, LDAP, expression flows | SAST coverage varies by framework |
| A06 | Insecure Design | Abuse cases, rate limits, trust boundaries | Primarily threat modeling and review |
| A07 | Authentication Failures | Login, recovery, session and MFA controls | Runtime and policy review required |
| A08 | Software or Data Integrity Failures | Deserialization, signatures, CI/CD trust | Pipeline and trust-boundary review |
| A09 | Security Logging and Alerting Failures | Audit events, protection, detection, response | Operational validation required |
| A10 | Mishandling of Exceptional Conditions | Fail-open paths, resource errors, races | Tests and design review are essential |

## Translate Legacy Labels

Semgrep rules may contain 2017, 2021, and 2025 metadata together. Match the full versioned label,
not only the `Axx` number.

| OWASP 2021 label | OWASP 2025 destination |
| --- | --- |
| A01 Broken Access Control | A01 Broken Access Control |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | A02 Security Misconfiguration |
| A06 Vulnerable and Outdated Components | A03 Software Supply Chain Failures |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery | A01 Broken Access Control |

If a scanner's numeric label conflicts with the category name or CWE, prefer the official 2025
category meaning, preserve the original metadata, and record that normalization occurred.

## Mapping Rules

- Map dependency advisories to A03 when they concern vulnerable components or supply-chain risk.
- Map code findings using verified CWE/category meaning. Do not infer from a bare `A03` string.
- `JSON.parse(userInput)` is not insecure deserialization by itself. Require an unsafe object,
  type-confusion, gadget, or trust-boundary condition before reporting A08.
- Missing MFA, rate limits, logging, or alerting usually require configuration or design evidence;
  absence of a Semgrep finding is not evidence those controls exist.
- SSRF belongs to A01 in 2025. Preserve an `A10:2021` source label, then normalize it to A01:2025.

## Coverage States

For every category, report one of:

- `findings`: relevant findings exist.
- `automated-covered`: at least one applicable scanner ran successfully; this is not a guarantee.
- `manual-review-needed`: the category cannot be assessed adequately from automated results.
- `not-scanned`: no applicable check ran.
- `not-applicable`: supported by documented scope evidence, not assumption.

A full scan should almost always retain manual-review work for A06, A07, A09, and A10.
