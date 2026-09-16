# Real scanner fixtures

Findings fixtures are real scanner output trimmed to at most two findings. Clean fixtures came from the same commands against empty or current projects.

| Tool | Verified version | Finding command | Date |
| --- | --- | --- | --- |
| npm | 11.19.1 | `npm audit --json` | 2026-09-16 |
| pnpm | 10.30.3 | `pnpm audit --json` | 2026-09-16 |
| Yarn | 1.22.22 | `yarn audit --json` | 2026-09-16 |
| Bun | 1.3.11 | `bun audit --json` | 2026-09-16 |
| pip-audit | 2.10.1 | `pip-audit --format json --no-deps --disable-pip -r requirements.txt` | 2026-09-16 |
| govulncheck | 1.8.0 | `govulncheck -json ./...` | 2026-09-16 |
| cargo-audit | 0.22.2 | `cargo audit --json` | 2026-09-16 |
| Composer | 2.10.3 | `composer audit --locked --format=json` | 2026-09-16 |
| bundler-audit | 0.9.3 | `bundle-audit check --format json` | 2026-09-16 |
| Trivy | 0.74.0 | `trivy fs --format json --scanners misconfig .` | 2026-09-16 |
| OSV-Scanner | 2.6.0 | `osv-scanner scan source --lockfile uv.lock --format json` | 2026-09-16 |
| Semgrep | 1.176.0 | `semgrep scan --config p/owasp-top-ten --json --metrics=off .` | 2026-09-16 |
| Gitleaks | 8.30.1 | `gitleaks dir . --no-banner --redact --report-format json --report-path -` | 2026-09-16 |
| zizmor | 1.30.1 | `zizmor --format json --offline .github/workflows` | 2026-09-16 |
