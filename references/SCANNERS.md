# Scanner Contract

Use this reference when planning or running dependency scanners.

## Plan First

Run the bundled planner from the skill directory:

```bash
python3 scripts/scan_plan.py <project-root> --pretty
```

The planner is read-only. It recursively detects projects, skips dependency and build directories,
and emits one record per ecosystem. Each record has a working directory, tool, command, and state:

- `ready`: run the exact argument list from the recorded working directory.
- `needs-lockfile`: do not perform a non-reproducible audit; mark the project inconclusive.
- `needs-export`: the manifest cannot be audited reliably without user preparation.

Do not replace the planner's package-manager choice with an `npm || yarn || pnpm` fallback.

## Tool Matrix

| Ecosystem | Evidence | Read-only command |
| --- | --- | --- |
| pnpm | `pnpm-lock.yaml` | `pnpm audit --json` |
| Yarn 2+ | `yarn.lock` plus `packageManager` or `.yarnrc.yml` | `yarn npm audit --json --all --recursive` |
| Yarn 1 | `yarn.lock` | `yarn audit --json` |
| npm | `package-lock.json` or `npm-shrinkwrap.json` | `npm audit --json` |
| Python requirements | `requirements*.txt` | `pip-audit --format json -r <file>` |
| Python locked project | `pylock.*.toml` | `pip-audit --format json --locked .` |
| Go | `go.mod` | `govulncheck -json ./...` |
| Rust | `Cargo.lock` | `cargo audit --json` |
| PHP | `composer.lock` | `composer audit --locked --format=json` |
| Ruby | `Gemfile.lock` | `bundle-audit check --format json` |
| Java fallback | Maven or Gradle manifest | `trivy fs --format json --scanners vuln .` |
| Dockerfile | `Dockerfile*` | `trivy fs --format json --scanners misconfig .` |

Important limitations:

- A bare `package.json`, `pyproject.toml`, or `Cargo.toml` is not a reproducible vulnerability
  inventory. Do not resolve and install an untrusted project merely to make it scannable.
- `pip-audit` without a path or `-r` audits the ambient Python environment; never use that as the
  project result.
- `Pipfile.lock` is not directly supported by `pip-audit`. Ask the user to export a requirements
  file or use an explicitly approved fallback.
- A Dockerfile scan checks configuration only. Do not claim image vulnerability coverage unless
  the user supplies a built image and authorizes an image scan.
- `govulncheck` may not provide a severity. Preserve `unknown`; never invent a CVSS value.
- pnpm 11 reports GHSA identifiers from its registry endpoint. Do not relabel them as CVEs without
  a verified alias.
- `bundler-audit` depends on a local advisory database. Record its freshness; ask before updating
  it, and mark stale or missing data as inconclusive.

## Classify Results

Capture stdout, stderr, exit code, command, working directory, duration, and tool version. Parse
machine-readable output before classifying the run:

- Valid output with findings: `findings`, even if the process exits non-zero.
- Valid output with no findings: `clean` for that scanner and scope only.
- Invalid or truncated output, timeout, network error, or unexpected exit: `failed`.
- Tool unavailable: `skipped`.
- Missing lockfile, unsupported manifest, or stale data: `inconclusive`.

Never discard stderr with `2>/dev/null`. Never merge output from different package managers.

## Semgrep

Use the community ruleset for pattern coverage:

```bash
semgrep scan --config p/owasp-top-ten --json --metrics=off <project-root>
```

Registry rules change over time. Record the Semgrep version, ruleset name, scan date, and rule IDs.
Do not describe this ruleset as complete OWASP 2025 coverage.

## Missing Tools

Offer official installation options, but do not execute them without approval:

```bash
pipx install semgrep
uv tool install semgrep
uv tool install pip-audit
go install golang.org/x/vuln/cmd/govulncheck@latest
cargo install cargo-audit
gem install bundler-audit
brew install trivy
```

Composer and the relevant Node package manager are expected to come from the project toolchain.
Avoid remote-script pipelines such as `curl ... | sh`.

## NVD Enrichment

Use the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) only for verified CVE IDs.
The `cveId` parameter is deprecated; use comma-separated `cveIds`, at most 100 per request. Without
an API key, limit requests to 5 per rolling 30 seconds and wait at least 6 seconds between calls.

Use `curl --fail --show-error --silent`, validate the JSON response, cache results for the scan, and
handle 403/429/5xx responses. Pass an API key through the `apiKey` header and never print it. If NVD
is unavailable, keep the original advisory result and mark enrichment failed rather than removing
the finding.
