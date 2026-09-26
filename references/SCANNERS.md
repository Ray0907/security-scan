# Scanner Contract

Use this reference when planning or running dependency scanners.

## Plan First

Run the bundled planner from the skill directory:

```bash
python3 scripts/scan_plan.py <project-root> [--exclude <relative-path>] --pretty
```

The planner is read-only. It recursively detects projects, skips dependency and build directories,
and emits one record per ecosystem. Repeat `--exclude` for user-requested paths relative to the scan
root, using POSIX separators. Plan schema v2 adds optional `fallback`, `note`, and `evidence`
fields to scanner records. Each record has a working directory, tool, command, and state:

- `ready`: run the exact argument list from the recorded working directory.
- `needs-lockfile`: do not perform a non-reproducible audit; mark the project inconclusive.
- `needs-export`: the manifest cannot be audited reliably without user preparation.
- `inconclusive`: ambiguous or invalid project evidence prevents safe tool selection. The tool and
  command are null; do not run a fallback command. Preserve the reason and report incomplete
  coverage for that project.

For Node.js, conflicting package-manager lockfiles, a `packageManager`/lockfile mismatch, an
unsupported or malformed `packageManager`, or invalid `package.json` data is inconclusive. Do not
replace the planner's package-manager choice with an `npm || yarn || pnpm` fallback.

## Tool Matrix

| Ecosystem | Evidence | Read-only command |
| --- | --- | --- |
| pnpm | `pnpm-lock.yaml` | `pnpm audit --json` |
| Yarn 2+ | `yarn.lock` plus `packageManager` or `.yarnrc.yml` | `yarn npm audit --json --all --recursive` |
| Yarn 1 | `yarn.lock` | `yarn audit --json` |
| npm | `package-lock.json` or `npm-shrinkwrap.json` | `npm audit --json` |
| Bun | `bun.lock` or `bun.lockb` | `bun audit --json` |
| Python requirements | `requirements*.txt` | `pip-audit --format json --no-deps --disable-pip -r <file>` |
| Python locked project | `pylock.*.toml` | `pip-audit --format json --locked .` |
| Node/Python/Rust licenses | detected lockfile | `osv-scanner scan source --lockfile <file> --all-packages --no-resolve --licenses= --format json` (`osv-scanner-license` record) |
| Lockfile fallback | uv, Poetry, Pipenv, Dart, Elixir, Swift, .NET, Deno | `osv-scanner scan source --lockfile <file> --format json` |
| Go | `go.mod` | `govulncheck -json ./...` |
| Rust | `Cargo.lock` | `cargo audit --json` |
| PHP | `composer.lock` | `composer audit --locked --format=json` |
| Ruby | `Gemfile.lock` | `bundle-audit check --format json` |
| Java fallback | Maven or Gradle manifest | `trivy fs --format json --scanners vuln .` |
| Container | `Dockerfile*` or `Containerfile*` | `trivy fs --format json --scanners misconfig .` |
| Infrastructure as code | Terraform, Compose, or Kubernetes YAML | `trivy fs --format json --scanners misconfig .` |
| Filesystem secrets | Repository root | `gitleaks dir . --no-banner --redact --report-format json --report-path -` |
| GitHub Actions | `.github/workflows/*.yml` | `zizmor --format json --offline .github/workflows` |

Schema v2 always includes one root-level gitleaks record. Planner exclusions do not apply inside
gitleaks; use `.gitleaksignore` or tool configuration. Zizmor runs offline audits only, and IaC
records list at most ten evidence filenames.

Important limitations:

- A bare `package.json`, `pyproject.toml`, or `Cargo.toml` is not a reproducible vulnerability
  inventory. Do not resolve and install an untrusted project merely to make it scannable.
- `pip-audit` without a path or `-r` audits the ambient Python environment; never use that as the
  project result. Requirements scans use `--no-deps --disable-pip`, so every audited dependency
  must be explicitly pinned in the file; report omitted transitive pins as incomplete inventory.
- `Pipfile.lock` is not directly supported by `pip-audit`. Ask the user to export a requirements
  file or use an explicitly approved fallback.
- For `uv.lock`, ask the user to run
  `uv export --format requirements-txt --output-file requirements.txt`. For `poetry.lock`, ask for
  `poetry export -f requirements.txt --output requirements.txt`, then rescan.
- A Dockerfile or Containerfile scan checks configuration only. Do not claim image vulnerability
  coverage unless
  the user supplies a built image and authorizes an image scan.
- `govulncheck` may not provide a severity. Preserve `unknown`; never invent a CVSS value.
- pnpm 11 reports GHSA identifiers from its registry endpoint. Do not relabel them as CVEs without
  a verified alias.
- `bundler-audit` depends on a local advisory database. Record its freshness; ask before updating
  it, and mark stale or missing data as inconclusive.
- License lookup uses **deps.dev over the network**; `--offline` cannot retrieve licenses (exit 127).
  This is the same network dependency as the existing OSV vulnerability fallback, not an offline
  audit. `--no-resolve` limits Python to explicitly pinned requirements; `--licenses=` disables
  OSV's allowlist verdict; `--all-packages` returns permissive packages too. A license lookup
  failure is inconclusive, never clean; vulnerability-only exit 1 with valid license JSON is not
  a license failure. License findings do not map to OWASP 2025.
- OSV's license JSON omits provenance and may falsely assign a public package's license to a
  same-named local/workspace package. Normalization re-reads the original lockfile: only registry
  `source` entries in Cargo.lock, registry-tarball `resolved` entries in npm package-locks, and
  pinned `name==version` requirements are trusted. Local or unpinned entries are not reported as
  licensed; requirements with unpinned or path/git references are not sent to OSV at planning time.
  Coverage is inconclusive. Keep the original lockfile unchanged and available through
  normalization; it is not copied into evidence. If unavailable, do not claim clean coverage. Other Node/Python lockfile
  formats currently lack a safe local-package provenance filter and remain inconclusive, even if
  the scanner runs; symlinked lockfiles are not sent to OSV. Other ecosystems are explicitly marked
  unsupported.

## Evidence Runner

Execute a saved plan without a shell:

```bash
python3 scripts/run_plan.py plan.json --out scan-evidence [--semgrep] [--jobs N]
```

`--jobs` runs distinct tools concurrently (default 1, sequential). Records that share the same
tool always run one at a time in plan order, even with `--jobs` set higher. This is a precaution,
not a confirmed fix for every version: Trivy documents that its default BoltDB cache uses file
locks and multiple processes on the same cache directory are unsupported, and cargo-audit updates
a local advisory-database clone. Concurrent `trivy fs --scanners misconfig` runs against the local
policy cache did not reproduce a lock error in manual testing (Trivy 0.74.0), but the constraint
stays because the failure mode is documented upstream and the cost of serializing same-tool records
is low. `run.json` records stay in original plan order regardless of `--jobs`.

`--semgrep` appends a root-level `p/owasp-top-ten` code scan to the saved plan records. The runner
writes `run.json` schema v1 with the plan root, timestamps, Git commit/branch/dirty
state, and one execution record per selected planner record. Each record includes command, working
directory, tool version, exit code, duration, execution state, reason, and redaction count. Raw
redacted evidence is stored as:

```text
scan-evidence/
├── run.json
└── NN-kind-path/
    ├── meta.json
    ├── stderr.txt
    └── stdout.txt
```

Execution states are `ran`, `skipped`, and `failed`; finding classification remains a separate
step. The runner refuses a non-empty evidence directory unless `--force` is explicit. Normalize
saved evidence with `scripts/normalize_findings.py`; malformed or empty output from a ran scanner
is classified as `failed`, not clean.

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
Do not describe this ruleset as complete OWASP 2025 coverage. Pass `--semgrep` to the evidence
runner to execute and save this command with the other scanner records. Without `semgrep login`,
Semgrep may return `requires login` instead of source lines; reports record the snippet as omitted.

## Verified Versions

The real-output parser fixtures were captured on 2026-09-16.

| Tool | Verified version | Command |
| --- | --- | --- |
| npm | 11.19.1 | `npm audit --json` |
| pnpm | 10.30.3 | `pnpm audit --json` |
| Yarn | 1.22.22 | `yarn audit --json` |
| Bun | 1.3.11 | `bun audit --json` |
| pip-audit | 2.10.1 | `pip-audit --format json --no-deps --disable-pip -r requirements.txt` |
| govulncheck | 1.8.0 | `govulncheck -json ./...` |
| cargo-audit | 0.22.2 | `cargo audit --json` |
| Composer | 2.10.3 | `composer audit --locked --format=json` |
| bundler-audit | 0.9.3 | `bundle-audit check --format json` |
| Trivy | 0.74.0 | `trivy fs --format json --scanners misconfig .` |
| OSV-Scanner | 2.6.0 | `osv-scanner scan source --lockfile uv.lock --format json` |
| Semgrep | 1.176.0 | `semgrep scan --config p/owasp-top-ten --json --metrics=off .` |
| Gitleaks | 8.30.1 | `gitleaks dir . --no-banner --redact --report-format json --report-path -` |
| zizmor | 1.30.1 | `zizmor --format json --offline .github/workflows` |

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
brew install osv-scanner gitleaks zizmor
cargo install zizmor
uv tool install zizmor
```

Composer, Bun, and the relevant Node package manager are expected to come from the project
toolchain. Choose one supported Zizmor installation method; do not install it three times.
Avoid remote-script pipelines such as `curl ... | sh`.

## NVD Enrichment

Use the [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) only for verified CVE IDs.
The `cveId` parameter is deprecated; use comma-separated `cveIds`, at most 100 per request. Without
an API key, limit requests to 5 per rolling 30 seconds and wait at least 6 seconds between calls.

Use `curl --fail --show-error --silent`, validate the JSON response, cache results for the scan, and
handle 403/429/5xx responses. Pass an API key through the `apiKey` header and never print it. If NVD
is unavailable, keep the original advisory result and mark enrichment failed rather than removing
the finding.
