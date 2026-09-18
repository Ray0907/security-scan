# Jev verdict suggestions

## Goal

Add an optional, explicit command that asks TypeSafe Jev to suggest a verdict for unreviewed Semgrep code findings. Suggestions assist human review; they never become evidence-backed verdicts automatically.

## Interface

```bash
TYPESAFE_API_KEY=... python3 scripts/suggest_verdicts.py \
  security-findings.json --out jev-suggestions.json
```

The command requires the optional `typesafe-sdk` package. It uses `jev-latest` and reads credentials only from `TYPESAFE_API_KEY`.

## Scope and data handling

The script considers only findings where:

- `source` is `semgrep`;
- `type` is `code`;
- no `verdict` is present; and
- the normalized report contains a redacted `snippet`.

It sends the normalized finding metadata and existing redacted snippet to TypeSafe. It does not read additional repository source. Findings without snippets are reported as skipped. Running the script is the user's explicit approval for this external transmission.

## Judgment

Each eligible finding gets one independent Jev `Choice` question with these outcomes:

- `confirmed`: the supplied evidence establishes that an input surface reaches the reported vulnerable condition without an effective control;
- `needs_validation`: the supplied evidence is insufficient to establish reachability or whether a control is effective;
- `rejected`: the supplied evidence establishes that the condition is unreachable or effectively controlled.

The question includes the repository's verdict rules. The result records the selected outcome, its confidence, the full probability distribution, and the versioned model returned by TypeSafe.

## Output

`jev-suggestions.json` is a separate artifact keyed by finding fingerprint. It includes generation metadata, suggestions, and skipped findings. It deliberately does not match `verdicts.json`: Jev does not generate the required technical `reason`, `trace`, or `unresolved_fact`, so its output cannot be merged by `normalize_findings.py` without human review.

The command writes atomically after all eligible requests succeed. Missing credentials, invalid input, SDK/API failures, or malformed responses produce a non-zero exit and do not leave a partial output file. An input with no eligible findings succeeds and writes an empty suggestions object plus skip records.

## Changes

- Add `scripts/suggest_verdicts.py`.
- Add focused unit tests using a fake TypeSafe client; tests make no network calls and require no API key.
- Document optional SDK installation, external data transmission, command usage, and the human-review boundary in `README.md` and `SKILL.md`.

No scanner, normalization, report schema, or existing pipeline behavior changes.
