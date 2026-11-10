"""Normalize redacted scanner evidence into JSON, SARIF, or Markdown."""

import argparse
import json
import sys
from pathlib import Path

try:
	from scripts.code_parsers import (
		OWASP_2021,
		normalizeSemgrepOwasp,
		parseGitleaks,
		parseSemgrep,
		parseZizmor,
	)
	from scripts.dependency_parsers import (
		LOCKFILES_NODE,
		parseAdvisory,
		parseBun,
		parseBundlerAudit,
		parseCargoAudit,
		parseComposer,
		parseGovulncheck,
		parseJsonStream,
		parseNpm,
		parseOsvScanner,
		parsePipAudit,
		parsePnpm,
		parseTrivy,
		parseYarn,
	)
	from scripts.finding_core import (
		CONFIDENCE_ORDER,
		DEPENDENCY_TOOLS,
		SEVERITY_ORDER,
		getFingerprint,
		getIdentifier,
		getTimestamp,
		makeFinding,
		normalizeSeverity,
	)
	from scripts.license_records import (
		UnsupportedLockfileError,
		classifySpdxLicense,
		getRegistryPackages,
		licenseAtom,
		normalizeLicenseRecord,
		normalizeRuntimeRecord,
		parseOsvScannerLicense,
		parseRuntimeVersions,
	)
	from scripts.redaction import redactText
	from scripts.report_output import getMarkdownRow, toMarkdown, toSarif
	from scripts.validate_report import loadSchema, validateDocument
	from scripts.verdict_rules import validateVerdicts
except ModuleNotFoundError:
	from code_parsers import (
		OWASP_2021,
		normalizeSemgrepOwasp,
		parseGitleaks,
		parseSemgrep,
		parseZizmor,
	)
	from dependency_parsers import (
		LOCKFILES_NODE,
		parseAdvisory,
		parseBun,
		parseBundlerAudit,
		parseCargoAudit,
		parseComposer,
		parseGovulncheck,
		parseJsonStream,
		parseNpm,
		parseOsvScanner,
		parsePipAudit,
		parsePnpm,
		parseTrivy,
		parseYarn,
	)
	from finding_core import (
		CONFIDENCE_ORDER,
		DEPENDENCY_TOOLS,
		SEVERITY_ORDER,
		getFingerprint,
		getIdentifier,
		getTimestamp,
		makeFinding,
		normalizeSeverity,
	)
	from license_records import (
		UnsupportedLockfileError,
		classifySpdxLicense,
		getRegistryPackages,
		licenseAtom,
		normalizeLicenseRecord,
		normalizeRuntimeRecord,
		parseOsvScannerLicense,
		parseRuntimeVersions,
	)
	from redaction import redactText
	from report_output import getMarkdownRow, toMarkdown, toSarif
	from validate_report import loadSchema, validateDocument
	from verdict_rules import validateVerdicts


#!/usr/bin/env python3



PARSERS = {
	"npm": parseNpm, "pnpm": parsePnpm, "yarn": parseYarn, "bun": parseBun,
	"pip-audit": parsePipAudit, "govulncheck": parseGovulncheck,
	"cargo-audit": parseCargoAudit, "composer": parseComposer,
	"bundler-audit": parseBundlerAudit, "trivy": parseTrivy,
	"osv-scanner": parseOsvScanner, "osv-scanner-license": parseOsvScannerLicense,
	"semgrep": parseSemgrep,
	"gitleaks": parseGitleaks, "zizmor": parseZizmor,
}


def redactValue(value_data):
	if isinstance(value_data, str):
		return redactText(value_data)[0]
	if isinstance(value_data, list):
		return [redactValue(value) for value in value_data]
	if isinstance(value_data, dict):
		return {key: redactValue(value) for key, value in value_data.items()}
	return value_data


def getCoverage(items_scanner: list[dict], items_finding: list[dict]) -> dict:
	coverage = {f"A{number:02d}": "not-scanned" for number in range(1, 11)}
	for category in ("A06", "A07", "A09", "A10"):
		coverage[category] = "manual-review-needed"
	tools_success = {
		item["tool"] for item in items_scanner if item["state"] in ("clean", "findings")
	}
	if "semgrep" in tools_success:
		for category in ("A01", "A02", "A04", "A05", "A08"):
			coverage[category] = "automated-covered"
	if tools_success & DEPENDENCY_TOOLS or any(
		item["state"] in ("clean", "findings")
		and item["kind"] in {
			"node", "python", "go", "rust", "php", "ruby", "java", "dart", "elixir",
			"swift", "dotnet", "deno", "dependency",
		}
		for item in items_scanner
	):
		coverage["A03"] = "automated-covered"
	if "gitleaks" in tools_success:
		coverage["A04"] = "automated-covered"
	categories_finding = {
		category
		for finding in items_finding
		for category in finding.get("owasp_2025", [])
		if category in coverage
	}
	categories_active = {
		category
		for finding in items_finding if finding.get("verdict") != "rejected"
		for category in finding.get("owasp_2025", [])
		if category in coverage
	}
	for category in categories_finding:
		coverage[category] = "findings" if category in categories_active else "automated-covered"
	return coverage


def normalizeEvidence(
	path_evidence: Path,
	path_baseline: Path | None = None,
	path_verdicts: Path | None = None,
	severities: set[str] | None = None,
	categories_owasp: set[str] | None = None,
) -> dict:
	data_run = json.loads((path_evidence / "run.json").read_text(encoding="utf-8"))
	items_scanner = []
	items_finding = []
	fingerprints_by_scanner = []
	for meta_record in data_run["records"]:
		state_runner = meta_record["state"]
		reason_scanner = meta_record.get("reason")
		findings_scanner = []
		if state_runner == "skipped":
			state_scanner = (
				"inconclusive" if str(reason_scanner).startswith("planner ") else "skipped"
			)
		elif state_runner == "failed":
			state_scanner = "failed"
		else:
			try:
				path_stdout = next(path_evidence.glob(f"{meta_record['plan_index']:02d}-*/stdout.txt"))
				content_stdout = path_stdout.read_text(encoding="utf-8")
				if meta_record["tool"] == "runtime-versions":
					findings_scanner, state_scanner, reason_scanner = normalizeRuntimeRecord(
						content_stdout)
				elif meta_record["tool"] == "osv-scanner-license":
					findings_scanner, state_scanner, reason_scanner = normalizeLicenseRecord(
						content_stdout, meta_record, data_run["plan_root"], path_stdout)
				else:
					if not content_stdout.strip():
						raise ValueError("empty scanner output")
					findings_scanner = PARSERS[meta_record["tool"]](content_stdout)
					state_scanner = "findings" if findings_scanner else "clean"
			except (StopIteration, OSError, ValueError, KeyError, TypeError, AttributeError,
				IndexError, json.JSONDecodeError) as error_parse:
				state_scanner = "failed"
				reason_scanner = f"invalid scanner output: {error_parse}"
		for finding in findings_scanner:
			path_location = Path(finding["location"])
			if meta_record["tool"] == "osv-scanner" and path_location.is_absolute():
				try:
					finding["location"] = path_location.resolve().relative_to(
						Path(data_run["plan_root"]).resolve()).as_posix()
				except (ValueError, OSError, RuntimeError):
					continue
			elif meta_record["path"] != "." and not path_location.is_absolute():
				finding["location"] = f"{meta_record['path']}/{finding['location']}"
			else:
				continue
			finding["fingerprint"] = getFingerprint(finding)
		fingerprints_by_scanner.append({finding["fingerprint"] for finding in findings_scanner})
		items_finding.extend(findings_scanner)
		items_scanner.append(
			{
				"kind": meta_record["kind"], "path": meta_record["path"],
				"tool": meta_record["tool"], "tool_version": meta_record.get("tool_version"),
				"state": state_scanner, "reason": reason_scanner,
				"finding_count": len(findings_scanner),
				**({"note": meta_record["note"]} if "note" in meta_record else {}),
			}
		)

	findings_by_fingerprint = {}
	for finding in items_finding:
		findings_by_fingerprint.setdefault(finding["fingerprint"], finding)
	items_finding = list(findings_by_fingerprint.values())

	items_baseline = []
	if path_baseline:
		items_baseline = json.loads(path_baseline.read_text(encoding="utf-8")).get("findings", [])
	baseline_by_fingerprint = {item["fingerprint"]: item for item in items_baseline}
	fingerprints_baseline = set(baseline_by_fingerprint)
	fingerprints_current = {item["fingerprint"] for item in items_finding}
	if path_baseline:
		for finding in items_finding:
			finding["change"] = (
				"unchanged" if finding["fingerprint"] in fingerprints_baseline else "new"
			)
			baseline = baseline_by_fingerprint.get(finding["fingerprint"])
			if baseline and baseline.get("verdict") and all(
				finding.get(field) == baseline.get(field)
				for field in ("location", "line", "installed_version")
			):
				finding["verdict"] = baseline["verdict"]
				finding["verdict_evidence"] = baseline.get("verdict_evidence")
				finding["verdict_carried_forward"] = True

	verdicts_unmatched = []
	if path_verdicts:
		verdicts = json.loads(path_verdicts.read_text(encoding="utf-8"))
		findings_by_fingerprint = {item["fingerprint"]: item for item in items_finding}
		for fingerprint, verdict_data in verdicts.items():
			finding = findings_by_fingerprint.get(fingerprint)
			if finding is None:
				verdicts_unmatched.append(fingerprint)
				print(f"unmatched verdict fingerprint: {fingerprint}", file=sys.stderr)
				continue
			finding["verdict"] = verdict_data["verdict"]
			finding["verdict_evidence"] = verdict_data["verdict_evidence"]
			finding.pop("verdict_carried_forward", None)
	coverage_owasp = getCoverage(items_scanner, items_finding)
	items_fixed = [
		{"fingerprint": item["fingerprint"], "id": item.get("id"), "package": item.get("package")}
		for item in items_baseline if item["fingerprint"] not in fingerprints_current
	]
	if severities:
		items_finding = [item for item in items_finding if item["normalized_severity"] in severities]
	if categories_owasp:
		items_finding = [
			item for item in items_finding if categories_owasp & set(item.get("owasp_2025", []))
		]
	items_finding.sort(
		key=lambda item: (
			SEVERITY_ORDER[item["normalized_severity"]],
			CONFIDENCE_ORDER.get(item.get("confidence", "unknown"), 3),
			item["fingerprint"],
		)
	)
	fingerprints_reported = {item["fingerprint"] for item in items_finding}
	for scanner, fingerprints in zip(items_scanner, fingerprints_by_scanner):
		scanner["finding_count"] = len(fingerprints & fingerprints_reported)
	data_output = redactValue({
		"schema_version": 1,
		"generated_at": getTimestamp(),
		"plan_root": data_run["plan_root"],
		"git": data_run.get("git"),
		"scanners": items_scanner,
		"findings": items_finding,
		"fixed": items_fixed,
		"owasp_coverage": coverage_owasp,
		"verdicts_unmatched": sorted(verdicts_unmatched),
	})
	schema_report = loadSchema(Path(__file__).parents[1] / "schema" / "security-findings.schema.json")
	errors_schema = validateDocument(data_output, schema_report)
	if errors_schema:
		raise ValueError("normalized report schema mismatch:\n" + "\n".join(errors_schema))
	return data_output


def parseArguments() -> argparse.Namespace:
	parser_output = argparse.ArgumentParser(description="Normalize scanner evidence.")
	parser_output.add_argument("evidence", type=Path)
	parser_output.add_argument("--baseline", type=Path)
	parser_output.add_argument("--verdicts", type=Path)
	parser_output.add_argument("--format", choices=("json", "sarif", "markdown"), default="json")
	parser_output.add_argument("--severity")
	parser_output.add_argument("--owasp")
	parser_output.add_argument("--out", type=Path)
	return parser_output.parse_args()


def runMain() -> None:
	args_output = parseArguments()
	try:
		data_report = normalizeEvidence(
			args_output.evidence,
			path_baseline=args_output.baseline,
			path_verdicts=args_output.verdicts,
			severities=set(args_output.severity.lower().split(",")) if args_output.severity else None,
			categories_owasp=set(args_output.owasp.upper().split(",")) if args_output.owasp else None,
		)
	except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error_output:
		print(f"normalize-findings: {error_output}", file=sys.stderr)
		raise SystemExit(1) from error_output
	if args_output.format == "sarif":
		errors_verdict = validateVerdicts(data_report)
		if errors_verdict:
			for error_verdict in errors_verdict:
				print(error_verdict, file=sys.stderr)
			raise SystemExit(1)
		content_output = json.dumps(toSarif(data_report), indent=2, sort_keys=True) + "\n"
	elif args_output.format == "markdown":
		content_output = toMarkdown(data_report)
	else:
		content_output = json.dumps(data_report, indent=2, sort_keys=True) + "\n"
	if args_output.out:
		args_output.out.write_text(content_output, encoding="utf-8")
	else:
		print(content_output, end="")


if __name__ == "__main__":
	runMain()
