#!/usr/bin/env python3
"""Normalize redacted scanner evidence into JSON, SARIF, or Markdown."""

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
	from scripts.redaction import redactText
except ModuleNotFoundError:
	from redaction import redactText

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
OWASP_2021 = {
	"A01": "A01", "A02": "A04", "A03": "A05", "A04": "A06", "A05": "A02",
	"A06": "A03", "A07": "A07", "A08": "A08", "A09": "A09", "A10": "A01",
}
DEPENDENCY_TOOLS = {
	"npm", "pnpm", "yarn", "bun", "pip-audit", "govulncheck", "cargo-audit",
	"composer", "bundler-audit", "osv-scanner",
}


def getTimestamp() -> str:
	return datetime.now(timezone.utc).isoformat()


def normalizeSeverity(value_severity=None, score_cvss=None) -> str:
	if value_severity is not None:
		value_normalized = str(value_severity).lower()
		values_map = {
			"critical": "critical", "high": "high", "error": "high", "medium": "medium",
			"moderate": "medium", "warning": "medium", "low": "low", "info": "info",
		}
		if value_normalized in values_map:
			return values_map[value_normalized]
	if score_cvss is not None:
		try:
			score_value = float(score_cvss)
		except (TypeError, ValueError):
			return "unknown"
		if score_value >= 9:
			return "critical"
		if score_value >= 7:
			return "high"
		if score_value >= 4:
			return "medium"
		if score_value > 0:
			return "low"
		return "info"
	return "unknown"


def getIdentifier(value_url, fallback=None):
	if isinstance(value_url, str) and value_url:
		return value_url.rstrip("/").rsplit("/", 1)[-1]
	return str(fallback) if fallback is not None else "unknown"


def makeFinding(
	source: str,
	identifier: str,
	type_finding: str,
	package=None,
	installed=None,
	fixed=None,
	severity=None,
	score=None,
	location=None,
	summary=None,
	references=None,
	aliases=None,
	cwe=None,
	rule_id=None,
	line=None,
	confidence=None,
	snippet=None,
	owasp=None,
) -> dict:
	location = location or "."
	identifier = str(identifier)
	item_finding = {
		"id": identifier,
		"aliases": list(aliases or ()),
		"source": source,
		"type": type_finding,
		"package": package,
		"installed_version": installed,
		"fixed_versions": list(fixed or ()),
		"native_severity": str(severity) if severity is not None else None,
		"normalized_severity": normalizeSeverity(severity, score),
		"owasp_2025": list(owasp or (["A03"] if type_finding == "dependency" else ())),
		"location": location,
		"summary": summary or identifier,
		"references": list(references or ()),
		"cwe": list(cwe or ()),
		"rule_id": rule_id,
		"line": line,
		"confidence": str(confidence).lower() if confidence else "unknown",
	}
	if snippet is not None:
		snippet_redacted, count_redaction = redactText(str(snippet))
		if count_redaction and len(str(snippet)) > 200:
			item_finding["snippet_omitted_reason"] = (
				"snippet exceeded 200 characters and contained redacted content"
			)
		else:
			item_finding["snippet"] = snippet_redacted
	value_fingerprint = "|".join(
		str(value or "")
		for value in (source, identifier, package, location, line)
	)
	item_finding["fingerprint"] = hashlib.sha256(value_fingerprint.encode()).hexdigest()[:16]
	return item_finding


LOCKFILES_NODE = {
	"npm": "package-lock.json",
	"pnpm": "pnpm-lock.yaml",
	"yarn": "yarn.lock",
	"bun": "bun.lock",
}


def parseAdvisory(source: str, package: str, advisory: dict) -> dict:
	identifier = advisory.get("id") or advisory.get("advisoryId") or advisory.get("cve")
	url_advisory = advisory.get("url") or advisory.get("link")
	aliases = list(advisory.get("cves") or [])
	identifier_github = advisory.get("github_advisory_id") or (
		getIdentifier(url_advisory) if url_advisory and "GHSA-" in url_advisory else None
	)
	if identifier_github and (not identifier or str(identifier).isdigit()):
		if identifier:
			aliases.append(str(identifier))
		identifier = identifier_github
	if not identifier:
		identifier = getIdentifier(url_advisory)
	fixed_versions = advisory.get("fix_versions") or []
	patched = advisory.get("patched_versions")
	if patched and not fixed_versions:
		fixed_versions = [patched]
	return makeFinding(
		source, identifier, "dependency", package=package,
		fixed=fixed_versions, severity=advisory.get("severity"),
		location=LOCKFILES_NODE.get(source, "package-lock.json"),
		summary=advisory.get("title") or advisory.get("summary"),
		references=[url_advisory] if url_advisory else [], aliases=aliases,
		cwe=advisory.get("cwe") or advisory.get("cwes") or [],
	)


def parseNpm(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for package, vulnerability in data["vulnerabilities"].items():
		for advisory in vulnerability.get("via", []):
			if isinstance(advisory, dict):
				item = parseAdvisory("npm", package, advisory)
				item["native_severity"] = advisory.get("severity") or vulnerability.get("severity")
				item["normalized_severity"] = normalizeSeverity(item["native_severity"])
				fix_available = vulnerability.get("fixAvailable")
				if isinstance(fix_available, dict) and fix_available.get("version"):
					item["fixed_versions"] = [fix_available["version"]]
				items.append(item)
	return items


def parsePnpm(content: str) -> list[dict]:
	data = json.loads(content)
	return [
		parseAdvisory("pnpm", advisory.get("module_name", "unknown"), advisory)
		for advisory in data["advisories"].values()
	]


def parseYarn(content: str) -> list[dict]:
	items = []
	found_shape = False
	for line in content.splitlines():
		if not line.strip():
			continue
		data = json.loads(line)
		if data.get("type") == "auditAdvisory":
			found_shape = True
			advisory = data["data"]["advisory"]
			items.append(parseAdvisory("yarn", advisory.get("module_name", "unknown"), advisory))
		elif "advisories" in data:
			found_shape = True
			for advisory in data["advisories"].values():
				items.append(parseAdvisory("yarn", advisory.get("module_name", "unknown"), advisory))
		elif data.get("type") == "auditSummary":
			found_shape = True
	if not found_shape:
		raise ValueError("unsupported yarn JSON stream")
	return items


def parseBun(content: str) -> list[dict]:
	data = json.loads(content)
	return [parseAdvisory("bun", package, advisory) for package, values in data.items() for advisory in values]


def parsePipAudit(content: str) -> list[dict]:
	data = json.loads(content)
	return [
		makeFinding(
			"pip-audit", vuln["id"], "dependency", package=dependency.get("name"),
			installed=dependency.get("version"), fixed=vuln.get("fix_versions"),
			location="requirements.txt", summary=vuln.get("description"),
			aliases=vuln.get("aliases"),
		)
		for dependency in data["dependencies"] for vuln in dependency.get("vulns", [])
	]


def parseGovulncheck(content: str) -> list[dict]:
	values_osv = {}
	values_finding = []
	found_shape = False
	for line in content.splitlines():
		if not line.strip():
			continue
		data = json.loads(line)
		if "osv" in data:
			found_shape = True
			values_osv[data["osv"]["id"]] = data["osv"]
		elif "finding" in data:
			found_shape = True
			values_finding.append(data["finding"])
		elif "config" in data:
			found_shape = True
	if not found_shape:
		raise ValueError("unsupported govulncheck JSON stream")
	items = []
	for finding in values_finding:
		identifier = finding.get("osv") or finding.get("id")
		osv = values_osv.get(identifier, {})
		trace = finding.get("trace") or [{}]
		frame = trace[-1]
		position = frame.get("position") or {}
		items.append(
			makeFinding(
				"govulncheck", identifier, "dependency", package=frame.get("module") or frame.get("package"),
				fixed=[finding["fixed_version"]] if finding.get("fixed_version") else [],
				location=position.get("filename") or "go.mod", line=position.get("line"),
				summary=osv.get("summary"), aliases=osv.get("aliases"),
				references=[osv.get("database_specific", {}).get("url")] if osv.get("database_specific", {}).get("url") else [],
			)
		)
	return items


def parseCargoAudit(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for value in data["vulnerabilities"]["list"]:
		advisory = value["advisory"]
		package = value.get("package", {})
		items.append(
			makeFinding(
				"cargo-audit", advisory["id"], "dependency", package=package.get("name") or advisory.get("package"),
				installed=package.get("version"), fixed=value.get("versions", {}).get("patched"),
				score=advisory.get("cvss"), location="Cargo.lock",
				summary=advisory.get("title") or advisory.get("description"),
				references=[advisory["url"]] if advisory.get("url") else [],
			)
		)
	return items


def parseComposer(content: str) -> list[dict]:
	data = json.loads(content)
	return [parseAdvisory("composer", package, advisory) for package, values in data["advisories"].items() for advisory in values]


def parseBundlerAudit(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for result in data["results"]:
		if result.get("type") != "unpatched_gem":
			continue
		advisory = result["advisory"]
		gem = result.get("gem", {})
		items.append(
			makeFinding(
				"bundler-audit", advisory["id"], "dependency", package=gem.get("name"),
				installed=gem.get("version"), fixed=[advisory["solution"]] if advisory.get("solution") else [],
				severity=advisory.get("criticality"), location="Gemfile.lock",
				summary=advisory.get("title"), references=[advisory["url"]] if advisory.get("url") else [],
			)
		)
	return items


def parseTrivy(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for result in data.get("Results", []):
		location = result.get("Target", ".")
		for vulnerability in result.get("Vulnerabilities") or []:
			items.append(
				makeFinding(
					"trivy", vulnerability["VulnerabilityID"], "dependency",
					package=vulnerability.get("PkgName"), installed=vulnerability.get("InstalledVersion"),
					fixed=[vulnerability["FixedVersion"]] if vulnerability.get("FixedVersion") else [],
					severity=vulnerability.get("Severity"), location=location,
					summary=vulnerability.get("Title"),
					references=[vulnerability["PrimaryURL"]] if vulnerability.get("PrimaryURL") else [],
					cwe=vulnerability.get("CweIDs"),
				)
			)
		for misconfiguration in result.get("Misconfigurations") or []:
			cause = misconfiguration.get("CauseMetadata") or {}
			items.append(
				makeFinding(
					"trivy", misconfiguration["ID"], "misconfiguration",
					severity=misconfiguration.get("Severity"), location=location,
					summary=misconfiguration.get("Title") or misconfiguration.get("Description"),
					references=[misconfiguration["PrimaryURL"]] if misconfiguration.get("PrimaryURL") else [],
					rule_id=misconfiguration["ID"], line=cause.get("StartLine"),
					snippet=misconfiguration.get("Message"), owasp=["A02"],
				)
			)
	return items


def parseOsvScanner(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for result in data["results"]:
		location = result.get("source", {}).get("path", ".")
		for package_data in result.get("packages", []):
			package = package_data.get("package", {})
			groups_score = {
				identifier: group.get("max_severity")
				for group in package_data.get("groups", []) for identifier in group.get("ids", [])
			}
			for vulnerability in package_data.get("vulnerabilities", []):
				items.append(
					makeFinding(
						"osv-scanner", vulnerability["id"], "dependency", package=package.get("name"),
						installed=package.get("version"), score=groups_score.get(vulnerability["id"]),
						location=location, summary=vulnerability.get("summary"),
						aliases=vulnerability.get("aliases"),
					)
				)
	return items


def normalizeSemgrepOwasp(labels_owasp, values_cwe) -> tuple[list[str], bool]:
	categories = []
	ambiguous = False
	for label in labels_owasp or ():
		match_label = re.search(r"(A(?:0[1-9]|10))(?::(2021|2025))?", str(label))
		if not match_label:
			continue
		category, year_category = match_label.groups()
		if year_category == "2021":
			category = OWASP_2021[category]
		elif year_category is None:
			if any(str(value).upper() in {"CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-95"} for value in values_cwe or ()):
				category = "A05"
			else:
				ambiguous = True
		categories.append(category)
	return sorted(set(categories)), ambiguous


def parseSemgrep(content: str) -> list[dict]:
	data = json.loads(content)
	items = []
	for result in data["results"]:
		extra = result.get("extra", {})
		metadata = extra.get("metadata") or {}
		values_cwe = metadata.get("cwe") or []
		if isinstance(values_cwe, str):
			values_cwe = [values_cwe]
		values_owasp = metadata.get("owasp") or []
		if isinstance(values_owasp, str):
			values_owasp = [values_owasp]
		categories, ambiguous = normalizeSemgrepOwasp(values_owasp, values_cwe)
		item = makeFinding(
			"semgrep", result["check_id"], "code", severity=extra.get("severity"),
			location=result.get("path"), summary=extra.get("message"), cwe=values_cwe,
			rule_id=result["check_id"], line=result.get("start", {}).get("line"),
			confidence=metadata.get("confidence"), snippet=extra.get("lines"), owasp=categories,
		)
		if ambiguous:
			item["owasp_normalization"] = "ambiguous"
		items.append(item)
	return items


def parseGitleaks(content: str) -> list[dict]:
	data = json.loads(content)
	return [
		makeFinding(
			"gitleaks", leak["Fingerprint"], "secret", severity="high",
			location=leak.get("File"), summary=leak.get("Description") or leak.get("RuleID"),
			rule_id=leak.get("RuleID"), line=leak.get("StartLine"), snippet=leak.get("Secret"),
			owasp=["A04"],
		)
		for leak in data
	]


def parseZizmor(content: str) -> list[dict]:
	data = json.loads(content)
	values = data.get("findings", []) if isinstance(data, dict) else data
	items = []
	for finding in values:
		determinations = finding.get("determinations") or {}
		location_data = (finding.get("locations") or [{}])[0]
		concrete = location_data.get("concrete") or location_data
		items.append(
			makeFinding(
				"zizmor", finding["ident"], "ci", severity=determinations.get("severity"),
				location=concrete.get("path", ".github/workflows"),
				line=concrete.get("line"), summary=finding.get("description"),
				references=[finding["url"]] if finding.get("url") else [],
				rule_id=finding["ident"], confidence=determinations.get("confidence"),
				owasp=["A03"],
			)
		)
	return items


PARSERS = {
	"npm": parseNpm, "pnpm": parsePnpm, "yarn": parseYarn, "bun": parseBun,
	"pip-audit": parsePipAudit, "govulncheck": parseGovulncheck,
	"cargo-audit": parseCargoAudit, "composer": parseComposer,
	"bundler-audit": parseBundlerAudit, "trivy": parseTrivy,
	"osv-scanner": parseOsvScanner, "semgrep": parseSemgrep,
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
	for finding in items_finding:
		for category in finding.get("owasp_2025", []):
			if category in coverage:
				coverage[category] = "findings"
	return coverage


def normalizeEvidence(
	path_evidence: Path,
	path_baseline: Path | None = None,
	severities: set[str] | None = None,
	categories_owasp: set[str] | None = None,
) -> dict:
	data_run = json.loads((path_evidence / "run.json").read_text(encoding="utf-8"))
	items_scanner = []
	items_finding = []
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
				if not content_stdout.strip():
					raise ValueError("empty scanner output")
				findings_scanner = PARSERS[meta_record["tool"]](content_stdout)
				state_scanner = "findings" if findings_scanner else "clean"
			except (StopIteration, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error_parse:
				state_scanner = "failed"
				reason_scanner = f"invalid scanner output: {error_parse}"
		items_finding.extend(findings_scanner)
		items_scanner.append(
			{
				"kind": meta_record["kind"], "path": meta_record["path"],
				"tool": meta_record["tool"], "tool_version": meta_record.get("tool_version"),
				"state": state_scanner, "reason": reason_scanner,
				"finding_count": len(findings_scanner),
			}
		)

	items_baseline = []
	if path_baseline:
		items_baseline = json.loads(path_baseline.read_text(encoding="utf-8")).get("findings", [])
	fingerprints_baseline = {item["fingerprint"] for item in items_baseline}
	fingerprints_current = {item["fingerprint"] for item in items_finding}
	if path_baseline:
		for finding in items_finding:
			finding["change"] = (
				"unchanged" if finding["fingerprint"] in fingerprints_baseline else "new"
			)
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
	for scanner in items_scanner:
		scanner["finding_count"] = sum(
			1 for finding in items_finding if finding["source"] == scanner["tool"]
		)
	data_output = {
		"schema_version": 1,
		"generated_at": getTimestamp(),
		"plan_root": data_run["plan_root"],
		"git": data_run.get("git"),
		"scanners": items_scanner,
		"findings": items_finding,
		"fixed": items_fixed,
		"owasp_coverage": getCoverage(items_scanner, items_finding),
	}
	return redactValue(data_output)


def toSarif(data_report: dict) -> dict:
	runs_sarif = []
	for scanner in data_report["scanners"]:
		findings_tool = [
			finding for finding in data_report["findings"] if finding["source"] == scanner["tool"]
		]
		rules = []
		results = []
		seen_rules = set()
		for finding in findings_tool:
			rule_id = finding.get("rule_id") or finding["id"]
			if rule_id not in seen_rules:
				rules.append({"id": rule_id, "name": rule_id, "shortDescription": {"text": finding["summary"]}})
				seen_rules.add(rule_id)
			region = {}
			if finding.get("line"):
				region["startLine"] = finding["line"]
			results.append(
				{
					"ruleId": rule_id,
					"level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note", "unknown": "note"}[finding["normalized_severity"]],
					"message": {"text": finding["summary"]},
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["location"]}, "region": region}}],
					"partialFingerprints": {"primaryLocationLineHash": finding["fingerprint"]},
				}
			)
		runs_sarif.append(
			{
				"tool": {"driver": {"name": scanner["tool"], "version": scanner.get("tool_version"), "rules": rules}},
				"results": results,
			}
		)
	return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs_sarif}


def toMarkdown(data_report: dict) -> str:
	counts = {severity: 0 for severity in SEVERITY_ORDER}
	for finding in data_report["findings"]:
		counts[finding["normalized_severity"]] += 1
	lines = [
		"# Security Scan Report", "", "## Executive Summary", "",
		f"{len(data_report['findings'])} findings. " + ", ".join(f"{key}: {value}" for key, value in counts.items()),
		"", "## Scope and Reproducibility", "", f"- Root: `{data_report['plan_root']}`",
		f"- Generated: {data_report['generated_at']}", "", "## Scanner Status", "",
		"| Scanner | Scope | State | Findings |", "| --- | --- | --- | ---: |",
	]
	for scanner in data_report["scanners"]:
		lines.append(f"| {scanner['tool']} | {scanner['path']} | {scanner['state']} | {scanner['finding_count']} |")
	lines.extend(["", "## Findings", "", "| Severity | ID | Package/location | Summary | Fixed |", "| --- | --- | --- | --- | --- |"])
	for finding in data_report["findings"]:
		fixed = ", ".join(finding.get("fixed_versions", [])) or "—"
		place = finding.get("package") or finding.get("location") or "."
		lines.append(f"| {finding['normalized_severity']} | {finding['id']} | {place} | {finding['summary']} | {fixed} |")
	lines.extend(["", "## OWASP 2025 Coverage", "", "| Category | State |", "| --- | --- |"])
	for category, state in data_report["owasp_coverage"].items():
		lines.append(f"| {category} | {state} |")
	lines.extend(["", "## Limitations", "", "Failed, skipped, and inconclusive scanners remain incomplete coverage."])
	if any(finding.get("enrichment") for finding in data_report["findings"]):
		lines.extend(["", "> This product uses data from the NVD API but is not endorsed or certified by the NVD."])
	return "\n".join(lines) + "\n"


def parseArguments() -> argparse.Namespace:
	parser_output = argparse.ArgumentParser(description="Normalize scanner evidence.")
	parser_output.add_argument("evidence", type=Path)
	parser_output.add_argument("--baseline", type=Path)
	parser_output.add_argument("--format", choices=("json", "sarif", "markdown"), default="json")
	parser_output.add_argument("--severity")
	parser_output.add_argument("--owasp")
	parser_output.add_argument("--out", type=Path)
	return parser_output.parse_args()


def runMain() -> None:
	args_output = parseArguments()
	data_report = normalizeEvidence(
		args_output.evidence,
		path_baseline=args_output.baseline,
		severities=set(args_output.severity.lower().split(",")) if args_output.severity else None,
		categories_owasp=set(args_output.owasp.upper().split(",")) if args_output.owasp else None,
	)
	if args_output.format == "sarif":
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
