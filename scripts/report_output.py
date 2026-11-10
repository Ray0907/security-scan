import json

try:
	from scripts.finding_core import SEVERITY_ORDER
except ModuleNotFoundError:
	from finding_core import SEVERITY_ORDER


def toSarif(data_report: dict) -> dict:
	runs_sarif = []
	scanner_by_tool = {}
	for scanner in data_report["scanners"]:
		if scanner["tool"] is None:
			continue
		scanner_first = scanner_by_tool.setdefault(scanner["tool"], scanner)
		if scanner_first.get("tool_version") is None and scanner.get("tool_version") is not None:
			scanner_by_tool[scanner["tool"]] = scanner
	for scanner in scanner_by_tool.values():
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
			result_sarif = {
				"ruleId": rule_id,
				"kind": "fail",
				"level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note", "unknown": "note"}[finding["normalized_severity"]],
				"message": {"text": finding["summary"]},
				"locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["location"]}, "region": region}}],
				"partialFingerprints": {"primaryLocationLineHash": finding["fingerprint"]},
			}
			if finding.get("verdict") == "rejected":
				result_sarif["suppressions"] = [{
					"kind": "external", "status": "accepted",
					"justification": json.dumps(finding["verdict_evidence"], sort_keys=True),
				}]
			if finding.get("change") in ("new", "unchanged"):
				result_sarif["baselineState"] = finding["change"]
			results.append(result_sarif)
		driver = {"name": scanner["tool"], "rules": rules}
		if scanner.get("tool_version") is not None:
			driver["version"] = scanner["tool_version"]
		runs_sarif.append({"tool": {"driver": driver}, "results": results})
	return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs_sarif}


def getMarkdownRow(finding: dict) -> str:
	fixed = ", ".join(finding.get("fixed_versions", [])) or "—"
	place = finding.get("package") or finding.get("location") or "."
	summary = finding["summary"].replace("|", "\\|").replace("\n", " ")
	return f"| {finding['normalized_severity']} | {finding['id']} | {place} | {summary} | {fixed} |"


def escapeCell(value) -> str:
	return str(value or "—").replace("|", "\\|").replace("\n", " ")


def getNotCoveredLines(data_report: dict) -> list[str]:
	lines = []
	for scanner in data_report["scanners"]:
		if scanner["state"] in ("skipped", "inconclusive", "failed"):
			lines.append(
				f"- {scanner['tool']} at `{scanner['path']}`: {scanner['state']}"
				f" ({escapeCell(scanner['reason'])})"
			)
	for category, state in data_report["owasp_coverage"].items():
		if state in ("not-scanned", "manual-review-needed"):
			lines.append(f"- OWASP {category}: {state}")
	lines.append(
		"- Paths excluded and parts omitted by a scoped run are not recorded in the evidence."
		" A scoped or partial scan says nothing about the omitted parts."
	)
	return lines


def toMarkdown(data_report: dict) -> str:
	counts = {severity: 0 for severity in SEVERITY_ORDER}
	for finding in data_report["findings"]:
		counts[finding["normalized_severity"]] += 1
	lines = [
		"# Security Scan Report", "", "## Executive Summary", "",
		f"{len(data_report['findings'])} findings. " + ", ".join(f"{key}: {value}" for key, value in counts.items()),
		"", "## Scope and Reproducibility", "", f"- Root: `{data_report['plan_root']}`",
		f"- Generated: {data_report['generated_at']}", "", "## Scanner Status", "",
		"| Scanner | Scope | State | Findings | Reason |", "| --- | --- | --- | ---: | --- |",
	]
	for scanner in data_report["scanners"]:
		lines.append(
			f"| {scanner['tool']} | {scanner['path']} | {scanner['state']} |"
			f" {scanner['finding_count']} | {escapeCell(scanner['reason'])} |"
		)
	lines.extend(["", "## Findings"])
	groups_verdict = (
		("Confirmed", "confirmed"),
		("Needs validation", "needs_validation"),
		("Unreviewed", None),
	)
	for heading_verdict, verdict in groups_verdict:
		lines.extend(["", f"### {heading_verdict}", "", "| Severity | ID | Package/location | Summary | Fixed |", "| --- | --- | --- | --- | --- |"])
		for finding in data_report["findings"]:
			if finding.get("verdict") != verdict:
				continue
			lines.append(getMarkdownRow(finding))
	lines.extend(["", "## OWASP 2025 Coverage", "", "| Category | State |", "| --- | --- |"])
	for category, state in data_report["owasp_coverage"].items():
		lines.append(f"| {category} | {state} |")
	lines.extend(["", "## Reviewed False Positives", "", "### Rejected", "", "| Severity | ID | Package/location | Summary | Fixed |", "| --- | --- | --- | --- | --- |"])
	for finding in data_report["findings"]:
		if finding.get("verdict") != "rejected":
			continue
		lines.append(getMarkdownRow(finding))
	lines.extend(["", "## Limitations", "", "Failed, skipped, and inconclusive scanners remain incomplete coverage."])
	lines.extend(["", "## Not Covered", "", *getNotCoveredLines(data_report)])
	if any(finding.get("enrichment") for finding in data_report["findings"]):
		lines.extend(["", "> This product uses data from the NVD API but is not endorsed or certified by the NVD."])
	return "\n".join(lines) + "\n"
