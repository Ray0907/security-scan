"""Shared semantic checks for security finding verdicts."""

import re


REGEX_FILE_LINE = re.compile(r"[^\s:]*[A-Za-z][^\s:]*:[1-9][0-9]*(?![0-9])")
VERDICTS = ("confirmed", "needs_validation", "rejected")
FIELDS_REVIEW = ("reason", "reviewer", "reviewed_at")


def isBlank(value) -> bool:
	return not isinstance(value, str) or not value.strip()


def validateFinding(index_finding: int, data_finding: dict) -> list[str]:
	verdict = data_finding.get("verdict")
	if verdict not in VERDICTS:
		return []
	data_evidence = data_finding.get("verdict_evidence")
	data_evidence = data_evidence if isinstance(data_evidence, dict) else {}
	prefix = f"/findings/{index_finding}/verdict_evidence"
	items_error = [
		f"{prefix}/{field}: must not be blank"
		for field in FIELDS_REVIEW
		if isinstance(data_evidence.get(field), str) and isBlank(data_evidence[field])
	]
	value_trace = data_evidence.get("trace")
	if verdict == "needs_validation" and isBlank(data_evidence.get("unresolved_fact")):
		items_error.append(
			f"{prefix}/unresolved_fact: needs_validation verdict requires a non-empty unresolved_fact"
		)
	if verdict == "confirmed" and isBlank(value_trace):
		items_error.append(f"{prefix}/trace: confirmed verdict requires a non-empty trace")
	if verdict == "rejected" and (
		not isinstance(value_trace, str) or not REGEX_FILE_LINE.search(value_trace)
	):
		items_error.append(f"{prefix}/trace: rejected verdict requires a file:line reference")
	return items_error


def validateVerdicts(document) -> list[str]:
	if not isinstance(document, dict):
		return []
	items_finding = document.get("findings")
	if not isinstance(items_finding, list):
		return []
	items_error = []
	for index_finding, data_finding in enumerate(items_finding):
		if isinstance(data_finding, dict):
			items_error.extend(validateFinding(index_finding, data_finding))
	return items_error
