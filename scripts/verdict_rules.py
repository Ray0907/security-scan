"""Shared semantic checks for security finding verdicts."""

import re


REGEX_FILE_LINE = re.compile(r"[^\s:]*[A-Za-z][^\s:]*:[1-9][0-9]*(?![0-9])")


def validateVerdicts(document) -> list[str]:
	if not isinstance(document, dict):
		return []
	items_finding = document.get("findings")
	if not isinstance(items_finding, list):
		return []
	items_error = []
	for index_finding, data_finding in enumerate(items_finding):
		if not isinstance(data_finding, dict) or data_finding.get("verdict") != "rejected":
			continue
		data_evidence = data_finding.get("verdict_evidence")
		value_trace = data_evidence.get("trace") if isinstance(data_evidence, dict) else None
		if not isinstance(value_trace, str) or not REGEX_FILE_LINE.search(value_trace):
			items_error.append(
				f"/findings/{index_finding}/verdict_evidence/trace: "
				"rejected verdict requires a file:line reference"
			)
	return items_error
