import json
import re

try:
	from scripts.finding_core import makeFinding
except ModuleNotFoundError:
	from finding_core import makeFinding


OWASP_2021 = {
	"A01": "A01", "A02": "A04", "A03": "A05", "A04": "A06", "A05": "A02",
	"A06": "A03", "A07": "A07", "A08": "A08", "A09": "A09", "A10": "A01",
}


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
		content_lines = extra.get("lines")
		item = makeFinding(
			"semgrep", result["check_id"], "code", severity=extra.get("severity"),
			location=result.get("path"), summary=extra.get("message"), cwe=values_cwe,
			rule_id=result["check_id"], line=result.get("start", {}).get("line"),
			confidence=metadata.get("confidence"),
			snippet=None if content_lines == "requires login" else content_lines,
			owasp=categories,
		)
		if content_lines == "requires login":
			item["snippet_omitted_reason"] = (
				"unauthenticated Semgrep CLI does not return source snippets"
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
		symbolic = location_data.get("symbolic") or {}
		key_local = symbolic.get("key", {}).get("Local", {})
		start_point = concrete.get("location", {}).get("start_point", {})
		line = concrete.get("line")
		if line is None and start_point.get("row") is not None:
			line = start_point["row"] + 1
		items.append(
			makeFinding(
				"zizmor", finding["ident"], "ci", severity=determinations.get("severity"),
				location=concrete.get("path") or key_local.get("path") or key_local.get("verbatim_path") or ".github/workflows",
				line=line, summary=finding.get("description") or finding.get("desc"),
				references=[finding["url"]] if finding.get("url") else [],
				rule_id=finding["ident"], confidence=determinations.get("confidence"),
				owasp=["A03"],
			)
		)
	return items
