import hashlib
from datetime import datetime, timezone

try:
	from scripts.redaction import redactText
except ModuleNotFoundError:
	from redaction import redactText


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}


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


def getFingerprint(finding: dict) -> str:
	value_fingerprint = "|".join(
		str(finding.get(key) or "")
		for key in ("source", "id", "package", "location", "line")
	)
	return hashlib.sha256(value_fingerprint.encode()).hexdigest()[:16]


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
		"cwe": [cwe] if isinstance(cwe, str) else list(cwe or ()),
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
	item_finding["fingerprint"] = getFingerprint(item_finding)
	return item_finding
