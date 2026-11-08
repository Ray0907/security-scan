import json
import re

try:
	from scripts.finding_core import getIdentifier, makeFinding, normalizeSeverity
except ModuleNotFoundError:
	from finding_core import getIdentifier, makeFinding, normalizeSeverity


LOCKFILES_NODE = {
	"npm": "package-lock.json",
	"pnpm": "pnpm-lock.yaml",
	"yarn": "yarn.lock",
	"bun": "bun.lock",
	"composer": "composer.lock",
}


def parseAdvisory(source: str, package: str, advisory: dict) -> dict:
	identifier = advisory.get("id") or advisory.get("advisoryId") or advisory.get("cve")
	url_advisory = advisory.get("url") or advisory.get("link")
	aliases = list(advisory.get("cves") or [])
	if advisory.get("cve"):
		aliases.append(advisory["cve"])
	aliases.extend(
		source["remoteId"] for source in advisory.get("sources", [])
		if source.get("remoteId")
	)
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
		fixed_versions = patched if isinstance(patched, list) else [patched]
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
	items = []
	for advisory in data["advisories"].values():
		item = parseAdvisory("pnpm", advisory.get("module_name", "unknown"), advisory)
		findings = advisory.get("findings") or []
		item["installed_version"] = findings[0].get("version") if findings else None
		items.append(item)
	return items


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
			item = parseAdvisory("yarn", advisory.get("module_name", "unknown"), advisory)
			findings = advisory.get("findings") or []
			item["installed_version"] = findings[0].get("version") if findings else None
			items.append(item)
		elif "advisories" in data:
			found_shape = True
			for advisory in data["advisories"].values():
				item = parseAdvisory("yarn", advisory.get("module_name", "unknown"), advisory)
				findings = advisory.get("findings") or []
				item["installed_version"] = findings[0].get("version") if findings else None
				items.append(item)
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
	items = []
	for dependency in data["dependencies"]:
		vulnerabilities = {}
		for vulnerability in dependency.get("vulns", []):
			vulnerabilities.setdefault(vulnerability["id"], vulnerability)
		for vulnerability in vulnerabilities.values():
			items.append(
				makeFinding(
					"pip-audit", vulnerability["id"], "dependency",
					package=dependency.get("name"), installed=dependency.get("version"),
					fixed=vulnerability.get("fix_versions"), location="requirements.txt",
					summary=vulnerability.get("description"), aliases=vulnerability.get("aliases"),
				)
			)
	return items


def parseJsonStream(content: str) -> list[dict]:
	decoder_json = json.JSONDecoder()
	items_json = []
	index_json = 0
	while index_json < len(content):
		match_space = re.match(r"\s*", content[index_json:])
		index_json += len(match_space.group())
		if index_json == len(content):
			break
		item_json, index_end = decoder_json.raw_decode(content, index_json)
		items_json.append(item_json)
		index_json = index_end
	return items_json


def parseGovulncheck(content: str) -> list[dict]:
	values_osv = {}
	values_finding = []
	found_shape = False
	for data in parseJsonStream(content):
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
		frame = trace[0]
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
				severity=advisory.get("cvss"), score=advisory.get("cvss"), location="Cargo.lock",
				summary=advisory.get("title") or advisory.get("description"),
				references=[advisory["url"]] if advisory.get("url") else [],
			)
		)
	return items


def parseComposer(content: str) -> list[dict]:
	data = json.loads(content)
	advisories = data["advisories"]
	if isinstance(advisories, list):
		return []
	return [parseAdvisory("composer", package, advisory) for package, values in advisories.items() for advisory in values]


def parseBundlerAudit(content: str) -> list[dict]:
	data = json.loads(content[content.index("{"):])
	items = []
	for result in data["results"]:
		if result.get("type") != "unpatched_gem":
			continue
		advisory = result["advisory"]
		gem = result.get("gem", {})
		items.append(
			makeFinding(
				"bundler-audit", advisory["id"], "dependency", package=gem.get("name"),
				installed=gem.get("version"),
				fixed=advisory.get("patched_versions") or ([advisory["solution"]] if advisory.get("solution") else []),
				severity=advisory.get("criticality"), score=advisory.get("cvss_v3"), location="Gemfile.lock",
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
				fixed_versions = sorted({
					event["fixed"]
					for affected in vulnerability.get("affected", [])
					for range_data in affected.get("ranges", [])
					for event in range_data.get("events", [])
					if event.get("fixed")
				})
				score = groups_score.get(vulnerability["id"])
				items.append(
					makeFinding(
						"osv-scanner", vulnerability["id"], "dependency", package=package.get("name"),
						installed=package.get("version"), fixed=fixed_versions,
						severity=score, score=score, location=location,
						summary=vulnerability.get("summary") or vulnerability.get("details"),
						aliases=vulnerability.get("aliases"),
						references=[reference["url"] for reference in vulnerability.get("references", []) if reference.get("url")],
					)
				)
	return items
