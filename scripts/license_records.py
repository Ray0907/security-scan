import json
import re
from pathlib import Path

try:
	from scripts.finding_core import makeFinding
except ModuleNotFoundError:
	from finding_core import makeFinding


def licenseAtom(atom: str) -> str | None:
	if atom.startswith(("AGPL-", "GPL-", "SSPL-")) or atom in {"AGPL", "GPL", "SSPL"}:
		return "high"
	if atom.startswith(("MPL-", "LGPL-", "EPL-", "CDDL-")) or atom in {
		"MPL", "LGPL", "EPL", "CDDL"
	}:
		return "medium"
	if atom in {"MIT", "Apache-2.0", "ISC", "0BSD", "Unlicense", "Unicode-3.0"} \
			or atom.startswith("BSD-"):
		return None
	return "unknown"


def classifySpdxLicense(expression: str | None) -> str | None:
	"""AND applies all terms; OR permits the least restrictive branch."""
	if not isinstance(expression, str) or not expression.strip():
		return "unknown"
	tokens = re.findall(r"\(|\)|[^\s()]+", expression)
	values, operators = [], []
	levels = {"OR": 1, "AND": 2}
	ranks = {None: 0, "unknown": 1, "medium": 2, "high": 3}
	expecting_atom = True

	def applyOperator():
		operator = operators.pop()
		right, left = values.pop(), values.pop()
		values.append(max((left, right), key=ranks.get) if operator == "AND"
			else min((left, right), key=ranks.get))

	for token in tokens:
		if token == "(":
			if not expecting_atom:
				return "unknown"
			operators.append(token)
		elif token == ")":
			if expecting_atom or "(" not in operators:
				return "unknown"
			while operators[-1] != "(":
				applyOperator()
			operators.pop()
		elif token in levels:
			if expecting_atom:
				return "unknown"
			while operators and operators[-1] != "(" and levels[operators[-1]] >= levels[token]:
				applyOperator()
			operators.append(token)
			expecting_atom = True
		else:
			if not expecting_atom:
				return "unknown"
			values.append(licenseAtom(token))
			expecting_atom = False
	if expecting_atom or "(" in operators:
		return "unknown"
	while operators:
		applyOperator()
	return values[0]


class UnsupportedLockfileError(ValueError):
	"""Lockfile format/shape has no reliable provenance signal; caller must report inconclusive, not failed."""


def getRegistryPackages(path_lock: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
	"""Read lockfile-native provenance; never trust OSV's name-only license for local packages."""
	registry, local = set(), set()
	if path_lock.name == "Cargo.lock":
		for block in path_lock.read_text(encoding="utf-8").split("[[package]]")[1:]:
			name = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
			version = re.search(r'^version = "([^"]+)"$', block, re.MULTILINE)
			if name and version:
				key = (name[1], version[1])
				(registry if re.search(r'^source = "registry\+', block, re.MULTILINE)
					else local).add(key)
	elif path_lock.name in {"package-lock.json", "npm-shrinkwrap.json"}:
		data_lock = json.loads(path_lock.read_text(encoding="utf-8"))
		if "packages" not in data_lock:
			raise UnsupportedLockfileError("npm lockfile v1 (no \"packages\" map) has no provenance data")
		for path_package, value in data_lock["packages"].items():
			if not isinstance(value, dict) or not value.get("version"):
				continue
			name = value.get("name") or path_package.rsplit("node_modules/", 1)[-1]
			key = (name, value["version"])
			resolved = value.get("resolved", "")
			# ponytail: non-tarball registry URLs remain inconclusive until provenance is verifiable.
			(registry if isinstance(resolved, str) and
				re.fullmatch(r"https?://[^/]+/.+/-/[^/]+\.tgz(?:\?.*)?", resolved)
				and not value.get("link") and path_package else local).add(key)
	else:
		raise UnsupportedLockfileError("lockfile provenance not supported")
	return registry - local, local


def parseOsvScannerLicense(content: str, path_lock: Path) -> tuple[list[dict], str | None]:
	if path_lock.name == "requirements.txt" or re.fullmatch(r"requirements.*\.txt", path_lock.name):
		lines = path_lock.read_text(encoding="utf-8").splitlines()
		pinned = {(match[1].lower().replace("_", "-"), match[2]) for line in lines
			if (match := re.fullmatch(r"\s*([a-zA-Z0-9_.-]+)==([^\s;]+).*", line))}
		unscanned = any(line.strip() and not line.lstrip().startswith("#") and
			not re.fullmatch(r"\s*[a-zA-Z0-9_.-]+==[^\s;]+.*", line) for line in lines)
		registry, local = None, set()
	else:
		registry, local = getRegistryPackages(path_lock)
		unscanned = False
	data = json.loads(content)
	results = data["results"]
	if not isinstance(results, list) or not any(result.get("packages") for result in results):
		raise ValueError("no license packages in scanner output")
	items = []
	for result in results:
		if Path(result["source"]["path"]).name != path_lock.name:
			raise ValueError("scanner source does not match lockfile")
		for entry in result["packages"]:
			package = entry["package"]
			name, version = package["name"], package["version"]
			key = (name, version)
			if (registry is None and (name.lower().replace("_", "-"), version) not in pinned) or (
				registry is not None and key not in registry):
				unscanned = True
				continue
			licenses = entry.get("licenses")
			if licenses is not None and (not isinstance(licenses, list) or
				any(value is not None and not isinstance(value, str) for value in licenses)):
				raise ValueError("invalid license list")
			licenses = licenses or [None]
			severity = max((classifySpdxLicense(value) for value in licenses),
				key={None: 0, "unknown": 1, "medium": 2, "high": 3}.get)
			if severity:
				items.append(makeFinding("osv-scanner-license", f"LICENSE:{name}:{version}",
					"license", package=name, installed=version, severity=severity,
					location=path_lock.name, owasp=[], confidence="low" if severity == "unknown" else "high",
					summary=(f"{name} {version}: needs manual license review" if severity == "unknown"
						else f"{name} {version}: {severity} copyleft license ({', '.join(map(str, licenses))})")))
	return items, ("unpinned or local dependency, license not scanned" if registry is None
		else "local package, license not scanned") if unscanned else None


def normalizeLicenseRecord(content: str, meta: dict, root: str, path_stdout: Path) -> tuple:
	stderr_scan = path_stdout.with_name("stderr.txt").read_text(encoding="utf-8")
	if meta.get("exit_code") not in (0, 1) or re.search(
		r"error|fail|timeout|network|retrieve|deps\.dev", stderr_scan, re.IGNORECASE
	):
		return [], "inconclusive", "license lookup unavailable (deps.dev/network)"
	if not content.strip():
		raise ValueError("empty scanner output")
	name_lock = meta["command"][4]
	if Path(name_lock).name != name_lock:
		raise ValueError("unsafe lockfile path")
	path_lock = Path(root) / meta["path"] / name_lock
	if not path_lock.is_file() or path_lock.is_symlink():
		return [], "inconclusive", "original lockfile unavailable for local-package filtering"
	if name_lock not in {"Cargo.lock", "package-lock.json", "npm-shrinkwrap.json"} and not \
			re.fullmatch(r"requirements.*\.txt", name_lock):
		json.loads(content)
		return [], "inconclusive", "license scanning not supported for this lockfile"
	try:
		findings, reason = parseOsvScannerLicense(content, path_lock)
	except UnsupportedLockfileError as error_provenance:
		return [], "inconclusive", f"license scanning not supported for this lockfile: {error_provenance}"
	return findings, "inconclusive" if reason else "findings" if findings else "clean", reason


def parseRuntimeVersions(content: str) -> list[dict]:
	data_runtime = json.loads(content)
	return [
		makeFinding(
			"runtime-versions", item["id"], "runtime", package=item["runtime"],
			installed=item["version"], fixed=item["fixed"], severity=item["severity"],
			location=item["location"], line=item["line"], summary=item["summary"],
			references=item["references"], aliases=item["aliases"],
			confidence=item["confidence"], owasp=["A03"],
		)
		for item in data_runtime["findings"]
	]


def normalizeRuntimeRecord(content: str) -> tuple:
	"""Findings win; feed errors beat clean; every open item stays visible in the reason."""
	data_runtime = json.loads(content)
	findings = parseRuntimeVersions(content)
	notes = [f"feed error: {error}" for error in data_runtime["errors"]]
	if data_runtime["unparsed"]:
		notes.append("unparsed advisory entries: " + ", ".join(data_runtime["unparsed"]))
	notes.extend(
		f"{item['file']}: {item['reason']}" for item in data_runtime["inconclusive"]
	)
	reason = "; ".join(notes) or None
	if findings:
		return findings, "findings", reason
	if data_runtime["errors"]:
		return [], "failed", reason
	return [], "inconclusive" if notes else "clean", reason
