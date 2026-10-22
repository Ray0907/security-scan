#!/usr/bin/env python3
"""Check declared Node.js and PHP runtime versions against security release feeds.

Coverage is declared-version-only: the repository declares a version, the deployment may run
another one. Ranges and floating tags are never reported as vulnerable.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_FEED_BYTES = 20_000_000
COVERAGE = "declared-version-only"
URL_NODE_CORE = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
URL_NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
URL_PHP_ACTIVE = "https://www.php.net/releases/active.php"
URL_PHP_RELEASES = "https://www.php.net/releases/index.php?json&version={major}&max=1000"
RUNTIME_IMAGES = {"node", "php"}
PATTERN_TAG = re.compile(r"v?(\d+(?:\.\d+){0,2})(?:-[A-Za-z0-9._-]+)?")
PATTERN_X_RANGE = re.compile(r"v?(\d+)(?:\.(\d+))?\.x")
PATTERN_FROM = re.compile(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", re.IGNORECASE)


def toTuple(text_version: str) -> tuple[int, int, int]:
	match_version = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(text_version).strip())
	if not match_version:
		raise ValueError(f"not an exact version: {text_version!r}")
	return tuple(int(part) for part in match_version.groups())


def matchesComparator(tuple_version: tuple, token: str) -> bool:
	match_exact = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", token)
	match_caret = re.fullmatch(r"\^(\d+)\.(\d+)\.(\d+)", token)
	match_x = PATTERN_X_RANGE.fullmatch(token)
	match_op = re.fullmatch(r"(>=|<=|>|<)(\d+(?:\.\d+){0,2})", token)
	if match_exact:
		return tuple_version == tuple(int(part) for part in match_exact.groups())
	if match_caret:
		tuple_base = tuple(int(part) for part in match_caret.groups())
		depth = 1 if tuple_base[0] > 0 else 2
		return tuple_version >= tuple_base and tuple_version[:depth] == tuple_base[:depth]
	if match_x:
		parts_prefix = [int(part) for part in match_x.groups() if part is not None]
		return list(tuple_version[:len(parts_prefix)]) == parts_prefix
	if match_op:
		return matchesOperator(tuple_version, match_op.group(1), match_op.group(2))
	raise ValueError(f"unsupported range syntax: {token!r}")


def padVersion(parts: list[int]) -> tuple[int, int, int]:
	return tuple(parts + [0] * (3 - len(parts)))


def matchesOperator(tuple_version: tuple, operator: str, text_bound: str) -> bool:
	parts_bound = [int(part) for part in text_bound.split(".")]
	is_full = len(parts_bound) == 3
	# A partial bound such as "<= 10" covers the whole major, so it compares against 11.0.0.
	bumped = padVersion(parts_bound[:-1] + [parts_bound[-1] + 1])
	if operator == ">=":
		return tuple_version >= padVersion(parts_bound)
	if operator == "<":
		return tuple_version < padVersion(parts_bound)
	if operator == "<=":
		return tuple_version <= padVersion(parts_bound) if is_full else tuple_version < bumped
	return tuple_version > padVersion(parts_bound) if is_full else tuple_version >= bumped


def matchesRange(text_version: str, text_range: str) -> bool:
	tuple_version = toTuple(text_version)
	for alternative in str(text_range).split("||"):
		text_alternative = re.sub(r"(>=|<=|>|<)\s+", r"\1", alternative.strip())
		tokens = text_alternative.split()
		if tokens and all(matchesComparator(tuple_version, token) for token in tokens):
			return True
	return False


def parseDeclaration(runtime: str, raw: str) -> dict:
	text_raw = (raw or "").strip().strip("\"'")
	match_tag = PATTERN_TAG.fullmatch(text_raw)
	match_x = PATTERN_X_RANGE.fullmatch(text_raw)
	if not text_raw:
		return {"class": "unparseable", "version": None, "reason": "empty version"}
	if match_tag:
		version = match_tag.group(1)
		kind = "exact" if version.count(".") == 2 else "floating"
		return {"class": kind, "version": version, "reason": None}
	if match_x:
		version = ".".join(part for part in match_x.groups() if part is not None)
		return {"class": "floating", "version": version, "reason": None}
	if re.search(r"[$\{]|lts|latest", text_raw, re.IGNORECASE):
		return {"class": "unparseable", "version": None,
			"reason": f"cannot resolve {text_raw!r} without the build environment"}
	if re.search(r"[\^~<>|=*\s]", text_raw):
		return {"class": "range", "version": None,
			"reason": f"range {text_raw!r} admits vulnerable versions; resolved version unknown"}
	return {"class": "unparseable", "version": None, "reason": f"unrecognized version {text_raw!r}"}


def readText(path_file: Path) -> str:
	if path_file.is_symlink():
		raise OSError("symlink not followed")
	with path_file.open("rb") as handle:
		return handle.read(MAX_FILE_BYTES).decode("utf-8", errors="replace")


def getJsonLine(text_file: str, key: str) -> int | None:
	for number_line, line in enumerate(text_file.splitlines(), 1):
		if re.search(rf'"{re.escape(key)}"\s*:', line):
			return number_line
	return None


def readVersionFile(text_file: str, name_file: str) -> list[dict]:
	for number_line, line in enumerate(text_file.splitlines(), 1):
		text_line = line.split("#")[0].strip()
		if text_line:
			return [{"runtime": "node", "file": name_file, "line": number_line, "raw": text_line}]
	return []


def readJsonField(text_file: str, name_file: str, runtime: str, path_keys: tuple) -> list[dict]:
	data_json = json.loads(text_file)
	value = data_json
	for key in path_keys:
		value = value.get(key) if isinstance(value, dict) else None
	if value is None:
		return []
	return [{"runtime": runtime, "file": name_file, "line": getJsonLine(text_file, path_keys[-1]),
		"raw": str(value)}]


def readDockerfile(text_file: str, name_file: str) -> list[dict]:
	items = []
	for number_line, line in enumerate(text_file.splitlines(), 1):
		match_from = PATTERN_FROM.match(line)
		if not match_from:
			continue
		part_image = match_from.group(1).split("@")[0].rsplit("/", 1)[-1]
		name_image, _, tag_image = part_image.partition(":")
		if name_image in RUNTIME_IMAGES:
			items.append({"runtime": name_image, "file": name_file, "line": number_line,
				"raw": tag_image})
	return items


def getFileReader(name_file: str):
	if name_file in (".nvmrc", ".node-version"):
		return readVersionFile
	if name_file == "package.json":
		return lambda text, name: readJsonField(text, name, "node", ("engines", "node"))
	if name_file == "composer.json":
		return lambda text, name: readJsonField(text, name, "php", ("require", "php"))
	if name_file.startswith(("Dockerfile", "Containerfile")):
		return readDockerfile
	return None


def getDeclarations(path_dir: Path) -> tuple[list[dict], list[dict]]:
	"""Return (declarations, problems) for the runtime files directly inside path_dir."""
	declarations, problems = [], []
	for name_file in sorted(os.listdir(path_dir)):
		reader = getFileReader(name_file)
		path_file = path_dir / name_file
		if reader is None or not (path_file.is_file() or path_file.is_symlink()):
			continue
		try:
			declarations.extend(reader(readText(path_file), name_file))
		except (OSError, ValueError, AttributeError, RecursionError) as error_read:
			kind_problem = "symlink" if "symlink" in str(error_read) else "invalid file"
			problems.append({"file": name_file, "line": None, "runtime": None, "raw": "",
				"class": "unreadable",
				"reason": f"{kind_problem}: {type(error_read).__name__} {error_read}".strip()})
	return declarations, problems


class FeedSet:
	"""Load feeds once, from the network or a fixtures directory, and record their hashes."""

	def __init__(self, path_fixtures: Path | None):
		self.path_fixtures = path_fixtures
		self.cache: dict = {}
		self.metas: list[dict] = []
		self.errors: list[str] = []

	def get(self, name_feed: str, url_feed: str):
		if name_feed in self.cache:
			return self.cache[name_feed]
		try:
			if self.path_fixtures is not None:
				path_feed = self.path_fixtures / name_feed
				body, url_record = path_feed.read_bytes(), path_feed.as_uri()
			else:
				request = urllib.request.Request(
					url_feed, headers={"User-Agent": "security-scan-runtime-check"})
				with urllib.request.urlopen(request, timeout=30) as response:
					body, url_record = response.read(MAX_FEED_BYTES), url_feed
			data_feed = json.loads(body)
			self.metas.append({"name": name_feed, "url": url_record,
				"fetched_at": datetime.now(timezone.utc).isoformat(),
				"sha256": hashlib.sha256(body).hexdigest()})
		except (OSError, ValueError) as error_feed:
			self.errors.append(f"{name_feed}: {error_feed}")
			data_feed = None
		self.cache[name_feed] = data_feed
		return data_feed


def makeFinding(declaration: dict, parsed: dict, **fields) -> dict:
	item = {
		"runtime": declaration["runtime"], "location": declaration["file"],
		"line": declaration["line"], "declared": declaration["raw"],
		"version": parsed["version"], "aliases": [], "fixed": [], "severity": None,
		"references": [], "confidence": "medium",
	}
	item.update(fields)
	return item


def getFixedVersions(text_patched: str, text_major: str) -> list[str]:
	alternatives = [alt.strip() for alt in str(text_patched).split("||") if alt.strip()]
	same_major = [alt for alt in alternatives if alt.lstrip("^>= ").split(".")[0] == text_major]
	return [alt.lstrip("^") for alt in same_major or alternatives]


def checkNodeEol(declaration: dict, parsed: dict, data_schedule: dict, now: date) -> list[dict]:
	major = parsed["version"].split(".")[0]
	text_end = (data_schedule.get(f"v{major}") or {}).get("end")
	if not text_end or date.fromisoformat(text_end) >= now:
		return []
	return [makeFinding(declaration, parsed, id=f"NODE-EOL-{major}", kind="eol",
		severity="medium", confidence="high",
		summary=f"Node.js {major} reached end of life on {text_end} and gets no security fixes",
		references=["https://github.com/nodejs/Release/blob/main/schedule.json"])]


def checkNodeCves(declaration: dict, parsed: dict, data_core: dict, unparsed: set) -> list[dict]:
	findings = []
	for key_entry, entry in data_core.items():
		try:
			is_hit = matchesRange(parsed["version"], entry["vulnerable"]) and \
				not matchesRange(parsed["version"], entry.get("patched", ""))
		except ValueError:
			unparsed.add(key_entry)
			continue
		if not is_hit:
			continue
		cves = list(entry.get("cve") or [])
		is_all = "all" in (entry.get("affectedEnvironments") or ["all"])
		findings.append(makeFinding(
			declaration, parsed, id=cves[0] if cves else f"NODEJS-SECURITY-WG-{key_entry}",
			aliases=cves[1:], kind="cve", severity=entry.get("severity"),
			fixed=getFixedVersions(entry.get("patched", ""), parsed["version"].split(".")[0]),
			summary=entry.get("description") or "Node.js core vulnerability",
			references=[entry["ref"]] if entry.get("ref") else [],
			confidence="medium" if is_all else "low"))
	return findings


def checkPhp(declaration: dict, parsed: dict, feeds: FeedSet, now: date) -> list[dict]:
	parts = parsed["version"].split(".")
	if len(parts) < 2:
		return []
	major, branch = parts[0], ".".join(parts[:2])
	data_active = feeds.get("php_active.json", URL_PHP_ACTIVE)
	if data_active is None:
		return []
	if branch not in (data_active.get(major) or {}):
		return [makeFinding(declaration, parsed, id=f"PHP-EOL-{branch}", kind="eol",
			severity="medium", confidence="high",
			summary=f"PHP {branch} is not in php.net's active list and gets no security fixes",
			references=["https://www.php.net/supported-versions.php"])]
	if parsed["class"] != "exact":
		return []
	data_releases = feeds.get(f"php_releases_{major}.json", URL_PHP_RELEASES.format(major=major))
	return checkPhpBehind(declaration, parsed, data_releases or {}, branch)


def checkPhpBehind(declaration: dict, parsed: dict, data_releases: dict, branch: str) -> list[dict]:
	tuple_pin = toTuple(parsed["version"])
	versions_security = [
		version for version, release in data_releases.items()
		if version.startswith(branch + ".") and re.fullmatch(r"\d+\.\d+\.\d+", version)
		and toTuple(version) > tuple_pin and "security" in (release.get("tags") or [])
	]
	if not versions_security:
		return []
	latest = max(versions_security, key=toTuple)
	return [makeFinding(declaration, parsed, id=f"PHP-SECURITY-RELEASE-{latest}",
		kind="behind-security-release", fixed=[latest],
		summary=(f"PHP {parsed['version']} is older than security release {latest}; "
			"php.net publishes no CVE mapping, so this is not CVE-matched"),
		references=[f"https://www.php.net/ChangeLog-{branch.split('.')[0]}.php#{latest}"])]


def checkDeclaration(declaration: dict, parsed: dict, feeds: FeedSet, now: date,
		unparsed: set) -> list[dict]:
	if declaration["runtime"] == "php":
		return checkPhp(declaration, parsed, feeds, now)
	data_schedule = feeds.get("node_schedule.json", URL_NODE_SCHEDULE)
	findings = checkNodeEol(declaration, parsed, data_schedule, now) if data_schedule else []
	data_core = feeds.get("node_core.json", URL_NODE_CORE) if parsed["class"] == "exact" else None
	if data_core:
		findings.extend(checkNodeCves(declaration, parsed, data_core, unparsed))
	return findings


def checkRuntime(
	path_dir: Path, path_fixtures: Path | None = None, now: date | None = None
) -> dict:
	now = now or date.today()
	declarations, problems = getDeclarations(path_dir)
	feeds, findings, unparsed = FeedSet(path_fixtures), [], set()
	inconclusive = list(problems)
	for declaration in declarations:
		parsed = parseDeclaration(declaration["runtime"], declaration["raw"])
		if parsed["class"] in ("range", "unparseable"):
			inconclusive.append({**declaration, **parsed})
		elif declaration["runtime"] == "php" and "." not in parsed["version"]:
			inconclusive.append({**declaration, **parsed,
				"reason": "major-only PHP tag; branch unknown"})
		else:
			findings.extend(checkDeclaration(declaration, parsed, feeds, now, unparsed))
	return {
		"schema_version": 1, "coverage": COVERAGE,
		"generated_at": datetime.now(timezone.utc).isoformat(),
		"feeds": feeds.metas, "declarations": declarations, "findings": findings,
		"inconclusive": inconclusive, "errors": feeds.errors, "unparsed": sorted(unparsed),
	}


def parseArguments() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("path", nargs="?", default=".", type=Path)
	parser.add_argument("--fixtures", type=Path,
		help="read feeds from this directory instead of the network (tests, offline runs)")
	parser.add_argument("--today", type=date.fromisoformat,
		help="date used for end-of-life checks, YYYY-MM-DD (default: today)")
	return parser.parse_args()


def runMain() -> None:
	args_check = parseArguments()
	report = checkRuntime(args_check.path, args_check.fixtures, args_check.today)
	sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
	runMain()
