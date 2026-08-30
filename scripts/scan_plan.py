#!/usr/bin/env python3
"""Build a deterministic, read-only dependency scan plan for a repository."""

import argparse
import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

NAMES_SKIPPED = {
	".git",
	".mypy_cache",
	".pytest_cache",
	".tox",
	".venv",
	"__pycache__",
	"build",
	"dist",
	"node_modules",
	"target",
	"vendor",
	"venv",
}

IDENTIFIER_PRERELEASE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
PATTERN_PACKAGE_MANAGER = re.compile(
	r"(npm|pnpm|yarn)@((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
	rf"(?:-{IDENTIFIER_PRERELEASE}(?:\.{IDENTIFIER_PRERELEASE})*)?"
	r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
)


def getRelativePath(path_project: Path, path_root: Path) -> str:
	path_relative = path_project.relative_to(path_root)
	return "." if not path_relative.parts else path_relative.as_posix()


def rejectJsonConstant(value_constant: str) -> None:
	raise ValueError(f"non-standard JSON constant: {value_constant}")


def isSafeWorkspacePattern(pattern_workspace: str) -> bool:
	if not pattern_workspace or pattern_workspace != pattern_workspace.strip(" \t"):
		return False
	pattern_path = pattern_workspace[1:] if pattern_workspace.startswith("!") else pattern_workspace
	if not pattern_path or "\\" in pattern_path or pattern_path.startswith("/"):
		return False
	if re.match(r"^[A-Za-z]:", pattern_path):
		return False
	parts_path = pattern_path.split("/")
	return all(part_path not in ("", ".", "..") for part_path in parts_path)


def matchesWorkspacePattern(path_workspace: PurePosixPath, pattern_workspace: str) -> bool:
	parts_path = path_workspace.parts
	parts_pattern = tuple(pattern_workspace.split("/"))
	states_match = [(0, 0)]
	states_seen = set()
	while states_match:
		index_path, index_pattern = states_match.pop()
		state_match = (index_path, index_pattern)
		if state_match in states_seen:
			continue
		states_seen.add(state_match)
		if index_pattern == len(parts_pattern):
			if index_path == len(parts_path):
				return True
			continue
		if parts_pattern[index_pattern] == "**":
			states_match.append((index_path, index_pattern + 1))
			if index_path < len(parts_path):
				states_match.append((index_path + 1, index_pattern))
		elif index_path < len(parts_path) and fnmatchcase(
			parts_path[index_path], parts_pattern[index_pattern]
		):
			states_match.append((index_path + 1, index_pattern + 1))
	return False


def getPackageWorkspacePatterns(data_package: dict) -> tuple[str, ...] | None:
	if "workspaces" not in data_package:
		return ()
	value_workspaces = data_package["workspaces"]
	if isinstance(value_workspaces, dict):
		value_workspaces = value_workspaces.get("packages")
	if not isinstance(value_workspaces, list):
		return None
	if not all(
		isinstance(pattern_workspace, str) and isSafeWorkspacePattern(pattern_workspace)
		for pattern_workspace in value_workspaces
	):
		return None
	return tuple(value_workspaces)


def isYamlNonStringPlainScalar(value_scalar: str) -> bool:
	if value_scalar.lower() in {
		"~",
		"null",
		"true",
		"false",
		"yes",
		"no",
		"on",
		"off",
		"y",
		"n",
		".nan",
		".inf",
		"+.inf",
		"-.inf",
	}:
		return True
	if re.fullmatch(
		r"[-+]?(?:"
		r"0[bB][01_]+|"
		r"0[oO][0-7_]+|"
		r"0[xX][0-9a-fA-F_]+|"
		r"[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|"
		r"(?:(?:[0-9][0-9_]*)?\.[0-9_]+|[0-9][0-9_]*\.)"
		r"(?:[eE][-+]?[0-9]+)?|"
		r"[0-9][0-9_]*(?:[eE][-+]?[0-9]+)?"
		r")",
		value_scalar,
	):
		return True
	return (
		re.fullmatch(
			r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}"
			r"(?:"
			r"(?:[Tt]|[ \t]+)"
			r"[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
			r"(?:\.[0-9]+)?"
			r"(?:[ \t]*(?:[Zz]|[-+][0-9]{1,2}(?::[0-9]{2})?))?"
			r")?",
			value_scalar,
		)
		is not None
	)


def parsePnpmWorkspaceScalar(value_scalar: str) -> str | None:
	if value_scalar.startswith("'"):
		match_scalar = re.fullmatch(
			r"'((?:[^']|'')*)'(?:[ \t]+(?:#.*)?)?",
			value_scalar,
		)
		if match_scalar is None:
			return None
		return match_scalar.group(1).replace("''", "'")
	if value_scalar.startswith('"'):
		return None

	value_unquoted = re.split(r"[ \t]+#", value_scalar, maxsplit=1)[0].rstrip(" \t")
	if not value_unquoted or value_unquoted[0] in "-?:,[]{}#&*!|>'\"%@`":
		return None
	if re.search(r":(?:[ \t]|$)", value_unquoted):
		return None
	if isYamlNonStringPlainScalar(value_unquoted):
		return None
	return value_unquoted


def hasForbiddenYamlSourceCharacter(content_workspace: str) -> bool:
	for character_workspace in content_workspace:
		value_character = ord(character_workspace)
		if value_character in (0x09, 0x0A, 0x0D, 0x85):
			continue
		if 0x20 <= value_character <= 0x7E:
			continue
		if 0xA0 <= value_character <= 0xD7FF:
			continue
		if 0xE000 <= value_character <= 0xFFFD:
			continue
		if 0x10000 <= value_character <= 0x10FFFF:
			continue
		return True
	return False


def getPnpmWorkspacePatterns(path_project: Path) -> tuple[str, ...] | None:
	path_workspace = path_project / "pnpm-workspace.yaml"
	if path_workspace.is_symlink():
		return None
	if not path_workspace.exists():
		return ()
	try:
		content_workspace = path_workspace.read_text(encoding="utf-8")
	except (OSError, UnicodeError):
		return None
	if hasForbiddenYamlSourceCharacter(content_workspace):
		return None
	if any(
		character_workspace.isspace() and character_workspace not in " \t\r\n"
		for character_workspace in content_workspace
	):
		return None
	lines_workspace = [
		line_workspace[:-1] if line_workspace.endswith("\r") else line_workspace
		for line_workspace in content_workspace.split("\n")
	]

	indexes_packages = []
	for index_line, line_workspace in enumerate(lines_workspace):
		if line_workspace.startswith((" ", "\t")):
			continue
		if re.fullmatch(r"packages:(?:[ \t]+(?:#.*)?)?", line_workspace):
			indexes_packages.append(index_line)
		elif re.match(r"packages[ \t]*:", line_workspace):
			return None
	if not indexes_packages:
		return ()
	if len(indexes_packages) != 1:
		return None
	if any(
		line_workspace.strip(" \t")
		and not line_workspace.lstrip(" \t").startswith("#")
		for line_workspace in lines_workspace[: indexes_packages[0]]
	):
		return None

	patterns_workspace = []
	indent_list: int | None = None
	for line_workspace in lines_workspace[indexes_packages[0] + 1 :]:
		if not line_workspace.strip(" \t") or line_workspace.lstrip(" \t").startswith("#"):
			continue
		if not line_workspace.startswith((" ", "\t")):
			return None
		if "\t" in line_workspace:
			return None
		match_item = re.fullmatch(r"( +)-[ \t]+(.+?)[ \t]*", line_workspace)
		if match_item is None:
			return None
		indent_item = len(match_item.group(1))
		if indent_list is None:
			indent_list = indent_item
		elif indent_item != indent_list:
			return None
		pattern_workspace = parsePnpmWorkspaceScalar(match_item.group(2))
		if pattern_workspace is None or not isSafeWorkspacePattern(pattern_workspace):
			return None
		patterns_workspace.append(pattern_workspace)
	return tuple(patterns_workspace)


def getYarnCommand(path_project: Path, version_manager: str | None) -> list[str]:
	version_major: int | None = None
	if version_manager is not None:
		try:
			version_major = int(version_manager.split(".", 1)[0])
		except ValueError:
			pass

	if version_major and version_major >= 2 or (path_project / ".yarnrc.yml").exists():
		return ["yarn", "npm", "audit", "--json", "--all", "--recursive"]
	return ["yarn", "audit", "--json"]


def getNodeProject(path_project: Path, names_file: set[str], path_root: Path) -> dict:
	data_base = {
		"kind": "node",
		"path": getRelativePath(path_project, path_root),
	}

	path_package = path_project / "package.json"
	if path_package.is_symlink():
		data_package = None
	else:
		try:
			data_package = json.loads(
				path_package.read_text(encoding="utf-8"),
				parse_constant=rejectJsonConstant,
			)
		except (OSError, UnicodeError, ValueError, RecursionError):
			data_package = None
	if not isinstance(data_package, dict):
		return {
			**data_base,
			"status": "inconclusive",
			"tool": None,
			"command": None,
			"reason": "package.json is invalid",
		}

	manager_declared: str | None = None
	version_manager: str | None = None
	if "packageManager" in data_package:
		value_manager = data_package["packageManager"]
		match_manager = (
			PATTERN_PACKAGE_MANAGER.fullmatch(value_manager)
			if isinstance(value_manager, str)
			else None
		)
		if match_manager is None:
			return {
				**data_base,
				"status": "inconclusive",
				"tool": None,
				"command": None,
				"reason": "packageManager declaration is unsupported or malformed",
			}
		manager_declared, version_manager = match_manager.groups()

	managers_lockfile = set()
	if "pnpm-lock.yaml" in names_file:
		managers_lockfile.add("pnpm")
	if "yarn.lock" in names_file:
		managers_lockfile.add("yarn")
	if {"package-lock.json", "npm-shrinkwrap.json"} & names_file:
		managers_lockfile.add("npm")

	if len(managers_lockfile) > 1:
		return {
			**data_base,
			"status": "inconclusive",
			"tool": None,
			"command": None,
			"reason": "lockfiles for multiple package managers are present",
		}
	if managers_lockfile and manager_declared not in (None, next(iter(managers_lockfile))):
		return {
			**data_base,
			"status": "inconclusive",
			"tool": None,
			"command": None,
			"reason": "packageManager does not match available lockfile",
		}
	if not managers_lockfile:
		return {
			**data_base,
			"status": "needs-lockfile",
			"tool": None,
			"command": None,
			"reason": "package.json exists without a supported lockfile",
		}

	manager_lockfile = next(iter(managers_lockfile))
	commands_manager = {
		"npm": ["npm", "audit", "--json"],
		"pnpm": ["pnpm", "audit", "--json"],
		"yarn": getYarnCommand(path_project, version_manager),
	}
	patterns_workspace = (
		getPnpmWorkspacePatterns(path_project)
		if manager_lockfile == "pnpm"
		else getPackageWorkspacePatterns(data_package)
	)
	return {
		**data_base,
		"status": "ready",
		"tool": manager_lockfile,
		"command": commands_manager[manager_lockfile],
		"_workspace_patterns": patterns_workspace,
	}


def getPythonProject(path_project: Path, names_file: set[str], path_root: Path) -> dict:
	data_base = {
		"kind": "python",
		"path": getRelativePath(path_project, path_root),
		"tool": "pip-audit",
		"status": "ready",
	}
	files_requirement = sorted(
		name_file
		for name_file in names_file
		if name_file.startswith("requirements") and name_file.endswith(".txt")
	)
	if files_requirement:
		command_scan = ["pip-audit", "--format", "json"]
		for name_file in files_requirement:
			command_scan.extend(["-r", name_file])
		return {**data_base, "command": command_scan}
	if any(name_file.startswith("pylock.") for name_file in names_file):
		return {
			**data_base,
			"command": ["pip-audit", "--format", "json", "--locked", "."],
		}
	if "Pipfile.lock" in names_file:
		return {
			**data_base,
			"status": "needs-export",
			"command": None,
			"reason": "Pipfile.lock must be exported to a requirements file before scanning",
		}
	if "pyproject.toml" in names_file:
		return {
			**data_base,
			"status": "needs-lockfile",
			"command": None,
			"reason": "pyproject.toml exists without a supported lockfile",
		}
	return {
		**data_base,
		"status": "needs-export",
		"command": None,
		"reason": "Python project does not include supported dependency evidence",
	}


def getProjects(path_project: Path, names_file: set[str], path_root: Path) -> list[dict]:
	items_project = []
	if "package.json" in names_file:
		items_project.append(getNodeProject(path_project, names_file, path_root))
	if (
		"pyproject.toml" in names_file
		or "Pipfile.lock" in names_file
		or any(name_file.startswith("pylock.") for name_file in names_file)
		or any(
			name_file.startswith("requirements") and name_file.endswith(".txt")
			for name_file in names_file
		)
	):
		items_project.append(getPythonProject(path_project, names_file, path_root))
	if "go.mod" in names_file:
		items_project.append(
			{
				"kind": "go",
				"path": getRelativePath(path_project, path_root),
				"tool": "govulncheck",
				"status": "ready",
				"command": ["govulncheck", "-json", "./..."],
			}
		)
	if "Cargo.toml" in names_file:
		data_rust = {
			"kind": "rust",
			"path": getRelativePath(path_project, path_root),
			"tool": "cargo-audit",
		}
		if "Cargo.lock" in names_file:
			items_project.append(
				{
					**data_rust,
					"status": "ready",
					"command": ["cargo", "audit", "--json"],
				}
			)
		else:
			items_project.append(
				{
					**data_rust,
					"status": "needs-lockfile",
					"command": None,
					"reason": "Cargo.toml exists without Cargo.lock",
				}
			)
	if "composer.lock" in names_file:
		items_project.append(
			{
				"kind": "php",
				"path": getRelativePath(path_project, path_root),
				"tool": "composer",
				"status": "ready",
				"command": ["composer", "audit", "--locked", "--format=json"],
			}
		)
	if "Gemfile.lock" in names_file:
		items_project.append(
			{
				"kind": "ruby",
				"path": getRelativePath(path_project, path_root),
				"tool": "bundler-audit",
				"status": "ready",
				"command": ["bundle-audit", "check", "--format", "json"],
			}
		)
	if {"pom.xml", "build.gradle", "build.gradle.kts"} & names_file:
		items_project.append(
			{
				"kind": "java",
				"path": getRelativePath(path_project, path_root),
				"tool": "trivy",
				"status": "ready",
				"command": ["trivy", "fs", "--format", "json", "--scanners", "vuln", "."],
			}
		)
	if any(
		name_file == "Dockerfile" or name_file.startswith("Dockerfile.") for name_file in names_file
	):
		items_project.append(
			{
				"kind": "container",
				"path": getRelativePath(path_project, path_root),
				"tool": "trivy",
				"status": "ready",
				"coverage": "misconfiguration-only",
				"command": [
					"trivy",
					"fs",
					"--format",
					"json",
					"--scanners",
					"misconfig",
					".",
				],
			}
		)
	return items_project


def buildScanPlan(path_root: Path) -> dict:
	path_resolved = path_root.resolve()
	if not path_resolved.exists():
		raise FileNotFoundError(f"scan root does not exist: {path_resolved}")
	if not path_resolved.is_dir():
		raise NotADirectoryError(f"scan root is not a directory: {path_resolved}")

	items_project = []

	for name_root, names_dir, names_file in os.walk(path_resolved):
		names_dir[:] = sorted(name_dir for name_dir in names_dir if name_dir not in NAMES_SKIPPED)
		path_project = Path(name_root)
		items_project.extend(getProjects(path_project, set(names_file), path_resolved))

	parents_node_ready = [
		item_project
		for item_project in items_project
		if item_project["kind"] == "node"
		and item_project["status"] == "ready"
		and item_project.get("_workspace_patterns")
	]

	def isCoveredByReadyWorkspace(item_child: dict) -> bool:
		path_child = PurePosixPath(item_child["path"])
		for item_parent in parents_node_ready:
			path_parent = PurePosixPath(item_parent["path"])
			try:
				path_relative = path_child.relative_to(path_parent)
			except ValueError:
				continue
			if not path_relative.parts:
				continue
			patterns_workspace = item_parent["_workspace_patterns"]
			patterns_include = [
				pattern for pattern in patterns_workspace if not pattern.startswith("!")
			]
			patterns_exclude = [
				pattern[1:] for pattern in patterns_workspace if pattern.startswith("!")
			]
			if any(
				matchesWorkspacePattern(path_relative, pattern) for pattern in patterns_include
			) and not any(
				matchesWorkspacePattern(path_relative, pattern) for pattern in patterns_exclude
			):
				return True
		return False

	items_project = [
		item_project
		for item_project in items_project
		if not (
			item_project["kind"] == "node"
			and item_project["status"] == "needs-lockfile"
			and isCoveredByReadyWorkspace(item_project)
		)
	]
	for item_project in items_project:
		item_project.pop("_workspace_patterns", None)
	items_project.sort(key=lambda item_project: (item_project["path"], item_project["kind"]))
	return {
		"schema_version": 1,
		"root": str(path_resolved),
		"projects": items_project,
	}


def parseArguments() -> argparse.Namespace:
	parser_scan = argparse.ArgumentParser(
		description="Build a read-only dependency scan plan for a repository.",
	)
	parser_scan.add_argument("path", nargs="?", default=".")
	parser_scan.add_argument("--pretty", action="store_true")
	return parser_scan.parse_args()


def runMain() -> None:
	args_scan = parseArguments()
	try:
		plan_scan = buildScanPlan(Path(args_scan.path))
	except OSError as error_scan:
		raise SystemExit(f"scan-plan: {error_scan}") from error_scan
	indent_json = 2 if args_scan.pretty else None
	print(json.dumps(plan_scan, indent=indent_json, sort_keys=True))


if __name__ == "__main__":
	runMain()
