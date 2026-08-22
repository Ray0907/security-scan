#!/usr/bin/env python3
"""Build a deterministic, read-only dependency scan plan for a repository."""

import argparse
import json
import os
from pathlib import Path

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


def getRelativePath(path_project: Path, path_root: Path) -> str:
	path_relative = path_project.relative_to(path_root)
	return "." if not path_relative.parts else path_relative.as_posix()


def getYarnCommand(path_project: Path) -> list[str]:
	path_package = path_project / "package.json"
	version_major: int | None = None

	try:
		data_package = json.loads(path_package.read_text(encoding="utf-8"))
		value_manager = data_package.get("packageManager", "")
		if value_manager.startswith("yarn@"):
			version_major = int(value_manager.split("@", 1)[1].split(".", 1)[0])
	except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
		pass

	if version_major and version_major >= 2 or (path_project / ".yarnrc.yml").exists():
		return ["yarn", "npm", "audit", "--json", "--all", "--recursive"]
	return ["yarn", "audit", "--json"]


def getNodeProject(path_project: Path, names_file: set[str], path_root: Path) -> dict:
	data_base = {
		"kind": "node",
		"path": getRelativePath(path_project, path_root),
		"status": "ready",
	}

	if "pnpm-lock.yaml" in names_file:
		return {**data_base, "tool": "pnpm", "command": ["pnpm", "audit", "--json"]}
	if "yarn.lock" in names_file:
		return {**data_base, "tool": "yarn", "command": getYarnCommand(path_project)}
	if {"package-lock.json", "npm-shrinkwrap.json"} & names_file:
		return {**data_base, "tool": "npm", "command": ["npm", "audit", "--json"]}
	return {
		**data_base,
		"status": "needs-lockfile",
		"tool": None,
		"command": None,
		"reason": "package.json exists without a supported lockfile",
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

	paths_node_ready = {
		Path(item_project["path"])
		for item_project in items_project
		if item_project["kind"] == "node" and item_project["status"] == "ready"
	}
	items_project = [
		item_project
		for item_project in items_project
		if not (
			item_project["kind"] == "node"
			and item_project["status"] != "ready"
			and any(
				path_parent in Path(item_project["path"]).parents
				for path_parent in paths_node_ready
			)
		)
	]
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
