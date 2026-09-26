#!/usr/bin/env python3
"""Execute ready scan-plan records and persist redacted evidence."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

try:
	from scripts.redaction import redactText
except ModuleNotFoundError:
	from redaction import redactText


def getTimestamp() -> str:
	return datetime.now(timezone.utc).isoformat()


def getGitMetadata(path_root: Path) -> dict:
	values_git = []
	for arguments_git in (
		["rev-parse", "HEAD"],
		["rev-parse", "--abbrev-ref", "HEAD"],
		["status", "--porcelain"],
	):
		try:
			result_git = subprocess.run(
				["git", "-C", str(path_root), *arguments_git],
				capture_output=True,
				text=True,
				timeout=30,
				check=False,
			)
		except (OSError, subprocess.TimeoutExpired):
			values_git.append(None)
			continue
		values_git.append(result_git.stdout.strip() if result_git.returncode == 0 else None)
	return {
		"commit": values_git[0],
		"branch": values_git[1],
		"dirty": bool(values_git[2]) if values_git[2] is not None else None,
	}


def getToolVersion(command_version: list[str]) -> str | None:
	try:
		result_version = subprocess.run(
			command_version,
			capture_output=True,
			text=True,
			timeout=30,
			check=False,
		)
	except (OSError, subprocess.TimeoutExpired):
		return None
	for output_version in (result_version.stdout, result_version.stderr):
		for line_version in output_version.splitlines():
			if line_version.strip():
				return line_version.strip()
	return None


def getRecordDirectory(index_plan: int, item_plan: dict) -> str:
	name_path = "root" if item_plan["path"] == "." else item_plan["path"]
	name_path = re.sub(r"[^A-Za-z0-9._-]+", "-", name_path).strip("-") or "root"
	return f"{index_plan:02d}-{item_plan['kind']}-{name_path}"


def prepareOutput(path_out: Path, force_output: bool) -> None:
	if path_out.exists() and any(path_out.iterdir()):
		if not force_output:
			raise ValueError(f"output directory is non-empty: {path_out}; use --force")
		if not (path_out / "run.json").is_file():
			raise ValueError(f"refusing to remove non-evidence directory: {path_out}")
		shutil.rmtree(path_out)
	path_out.mkdir(parents=True, exist_ok=True)


def loadPlan(path_plan: Path | str) -> dict:
	if str(path_plan) == "-":
		return json.load(sys.stdin)
	with Path(path_plan).open(encoding="utf-8") as file_plan:
		return json.load(file_plan)


def prepareRecord(
	index_plan: int,
	item_plan: dict,
	path_root: Path,
	path_record: Path,
	set_only: set,
	set_skip: set,
	versions_tool: dict[str, str | None],
) -> dict:
	"""Decide state/reason/version without running the scanner (sequential, cache-safe)."""
	name_tool = item_plan.get("tool")
	command_scan = item_plan.get("command")
	reason_record = None
	runnable = False

	if set_only and item_plan["kind"] not in set_only:
		reason_record = "excluded by --only"
	elif item_plan["kind"] in set_skip:
		reason_record = "excluded by --skip"
	elif item_plan.get("status") != "ready":
		reason_record = "planner " + item_plan.get("status", "inconclusive")
		if item_plan.get("reason"):
			reason_record += ": " + item_plan["reason"]
	elif not command_scan or shutil.which(command_scan[0]) is None:
		reason_record = "tool unavailable"
	else:
		runnable = True
		if name_tool not in versions_tool:
			versions_tool[name_tool] = getToolVersion(
				["cargo", "audit", "--version"] if name_tool == "cargo-audit"
				else [command_scan[0], "--version"]
			)

	return {
		"plan_index": index_plan,
		"item_plan": item_plan,
		"path_cwd": path_root if item_plan["path"] == "." else path_root / item_plan["path"],
		"path_record": path_record,
		"name_tool": name_tool,
		"command_scan": command_scan,
		"version_tool": versions_tool.get(name_tool),
		"reason_record": reason_record,
		"runnable": runnable,
	}


def executeScan(command_scan: list[str], path_cwd: Path, timeout_seconds: int) -> dict:
	"""Run one scanner subprocess and classify the outcome. No shared state; thread-safe."""
	try:
		result_scan = subprocess.run(
			command_scan,
			cwd=path_cwd,
			capture_output=True,
			text=True,
			timeout=timeout_seconds,
			check=False,
		)
		return {
			"state": "ran",
			"reason": None,
			"exit_code": result_scan.returncode,
			"stdout": result_scan.stdout,
			"stderr": result_scan.stderr,
		}
	except subprocess.TimeoutExpired as error_timeout:
		def decodeOutput(value_output):
			return value_output.decode(errors="replace") if isinstance(value_output, bytes) else value_output

		return {
			"state": "failed",
			"reason": f"timed out after {timeout_seconds} seconds",
			"exit_code": None,
			"stdout": decodeOutput(error_timeout.stdout or ""),
			"stderr": decodeOutput(error_timeout.stderr or ""),
		}
	except OSError as error_run:
		return {
			"state": "failed", "reason": str(error_run), "exit_code": None, "stdout": "", "stderr": "",
		}


def runRecord(record: dict, timeout_seconds: int, patterns_redact: list[str] | None) -> dict:
	"""Execute (or record the skip state of) a single prepared record."""
	started_record = getTimestamp()
	started_clock = time.monotonic()
	if record["runnable"]:
		result_run = executeScan(record["command_scan"], record["path_cwd"], timeout_seconds)
	else:
		result_run = {
			"state": "skipped", "reason": record["reason_record"], "exit_code": None, "stdout": "", "stderr": "",
		}

	stdout_record, count_stdout = redactText(result_run["stdout"], patterns_redact)
	stderr_record, count_stderr = redactText(result_run["stderr"], patterns_redact)
	version_tool = record["version_tool"]
	if version_tool is not None:
		version_tool = redactText(version_tool, patterns_redact)[0]
	item_plan = record["item_plan"]
	meta_record = {
		"plan_index": record["plan_index"],
		"kind": item_plan["kind"],
		"path": item_plan["path"],
		"tool": record["name_tool"],
		"command": record["command_scan"],
		"cwd": str(record["path_cwd"]),
		"tool_version": version_tool,
		"exit_code": result_run["exit_code"],
		"duration_seconds": round(time.monotonic() - started_clock, 6),
		"started_at": started_record,
		"state": result_run["state"],
		"reason": result_run["reason"],
		"redactions": count_stdout + count_stderr,
	}
	path_record = record["path_record"]
	(path_record / "stdout.txt").write_text(stdout_record, encoding="utf-8")
	(path_record / "stderr.txt").write_text(stderr_record, encoding="utf-8")
	(path_record / "meta.json").write_text(
		json.dumps(meta_record, indent=2, sort_keys=True) + "\n",
		encoding="utf-8",
	)
	return meta_record


def runGroupedByTool(
	records_prepared: list[dict],
	timeout_seconds: int,
	patterns_redact: list[str] | None,
	jobs: int,
) -> list[dict]:
	"""Run records concurrently across tools, sequentially within the same tool, in plan order."""
	groups_tool: dict[str | None, list[dict]] = {}
	for record in records_prepared:
		groups_tool.setdefault(record["name_tool"], []).append(record)

	def runGroup(group: list[dict]) -> list[dict]:
		return [runRecord(record, timeout_seconds, patterns_redact) for record in group]

	metas_by_index: dict[int, dict] = {}
	with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
		for metas_group in executor.map(runGroup, groups_tool.values()):
			for meta_record in metas_group:
				metas_by_index[meta_record["plan_index"]] = meta_record
	return [metas_by_index[index] for index in sorted(metas_by_index)]


def buildSemgrepItem() -> dict:
	return {
		"kind": "code",
		"path": ".",
		"status": "ready",
		"tool": "semgrep",
		"command": ["semgrep", "scan", "--config", "p/owasp-top-ten", "--json", "--metrics=off", "."],
	}


def prepareAllRecords(
	items_plan: list[dict],
	path_root: Path,
	path_out: Path,
	set_only: set,
	set_skip: set,
	versions_tool: dict[str, str | None],
) -> list[dict]:
	records_prepared = []
	for index_plan, item_plan in enumerate(items_plan, start=1):
		path_record = path_out / getRecordDirectory(index_plan, item_plan)
		path_record.mkdir(parents=True)
		records_prepared.append(
			prepareRecord(index_plan, item_plan, path_root, path_record, set_only, set_skip, versions_tool)
		)
	return records_prepared


def runPlan(
	path_plan: Path | str,
	path_out: Path,
	timeout_seconds: int = 600,
	kinds_only: list[str] | None = None,
	kinds_skip: list[str] | None = None,
	patterns_redact: list[str] | None = None,
	quiet: bool = False,
	force: bool = False,
	semgrep: bool = False,
	jobs: int = 1,
) -> int:
	plan_scan = loadPlan(path_plan)
	path_root = Path(plan_scan["root"]).resolve()
	prepareOutput(path_out, force)
	started_run = getTimestamp()
	versions_tool: dict[str, str | None] = {}
	set_only = set(kinds_only or ())
	set_skip = set(kinds_skip or ())
	items_plan = list(plan_scan["projects"])
	if semgrep:
		items_plan.append(buildSemgrepItem())

	records_prepared = prepareAllRecords(
		items_plan, path_root, path_out, set_only, set_skip, versions_tool
	)
	items_meta = runGroupedByTool(records_prepared, timeout_seconds, patterns_redact, jobs)
	failed_run = any(item["state"] == "failed" for item in items_meta)

	data_run = {
		"schema_version": 1,
		"plan_root": str(path_root),
		"started_at": started_run,
		"finished_at": getTimestamp(),
		"git": getGitMetadata(path_root),
		"records": items_meta,
	}
	content_run = json.dumps(data_run, indent=2, sort_keys=True) + "\n"
	(path_out / "run.json").write_text(content_run, encoding="utf-8")
	if not quiet:
		print(content_run, end="")
	return 1 if failed_run else 0


def parsePositiveInt(value_raw: str) -> int:
	value_int = int(value_raw)
	if value_int < 1:
		raise argparse.ArgumentTypeError("must be a positive integer")
	return value_int


def parseArguments() -> argparse.Namespace:
	parser_run = argparse.ArgumentParser(description="Run a scan plan and save redacted evidence.")
	parser_run.add_argument("plan")
	parser_run.add_argument("--out", required=True, type=Path)
	parser_run.add_argument("--timeout", type=int, default=600)
	parser_run.add_argument("--only", action="append", default=[])
	parser_run.add_argument("--skip", action="append", default=[])
	parser_run.add_argument("--redact-pattern", action="append", default=[])
	parser_run.add_argument("--quiet", action="store_true")
	parser_run.add_argument("--force", action="store_true")
	parser_run.add_argument("--semgrep", action="store_true")
	parser_run.add_argument(
		"--jobs", type=parsePositiveInt, default=1,
		help="run scanners for distinct tools concurrently (same-tool records stay sequential)",
	)
	return parser_run.parse_args()


def runMain() -> None:
	args_run = parseArguments()
	try:
		exit_code = runPlan(
			args_run.plan,
			args_run.out,
			timeout_seconds=args_run.timeout,
			kinds_only=args_run.only,
			kinds_skip=args_run.skip,
			patterns_redact=args_run.redact_pattern,
			quiet=args_run.quiet,
			force=args_run.force,
			semgrep=args_run.semgrep,
			jobs=args_run.jobs,
		)
	except (OSError, ValueError, json.JSONDecodeError, KeyError, re.error) as error_run:
		print(f"run-plan: {error_run}", file=sys.stderr)
		raise SystemExit(2) from error_run
	raise SystemExit(exit_code)


if __name__ == "__main__":
	runMain()
