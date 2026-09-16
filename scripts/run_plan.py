#!/usr/bin/env python3
"""Execute ready scan-plan records and persist redacted evidence."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
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


def getToolVersion(name_tool: str) -> str | None:
	try:
		result_version = subprocess.run(
			[name_tool, "--version"],
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
		shutil.rmtree(path_out)
	path_out.mkdir(parents=True, exist_ok=True)


def loadPlan(path_plan: Path | str) -> dict:
	if str(path_plan) == "-":
		return json.load(sys.stdin)
	with Path(path_plan).open(encoding="utf-8") as file_plan:
		return json.load(file_plan)


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
) -> int:
	plan_scan = loadPlan(path_plan)
	path_root = Path(plan_scan["root"]).resolve()
	prepareOutput(path_out, force)
	started_run = getTimestamp()
	items_meta = []
	versions_tool: dict[str, str | None] = {}
	failed_run = False
	set_only = set(kinds_only or ())
	set_skip = set(kinds_skip or ())
	items_plan = list(plan_scan["projects"])
	if semgrep:
		items_plan.append(
			{
				"kind": "code",
				"path": ".",
				"status": "ready",
				"tool": "semgrep",
				"command": [
					"semgrep", "scan", "--config", "p/owasp-top-ten", "--json",
					"--metrics=off", ".",
				],
			}
		)

	for index_plan, item_plan in enumerate(items_plan, start=1):
		if set_only and item_plan["kind"] not in set_only or item_plan["kind"] in set_skip:
			continue
		path_cwd = path_root if item_plan["path"] == "." else path_root / item_plan["path"]
		path_record = path_out / getRecordDirectory(index_plan, item_plan)
		path_record.mkdir(parents=True)
		started_record = getTimestamp()
		started_clock = time.monotonic()
		state_record = "skipped"
		reason_record = None
		exit_code = None
		stdout_record = ""
		stderr_record = ""
		name_tool = item_plan.get("tool")
		command_scan = item_plan.get("command")
		version_tool = None

		if item_plan.get("status") != "ready":
			reason_record = "planner " + item_plan.get("status", "inconclusive")
			if item_plan.get("reason"):
				reason_record += ": " + item_plan["reason"]
		elif not command_scan or shutil.which(command_scan[0]) is None:
			reason_record = "tool unavailable"
		else:
			if name_tool not in versions_tool:
				versions_tool[name_tool] = getToolVersion(command_scan[0])
			version_tool = versions_tool[name_tool]
			try:
				result_scan = subprocess.run(
					command_scan,
					cwd=path_cwd,
					capture_output=True,
					text=True,
					timeout=timeout_seconds,
					check=False,
				)
				exit_code = result_scan.returncode
				stdout_record = result_scan.stdout
				stderr_record = result_scan.stderr
				state_record = "ran"
			except subprocess.TimeoutExpired as error_timeout:
				state_record = "failed"
				reason_record = f"timed out after {timeout_seconds} seconds"
				stdout_record = error_timeout.stdout or ""
				stderr_record = error_timeout.stderr or ""
				if isinstance(stdout_record, bytes):
					stdout_record = stdout_record.decode(errors="replace")
				if isinstance(stderr_record, bytes):
					stderr_record = stderr_record.decode(errors="replace")
				failed_run = True
			except OSError as error_run:
				state_record = "failed"
				reason_record = str(error_run)
				failed_run = True

		stdout_record, count_stdout = redactText(stdout_record, patterns_redact)
		stderr_record, count_stderr = redactText(stderr_record, patterns_redact)
		if version_tool is not None:
			version_tool = redactText(version_tool, patterns_redact)[0]
		duration_record = round(time.monotonic() - started_clock, 6)
		meta_record = {
			"plan_index": index_plan,
			"kind": item_plan["kind"],
			"path": item_plan["path"],
			"tool": name_tool,
			"command": command_scan,
			"cwd": str(path_cwd),
			"tool_version": version_tool,
			"exit_code": exit_code,
			"duration_seconds": duration_record,
			"started_at": started_record,
			"state": state_record,
			"reason": reason_record,
			"redactions": count_stdout + count_stderr,
		}
		(path_record / "stdout.txt").write_text(stdout_record, encoding="utf-8")
		(path_record / "stderr.txt").write_text(stderr_record, encoding="utf-8")
		(path_record / "meta.json").write_text(
			json.dumps(meta_record, indent=2, sort_keys=True) + "\n",
			encoding="utf-8",
		)
		items_meta.append(meta_record)

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
		)
	except (OSError, ValueError, json.JSONDecodeError, KeyError, re.error) as error_run:
		print(f"run-plan: {error_run}", file=sys.stderr)
		raise SystemExit(2) from error_run
	raise SystemExit(exit_code)


if __name__ == "__main__":
	runMain()
