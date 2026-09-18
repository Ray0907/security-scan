#!/usr/bin/env python3
"""Suggest non-authoritative verdicts for Semgrep findings with TypeSafe Jev."""

import argparse
import importlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

try:
	from scripts.redaction import redactText
except ModuleNotFoundError:
	from redaction import redactText


VERDICTS = ("confirmed", "needs_validation", "rejected")


def getTimestamp() -> str:
	return datetime.now(timezone.utc).isoformat()


def getChoice(data_response: dict) -> dict:
	try:
		model = data_response["model"]
		answer = data_response["answers"]["verdict"]
		choice = answer["choice"]
		confidence = answer["confidence"]
		probabilities = answer["probabilities"]
	except (KeyError, TypeError) as error:
		raise ValueError("malformed TypeSafe response") from error
	if not isinstance(model, str) or not model:
		raise ValueError("malformed TypeSafe model")
	if answer.get("type") != "choice" or choice not in VERDICTS:
		raise ValueError("malformed TypeSafe choice")
	if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
		raise ValueError("malformed TypeSafe confidence")
	if not isinstance(probabilities, dict) or set(probabilities) != set(VERDICTS):
		raise ValueError("malformed TypeSafe probabilities")
	return {
		"suggested_verdict": choice,
		"confidence": confidence,
		"probabilities": probabilities,
		"model": model,
	}


def buildSuggestions(report: dict, client, requested_model: str) -> dict:
	if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
		raise ValueError("report findings must be an array")
	suggestions = {}
	skipped = []
	for finding in report["findings"]:
		if not isinstance(finding, dict) or not isinstance(finding.get("fingerprint"), str):
			raise ValueError("each finding must have a fingerprint")
		fingerprint = finding["fingerprint"]
		if finding.get("source") != "semgrep" or finding.get("type") != "code":
			skipped.append({"fingerprint": fingerprint, "reason": "not_semgrep_code"})
			continue
		if finding.get("verdict"):
			skipped.append({"fingerprint": fingerprint, "reason": "already_reviewed"})
			continue
		if not finding.get("snippet"):
			skipped.append({"fingerprint": fingerprint, "reason": "missing_snippet"})
			continue

		state = {"finding": {
			key: finding[key]
			for key in (
				"id", "summary", "rule_id", "location", "line", "confidence",
				"cwe", "owasp_2025", "snippet",
			)
			if key in finding
		}}
		state["finding"]["snippet"] = redactText(state["finding"]["snippet"])[0]
		response = client.system_one(
			state=state,
			questions={
				"verdict": {
					"type": "choice",
					"instructions": (
						"Based only on `finding`, which security-review verdict is supported? "
						"Do not assume reachability or controls that are not shown."
					),
					"criteria": {
						"confirmed": (
							"The supplied evidence establishes that an input surface reaches the "
							"reported vulnerable condition without an effective control."
						),
						"needs_validation": (
							"The supplied evidence is insufficient to establish reachability or "
							"whether a control is effective."
						),
						"rejected": (
							"The supplied evidence establishes that the condition is unreachable "
							"or effectively controlled."
						),
					},
				}
			},
		)
		data_response = response.raw_http_response.json()
		suggestions[fingerprint] = getChoice(data_response)

	return {
		"schema_version": 1,
		"generated_at": getTimestamp(),
		"requested_model": requested_model,
		"suggestions": suggestions,
		"skipped": skipped,
	}


def writeSuggestions(path_output: Path, suggestions: dict) -> None:
	path_output.parent.mkdir(parents=True, exist_ok=True)
	path_temporary = None
	try:
		with tempfile.NamedTemporaryFile(
			"w", encoding="utf-8", dir=path_output.parent,
			prefix=f".{path_output.name}.", delete=False,
		) as file_output:
			path_temporary = Path(file_output.name)
			json.dump(suggestions, file_output, indent=2, sort_keys=True)
			file_output.write("\n")
		path_temporary.replace(path_output)
	finally:
		if path_temporary and path_temporary.exists():
			path_temporary.unlink()


def loadTypeSafe():
	try:
		return importlib.import_module("typesafe_sdk")
	except ModuleNotFoundError as error:
		raise RuntimeError("TypeSafe SDK is required: pip install typesafe-sdk") from error


def parseArguments() -> argparse.Namespace:
	parser_suggest = argparse.ArgumentParser(
		description="Suggest non-authoritative Semgrep verdicts with TypeSafe Jev."
	)
	parser_suggest.add_argument("report", type=Path)
	parser_suggest.add_argument("--out", required=True, type=Path)
	parser_suggest.add_argument("--model", default="jev-latest")
	return parser_suggest.parse_args()


def runMain() -> None:
	args_suggest = parseArguments()
	sdk_typesafe = None
	try:
		if not os.environ.get("TYPESAFE_API_KEY"):
			raise ValueError("TYPESAFE_API_KEY is required")
		report = json.loads(args_suggest.report.read_text(encoding="utf-8"))
		sdk_typesafe = loadTypeSafe()
		with sdk_typesafe.TypeSafeClient(model=args_suggest.model) as client:
			suggestions = buildSuggestions(report, client, args_suggest.model)
		writeSuggestions(args_suggest.out, suggestions)
	except (OSError, ValueError, RuntimeError) as error_suggest:
		print(f"suggest-verdicts: {error_suggest}", file=sys.stderr)
		raise SystemExit(1) from error_suggest
	except Exception as error_suggest:
		if sdk_typesafe and isinstance(error_suggest, sdk_typesafe.TypeSafeError):
			details = [type(error_suggest).__name__]
			if getattr(error_suggest, "status", None):
				details.append(f"status {error_suggest.status}")
			if getattr(error_suggest, "request_id", None):
				details.append(f"request {error_suggest.request_id}")
			print(f"suggest-verdicts: TypeSafe request failed ({', '.join(details)})", file=sys.stderr)
			raise SystemExit(1) from error_suggest
		raise
	print(
		f"wrote {len(suggestions['suggestions'])} suggestions to {args_suggest.out}",
		file=sys.stderr,
	)


if __name__ == "__main__":
	runMain()
