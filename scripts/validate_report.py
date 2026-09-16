#!/usr/bin/env python3
"""Validate security-scan JSON artifacts with the bundled schema subset."""

import argparse
import json
import sys
from pathlib import Path


TYPE_CHECKS = {
	"array": lambda value: isinstance(value, list),
	"boolean": lambda value: isinstance(value, bool),
	"integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
	"null": lambda value: value is None,
	"number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
	"object": lambda value: isinstance(value, dict),
	"string": lambda value: isinstance(value, str),
}


def escapePointer(value: str) -> str:
	return value.replace("~", "~0").replace("/", "~1")


def joinPointer(pointer: str, value: str | int) -> str:
	return f"{pointer}/{escapePointer(str(value))}"


def validateDocument(document, schema: dict, pointer: str = "") -> list[str]:
	for keyword in ("oneOf", "anyOf"):
		if keyword not in schema:
			continue
		results = [validateDocument(document, option, pointer) for option in schema[keyword]]
		matches = sum(not errors for errors in results)
		if keyword == "anyOf" and matches or keyword == "oneOf" and matches == 1:
			return []
		return [f"{pointer or '/'}: does not match {keyword}"]

	errors = []
	type_name = schema.get("type")
	if type_name and not TYPE_CHECKS[type_name](document):
		return [f"{pointer or '/'}: expected {type_name}"]
	if "const" in schema and document != schema["const"]:
		errors.append(f"{pointer or '/'}: expected constant {schema['const']!r}")
	if "enum" in schema and document not in schema["enum"]:
		errors.append(f"{pointer or '/'}: value is not in enum")
	if isinstance(document, dict):
		properties = schema.get("properties", {})
		for name_required in schema.get("required", []):
			if name_required not in document:
				errors.append(f"{joinPointer(pointer, name_required)}: required property is missing")
		for name_property, value_property in document.items():
			path_property = joinPointer(pointer, name_property)
			if name_property in properties:
				errors.extend(validateDocument(value_property, properties[name_property], path_property))
			elif schema.get("additionalProperties") is False:
				errors.append(f"{path_property}: additional property is not allowed")
	if isinstance(document, list) and "items" in schema:
		for index_item, value_item in enumerate(document):
			errors.extend(validateDocument(value_item, schema["items"], joinPointer(pointer, index_item)))
	return errors


def loadSchema(path_schema: Path) -> dict:
	return json.loads(path_schema.read_text(encoding="utf-8"))


def parseArguments() -> argparse.Namespace:
	parser_validate = argparse.ArgumentParser(description="Validate a security findings report.")
	parser_validate.add_argument("report", type=Path)
	parser_validate.add_argument(
		"--schema", type=Path,
		default=Path(__file__).parents[1] / "schema" / "security-findings.schema.json",
	)
	return parser_validate.parse_args()


def runMain() -> int:
	args_validate = parseArguments()
	try:
		document = json.loads(args_validate.report.read_text(encoding="utf-8"))
		schema = loadSchema(args_validate.schema)
	except (OSError, json.JSONDecodeError) as error_validate:
		print(f"validate-report: {error_validate}", file=sys.stderr)
		return 2
	errors = validateDocument(document, schema)
	for error_validate in errors:
		print(error_validate, file=sys.stderr)
	return 1 if errors else 0


if __name__ == "__main__":
	raise SystemExit(runMain())
