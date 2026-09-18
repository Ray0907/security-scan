import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.suggest_verdicts import (
	buildSuggestions,
	loadTypeSafe,
	parseArguments,
	writeSuggestions,
)


class RawResponse:
	def json(self):
		return {
			"model": "jev-1.13.0",
			"answers": {
				"verdict": {
					"type": "choice",
					"choice": "needs_validation",
					"probabilities": {
						"confirmed": 0.2,
						"needs_validation": 0.7,
						"rejected": 0.1,
					},
					"confidence": 0.61,
				}
			},
			"usage": {"input_tokens": 100, "output_tokens": 10},
		}


class Response:
	raw_http_response = RawResponse()


class FakeClient:
	def __init__(self):
		self.calls = []

	def system_one(self, **kwargs):
		self.calls.append(kwargs)
		return Response()


class SuggestVerdictsTest(unittest.TestCase):
	def testSuggestsOnlyUnreviewedSemgrepCodeWithSnippet(self):
		report = {
			"findings": [
				{
					"fingerprint": "eligible",
					"source": "semgrep",
					"type": "code",
					"id": "python.lang.security.eval",
					"summary": "User input reaches eval",
					"location": "app.py",
					"line": 9,
					"snippet": "eval(value)",
				},
				{
					"fingerprint": "reviewed", "source": "semgrep", "type": "code",
					"snippet": "eval(value)", "verdict": "confirmed",
				},
				{"fingerprint": "no-snippet", "source": "semgrep", "type": "code"},
				{"fingerprint": "dependency", "source": "npm", "type": "dependency"},
			]
		}
		client = FakeClient()

		result = buildSuggestions(report, client, requested_model="jev-latest")

		self.assertEqual(1, len(client.calls))
		self.assertEqual("eval(value)", client.calls[0]["state"]["finding"]["snippet"])
		self.assertEqual(
			{
				"suggested_verdict": "needs_validation",
				"confidence": 0.61,
				"probabilities": {
					"confirmed": 0.2, "needs_validation": 0.7, "rejected": 0.1,
				},
				"model": "jev-1.13.0",
			},
			result["suggestions"]["eligible"],
		)
		self.assertEqual(
			{
				"reviewed": "already_reviewed",
				"no-snippet": "missing_snippet",
				"dependency": "not_semgrep_code",
			},
			{item["fingerprint"]: item["reason"] for item in result["skipped"]},
		)

	def testRedactsSnippetAgainBeforeTransmission(self):
		report = {"findings": [{
			"fingerprint": "secret", "source": "semgrep", "type": "code",
			"snippet": "api_key=abcdef123456",
		}]}
		client = FakeClient()

		buildSuggestions(report, client, requested_model="jev-latest")

		self.assertEqual("api_key=[REDACTED]", client.calls[0]["state"]["finding"]["snippet"])

	def testRejectsMalformedReportAndResponse(self):
		with self.assertRaisesRegex(ValueError, "findings"):
			buildSuggestions({}, FakeClient(), requested_model="jev-latest")

		class BadResponse(RawResponse):
			def json(self):
				data = super().json()
				data["answers"]["verdict"]["choice"] = "maybe"
				return data

		class BadClient(FakeClient):
			def system_one(self, **kwargs):
				return type("Response", (), {"raw_http_response": BadResponse()})()

		with self.assertRaisesRegex(ValueError, "choice"):
			buildSuggestions(
				{"findings": [{
					"fingerprint": "bad", "source": "semgrep", "type": "code",
					"snippet": "eval(value)",
				}]},
				BadClient(),
				requested_model="jev-latest",
			)

	def testWritesAtomically(self):
		with tempfile.TemporaryDirectory() as directory:
			path_output = Path(directory) / "nested" / "suggestions.json"
			writeSuggestions(path_output, {"suggestions": {"one": {"confidence": 0.8}}})
			self.assertEqual(
				{"suggestions": {"one": {"confidence": 0.8}}},
				json.loads(path_output.read_text(encoding="utf-8")),
			)

			with self.assertRaises(TypeError):
				writeSuggestions(path_output, {"not_json": {"a-set"}})
			self.assertEqual(
				{"suggestions": {"one": {"confidence": 0.8}}},
				json.loads(path_output.read_text(encoding="utf-8")),
			)

	def testParsesRequiredOutputAndOptionalModel(self):
		with patch(
			"sys.argv",
			["suggest_verdicts.py", "report.json", "--out", "out.json", "--model", "jev-1.13.0"],
		):
			arguments = parseArguments()

		self.assertEqual(Path("report.json"), arguments.report)
		self.assertEqual(Path("out.json"), arguments.out)
		self.assertEqual("jev-1.13.0", arguments.model)

	def testExplainsHowToInstallMissingSdk(self):
		with patch("scripts.suggest_verdicts.importlib.import_module", side_effect=ModuleNotFoundError):
			with self.assertRaisesRegex(RuntimeError, "pip install typesafe-sdk"):
				loadTypeSafe()


if __name__ == "__main__":
	unittest.main()
