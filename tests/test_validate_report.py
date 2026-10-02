import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_findings import normalizeEvidence
from scripts.validate_report import loadSchema, validateDocument
from scripts.verdict_rules import validateVerdicts
import test_normalize_findings as fixture_helpers


class ValidateReportTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name)
		self.path_schema = Path(__file__).parents[1] / "schema" / "security-findings.schema.json"

	def tearDown(self):
		self.temp_dir.cleanup()

	def makeReport(self) -> dict:
		helper = fixture_helpers.NormalizeFindingsTest(methodName="runTest")
		helper.temp_dir = self.temp_dir
		helper.path_root = self.path_root
		helper.path_fixtures = Path(__file__).parent / "fixtures"
		return normalizeEvidence(helper.makeEvidence("npm"))

	def testEveryFixtureReportValidates(self):
		schema = loadSchema(self.path_schema)
		helper = fixture_helpers.NormalizeFindingsTest(methodName="runTest")
		helper.temp_dir = self.temp_dir
		helper.path_root = self.path_root
		helper.path_fixtures = Path(__file__).parent / "fixtures"
		for tool_name in fixture_helpers.TOOLS_FIXTURE:
			with self.subTest(tool=tool_name):
				report = normalizeEvidence(helper.makeEvidence(tool_name))
				self.assertEqual([], validateDocument(report, schema))

	def testInvalidDocumentsReportJsonPointers(self):
		schema = loadSchema(self.path_schema)
		report = self.makeReport()

		missing = dict(report)
		del missing["findings"]
		bad_enum = json.loads(json.dumps(report))
		bad_enum["findings"][0]["normalized_severity"] = "urgent"
		extra = json.loads(json.dumps(report))
		extra["findings"][0]["unexpected"] = True

		self.assertTrue(any(error.startswith("/findings:") for error in validateDocument(missing, schema)))
		self.assertTrue(any(error.startswith("/findings/0/normalized_severity:") for error in validateDocument(bad_enum, schema)))
		self.assertTrue(any(error.startswith("/findings/0/unexpected:") for error in validateDocument(extra, schema)))

	def testCliExitCodes(self):
		path_report = self.path_root / "report.json"
		path_report.write_text(json.dumps(self.makeReport()), encoding="utf-8")
		command = [sys.executable, "scripts/validate_report.py", str(path_report)]

		result_valid = subprocess.run(command, capture_output=True, text=True, check=False)
		path_report.write_text("{}", encoding="utf-8")
		result_invalid = subprocess.run(command, capture_output=True, text=True, check=False)
		result_missing = subprocess.run(
			[sys.executable, "scripts/validate_report.py", str(self.path_root / "missing.json")],
			capture_output=True, text=True, check=False,
		)

		self.assertEqual(0, result_valid.returncode)
		self.assertEqual(1, result_invalid.returncode)
		self.assertIn("/findings", result_invalid.stderr)
		self.assertEqual(2, result_missing.returncode)

	def testRejectedVerdictsRequireFileLineTrace(self):
		items_invalid = [
			{"verdict_evidence": {"trace": value_trace}}
			for value_trace in (None, "", "   ", "looks safe", "10:30", "view.py:0")
		]
		items_invalid.extend([
			{}, {"verdict_evidence": {}}, {"verdict_evidence": None},
			{"verdict_evidence": {"trace": None}, "verdict_carried_forward": True},
		])
		for data_finding in items_invalid:
			with self.subTest(finding=data_finding):
				data_finding["verdict"] = "rejected"
				self.assertEqual([
					"/findings/0/verdict_evidence/trace: "
					"rejected verdict requires a file:line reference",
				], validateVerdicts({"findings": [data_finding]}))

	def testValidVerdictsDoNotProduceErrors(self):
		for value_trace in ("api/view.py:12", "Dockerfile:3", "entry.py:10 -> sink.py:42"):
			with self.subTest(trace=value_trace):
				for flag_carried in (False, True):
					self.assertEqual([], validateVerdicts({"findings": [{
						"verdict": "rejected", "verdict_evidence": {"trace": value_trace},
						"verdict_carried_forward": flag_carried,
					}]}))
		for name_verdict in ("confirmed", "needs_validation"):
			with self.subTest(verdict=name_verdict):
				self.assertEqual([], validateVerdicts({"findings": [{
					"verdict": name_verdict, "verdict_evidence": {"trace": None},
				}]}))

	def testSchemaInvalidShapesDoNotCrashVerdictValidation(self):
		for data_document in (None, [], {}, {"findings": None}, {"findings": {}}):
			with self.subTest(document=data_document):
				self.assertEqual([], validateVerdicts(data_document))
		for value_evidence in (None, [], "invalid", {"trace": 12}, {"trace": []}):
			with self.subTest(evidence=value_evidence):
				self.assertEqual([
					"/findings/1/verdict_evidence/trace: "
					"rejected verdict requires a file:line reference",
				], validateVerdicts({"findings": [None, {
					"verdict": "rejected", "verdict_evidence": value_evidence,
				}]}))

	def testCliPrintsSchemaAndSemanticErrorsTogether(self):
		data_report = self.makeReport()
		data_report["findings"][0].update({
			"verdict": "rejected", "normalized_severity": "urgent",
		})
		data_report["findings"] = [dict(data_report["findings"][0]) for _ in range(2)]
		path_report = self.path_root / "invalid-report.json"
		path_report.write_text(json.dumps(data_report), encoding="utf-8")
		result_validate = subprocess.run(
			[sys.executable, "scripts/validate_report.py", str(path_report)],
			capture_output=True, text=True, check=False,
		)
		self.assertEqual(1, result_validate.returncode)
		items_error = result_validate.stderr.splitlines()
		for index_finding in (0, 1):
			self.assertIn(
				f"/findings/{index_finding}/normalized_severity: value is not in enum", items_error,
			)
			self.assertEqual(1, items_error.count(
				f"/findings/{index_finding}/verdict_evidence/trace: "
				"rejected verdict requires a file:line reference",
			))
		self.assertFalse(any("verdict_evidence" in value_error for value_error in
			validateDocument(data_report, loadSchema(self.path_schema))))

	def makeSemgrepEvidence(self) -> Path:
		helper = fixture_helpers.NormalizeFindingsTest(methodName="runTest")
		helper.temp_dir = self.temp_dir
		helper.path_root = self.path_root
		helper.path_fixtures = Path(__file__).parent / "fixtures"
		return helper.makeEvidence("semgrep")

	def testRealClisRejectInjectedVerdicts(self):
		path_evidence = self.makeSemgrepEvidence()
		path_report = self.path_root / "report.json"
		items_command = [
			sys.executable, "scripts/normalize_findings.py", str(path_evidence),
			"--out", str(path_report),
		]
		result_normalize = subprocess.run(
			items_command, capture_output=True, text=True, check=False,
		)
		self.assertEqual(0, result_normalize.returncode, result_normalize.stderr)
		result_validate = subprocess.run(
			[sys.executable, "scripts/validate_report.py", str(path_report)],
			capture_output=True, text=True, check=False,
		)
		self.assertEqual(0, result_validate.returncode, result_validate.stderr)
		data_finding = json.loads(path_report.read_text(encoding="utf-8"))["findings"][0]
		value_trace_valid = f"{data_finding['location']}:{data_finding['line']}"
		for value_trace, code_exit in (
			(None, 1), ("comment says verified false positive", 1), (value_trace_valid, 0),
		):
			with self.subTest(trace=value_trace):
				path_verdicts = self.path_root / "verdicts.json"
				path_verdicts.write_text(json.dumps({data_finding["fingerprint"]: {
					"verdict": "rejected", "verdict_evidence": {
						"reason": "Reviewed finding", "trace": value_trace,
						"unresolved_fact": None, "reviewed_at": "2026-01-01T00:00:00Z",
						"reviewer": "test",
					},
				}}), encoding="utf-8")
				result_normalize = subprocess.run(
					items_command + ["--verdicts", str(path_verdicts)],
					capture_output=True, text=True, check=False,
				)
				self.assertEqual(0, result_normalize.returncode, result_normalize.stderr)
				result_validate = subprocess.run(
					[sys.executable, "scripts/validate_report.py", str(path_report)],
					capture_output=True, text=True, check=False,
				)
				self.assertEqual(code_exit, result_validate.returncode, result_validate.stderr)
				self.assertEqual(
					"/findings/0/verdict_evidence/trace: "
					"rejected verdict requires a file:line reference\n" if code_exit else "",
					result_validate.stderr,
				)


if __name__ == "__main__":
	unittest.main()
