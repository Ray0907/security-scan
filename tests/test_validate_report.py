import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_findings import normalizeEvidence
from scripts.validate_report import loadSchema, validateDocument
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


if __name__ == "__main__":
	unittest.main()
