import json
from pathlib import Path
from unittest.mock import patch

from normalize_base import NormalizeTestBase
from scripts.normalize_findings import getFingerprint, normalizeEvidence, toSarif


class ReportRegressionTests(NormalizeTestBase):
	def testSarifSkipsNullTools(self):
		data_report = {"scanners": [{"tool": None}, {"tool": "semgrep"}], "findings": []}
		runs = toSarif(data_report)["runs"]
		self.assertEqual(["semgrep"], [run["tool"]["driver"]["name"] for run in runs])
		self.assertTrue(all(isinstance(run["tool"]["driver"]["name"], str) for run in runs))

	def testSarifOmitsNullAndMissingVersions(self):
		data_report = {"scanners": [
			{"tool": "semgrep", "tool_version": None}, {"tool": "npm"}], "findings": []}
		runs = toSarif(data_report)["runs"]
		self.assertEqual(2, len(runs))
		for run in runs:
			self.assertNotIn("version", run["tool"]["driver"])

	def testSarifUsesFirstAvailableVersionWithoutMutatingReport(self):
		for scanner_first in ({"tool": "npm"}, {"tool": "npm", "tool_version": None},
			{"tool": "npm", "tool_version": "10.0.0"}):
			with self.subTest(scanner=scanner_first):
				data_report = {"scanners": [scanner_first,
					{"tool": "npm", "tool_version": "10.0.0"},
					{"tool": "npm", "tool_version": "11.0.0"}], "findings": []}
				data_before = json.loads(json.dumps(data_report))
				runs = toSarif(data_report)["runs"]
				self.assertEqual(1, len(runs))
				self.assertEqual("10.0.0", runs[0]["tool"]["driver"]["version"])
				self.assertEqual(data_before, data_report)

	def checkOsvLocation(self, location: str, expected: str, project: str = ".",
			root: str = "/work/app") -> list[str]:
		path_evidence = self.makeEvidence("osv-scanner",
			name_evidence=str(len(list(self.path_root.iterdir()))))
		path_stdout = next(path_evidence.glob("01-*/stdout.txt"))
		data_output = json.loads(path_stdout.read_text(encoding="utf-8"))
		for result in data_output["results"]:
			result["source"]["path"] = location
		path_stdout.write_text(json.dumps(data_output), encoding="utf-8")
		path_run = path_evidence / "run.json"
		data_run = json.loads(path_run.read_text(encoding="utf-8"))
		data_run["plan_root"] = root
		data_run["records"][0]["path"] = project
		path_run.write_text(json.dumps(data_run), encoding="utf-8")
		data_report = normalizeEvidence(path_evidence)
		self.assertEqual("findings", data_report["scanners"][0]["state"])
		self.assertTrue(data_report["findings"])
		for finding in data_report["findings"]:
			self.assertEqual(expected, finding["location"])
			self.assertEqual(getFingerprint({**finding, "location": expected}),
				finding["fingerprint"])
			if location != expected:
				self.assertNotEqual(getFingerprint({**finding, "location": location}),
					finding["fingerprint"])
		return [finding["fingerprint"] for finding in data_report["findings"]]

	def testOsvMakesRootAbsoluteLocationsRelativeBeforeFingerprinting(self):
		self.checkOsvLocation("/work/app/uv.lock", "uv.lock")

	def testOsvKeepsOutsideRootLocationsUnchanged(self):
		for location in ("/work/other/uv.lock", "/work/app-other/uv.lock",
			"/work/app/../other/uv.lock"):
			with self.subTest(location=location):
				self.checkOsvLocation(location, location)

	def testOsvKeepsLocationAndFingerprintForSymlinkLoop(self):
		path_root = self.path_root / "checkout"
		path_root.mkdir()
		(path_root / "loop").symlink_to("loop")
		location = str(path_root / "loop" / "uv.lock")
		resolve_original = Path.resolve
		# Python 3.13+ suppresses loop errors unless resolution is strict.
		with patch("scripts.normalize_findings.Path.resolve", autospec=True,
			side_effect=lambda path: resolve_original(path, strict=True)):
			self.checkOsvLocation(location, location, root=str(path_root))

	def testOsvDoesNotDoublePrefixAbsoluteSubprojectLocations(self):
		self.checkOsvLocation("/work/app/apps/api/uv.lock", "apps/api/uv.lock", "apps/api")

	def testOsvPreservesRelativeSubprojectPrefixing(self):
		self.checkOsvLocation("uv.lock", "apps/api/uv.lock", "apps/api")

	def testOsvFingerprintsDoNotDependOnCheckoutRoot(self):
		fingerprints_first = self.checkOsvLocation("/home/user/project/apps/api/uv.lock",
			"apps/api/uv.lock", "apps/api", "/home/user/project")
		fingerprints_second = self.checkOsvLocation("/opt/checkout/apps/api/uv.lock",
			"apps/api/uv.lock", "apps/api", "/opt/checkout")
		self.assertEqual(fingerprints_first, fingerprints_second)
