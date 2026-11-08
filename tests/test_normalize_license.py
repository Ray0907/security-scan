import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.normalize_findings import normalizeEvidence, parseArguments, toMarkdown, toSarif
from scripts.validate_report import loadSchema, validateDocument
from normalize_base import NormalizeTestBase


class NormalizeLicenseTest(NormalizeTestBase):
	def testRealLicenseFixturesIgnoreVulnsAndLocalRoot(self):
		for ecosystem, lockfile, expected in (("node", "package-lock.json", []),
			("python", "requirements.txt", [("flask", "unknown")]),
			("rust", "Cargo.lock", [])):
			with self.subTest(ecosystem=ecosystem):
				path = self.makeLicenseEvidence(ecosystem, lockfile,
					exit_code=1 if ecosystem == "python" else 0)
				report = normalizeEvidence(path)
				self.assertEqual(expected, [(f["package"], f["normalized_severity"])
					for f in report["findings"]])
				self.assertTrue(all(f["type"] == "license" and f["owasp_2025"] == []
					for f in report["findings"]))
				self.assertEqual("inconclusive" if ecosystem == "rust" else
					("findings" if expected else "clean"), report["scanners"][0]["state"])
				self.assertEqual("not-scanned", report["owasp_coverage"]["A03"])
				self.assertEqual([], validateDocument(report,
					loadSchema(Path(__file__).parents[1] / "schema/security-findings.schema.json")))
				self.assertIsInstance(toSarif(report), dict)
				if expected:
					self.assertIn("needs manual license review", toMarkdown(report))

	def testLicenseRecordRunsThroughGenericEvidenceRunner(self):
		from subprocess import CompletedProcess
		from scripts.run_plan import runPlan
		from scripts.scan_plan import buildScanPlan
		fixture = self.path_fixtures / "osv-scanner-license"
		(self.path_root / "requirements.txt").write_text(
			(fixture / "requirements.txt").read_text())
		path_plan = self.path_root / "plan.json"
		path_plan.write_text(json.dumps(buildScanPlan(self.path_root)))
		path_out = self.path_root / "runner-evidence"
		output = (fixture / "python.json").read_text()
		with patch("scripts.run_plan.shutil.which", return_value="osv-scanner"), patch(
			"scripts.run_plan.getToolVersion", return_value="osv-scanner 2.6.0"
		), patch("scripts.run_plan.getGitMetadata", return_value={"commit": None,
			"branch": None, "dirty": None}), patch("scripts.run_plan.subprocess.run",
			return_value=CompletedProcess([], 1, output, "")):
			self.assertEqual(0, runPlan(path_plan, path_out, kinds_only=["license"], quiet=True))
		report = normalizeEvidence(path_out)
		license_scanner = next(item for item in report["scanners"] if item["kind"] == "license")
		self.assertEqual("osv-scanner-license", license_scanner["tool"])
		self.assertEqual("findings", license_scanner["state"])
		self.assertEqual(["flask"], [item["package"] for item in report["findings"]])

	def testLicenseExpressionClassification(self):
		from scripts.normalize_findings import classifySpdxLicense
		for expression, expected in (("GPL-3.0-only", "high"), ("AGPL-3.0-only", "high"),
			("SSPL-1.0", "high"), ("LGPL-2.1-only", "medium"),
			("MPL-2.0", "medium"), ("EPL-2.0", "medium"),
			("CDDL-1.0", "medium"), ("GPL-3.0 OR MIT", None),
			("MIT AND LGPL-2.1-only", "medium"),
			("GPL-3.0 AND (MIT OR LGPL-2.1-only)", "high"),
			("Unicode-3.0 AND (Apache-2.0 OR MIT)", None),
			("non-standard", "unknown"), ("", "unknown"),
			("GPL-3.0 WITH Custom-exception", "unknown")):
			with self.subTest(expression=expression):
				self.assertEqual(expected, classifySpdxLicense(expression))

	def testLocalLicenseMisattributionIsNotReported(self):
		from scripts.normalize_findings import parseOsvScannerLicense
		fixture = self.path_fixtures / "osv-scanner-license"
		data = json.loads((fixture / "rust.json").read_text())
		for package in data["results"][0]["packages"]:
			if package["package"]["name"] == "rust-app":
				package["licenses"] = ["GPL-3.0-only"]
		findings, reason = parseOsvScannerLicense(json.dumps(data), fixture / "Cargo.lock")
		self.assertEqual([], findings)
		self.assertIn("local package, license not scanned", reason)

	def testNpmLockfileV1WithoutPackagesMapIsInconclusiveNotFailed(self):
		path_lock = self.path_root / "package-lock.json"
		path_lock.write_text(json.dumps(
			{"name": "old", "lockfileVersion": 1, "dependencies": {"foo": {"version": "1.0.0"}}}
		))
		content = json.dumps({"results": [{"source": {"path": "package-lock.json"},
			"packages": [{"package": {"name": "foo", "version": "1.0.0"}, "licenses": ["MIT"]}]}]})
		path_record = self.path_root / "evidence" / "01-license-root"
		path_record.mkdir(parents=True)
		(path_record / "stdout.txt").write_text(content, encoding="utf-8")
		(path_record / "stderr.txt").write_text("", encoding="utf-8")
		meta = {"plan_index": 1, "kind": "license", "path": ".", "tool": "osv-scanner-license",
			"tool_version": "2.6.0", "state": "ran", "exit_code": 0, "reason": None,
			"command": ["osv-scanner", "scan", "source", "--lockfile", "package-lock.json",
				"--all-packages", "--no-resolve", "--licenses=", "--format", "json"]}
		(path_record / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
		path_evidence = self.path_root / "evidence"
		(path_evidence / "run.json").write_text(json.dumps({"schema_version": 1,
			"plan_root": str(self.path_root), "git": {"commit": None, "branch": None, "dirty": None},
			"records": [meta]}), encoding="utf-8")
		report = normalizeEvidence(path_evidence)
		license_scanner = next(item for item in report["scanners"] if item["kind"] == "license")
		self.assertEqual("inconclusive", license_scanner["state"])
		self.assertIn("npm lockfile v1", license_scanner["reason"])
		self.assertEqual([], report["findings"])

	def testCopyleftSeverityAndUnknownLicenseInReport(self):
		path = self.makeLicenseEvidence("node", "package-lock.json")
		data = json.loads((next(path.glob("01-*/stdout.txt"))).read_text())
		packages = data["results"][0]["packages"]
		packages[0]["licenses"] = ["GPL-3.0-only"]
		packages[1]["licenses"] = ["LGPL-2.1-only"]
		path_stdout = next(path.glob("01-*/stdout.txt"))
		path_stdout.write_text(json.dumps(data))
		report = normalizeEvidence(path)
		self.assertEqual(["high", "medium"], [f["normalized_severity"]
			for f in report["findings"]])
		self.assertTrue(all(f["owasp_2025"] == [] for f in report["findings"]))
		self.assertIn("GPL-3.0", toMarkdown(report))
		self.assertEqual(2, len(toSarif(report)["runs"][0]["results"]))

	def testMalformedLicenseJsonFailsInsteadOfClaimingClean(self):
		path = self.makeLicenseEvidence("node", "package-lock.json", content="not-json")
		self.assertEqual("failed", normalizeEvidence(path)["scanners"][0]["state"])
		path = self.makeLicenseEvidence("node", "package-lock.json", content="")
		self.assertEqual("failed", normalizeEvidence(path)["scanners"][0]["state"])
		path = self.makeLicenseEvidence("node", "package-lock.json",
			content='{"results": [123]}')
		self.assertEqual("failed", normalizeEvidence(path)["scanners"][0]["state"])

	def testNpmNonRegistryTarballIsNotTrusted(self):
		from scripts.normalize_findings import parseOsvScannerLicense
		fixture = self.path_fixtures / "osv-scanner-license"
		lock = json.loads((fixture / "package-lock.json").read_text())
		lock["packages"]["node_modules/balanced-match"]["resolved"] = (
			"https://github.com/example/balanced-match/archive/main.tgz")
		lock_path = self.path_root / "package-lock.json"
		lock_path.write_text(json.dumps(lock))
		data = json.loads((fixture / "node.json").read_text())
		data["results"][0]["packages"][0]["licenses"] = ["GPL-3.0-only"]
		findings, reason = parseOsvScannerLicense(json.dumps(data), lock_path)
		self.assertEqual([], findings)
		self.assertIn("local package", reason)

	def testMissingOrEmptyLicenseNeedsManualReview(self):
		for licenses in (None, []):
			with self.subTest(licenses=licenses):
				path = self.makeLicenseEvidence("node", "package-lock.json")
				path_stdout = next(path.glob("01-*/stdout.txt"))
				data = json.loads(path_stdout.read_text())
				data["results"][0]["packages"][0]["licenses"] = licenses
				path_stdout.write_text(json.dumps(data))
				finding = normalizeEvidence(path)["findings"][0]
				self.assertEqual("unknown", finding["normalized_severity"])
				self.assertEqual("low", finding["confidence"])

	def testNonArrayLicenseFieldFails(self):
		path = self.makeLicenseEvidence("node", "package-lock.json")
		path_stdout = next(path.glob("01-*/stdout.txt"))
		data = json.loads(path_stdout.read_text())
		data["results"][0]["packages"][0]["licenses"] = "MIT"
		path_stdout.write_text(json.dumps(data))
		self.assertEqual("failed", normalizeEvidence(path)["scanners"][0]["state"])

	def testEmptyPackageListIsNotClean(self):
		path = self.makeLicenseEvidence("node", "package-lock.json",
			content=json.dumps({"results": [{"source": {"path": "package-lock.json"},
				"packages": []}]}))
		self.assertNotEqual("clean", normalizeEvidence(path)["scanners"][0]["state"])

	def testUnsupportedLockfileIsInconclusive(self):
		path = self.makeLicenseEvidence("node", "package-lock.json")
		meta = json.loads((path / "run.json").read_text())
		meta["records"][0]["command"][4] = "pnpm-lock.yaml"
		(path / "run.json").write_text(json.dumps(meta))
		(self.path_root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'")
		self.assertEqual("inconclusive", normalizeEvidence(path)["scanners"][0]["state"])

	def testRustRegistryCopyleftIsReportedButLocalIsNot(self):
		from scripts.normalize_findings import parseOsvScannerLicense
		fixture = self.path_fixtures / "osv-scanner-license"
		data = json.loads((fixture / "rust.json").read_text())
		for entry in data["results"][0]["packages"]:
			entry["licenses"] = ["GPL-3.0-only"]
		findings, reason = parseOsvScannerLicense(json.dumps(data), fixture / "Cargo.lock")
		self.assertEqual({"proc-macro2", "unicode-ident"}, {f["package"] for f in findings})
		self.assertIn("local package", reason)

	def testLocalNpmWorkspaceIsNotReported(self):
		from scripts.normalize_findings import parseOsvScannerLicense
		fixture = self.path_fixtures / "osv-scanner-license"
		lock = json.loads((fixture / "package-lock.json").read_text())
		lock["packages"]["node_modules/workspace"] = {"version": "1.0.0", "link": True}
		lock["packages"]["node_modules/no-resolved"] = {"version": "1.0.0"}
		lock_path = self.path_root / "package-lock.json"
		lock_path.write_text(json.dumps(lock))
		data = json.loads((fixture / "node.json").read_text())
		for name in ("workspace", "no-resolved"):
			data["results"][0]["packages"].append({"package": {"name": name,
				"version": "1.0.0", "ecosystem": "npm"}, "licenses": ["GPL-3.0-only"]})
		findings, reason = parseOsvScannerLicense(json.dumps(data), lock_path)
		self.assertEqual([], findings)
		self.assertIn("local package, license not scanned", reason)

	def testLicenseLookupFailureAndMissingLockfileAreInconclusive(self):
		path = self.makeLicenseEvidence("python", "requirements.txt", content="",
			exit_code=127, stderr="cannot retrieve licenses locally")
		self.assertEqual("inconclusive", normalizeEvidence(path)["scanners"][0]["state"])
		path = self.makeLicenseEvidence("python", "requirements.txt")
		(self.path_root / "requirements.txt").unlink()
		self.assertEqual("inconclusive", normalizeEvidence(path)["scanners"][0]["state"])

	def testEmptyUnsupportedLicenseOutputFails(self):
		path = self.makeLicenseEvidence("node", "package-lock.json", content="")
		meta = json.loads((path / "run.json").read_text())
		meta["records"][0]["command"][4] = "pnpm-lock.yaml"
		(path / "run.json").write_text(json.dumps(meta))
		(self.path_root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'")
		self.assertEqual("failed", normalizeEvidence(path)["scanners"][0]["state"])

	def testUnpinnedPythonReferenceIsInconclusive(self):
		path = self.makeLicenseEvidence("python", "requirements.txt")
		(self.path_root / "requirements.txt").write_text("flask==3.0.0\n-e .\n")
		report = normalizeEvidence(path)
		self.assertEqual("inconclusive", report["scanners"][0]["state"])
		self.assertIn("not scanned", report["scanners"][0]["reason"])

	def testParsesNormalizerOptions(self):
		with patch(
			"sys.argv",
			[
				"normalize_findings.py", "evidence", "--baseline", "old.json",
				"--format", "sarif", "--severity", "critical,high", "--owasp", "A03",
				"--verdicts", "verdicts.json", "--out", "result.sarif",
			],
		):
			args_normalize = parseArguments()

		self.assertEqual("sarif", args_normalize.format)
		self.assertEqual("critical,high", args_normalize.severity)
		self.assertEqual("A03", args_normalize.owasp)
		self.assertEqual(Path("verdicts.json"), args_normalize.verdicts)


if __name__ == "__main__":
	unittest.main()
