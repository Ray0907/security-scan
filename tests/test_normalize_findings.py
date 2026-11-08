import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.normalize_findings import (
	normalizeEvidence,
	parseGovulncheck,
	parsePipAudit,
	parseSemgrep,
	toMarkdown,
	toSarif,
)
from normalize_base import NormalizeTestBase, TOOLS_FIXTURE


class NormalizeFindingsTest(NormalizeTestBase):
	def testCliSarifRejectsWeakVerdictWithoutWritingOutput(self):
		path_evidence, path_verdicts, _ = self.makeRejectedEvidence()
		path_script = Path(__file__).parents[1] / "scripts/normalize_findings.py"
		for mode_output in ("stdout", "missing", "existing"):
			with self.subTest(output=mode_output):
				path_output = self.path_root / f"{mode_output}.sarif"
				if mode_output == "existing":
					path_output.write_bytes(b"previous SARIF\n")
				args_output = [] if mode_output == "stdout" else ["--out", str(path_output)]
				result_cli = subprocess.run(
					[sys.executable, str(path_script), str(path_evidence),
						"--verdicts", str(path_verdicts), "--format", "sarif", *args_output],
					capture_output=True, text=True, check=False,
				)
				self.assertEqual(1, result_cli.returncode, result_cli.stderr)
				self.assertEqual("", result_cli.stdout)
				self.assertEqual(
					"/findings/0/verdict_evidence/trace: "
					"rejected verdict requires a file:line reference\n", result_cli.stderr,
				)
				if mode_output == "existing":
					self.assertEqual(b"previous SARIF\n", path_output.read_bytes())
				else:
					self.assertFalse(path_output.exists())

	def testCliSarifSuppressesRejectedVerdictWithFileLineTrace(self):
		path_evidence, path_verdicts, data_report = self.makeRejectedEvidence(valid_trace=True)
		path_script = Path(__file__).parents[1] / "scripts/normalize_findings.py"
		result_cli = subprocess.run(
			[sys.executable, str(path_script), str(path_evidence),
				"--verdicts", str(path_verdicts), "--format", "sarif"],
			capture_output=True, text=True, check=False,
		)
		self.assertEqual(0, result_cli.returncode, result_cli.stderr)
		self.assertEqual("", result_cli.stderr)
		data_sarif = json.loads(result_cli.stdout)
		self.assertEqual(toSarif(data_report), data_sarif)
		data_finding = data_report["findings"][0]
		data_result = next(
			data_result for data_result in data_sarif["runs"][0]["results"]
			if data_result["partialFingerprints"]["primaryLocationLineHash"]
				== data_finding["fingerprint"]
		)
		self.assertEqual([{
			"kind": "external", "status": "accepted",
			"justification": json.dumps(data_finding["verdict_evidence"], sort_keys=True),
		}], data_result["suppressions"])

	def testStringCweStaysOneEntry(self):
		from scripts.normalize_findings import makeFinding
		finding = makeFinding("npm", "X", "dependency", package="p", cwe="CWE-79")
		self.assertEqual(["CWE-79"], finding["cwe"])

	def testCliJsonAndMarkdownKeepWeakRejectedVerdictOutput(self):
		path_evidence, path_verdicts, _ = self.makeRejectedEvidence()
		path_script = Path(__file__).parents[1] / "scripts/normalize_findings.py"
		data_expected = normalizeEvidence(path_evidence, path_verdicts=path_verdicts)
		for format_output in ("json", "markdown"):
			with self.subTest(format=format_output):
				args_format = [] if format_output == "json" else ["--format", "markdown"]
				result_cli = subprocess.run(
					[sys.executable, str(path_script), str(path_evidence),
						"--verdicts", str(path_verdicts), *args_format],
					capture_output=True, text=True, check=False,
				)
				self.assertEqual(0, result_cli.returncode, result_cli.stderr)
				self.assertEqual("", result_cli.stderr)
				if format_output == "json":
					data_actual = json.loads(result_cli.stdout)
					data_actual["generated_at"] = data_expected["generated_at"]
					self.assertEqual(data_expected, data_actual)
				else:
					lines_actual = result_cli.stdout.splitlines()
					lines_expected = toMarkdown(data_expected).splitlines()
					self.assertEqual(
						[line for line in lines_expected if not line.startswith("- Generated:")],
						[line for line in lines_actual if not line.startswith("- Generated:")],
					)

	def testEveryParserHandlesFindingsCleanAndMalformed(self):
		for tool_name in TOOLS_FIXTURE:
			with self.subTest(tool=tool_name, case="findings"):
				report_scan = normalizeEvidence(self.makeEvidence(tool_name))
				self.assertEqual("findings", report_scan["scanners"][0]["state"])
				self.assertGreaterEqual(len(report_scan["findings"]), 1)
				self.assertEqual(16, len(report_scan["findings"][0]["fingerprint"]))
			with self.subTest(tool=tool_name, case="clean"):
				report_scan = normalizeEvidence(self.makeEvidence(tool_name, "clean"))
				self.assertEqual("clean", report_scan["scanners"][0]["state"])
			with self.subTest(tool=tool_name, case="malformed"):
				path_evidence = self.makeEvidence(tool_name, "clean", "malformed")
				path_stdout = next(path_evidence.glob("01-*/stdout.txt"))
				path_stdout.write_text("not-json", encoding="utf-8")
				report_scan = normalizeEvidence(path_evidence)
				self.assertEqual("failed", report_scan["scanners"][0]["state"])

	def testSubdirectoryFindingsHaveUniqueProjectFingerprints(self):
		path_evidence = self.makeEvidence("pip-audit")
		path_first = next(path_evidence.glob("01-*/stdout.txt"))
		path_second = path_evidence / "02-python-p2" / "stdout.txt"
		path_second.parent.mkdir()
		path_second.write_text(path_first.read_text(encoding="utf-8"), encoding="utf-8")
		path_run = path_evidence / "run.json"
		data_run = json.loads(path_run.read_text(encoding="utf-8"))
		data_run["records"][0]["path"] = "p1"
		data_run["records"].append({**data_run["records"][0], "plan_index": 2, "path": "p2"})
		path_run.write_text(json.dumps(data_run), encoding="utf-8")

		report_scan = normalizeEvidence(path_evidence)
		findings = report_scan["findings"]
		self.assertEqual(4, len(findings))
		self.assertEqual(4, len({finding["fingerprint"] for finding in findings}))
		self.assertEqual({"p1/requirements.txt", "p2/requirements.txt"}, {finding["location"] for finding in findings})

	def testDuplicateFingerprintsKeepFirstFinding(self):
		path_evidence = self.makeEvidence("pip-audit")
		path_run = path_evidence / "run.json"
		data_run = json.loads(path_run.read_text(encoding="utf-8"))
		data_run["records"].append({**data_run["records"][0], "plan_index": 2})
		path_second = path_evidence / "02-python-root" / "stdout.txt"
		path_second.parent.mkdir()
		content_first = next(path_evidence.glob("01-*/stdout.txt")).read_text(encoding="utf-8")
		content_second = json.loads(content_first)
		content_second["dependencies"][0]["vulns"][0]["description"] = "later duplicate"
		path_second.write_text(json.dumps(content_second), encoding="utf-8")
		path_run.write_text(json.dumps(data_run), encoding="utf-8")

		findings = normalizeEvidence(path_evidence)["findings"]
		self.assertEqual(2, len(findings))
		self.assertEqual(2, len({finding["fingerprint"] for finding in findings}))
		self.assertEqual(parsePipAudit(content_first)[0]["summary"], next(
			finding["summary"] for finding in findings if finding["id"] == "PYSEC-2023-74"
		))

	def testGitleaksDuplicateFixtureYieldsOneFinding(self):
		path_evidence = self.makeEvidence("gitleaks")
		report_scan = normalizeEvidence(path_evidence)

		self.assertEqual(1, len(report_scan["findings"]))
		self.assertEqual("secrets/config.txt:private-key:2", report_scan["findings"][0]["id"])
		self.assertEqual("findings", report_scan["scanners"][0]["state"])

	def testAbsoluteFindingLocationRemainsUnchanged(self):
		path_evidence = self.makeEvidence("semgrep")
		path_run = path_evidence / "run.json"
		data_run = json.loads(path_run.read_text(encoding="utf-8"))
		data_run["records"][0]["path"] = "p1"
		path_run.write_text(json.dumps(data_run), encoding="utf-8")
		path_stdout = next(path_evidence.glob("01-*/stdout.txt"))
		data_stdout = json.loads(path_stdout.read_text(encoding="utf-8"))
		data_stdout["results"][0]["path"] = "/work/app/file.py"
		path_stdout.write_text(json.dumps(data_stdout), encoding="utf-8")

		finding = next(item for item in normalizeEvidence(path_evidence)["findings"] if item["location"] == "/work/app/file.py")
		self.assertEqual(parseSemgrep(json.dumps(data_stdout))[0]["fingerprint"], finding["fingerprint"])

	def testNodeAdvisoriesPreferGhsaIdAndLockfileLocation(self):
		result_scan = normalizeEvidence(self.makeEvidence("bun"))
		finding_first = result_scan["findings"][0]

		self.assertTrue(finding_first["id"].startswith("GHSA-"))
		self.assertTrue(all(alias.isdigit() for alias in finding_first["aliases"]))
		self.assertEqual("bun.lock", finding_first["location"])
		result_pnpm = normalizeEvidence(self.makeEvidence("pnpm"))
		self.assertEqual("pnpm-lock.yaml", result_pnpm["findings"][0]["location"])

	def testPipAuditDeduplicatesVulnerabilityIdsPerDependency(self):
		content_output = (
			self.path_fixtures / "pip-audit" / "duplicates.json"
		).read_text(encoding="utf-8")

		findings = parsePipAudit(content_output)

		self.assertEqual(1, len(findings))
		self.assertEqual("PYSEC-2023-74", findings[0]["id"])
		self.assertEqual("requests", findings[0]["package"])

	def testSemgrepOmitsRequiresLoginPlaceholderSnippet(self):
		content_output = (
			self.path_fixtures / "semgrep" / "requires-login.json"
		).read_text(encoding="utf-8")

		finding = parseSemgrep(content_output)[0]

		self.assertNotIn("snippet", finding)
		self.assertEqual(
			"unauthenticated Semgrep CLI does not return source snippets",
			finding["snippet_omitted_reason"],
		)

	def testGovulncheckParsesPrettyStreamAndUsesFirstTraceFrame(self):
		content_output = """
{
  "osv": {"id": "GO-TEST", "summary": "test"}
}
{
  "finding": {
    "osv": "GO-TEST",
    "fixed_version": "v1.2.3",
    "trace": [
      {"module": "vulnerable.module", "package": "vulnerable/package", "position": {"filename": "vulnerable.go", "line": 7}},
      {"module": "caller.module", "package": "caller/package", "position": {"filename": "main.go", "line": 20}}
    ]
  }
}
"""

		finding_scan = parseGovulncheck(content_output)[0]

		self.assertEqual("vulnerable.module", finding_scan["package"])
		self.assertEqual("vulnerable.go", finding_scan["location"])
		self.assertEqual(7, finding_scan["line"])

	def testRealFixturesPreserveScannerFields(self):
		finding_pnpm = normalizeEvidence(self.makeEvidence("pnpm"))["findings"][0]
		finding_yarn = normalizeEvidence(self.makeEvidence("yarn"))["findings"][0]
		finding_gov = normalizeEvidence(self.makeEvidence("govulncheck"))["findings"][0]
		finding_composer = normalizeEvidence(self.makeEvidence("composer"))["findings"][0]
		findings_bundler = {
			finding["id"]: finding
			for finding in normalizeEvidence(self.makeEvidence("bundler-audit"))["findings"]
		}
		finding_cargo = normalizeEvidence(self.makeEvidence("cargo-audit"))["findings"][0]
		finding_osv = normalizeEvidence(self.makeEvidence("osv-scanner"))["findings"][0]
		findings_zizmor = {
			finding["id"]: finding
			for finding in normalizeEvidence(self.makeEvidence("zizmor"))["findings"]
		}
		finding_zizmor = findings_zizmor["artipacked"]

		self.assertEqual("4.17.20", finding_pnpm["installed_version"])
		self.assertEqual("4.17.20", finding_yarn["installed_version"])
		self.assertTrue(finding_gov["id"].startswith("GO-"))
		self.assertEqual("golang.org/x/text", finding_gov["package"])
		self.assertTrue(finding_gov["fixed_versions"][0].startswith("v"))
		self.assertEqual("composer.lock", finding_composer["location"])
		self.assertIn("CVE-2026-69246", finding_composer["aliases"])
		self.assertIn(
			"~> 2.0.9, >= 2.0.9.4",
			findings_bundler["CVE-2024-26146"]["fixed_versions"],
		)
		self.assertEqual("critical", findings_bundler["CVE-2022-30123"]["native_severity"])
		self.assertTrue(finding_cargo["native_severity"].startswith("CVSS:"))
		self.assertEqual("7.5", finding_osv["native_severity"])
		self.assertIn("3.7", finding_osv["fixed_versions"])
		self.assertEqual(".github/workflows/ci.yml", finding_zizmor["location"])
		self.assertEqual(8, finding_zizmor["line"])
		self.assertEqual(
			"credential persistence through GitHub Actions artifacts",
			finding_zizmor["summary"],
		)

	def testNormalizesSemgrepOwaspAndSeverity(self):
		report_scan = normalizeEvidence(self.makeEvidence("semgrep"))
		finding_scan = report_scan["findings"][0]

		self.assertEqual("high", finding_scan["normalized_severity"])
		self.assertIn("A05", finding_scan["owasp_2025"])


if __name__ == "__main__":
	unittest.main()
