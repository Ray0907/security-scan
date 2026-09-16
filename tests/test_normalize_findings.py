import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.normalize_findings import (
	normalizeEvidence,
	parseArguments,
	parseGovulncheck,
	toMarkdown,
	toSarif,
)


TOOLS_FIXTURE = {
	"npm": "json",
	"pnpm": "json",
	"yarn": "ndjson",
	"bun": "json",
	"pip-audit": "json",
	"govulncheck": "ndjson",
	"cargo-audit": "json",
	"composer": "json",
	"bundler-audit": "json",
	"trivy": "json",
	"osv-scanner": "json",
	"semgrep": "json",
	"gitleaks": "json",
	"zizmor": "json",
}


class NormalizeFindingsTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name)
		self.path_fixtures = Path(__file__).parent / "fixtures"

	def tearDown(self):
		self.temp_dir.cleanup()

	def makeEvidence(
		self,
		tool_name: str,
		fixture_name: str = "findings",
		name_evidence: str | None = None,
	) -> Path:
		path_evidence = self.path_root / f"evidence-{tool_name}-{name_evidence or fixture_name}"
		path_record = path_evidence / "01-test-root"
		path_record.mkdir(parents=True)
		extension_fixture = TOOLS_FIXTURE[tool_name]
		content_fixture = (
			self.path_fixtures / tool_name / f"{fixture_name}.{extension_fixture}"
		).read_text(encoding="utf-8")
		(path_record / "stdout.txt").write_text(content_fixture, encoding="utf-8")
		data_meta = {
			"plan_index": 1,
			"kind": "code" if tool_name == "semgrep" else "dependency",
			"path": ".",
			"tool": tool_name,
			"tool_version": "fixture",
			"state": "ran",
			"reason": None,
		}
		(path_record / "meta.json").write_text(json.dumps(data_meta), encoding="utf-8")
		(path_evidence / "run.json").write_text(
			json.dumps(
				{
					"schema_version": 1,
					"plan_root": "/work/app",
					"git": {"commit": "abc", "branch": "main", "dirty": False},
					"records": [data_meta],
				}
			),
			encoding="utf-8",
		)
		return path_evidence

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

	def testNodeAdvisoriesPreferGhsaIdAndLockfileLocation(self):
		result_scan = normalizeEvidence(self.makeEvidence("bun"))
		finding_first = result_scan["findings"][0]

		self.assertTrue(finding_first["id"].startswith("GHSA-"))
		self.assertTrue(all(alias.isdigit() for alias in finding_first["aliases"]))
		self.assertEqual("bun.lock", finding_first["location"])
		result_pnpm = normalizeEvidence(self.makeEvidence("pnpm"))
		self.assertEqual("pnpm-lock.yaml", result_pnpm["findings"][0]["location"])

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

	def testBaselineMarksUnchangedAndFixedFindings(self):
		path_findings = self.makeEvidence("npm")
		report_first = normalizeEvidence(path_findings)
		path_baseline = self.path_root / "baseline.json"
		path_baseline.write_text(json.dumps(report_first), encoding="utf-8")

		report_same = normalizeEvidence(path_findings, path_baseline=path_baseline)
		report_clean = normalizeEvidence(
			self.makeEvidence("npm", "clean"),
			path_baseline=path_baseline,
		)

		self.assertTrue(all(item["change"] == "unchanged" for item in report_same["findings"]))
		self.assertNotIn("change", report_first["findings"][0])
		self.assertEqual(report_first["findings"][0]["fingerprint"], report_clean["fixed"][0]["fingerprint"])

	def testSarifContainsRequiredKeys(self):
		report_scan = normalizeEvidence(self.makeEvidence("semgrep"))
		data_sarif = toSarif(report_scan)

		self.assertEqual("2.1.0", data_sarif["version"])
		self.assertIn("driver", data_sarif["runs"][0]["tool"])
		self.assertIn("ruleId", data_sarif["runs"][0]["results"][0])
		self.assertIn("physicalLocation", data_sarif["runs"][0]["results"][0]["locations"][0])

	def testMarkdownUsesRequiredReportSections(self):
		content_markdown = toMarkdown(normalizeEvidence(self.makeEvidence("npm")))

		for heading_report in (
			"Executive Summary", "Scope and Reproducibility", "Scanner Status",
			"Findings", "OWASP 2025 Coverage", "Limitations",
		):
			self.assertIn(f"## {heading_report}", content_markdown)
		self.assertNotIn("not endorsed or certified by the NVD", content_markdown)

	def testSeverityAndOwaspFiltersApply(self):
		report_scan = normalizeEvidence(
			self.makeEvidence("semgrep"),
			severities={"low"},
			categories_owasp={"A01"},
		)

		self.assertEqual([], report_scan["findings"])

	def testParsesNormalizerOptions(self):
		with patch(
			"sys.argv",
			[
				"normalize_findings.py", "evidence", "--baseline", "old.json",
				"--format", "sarif", "--severity", "critical,high", "--owasp", "A03",
				"--out", "result.sarif",
			],
		):
			args_normalize = parseArguments()

		self.assertEqual("sarif", args_normalize.format)
		self.assertEqual("critical,high", args_normalize.severity)
		self.assertEqual("A03", args_normalize.owasp)


if __name__ == "__main__":
	unittest.main()
