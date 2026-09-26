import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts.validate_report import loadSchema, validateDocument
from scripts.normalize_findings import (
	getCoverage,
	normalizeEvidence,
	parseArguments,
	parseGovulncheck,
	parsePipAudit,
	parseSemgrep,
	runMain,
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

	def testMergesVerdictsAndReportsUnmatchedFingerprints(self):
		path_evidence = self.makeEvidence("semgrep")
		finding_first = normalizeEvidence(path_evidence)["findings"][0]
		verdict_data = {
			finding_first["fingerprint"]: {
				"verdict": "confirmed",
				"verdict_evidence": {
					"reason": "Untrusted input reaches eval without validation.",
					"trace": "code/app.js:3 -> eval",
					"unresolved_fact": None,
					"reviewed_at": "2026-09-16T00:00:00+00:00",
					"reviewer": "security-reviewer",
				},
			},
			"missing-fingerprint": {
				"verdict": "rejected",
				"verdict_evidence": {
					"reason": "Not present.", "trace": None, "unresolved_fact": None,
					"reviewed_at": "2026-09-16T00:00:00+00:00", "reviewer": "reviewer",
				},
			},
		}
		path_verdicts = self.path_root / "verdicts.json"
		path_verdicts.write_text(json.dumps(verdict_data), encoding="utf-8")
		output_error = io.StringIO()

		with redirect_stderr(output_error):
			report_scan = normalizeEvidence(path_evidence, path_verdicts=path_verdicts)

		finding_merged = next(
			finding for finding in report_scan["findings"]
			if finding["fingerprint"] == finding_first["fingerprint"]
		)
		self.assertEqual("confirmed", finding_merged["verdict"])
		self.assertEqual("security-reviewer", finding_merged["verdict_evidence"]["reviewer"])
		self.assertEqual(["missing-fingerprint"], report_scan["verdicts_unmatched"])
		self.assertIn("missing-fingerprint", output_error.getvalue())

	def testCarriesForwardVerdictUnlessFindingContextChanged(self):
		path_evidence = self.makeEvidence("pnpm")
		report_baseline = normalizeEvidence(path_evidence)
		finding_baseline = report_baseline["findings"][0]
		finding_baseline["verdict"] = "confirmed"
		finding_baseline["verdict_evidence"] = {
			"reason": "Locked vulnerable version.", "trace": "lodash -> pnpm-lock.yaml",
			"unresolved_fact": None, "reviewed_at": "2026-09-16T00:00:00+00:00",
			"reviewer": "security-reviewer",
		}
		path_baseline = self.path_root / "baseline.json"
		path_baseline.write_text(json.dumps(report_baseline), encoding="utf-8")

		report_same = normalizeEvidence(path_evidence, path_baseline=path_baseline)
		carried = next(
			finding for finding in report_same["findings"]
			if finding["fingerprint"] == finding_baseline["fingerprint"]
		)
		self.assertEqual("confirmed", carried["verdict"])
		self.assertTrue(carried["verdict_carried_forward"])

		finding_baseline["installed_version"] = "different"
		path_baseline.write_text(json.dumps(report_baseline), encoding="utf-8")
		report_changed = normalizeEvidence(path_evidence, path_baseline=path_baseline)
		invalidated = next(
			finding for finding in report_changed["findings"]
			if finding["fingerprint"] == finding_baseline["fingerprint"]
		)
		self.assertNotIn("verdict", invalidated)
		self.assertNotIn("verdict_carried_forward", invalidated)

	def testMarkdownGroupsVerdictsAndSarifMapsKinds(self):
		report_scan = normalizeEvidence(self.makeEvidence("semgrep"))
		finding_template = report_scan["findings"][0]
		findings = []
		for index_finding, verdict in enumerate(("confirmed", "needs_validation", None, "rejected")):
			finding = deepcopy(finding_template)
			finding["id"] = f"finding-{index_finding}"
			finding["rule_id"] = finding["id"]
			finding["fingerprint"] = f"fingerprint-{index_finding}"
			finding["change"] = "new" if index_finding == 0 else "unchanged"
			if verdict:
				finding["verdict"] = verdict
				finding["verdict_evidence"] = {"reason": "Reviewed with trace", "trace": "input -> sink"}
			findings.append(finding)
		report_scan["findings"] = findings

		content_markdown = toMarkdown(report_scan)
		data_sarif = toSarif(report_scan)
		results_sarif = data_sarif["runs"][0]["results"]
		kinds_sarif = {result["ruleId"]: result["kind"] for result in results_sarif}

		for heading_verdict in ("Confirmed", "Needs validation", "Unreviewed", "Rejected"):
			self.assertIn(f"## {heading_verdict}", content_markdown)
		self.assertLess(content_markdown.index("### Unreviewed"), content_markdown.index("## OWASP"))
		self.assertGreater(content_markdown.index("### Rejected"), content_markdown.index("## OWASP"))
		self.assertEqual({"fail"}, set(kinds_sarif.values()))
		self.assertEqual(
			[{"kind": "external", "status": "accepted", "justification": json.dumps(findings[3]["verdict_evidence"], sort_keys=True)}],
			results_sarif[3]["suppressions"],
		)
		self.assertTrue(all(result["level"] in ("error", "warning", "note") for result in results_sarif))
		self.assertEqual("new", results_sarif[0]["baselineState"])
		self.assertEqual("unchanged", results_sarif[1]["baselineState"])

	def testRejectedOnlyCoverageRevertsToAutomatedCovered(self):
		scanners = [{"tool": "semgrep", "kind": "code", "state": "findings"}]
		findings = [{"owasp_2025": ["A05"], "verdict": "rejected"}]

		self.assertEqual("automated-covered", getCoverage(scanners, findings)["A05"])
		findings.append({"owasp_2025": ["A05"]})
		self.assertEqual("findings", getCoverage(scanners, findings)["A05"])

	def testSarifContainsRequiredKeys(self):
		report_scan = normalizeEvidence(self.makeEvidence("semgrep"))
		data_sarif = toSarif(report_scan)

		self.assertEqual("2.1.0", data_sarif["version"])
		self.assertIn("driver", data_sarif["runs"][0]["tool"])
		self.assertIn("ruleId", data_sarif["runs"][0]["results"][0])
		self.assertIn("physicalLocation", data_sarif["runs"][0]["results"][0]["locations"][0])

	def testMarkdownEscapesSummaryInUnreviewedAndRejectedRows(self):
		report_scan = normalizeEvidence(self.makeEvidence("npm"))
		finding = report_scan["findings"][0]
		finding["summary"] = "alpha | beta\nnext line"
		rejected = deepcopy(finding)
		rejected["verdict"] = "rejected"
		report_scan["findings"] = [finding, rejected]

		content_markdown = toMarkdown(report_scan)
		self.assertEqual(2, content_markdown.count("alpha \\| beta next line"))
		self.assertNotIn("alpha | beta\nnext line", content_markdown)

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

	def testCoverageIncludesFindingsHiddenByFilters(self):
		path_evidence = self.makeEvidence("pip-audit")
		for filters_scan in ({"severities": {"high"}}, {"categories_owasp": {"A01"}}):
			with self.subTest(filters=filters_scan):
				report_scan = normalizeEvidence(path_evidence, **filters_scan)
				self.assertEqual([], report_scan["findings"])
				self.assertEqual(0, report_scan["scanners"][0]["finding_count"])
				self.assertEqual("findings", report_scan["owasp_coverage"]["A03"])

	def testNormalizerFailsWhenOwnReportViolatesSchema(self):
		path_evidence = self.makeEvidence("npm")
		output_error = io.StringIO()
		with patch("scripts.normalize_findings.validateDocument", return_value=["/findings: broken"]), patch(
			"sys.argv", ["normalize_findings.py", str(path_evidence)]
		), redirect_stderr(output_error), self.assertRaises(SystemExit) as raised_exit:
			runMain()

		self.assertEqual(1, raised_exit.exception.code)
		self.assertIn("/findings: broken", output_error.getvalue())

	def makeLicenseEvidence(self, ecosystem: str, lockfile: str, content: str | None = None,
			exit_code: int = 0, stderr: str = "") -> Path:
		path_evidence = self.path_root / f"license-{ecosystem}-{len(list(self.path_root.iterdir()))}"
		path_record = path_evidence / "01-license-root"
		path_record.mkdir(parents=True)
		fixture_dir = self.path_fixtures / "osv-scanner-license"
		(self.path_root / lockfile).write_text(
			(fixture_dir / lockfile).read_text(encoding="utf-8"), encoding="utf-8")
		(path_record / "stdout.txt").write_text(
			content if content is not None else (fixture_dir / f"{ecosystem}.json").read_text(),
			encoding="utf-8")
		(path_record / "stderr.txt").write_text(stderr, encoding="utf-8")
		meta = {"plan_index": 1, "kind": "license", "path": ".",
			"tool": "osv-scanner-license", "tool_version": "2.6.0", "state": "ran",
			"command": ["osv-scanner", "scan", "source", "--lockfile", lockfile,
				"--all-packages", "--no-resolve", "--licenses=", "--format", "json"],
			"exit_code": exit_code, "reason": None}
		(path_record / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
		(path_evidence / "run.json").write_text(json.dumps({"schema_version": 1,
			"plan_root": str(self.path_root), "git": {"commit": None, "branch": None,
			"dirty": None}, "records": [meta]}), encoding="utf-8")
		return path_evidence

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
