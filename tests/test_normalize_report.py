import io
import json
import unittest
from contextlib import redirect_stderr
from copy import deepcopy
from unittest.mock import patch

from scripts.normalize_findings import getCoverage, normalizeEvidence, runMain, toMarkdown, toSarif
from normalize_base import NormalizeTestBase


class NormalizeReportTest(NormalizeTestBase):
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
				finding["verdict_evidence"] = {
					"reason": "Reviewed with trace", "trace": "input -> sink",
					"unresolved_fact": "Unknown sanitizer behavior" if verdict == "needs_validation" else None,
				}
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


if __name__ == "__main__":
	unittest.main()
