"""Tests for the declared-runtime-version check.

Failure modes, written before the code:
1. A range such as engines.node ">=20" must never become a vulnerable finding.
2. A floating tag such as FROM node:22 must not match a CVE, but an EOL major is certain.
3. An unparseable declaration (ARG, lts/*, no tag) must be inconclusive with a reason.
4. An exact pin inside a vulnerable range and outside the patched range is a CVE finding.
5. A feed entry with unknown range syntax must fail loudly, never skip silently.
6. A failed feed fetch must produce errors, never a clean result.
7. A PHP pin older than any security release of its branch is flagged, even when a later
   bugfix-only release exists.
8. A PHP branch that is not in the active list is EOL.
9. Stages that build on other stages, other images, platform flags, and digests must not
   confuse the Dockerfile reader.
10. An advisory limited to one platform gets low confidence.
11. A symlinked or invalid declaration file is reported, never followed or ignored.
"""

import json
import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.check_runtime import (
	checkRuntime, getDeclarations, matchesRange, parseDeclaration,
)
from scripts.normalize_findings import normalizeEvidence
from scripts.run_plan import runPlan
from scripts.scan_plan import buildScanPlan
from scripts.validate_report import loadSchema, validateDocument

PATH_FIXTURES = Path(__file__).parent / "fixtures" / "runtime"
DATE_NOW = date(2026, 10, 22)


class RangeTest(unittest.TestCase):
	def testSupportsEverySyntaxInTheFeedSnapshot(self):
		data_feed = json.loads((PATH_FIXTURES / "node_core.json").read_text(encoding="utf-8"))
		for entry in data_feed.values():
			for field in ("vulnerable", "patched"):
				matchesRange("22.4.0", entry[field])

	def testRejectsUnknownSyntaxLoudly(self):
		with self.assertRaises(ValueError):
			matchesRange("22.4.0", "~22.4 || *")

	def testMatchesEachForm(self):
		cases = [
			("22.4.0", "22.x || 24.x", True), ("20.1.0", "22.x || 24.x", False),
			("0.10.5", "0.10.x", True), ("22.23.2", "^22.23.2", True),
			("22.23.1", "^22.23.2", False), ("23.0.0", "^22.23.2", False),
			("8.5.0", "8.5.0", True), ("8.5.1", "8.5.0", False),
			("10.9.0", ">= 10.9.0", True), ("6.1.0", ">=6.0.0 <6.2.0", True),
			("6.2.0", ">=6.0.0 <6.2.0", False), ("10.5.0", "<= 10", True),
			("11.0.0", "<= 10", False),
		]
		for version, range_text, expected in cases:
			with self.subTest(version=version, range_text=range_text):
				self.assertEqual(expected, matchesRange(version, range_text))


class DeclarationTest(unittest.TestCase):
	def testClassifiesDeclarations(self):
		cases = [
			("node", "22.4.0", "exact"), ("node", "v22.4.0", "exact"),
			("node", "22.4.0-alpine", "exact"), ("node", "22", "floating"),
			("node", "22-alpine", "floating"), ("php", "8.3", "floating"),
			("php", "8.3.30-fpm-bookworm", "exact"), ("node", ">=20", "range"),
			("php", "^8.2", "range"), ("node", "lts/*", "unparseable"),
			("node", "${NODE_VERSION}", "unparseable"), ("node", "latest", "unparseable"),
			("node", "", "unparseable"),
		]
		for runtime, raw, expected in cases:
			with self.subTest(raw=raw):
				self.assertEqual(expected, parseDeclaration(runtime, raw)["class"])


class CheckRuntimeTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name) / "repo"
		self.path_root.mkdir()

	def tearDown(self):
		self.temp_dir.cleanup()

	def writeFile(self, name_file: str, content_file: str) -> None:
		path_file = self.path_root / name_file
		path_file.parent.mkdir(parents=True, exist_ok=True)
		path_file.write_text(content_file, encoding="utf-8")

	def check(self, path_fixtures: Path = PATH_FIXTURES) -> dict:
		return checkRuntime(self.path_root, path_fixtures, DATE_NOW)

	def getKinds(self, report: dict) -> list[tuple]:
		return sorted(
			(item["runtime"], item["kind"], item["version"]) for item in report["findings"])

	def testExactNodePinInsideVulnerableRangeIsCve(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		report = self.check()
		ids = {item["id"] for item in report["findings"]}
		self.assertIn("CVE-2026-58045", ids)
		self.assertTrue(all(item["kind"] != "eol" for item in report["findings"]))

	def testPatchedNodePinIsClean(self):
		self.writeFile(".nvmrc", "22.23.2\n")
		report = self.check()
		self.assertEqual([], [i for i in report["findings"] if i["kind"] == "cve"])
		self.assertEqual([], report["errors"])

	def testRangeIsInconclusiveNeverVulnerable(self):
		self.writeFile("package.json", '{"engines": {"node": ">=20"}}')
		report = self.check()
		self.assertEqual([], report["findings"])
		self.assertEqual("range", report["inconclusive"][0]["class"])

	def testFloatingMajorHasNoCveButEolMajorIsFlagged(self):
		self.writeFile("Dockerfile", "FROM node:22-alpine\nFROM node:18\n")
		report = self.check()
		self.assertEqual([("node", "eol", "18")], self.getKinds(report))

	def testUnparseableDeclarationsAreInconclusive(self):
		self.writeFile(".node-version", "lts/*\n")
		self.writeFile("Dockerfile", "ARG V=22\nFROM node:${V}\nFROM node\n")
		report = self.check()
		self.assertEqual([], report["findings"])
		self.assertEqual(3, len(report["inconclusive"]))
		self.assertTrue(all(item["reason"] for item in report["inconclusive"]))

	def testDockerfileNoise(self):
		self.writeFile("Dockerfile", (
			"FROM --platform=linux/amd64 php:8.3.30-fpm@sha256:abc AS base\n"
			"FROM base AS build\nFROM alpine:3.20\nCOPY --from=base /a /b\n"
		))
		report = self.check()
		self.assertEqual(1, len(getDeclarations(self.path_root)[0]))
		self.assertEqual([("php", "behind-security-release", "8.3.30")], self.getKinds(report))

	def testPhpPinBehindSecurityReleaseEvenWithLaterBugfixRelease(self):
		self.writeFile("Dockerfile", "FROM php:8.3.34-apache\n")
		path_copy = Path(self.temp_dir.name) / "fixtures"
		shutil.copytree(PATH_FIXTURES, path_copy)
		path_releases = path_copy / "php_releases_8.json"
		data_releases = json.loads(path_releases.read_text(encoding="utf-8"))
		data_releases["8.3.37"] = {"date": "30 Oct 2026", "tags": [], "announcement": True}
		path_releases.write_text(json.dumps(data_releases), encoding="utf-8")
		report = self.check(path_copy)
		item = report["findings"][0]
		self.assertEqual("behind-security-release", item["kind"])
		self.assertEqual(["8.3.36"], item["fixed"])

	def testPhpPinAtLatestSecurityReleaseIsClean(self):
		self.writeFile("composer.json", '{"require": {"php": "8.3.36"}}')
		self.assertEqual([], self.check()["findings"])

	def testPhpEolBranchIsFlagged(self):
		self.writeFile("Dockerfile", "FROM php:7.4.33-cli\n")
		self.assertEqual([("php", "eol", "7.4.33")], self.getKinds(self.check()))

	def testPlatformOnlyAdvisoryHasLowConfidence(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		by_id = {i["id"]: i for i in self.check()["findings"] if i["kind"] == "cve"}
		self.assertEqual("low", by_id["CVE-2025-27210"]["confidence"])
		self.assertEqual("medium", by_id["CVE-2026-58045"]["confidence"])

	def testAdvisoryWithoutCveGetsStableId(self):
		self.writeFile(".nvmrc", "5.1.0\n")
		ids = {i["id"] for i in self.check()["findings"]}
		self.assertIn("NODEJS-SECURITY-WG-26", ids)

	def testMissingFeedIsAnErrorNotClean(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		path_empty = Path(self.temp_dir.name) / "empty"
		path_empty.mkdir()
		report = self.check(path_empty)
		self.assertEqual([], report["findings"])
		self.assertTrue(report["errors"])

	def testUnknownFeedSyntaxIsReportedNotSkipped(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		path_copy = Path(self.temp_dir.name) / "fixtures"
		shutil.copytree(PATH_FIXTURES, path_copy)
		path_feed = path_copy / "node_core.json"
		data_feed = json.loads(path_feed.read_text(encoding="utf-8"))
		data_feed["999"] = {"cve": ["CVE-0-0"], "vulnerable": "~22 || *", "patched": "",
			"severity": "high", "description": "x", "ref": "", "affectedEnvironments": ["all"]}
		path_feed.write_text(json.dumps(data_feed), encoding="utf-8")
		report = self.check(path_copy)
		self.assertEqual(["999"], report["unparsed"])

	def testSymlinkedAndInvalidFilesAreReported(self):
		self.writeFile("package.json", "{not json")
		(self.path_root / ".nvmrc").symlink_to("/etc/hosts")
		report = self.check()
		reasons = " ".join(item["reason"] for item in report["inconclusive"])
		self.assertIn("symlink", reasons)
		self.assertIn("invalid", reasons)


class PipelineTest(unittest.TestCase):
	"""Planner -> runner -> normalizer -> published schema, with feeds read from fixtures."""

	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_base = Path(self.temp_dir.name)
		self.path_root = self.path_base / "repo"
		self.path_root.mkdir()

	def tearDown(self):
		self.temp_dir.cleanup()

	def writeFile(self, name_file: str, content_file: str) -> None:
		path_file = self.path_root / name_file
		path_file.parent.mkdir(parents=True, exist_ok=True)
		path_file.write_text(content_file, encoding="utf-8")

	def getRuntimeItems(self, plan_scan: dict) -> list[dict]:
		return [item for item in plan_scan["projects"] if item["kind"] == "runtime"]

	def scan(self, path_fixtures: Path) -> dict:
		plan_scan = buildScanPlan(self.path_root)
		for item in self.getRuntimeItems(plan_scan):
			item["command"] = item["command"] + [
				"--fixtures", str(path_fixtures), "--today", DATE_NOW.isoformat()]
		path_plan = self.path_base / "plan.json"
		path_plan.write_text(json.dumps(plan_scan), encoding="utf-8")
		path_out = self.path_base / "evidence"
		runPlan(path_plan, path_out, quiet=True)
		report = normalizeEvidence(path_out)
		self.assertEqual([], validateDocument(report, loadSchema(
			Path(__file__).parents[1] / "schema" / "security-findings.schema.json")))
		return report

	def testPlannerEmitsRuntimeItemOnlyWithEvidence(self):
		self.writeFile("package.json", '{"name": "app"}')
		self.assertEqual([], self.getRuntimeItems(buildScanPlan(self.path_root)))
		self.writeFile("package.json", '{"engines": {"node": ">=20"}}')
		items = self.getRuntimeItems(buildScanPlan(self.path_root))
		self.assertEqual(["package.json"], items[0]["evidence"])
		self.assertEqual("declared-version-only", items[0]["coverage"])

	def testPlannerSkipsVendoredPackageManifests(self):
		self.writeFile("vendor/acme/lib/composer.json", '{"require": {"php": ">=7.2"}}')
		self.writeFile("node_modules/pkg/package.json", '{"engines": {"node": ">=12"}}')
		self.assertEqual([], self.getRuntimeItems(buildScanPlan(self.path_root)))

	def testPlanMatchesPublishedSchema(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		self.assertEqual([], validateDocument(buildScanPlan(self.path_root), loadSchema(
			Path(__file__).parents[1] / "schema" / "scan-plan.schema.json")))

	def testPinnedVersionBecomesRuntimeFinding(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		report = self.scan(PATH_FIXTURES)
		item_scanner = next(i for i in report["scanners"] if i["kind"] == "runtime")
		self.assertEqual("findings", item_scanner["state"])
		finding = next(i for i in report["findings"] if i["id"] == "CVE-2026-58045")
		self.assertEqual(
			("runtime", "node", "22.4.0", ".nvmrc", 1),
			(finding["type"], finding["package"], finding["installed_version"],
				finding["location"], finding["line"]))
		self.assertEqual(["A03"], finding["owasp_2025"])

	def testOnlyRangesGiveInconclusiveScanner(self):
		self.writeFile("composer.json", '{"require": {"php": "^8.2"}}')
		report = self.scan(PATH_FIXTURES)
		item_scanner = next(i for i in report["scanners"] if i["kind"] == "runtime")
		self.assertEqual("inconclusive", item_scanner["state"])
		self.assertEqual([], report["findings"])

	def testOpenItemsStayVisibleNextToFindings(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		self.writeFile("composer.json", '{"require": {"php": "^8.2"}}')
		item_scanner = next(i for i in self.scan(PATH_FIXTURES)["scanners"]
			if i["kind"] == "runtime")
		self.assertEqual("findings", item_scanner["state"])
		self.assertIn("composer.json", item_scanner["reason"])

	def testFeedFailureIsFailedNotClean(self):
		self.writeFile(".nvmrc", "22.4.0\n")
		path_empty = self.path_base / "empty"
		path_empty.mkdir()
		report = self.scan(path_empty)
		item_scanner = next(i for i in report["scanners"] if i["kind"] == "runtime")
		self.assertEqual("failed", item_scanner["state"])

	def testPatchedVersionIsClean(self):
		self.writeFile(".nvmrc", "24.18.1\n")
		item_scanner = next(i for i in self.scan(PATH_FIXTURES)["scanners"]
			if i["kind"] == "runtime")
		self.assertEqual("clean", item_scanner["state"])
