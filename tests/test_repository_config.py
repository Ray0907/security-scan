import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scan_plan_base import ScanPlanTestBase
from scripts.normalize_findings import normalizeEvidence
from scripts.report_output import toMarkdown
from scripts.run_plan import getToolVersion, prepareAllRecords, runPlan
from scripts.scan_plan import buildScanPlan
from scripts.validate_report import loadSchema, validateDocument


PATH_REPO = Path(__file__).parents[1]


class RepositoryConfigPlanTest(ScanPlanTestBase):
	def project(self, kind, path="."):
		return next(item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == kind and item["path"] == path)

	def writeYarn(self, path="."):
		self.writeFile(f"{path}/package.json", '{"packageManager":"yarn@4.0.0"}')
		self.writeFile(f"{path}/yarn.lock")

	def writeCargo(self, path="."):
		self.writeFile(f"{path}/Cargo.toml")
		self.writeFile(f"{path}/Cargo.lock")

	def assertBlocked(self, project, config, key):
		self.assertEqual("inconclusive", project["status"])
		self.assertIsNone(project["command"])
		self.assertIn(config, project["reason"])
		self.assertIn(key, project["reason"])
		self.assertIn("repository", project["reason"])

	def testYarnExecutionKeysAtEachAncestor(self):
		self.writeYarn("apps/web")
		for directory in (".", "apps", "apps/web"):
			for config, key, content in (
				(".yarnrc.yml", "yarnPath", "yarnPath: .yarn/releases/evil.cjs\n"),
				(".yarnrc.yml", "plugins", "plugins:\n  - path: ./evil.cjs\n"),
				(".yarnrc", "yarn-path", 'yarn-path "./evil.js"\n'),
			):
				with self.subTest(directory=directory, key=key):
					path_config = self.path_root / directory / config
					self.writeFile(f"{directory}/{config}", content)
					self.assertBlocked(self.project("node", "apps/web"), config, key)
					path_config.unlink()

	def testOrdinaryBerryConfigStaysReady(self):
		self.writeYarn()
		self.writeFile(".yarnrc.yml", "# ordinary Berry settings\nnodeLinker: node-modules\n"
			'enableGlobalCache: true\nnpmRegistryServer: "https://registry.npmjs.org"\n'
			'npmScopes:\n  company:\n    npmRegistryServer: "https://registry.example.com"\n')
		self.assertEqual("ready", self.project("node")["status"])
		self.assertEqual(["yarn", "npm", "audit", "--json", "--all", "--recursive"],
			self.project("node")["command"])

	def testYarnReviewBypassesAtEachAncestor(self):
		self.writeYarn("apps/web")
		for directory in (".", "apps", "apps/web"):
			for content in ('{yarnPath: ./payload.cjs}\n', '  yarnPath: ./payload.cjs\n',
				'"yarn\\u0050ath": ./payload.cjs\n', '{plugins: [{path: ./payload.cjs}]}\n'):
				with self.subTest(directory=directory, content=content):
					self.writeFile(f"{directory}/.yarnrc.yml", content)
					self.assertBlocked(self.project("node", "apps/web"), ".yarnrc.yml", "yarn")
					(self.path_root / directory / ".yarnrc.yml").unlink()

	def testUnsupportedBerrySyntaxFailsClosed(self):
		self.writeYarn()
		for content in (
			'# ordinary comment\n  nodeLinker: node-modules\n',
			'{nodeLinker: node-modules}\n', '[nodeLinker, node-modules]\n',
			'npmScopes:\n  {company: {}}\n', '"nodeLinker": node-modules\n',
			"'nodeLinker': node-modules\n", 'npmScopes:\n  "company": value\n',
			'npmScopes: {"company": {}}\n',
			'nodeLinker: "node\\u002dmodules"\n', 'nodeLinker: &setting node-modules\n',
			'nodeLinker: *setting\n', 'npmScopes:\n  <<: value\n',
			'nodeLinker: !tag node-modules\n', 'nodeLinker: node-modules\n---\n',
			'nodeLinker: node-modules\n...\n', '---\n---\nnodeLinker: node-modules\n',
			'node-linker: node-modules\n', 'nodeLinker:node-modules\n', 'not a mapping\n',
			'# yarnPath: evil.js\n', 'other:\n  plugins: []\n',
			'other: YARNPATH\n', '# PLUGINS disabled\n',
		):
			with self.subTest(content=content):
				self.writeFile(".yarnrc.yml", content)
				self.assertBlocked(self.project("node"), ".yarnrc.yml", "yarn")

	def testPlainBerryCommentsAndDocumentHeaderStayReady(self):
		self.writeYarn()
		for content in ('', '# ordinary comment\n\n',
			'---\nnodeLinker: node-modules\n', 'npmScopes:\n  company:\n    npmAlwaysAuth: true\n'):
			with self.subTest(content=content):
				self.writeFile(".yarnrc.yml", content)
				self.assertEqual("ready", self.project("node")["status"])

	def testLegacyYarnSuspiciousTextFailsClosed(self):
		self.writeYarn()
		for content in ('YARN-PATH "./payload.js"\n', '# yarn-path disabled\n',
			'"yarn\\u002dpath" "./payload.js"\n', 'registry "https:\\registry.example.com"\n'):
			with self.subTest(content=content):
				self.writeFile(".yarnrc", content)
				self.assertBlocked(self.project("node"), ".yarnrc", "yarn")

	def testLegacyYarnCamelCasePathAtEachAncestor(self):
		self.writeFile("apps/web/package.json", '{"packageManager":"yarn@1.22.22"}')
		self.writeFile("apps/web/yarn.lock")
		for directory in (".", "apps", "apps/web"):
			for key in ("yarnPath", "yarnpath", "YARNPATH"):
				with self.subTest(directory=directory, key=key):
					self.writeFile(f"{directory}/.yarnrc", f'{key} "./payload.cjs"\n')
					self.assertBlocked(self.project("node", "apps/web"), ".yarnrc", "yarn")
					(self.path_root / directory / ".yarnrc").unlink()

	def testPlainLegacyYarnStaysReady(self):
		self.writeFile("package.json", '{"packageManager":"yarn@1.22.22"}')
		self.writeFile("yarn.lock")
		self.writeFile(".yarnrc", '# ordinary registry\nregistry "https://registry.npmjs.org"\n')
		self.assertEqual("ready", self.project("node")["status"])
		self.assertEqual(["yarn", "audit", "--json"], self.project("node")["command"])

	def testQuotedYarnKeysBlock(self):
		self.writeYarn()
		for config, content in ((".yarnrc.yml", '"yarnPath": evil.cjs\n'),
			(".yarnrc.yml", "'plugins': []\n"), (".yarnrc", '"yarn-path" "evil.js"\n')):
			with self.subTest(content=content):
				self.writeFile(config, content)
				self.assertEqual("inconclusive", self.project("node")["status"])
				(self.path_root / config).unlink()

	def testCargoAuditAliasesAtEachAncestor(self):
		self.writeCargo("apps/rust")
		for directory in (".", "apps", "apps/rust"):
			for config in (".cargo/config.toml", ".cargo/config"):
				for content in ('[alias]\naudit = "run --bin evil"\n',
					'alias.audit = ["run", "--bin", "evil"]\n',
					'[alias] # aliases\n"audit" = "run"\n',
					'alias = { audit = "run --bin payload --" }\n',
					'["ali\\u0061s"]\naudit = "run --bin payload --"\n'):
					with self.subTest(directory=directory, config=config, content=content):
						self.writeFile(f"{directory}/{config}", content)
						self.assertBlocked(self.project("rust", "apps/rust"), config, "audit")
						(self.path_root / directory / config).unlink()

	def testCargoIncludesAtEachAncestor(self):
		self.writeCargo("apps/rust")
		for directory in (".", "apps", "apps/rust"):
			for config in (".cargo/config.toml", ".cargo/config"):
				for content in ('include = ["extra.toml"]\n',
					'InClUdE = ["extra.toml"]\n', '# prefixINCLUDEsuffix\n'):
					with self.subTest(directory=directory, config=config, content=content):
						self.writeFile(f"{directory}/{config}", content)
						self.assertBlocked(self.project("rust", "apps/rust"), config, "cargo")
						(self.path_root / directory / config).unlink()

	def testOtherCargoAliasesStayReady(self):
		self.writeCargo()
		self.writeFile(".cargo/config.toml", '[alias]\nbuild-fast = "build"\n'
			'[env]\nMODE = "test"\n')
		self.writeFile(".cargo/config", '# ordinary alias\nalias.check = "check"\n')
		self.assertEqual("ready", self.project("rust")["status"])

	def testCargoSuspiciousTextFailsClosed(self):
		self.writeCargo()
		for config in (".cargo/config.toml", ".cargo/config"):
			for content in ('[env]\naudit = "not an alias"\n', '# AUDIT disabled\n',
				'alias = { "a\\u0075dit" = "run" }\n',
				'alias = { "a\\U00000075dit" = "run" }\n'):
				with self.subTest(config=config, content=content):
					self.writeFile(config, content)
					self.assertBlocked(self.project("rust"), config, "cargo")
					(self.path_root / config).unlink()

	def testRustToolchainPathsAtEachAncestor(self):
		self.writeCargo("apps/rust")
		for directory in (".", "apps", "apps/rust"):
			for config in ("rust-toolchain.toml", "rust-toolchain"):
				for content in ('[toolchain]\npath = "/checkout/payload"\n',
					'[toolchain]\nPATH = "payload"\n', 'custom/toolchain\n',
					'[toolchain]\n"pa\\u0074h" = "payload"\n', 'custom\\toolchain\n'):
					with self.subTest(directory=directory, config=config, content=content):
						self.writeFile(f"{directory}/{config}", content)
						self.assertBlocked(self.project("rust", "apps/rust"), config, "cargo")
						(self.path_root / directory / config).unlink()

	def testPinnedRustToolchainsStayReady(self):
		self.writeCargo("apps/rust")
		for directory in (".", "apps", "apps/rust"):
			for config in ("rust-toolchain.toml", "rust-toolchain"):
				contents = ('[toolchain]\nchannel = "1.80"\n',)
				if config == "rust-toolchain":
					contents += ('stable\n',)
				for content in contents:
					with self.subTest(directory=directory, config=config, content=content):
						self.writeFile(f"{directory}/{config}", content)
						self.assertEqual("ready", self.project("rust", "apps/rust")["status"])
						(self.path_root / directory / config).unlink()

	def testAncestorWalkStopsAtScanRoot(self):
		self.writeFile(".yarnrc.yml", "yarnPath: evil.cjs\n")
		self.writeFile(".yarnrc", 'yarn-path "evil.js"\n')
		self.writeFile(".cargo/config.toml", '[alias]\naudit = "run"\n')
		self.writeFile(".cargo/config", 'alias.audit = "run"\n')
		self.writeFile("rust-toolchain.toml", '[toolchain]\npath = "/outside"\n')
		self.writeFile("rust-toolchain", '/outside\n')
		self.writeYarn("scan/apps/web")
		self.writeCargo("scan/apps/rust")
		plan = buildScanPlan(self.path_root / "scan")
		self.assertEqual(["ready", "ready"], [item["status"] for item in plan["projects"]
			if item["kind"] in ("node", "rust")])

	def testOsvLicenseCommandIsNotBlockedByCargoAlias(self):
		self.writeCargo()
		self.writeFile(".cargo/config.toml", '[alias]\naudit = "run"\n')
		self.assertEqual("inconclusive", self.project("rust")["status"])
		license_project = self.project("license")
		self.assertEqual("ready", license_project["status"])
		self.assertEqual("osv-scanner", license_project["command"][0])

	def testYarnLicenseDoesNotInvokeYarn(self):
		self.writeYarn()
		self.writeFile(".yarnrc.yml", "plugins: []\n")
		self.assertEqual("inconclusive", self.project("node")["status"])
		self.assertIsNone(self.project("license")["command"])
		self.assertNotIn("repository code", self.project("license")["reason"])

	def testConfirmedSuppressionFilesAreNotedWithEvidence(self):
		self.writeFile("service/pom.xml")
		self.writeFile("service/Dockerfile", "FROM scratch\n")
		self.writeFile("infra/main.tf")
		for config in (".gitleaksignore", ".gitleaks.toml", "service/.trivyignore",
			"service/trivy.yaml", "infra/.trivyignore", "infra/trivy.yaml"):
			self.writeFile(config)
		for kind, path, configs in (
			("secrets", ".", [".gitleaksignore", ".gitleaks.toml"]),
			("java", "service", [".trivyignore", "trivy.yaml"]),
			("container", "service", [".trivyignore", "trivy.yaml"]),
			("iac", "infra", [".trivyignore", "trivy.yaml"]),
		):
			with self.subTest(kind=kind):
				project = self.project(kind, path)
				self.assertEqual("ready", project["status"])
				self.assertIn("repository suppression config present:", project.get("note", ""))
				self.assertIn("results may omit findings", project["note"])
				for config in configs:
					self.assertIn(config, project["note"])
					self.assertIn(config, project["evidence"])
		self.assertIn("main.tf", self.project("iac", "infra")["evidence"])

	def testGitleaksExclusionNoteIsPreserved(self):
		self.writeFile(".gitleaksignore")
		secrets = next(item for item in buildScanPlan(self.path_root, ["vendor"])["projects"]
			if item["kind"] == "secrets")
		self.assertIn("gitleaks does not honor planner exclusions", secrets["note"])
		self.assertIn("repository suppression config present:", secrets["note"])

	def testPythonNotesRemainIntact(self):
		self.writeFile("uv.lock")
		self.writeFile("osv-scanner.toml")
		self.assertIn("pip-audit export alternative:", self.project("python")["note"])

	def testSuppressionLookupDoesNotLeakBetweenScopes(self):
		self.writeFile(".trivyignore")
		self.writeFile("trivy.yaml")
		self.writeFile("service/pom.xml")
		self.writeFile("service/.gitleaksignore")
		self.assertNotIn("note", self.project("java", "service"))
		self.assertNotIn("note", self.project("secrets"))

	def testUnconfirmedSuppressionNamesAreNotAdvertised(self):
		self.writeCargo()
		self.writeFile("uv.lock")
		self.writeFile("Gemfile.lock")
		self.writeFile(".github/workflows/ci.yml", "name: ci\n")
		for config in ("osv-scanner.toml", ".cargo/audit.toml", ".bundler-audit.yml",
			"zizmor.yml", ".github/zizmor.yml"):
			self.writeFile(config)
		for project in buildScanPlan(self.path_root)["projects"]:
			self.assertNotIn("repository suppression config present:", project.get("note", ""))

	def testSymlinkedExecutionConfigIsBlockedWithoutReading(self):
		self.writeYarn("scan/web")
		self.writeCargo("scan/rust")
		self.writeFile("outside", "ordinary harmless data\n")
		for project, config in (("web", ".yarnrc.yml"), ("web", ".yarnrc"),
			("rust", ".cargo/config.toml"), ("rust", ".cargo/config"),
			("rust", "rust-toolchain.toml"), ("rust", "rust-toolchain")):
			with self.subTest(config=config):
				path_config = self.path_root / "scan" / project / config
				path_config.parent.mkdir(parents=True, exist_ok=True)
				path_config.symlink_to(self.path_root / "outside")
				with patch.object(Path, "read_bytes", side_effect=AssertionError("read symlink")), patch.object(
					Path, "read_text", autospec=True, side_effect=Path.read_text) as read_text:
					plan = buildScanPlan(self.path_root / "scan")
				self.assertNotIn(path_config, [call.args[0] for call in read_text.call_args_list])
				item = next(item for item in plan["projects"] if item["path"] == project
					and item["kind"] in ("node", "rust"))
				self.assertBlocked(item, config, "symlink")
				path_config.unlink()

	def testSymlinkedCargoDirectoryIsBlocked(self):
		self.writeCargo("scan/rust")
		self.writeFile("outside/config.toml", "# harmless\n")
		(self.path_root / "scan/rust/.cargo").symlink_to(self.path_root / "outside",
			target_is_directory=True)
		item = next(item for item in buildScanPlan(self.path_root / "scan")["projects"]
			if item["kind"] == "rust")
		self.assertBlocked(item, ".cargo", "symlink")

	def testSymlinkedSuppressionFilesArePresentWithoutReading(self):
		self.writeFile("scan/pom.xml")
		self.writeFile("outside", "apiVersion: v1\nkind: Pod\n")
		for config in (".gitleaksignore", ".gitleaks.toml", ".trivyignore", "trivy.yaml"):
			(self.path_root / "scan" / config).symlink_to(self.path_root / "outside")
		with patch.object(Path, "read_bytes", side_effect=AssertionError("read symlink")), patch.object(
			Path, "read_text", autospec=True, side_effect=Path.read_text) as read_text:
			plan = buildScanPlan(self.path_root / "scan")
		self.assertTrue(all(not call.args[0].is_symlink() for call in read_text.call_args_list))
		for kind, configs in (("secrets", [".gitleaksignore", ".gitleaks.toml"]),
			("java", [".trivyignore", "trivy.yaml"])):
			item = next(item for item in plan["projects"] if item["kind"] == kind)
			for config in configs:
				self.assertIn(config, item.get("evidence", []))
		self.assertFalse(any(item["kind"] == "iac" for item in plan["projects"]))

	def testGuardedPlanMatchesSchema(self):
		self.writeYarn()
		self.writeFile(".yarnrc.yml", "plugins: []\n")
		self.writeFile(".gitleaks.toml")
		self.assertEqual([], validateDocument(buildScanPlan(self.path_root),
			loadSchema(PATH_REPO / "schema/scan-plan.schema.json")))


class RepositoryConfigRunTest(unittest.TestCase):
	@patch("scripts.run_plan.subprocess.run")
	def testEveryVersionProbeUsesNeutralDirectory(self, run_mock):
		run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="version 1\n", stderr="")
		for command in (["yarn", "--version"], ["cargo", "audit", "--version"],
			["npm", "--version"]):
			with self.subTest(command=command):
				self.assertEqual("version 1", getToolVersion(command))
				self.assertEqual(tempfile.gettempdir(), run_mock.call_args.kwargs.get("cwd"))

	def runFixture(self, root, plan, semgrep=False, missing=False):
		path_plan, path_out = root / "plan.json", root / "evidence"
		path_plan.write_text(json.dumps(plan), encoding="utf-8")
		with patch("scripts.run_plan.getGitMetadata", return_value={
			"commit": None, "branch": None, "dirty": None}), patch(
			"scripts.run_plan.getToolVersion", return_value="tool 1"), patch(
			"scripts.run_plan.shutil.which", return_value=None if missing else "/tool"), patch(
			"scripts.run_plan.executeScan", return_value={"state": "ran", "reason": None,
				"exit_code": 0, "stdout": "[]", "stderr": ""}):
			self.assertEqual(0, runPlan(path_plan, path_out, quiet=True, semgrep=semgrep))
		return path_out, json.loads((path_out / "run.json").read_text())

	def testNoteTravelsFromPlanThroughMetadataToValidatedReportAndMarkdown(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			(root / ".gitleaksignore").touch()
			plan = buildScanPlan(root, ["vendor"])
			note = plan["projects"][0].get("note", "")
			self.assertIn("repository suppression config present:", note)
			path_out, run = self.runFixture(root, plan)
			self.assertEqual(note, run["records"][0].get("note"))
			self.assertEqual(note, json.loads(next(path_out.glob("*/meta.json")).read_text())["note"])
			self.assertEqual([], validateDocument(run, loadSchema(PATH_REPO / "schema/run.schema.json")))
			report = normalizeEvidence(path_out)
			self.assertEqual("clean", report["scanners"][0]["state"])
			self.assertEqual(note, report["scanners"][0].get("note"))
			self.assertEqual([], validateDocument(report,
				loadSchema(PATH_REPO / "schema/security-findings.schema.json")))
			self.assertIn(note, toMarkdown(report))

	def testNoteWithExistingReasonStillAppearsInMarkdown(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			plan = buildScanPlan(root)
			note = "repository suppression config present: .gitleaksignore; results may omit findings"
			plan["projects"][0]["note"] = note
			path_out, _ = self.runFixture(root, plan, missing=True)
			report = normalizeEvidence(path_out)
			self.assertEqual("tool unavailable", report["scanners"][0]["reason"])
			self.assertIn(note, toMarkdown(report))
			self.assertIn("tool unavailable", toMarkdown(report))

	def testSemgrepIgnoreIsDetectedByRunner(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			(root / ".semgrepignore").symlink_to(root / "missing")
			with patch("scripts.run_plan.prepareAllRecords", wraps=prepareAllRecords) as prepare:
				path_out, run = self.runFixture(root, {"root": str(root), "projects": []}, semgrep=True)
			self.assertIn(".semgrepignore", run["records"][0].get("note", ""))
			self.assertIn(".semgrepignore", normalizeEvidence(path_out)["scanners"][0]["note"])
			self.assertIn(".semgrepignore", prepare.call_args.args[0][0]["evidence"])

	def testOldReportWithoutNoteRemainsValid(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			path_out, run = self.runFixture(root, buildScanPlan(root))
			self.assertNotIn("note", run["records"][0])
			report = normalizeEvidence(path_out)
			self.assertNotIn("note", report["scanners"][0])
			self.assertEqual([], validateDocument(report,
				loadSchema(PATH_REPO / "schema/security-findings.schema.json")))


if __name__ == "__main__":
	unittest.main()
