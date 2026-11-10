from pathlib import Path
from unittest.mock import patch

from scan_plan_base import ScanPlanTestBase
from scripts.repository_config import getExecutionConfigReason
from scripts.scan_plan import buildScanPlan
from test_repository_config import RepositoryConfigHelpers


class RepositoryConfigScopeTest(RepositoryConfigHelpers, ScanPlanTestBase):
	def testAncestorConfigsAboveScanRootBlockUnlessInHome(self):
		self.writeYarn("scan/apps/web")
		self.writeCargo("scan/apps/rust")
		for name_config, content_config, kind_project in (
			(".yarnrc.yml", "yarnPath: evil.cjs\n", "node"),
			(".yarnrc", 'yarn-path "evil.js"\n', "node"),
			(".env.yarn", "", "node"),
			(".cargo/config.toml", '[alias]\naudit = "run"\n', "rust"),
			(".cargo/config", 'alias.audit = "run"\n', "rust"),
			("rust-toolchain.toml", '[toolchain]\npath = "/outside"\n', "rust"),
			("rust-toolchain", '/outside\n', "rust"),
		):
			self.writeFile(name_config, content_config)
			with self.subTest(config=name_config, trusted_home=False), patch(
				"scripts.repository_config.Path.home", return_value=self.path_root.resolve() / "trusted-home"):
				plan = buildScanPlan(self.path_root / "scan")
				self.assertBlocked(self.getProject(plan, kind_project), name_config, "repository")
			with self.subTest(config=name_config, trusted_home=True), patch(
				"scripts.repository_config.Path.home", return_value=self.path_root.resolve()):
				plan = buildScanPlan(self.path_root / "scan")
				self.assertEqual(["ready", "ready"], [item["status"]
					for item in plan["projects"] if item["kind"] in ("node", "rust")])
			(self.path_root / name_config).unlink()

	def testSymlinkedHomeComponentIsStillTrusted(self):
		self.writeYarn("physical/home/repo/web")
		self.writeCargo("physical/home/repo/rust")
		self.writeFile("physical/home/.yarnrc.yml", "yarnPath: never-execute.cjs\n")
		self.writeFile("physical/home/.env.yarn")
		self.writeFile("physical/home/.cargo/config.toml", '[alias]\naudit = "run"\n')
		(self.path_root / "alias").symlink_to(self.path_root / "physical", target_is_directory=True)
		path_home = self.path_root / "alias/home"
		self.assertNotEqual(path_home, path_home.resolve())
		with patch("scripts.repository_config.Path.home", return_value=path_home):
			plan = buildScanPlan(path_home / "repo")
		self.assertEqual(["ready", "ready"], [item["status"]
			for item in plan["projects"] if item["kind"] in ("node", "rust")])

	def testHomeResolveErrorsFallBackToUnresolvedHome(self):
		self.writeYarn("scan")
		self.writeFile(".env.yarn")
		path_home = self.path_root.resolve()
		for error in (OSError("home resolution failed"), RuntimeError("symlink loop")):
			with self.subTest(error=type(error).__name__), patch.object(
				Path, "home", return_value=path_home), patch.object(
				Path, "resolve", side_effect=error) as resolve_mock:
				self.assertIsNone(getExecutionConfigReason(path_home / "scan", path_home / "scan", "yarn"))
				resolve_mock.assert_called_once_with()

	def testAncestorWalkIncludesFilesystemRoot(self):
		with patch.object(Path, "home", return_value=Path("/trusted-home")), patch.object(
			Path, "is_symlink", return_value=False), patch.object(
			Path, "exists", autospec=True, side_effect=lambda path: path == Path("/.env.yarn")):
			reason = getExecutionConfigReason(Path("/project/app"), Path("/project"), "yarn")
		self.assertIn("/.env.yarn", reason or "")

	def testAncestorWalkContinuesAboveHome(self):
		self.writeYarn("home/scan/apps/web")
		self.writeCargo("home/scan/apps/rust")
		self.writeFile(".yarnrc.yml", "yarnPath: evil.cjs\n")
		self.writeFile(".cargo/config.toml", '[alias]\naudit = "run"\n')
		with patch("scripts.repository_config.Path.home", return_value=self.path_root.resolve() / "home"):
			plan = buildScanPlan(self.path_root / "home/scan")
		self.assertEqual(["inconclusive", "inconclusive"], [item["status"]
			for item in plan["projects"] if item["kind"] in ("node", "rust")])

	def testHomeDescendantConfigsRemainUntrusted(self):
		self.writeYarn("scan/apps/web")
		self.writeCargo("scan/apps/rust")
		self.writeFile("scan/.env.yarn")
		self.writeFile("scan/.cargo/config.toml", '[alias]\naudit = "run"\n')
		with patch("scripts.repository_config.Path.home", return_value=self.path_root.resolve()):
			plan = buildScanPlan(self.path_root / "scan")
		self.assertEqual(["inconclusive", "inconclusive"], [item["status"]
			for item in plan["projects"] if item["kind"] in ("node", "rust")])

	def testYarnEnvFileBlocksInProjectAndAncestor(self):
		self.writeYarn("apps/web")
		for directory in (".", "apps", "apps/web"):
			with self.subTest(directory=directory):
				self.writeFile(f"{directory}/.env.yarn")
				self.assertBlocked(self.project("node", "apps/web"), ".env.yarn", "repository")
				(self.path_root / directory / ".env.yarn").unlink()

	def testYarnEnvDirectoryAndSymlinksBlockWithoutReading(self):
		self.writeYarn()
		self.writeFile("env-target", "NODE_OPTIONS=--require=./never-execute.cjs\n")
		path_env = self.path_root / ".env.yarn"
		path_env.mkdir()
		self.assertBlocked(self.project("node"), ".env.yarn", "repository")
		path_env.rmdir()
		for name_target in ("env-target", "missing", "."):
			with self.subTest(target=name_target):
				path_env.symlink_to(name_target)
				self.assertBlocked(self.project("node"), ".env.yarn", "symlink")
				path_env.unlink()

	def testYarnEnvConfigMentionsBlock(self):
		self.writeYarn()
		for content_config in (
			"injectEnvironmentFiles: []\n",
			"INJECTENVIRONMENTFILES: []\n",
			"# injectEnvironmentFiles\n",
			"cacheFolder: .env\n",
			"# custom .ENV file\n",
		):
			with self.subTest(config=content_config):
				self.writeFile(".yarnrc.yml", content_config)
				self.assertBlocked(self.project("node"), ".yarnrc.yml", "yarn")
