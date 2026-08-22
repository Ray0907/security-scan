import json
import tempfile
import unittest
from pathlib import Path

from scripts.scan_plan import buildScanPlan


class ScanPlanTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name)

	def tearDown(self):
		self.temp_dir.cleanup()

	def writeFile(self, name_file: str, content_file: str = "") -> None:
		path_file = self.path_root / name_file
		path_file.parent.mkdir(parents=True, exist_ok=True)
		path_file.write_text(content_file, encoding="utf-8")

	def getProject(self, plan_scan: dict, kind_project: str) -> dict:
		return next(
			item_project
			for item_project in plan_scan["projects"]
			if item_project["kind"] == kind_project
		)

	def testSelectsPnpmWhenPackageJsonAlsoExists(self):
		self.writeFile("package.json", '{"name":"app"}')
		self.writeFile("pnpm-lock.yaml", "lockfileVersion: '9.0'")

		plan_scan = buildScanPlan(self.path_root)
		project_node = self.getProject(plan_scan, "node")

		self.assertEqual("pnpm", project_node["tool"])
		self.assertEqual(["pnpm", "audit", "--json"], project_node["command"])

	def testMarksNpmProjectWithoutLockfileAsNotReady(self):
		self.writeFile("package.json", '{"name":"app"}')

		plan_scan = buildScanPlan(self.path_root)
		project_node = self.getProject(plan_scan, "node")

		self.assertEqual("needs-lockfile", project_node["status"])
		self.assertIsNone(project_node["command"])

	def testDiscoversNestedProjectsAndSkipsDependencyDirectories(self):
		self.writeFile("apps/web/package.json", '{"name":"web"}')
		self.writeFile("apps/web/yarn.lock")
		self.writeFile("services/api/go.mod", "module example.com/api")
		self.writeFile("node_modules/ignored/package.json", '{"name":"ignored"}')
		self.writeFile("node_modules/ignored/package-lock.json")

		plan_scan = buildScanPlan(self.path_root)
		paths_project = {item_project["path"] for item_project in plan_scan["projects"]}

		self.assertEqual({"apps/web", "services/api"}, paths_project)

	def testDoesNotDuplicateWorkspacePackagesCoveredByRootLockfile(self):
		self.writeFile("package.json", '{"name":"workspace"}')
		self.writeFile("pnpm-lock.yaml", "lockfileVersion: '9.0'")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		plan_scan = buildScanPlan(self.path_root)
		projects_node = [
			item_project for item_project in plan_scan["projects"] if item_project["kind"] == "node"
		]

		self.assertEqual(["."], [item_project["path"] for item_project in projects_node])

	def testUsesRequirementsFileInsteadOfAmbientPythonEnvironment(self):
		self.writeFile("requirements.txt", "flask==0.5")

		plan_scan = buildScanPlan(self.path_root)
		project_python = self.getProject(plan_scan, "python")

		self.assertEqual(
			["pip-audit", "--format", "json", "-r", "requirements.txt"],
			project_python["command"],
		)

	def testUsesLockedModeForPylockProject(self):
		self.writeFile("pyproject.toml", "[project]\nname = 'app'")
		self.writeFile("pylock.toml")

		plan_scan = buildScanPlan(self.path_root)
		project_python = self.getProject(plan_scan, "python")

		self.assertEqual(
			["pip-audit", "--format", "json", "--locked", "."],
			project_python["command"],
		)

	def testMarksUnlockedPyprojectAsNotReady(self):
		self.writeFile("pyproject.toml", "[project]\nname = 'app'")

		plan_scan = buildScanPlan(self.path_root)
		project_python = self.getProject(plan_scan, "python")

		self.assertEqual("needs-lockfile", project_python["status"])
		self.assertIsNone(project_python["command"])

	def testCliOutputIsSerializable(self):
		self.writeFile("Cargo.toml", "[package]\nname = 'crate'")

		plan_scan = buildScanPlan(self.path_root)

		json.dumps(plan_scan)

	def testRequiresCargoLockForRustAudit(self):
		self.writeFile("Cargo.toml", "[package]\nname = 'crate'")

		plan_scan = buildScanPlan(self.path_root)
		project_rust = self.getProject(plan_scan, "rust")

		self.assertEqual("needs-lockfile", project_rust["status"])
		self.assertIsNone(project_rust["command"])

	def testComposerAuditUsesCommittedLockfile(self):
		self.writeFile("composer.json", "{}")
		self.writeFile("composer.lock", "{}")

		plan_scan = buildScanPlan(self.path_root)
		project_php = self.getProject(plan_scan, "php")

		self.assertEqual(
			["composer", "audit", "--locked", "--format=json"],
			project_php["command"],
		)

	def testDockerfilePlansMisconfigurationScanWithoutBuildingImage(self):
		self.writeFile("Dockerfile", "FROM alpine:3.22")

		plan_scan = buildScanPlan(self.path_root)
		project_container = self.getProject(plan_scan, "container")

		self.assertEqual(
			["trivy", "fs", "--format", "json", "--scanners", "misconfig", "."],
			project_container["command"],
		)
		self.assertEqual("misconfiguration-only", project_container["coverage"])

	def testRejectsMissingScanRoot(self):
		path_missing = self.path_root / "missing"

		with self.assertRaises(FileNotFoundError):
			buildScanPlan(path_missing)


if __name__ == "__main__":
	unittest.main()
