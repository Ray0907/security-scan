import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.scan_plan import buildScanPlan, parseArguments
from scripts.validate_report import loadSchema, validateDocument
from scan_plan_base import ScanPlanTestBase


class ScanPlanTest(ScanPlanTestBase):
	def testPlannerOutputMatchesPublishedSchema(self):
		plan_scan = buildScanPlan(self.path_root)
		schema = loadSchema(Path(__file__).parents[1] / "schema" / "scan-plan.schema.json")

		self.assertEqual([], validateDocument(plan_scan, schema))

	def testSelectsPnpmWhenPackageJsonAlsoExists(self):
		self.writeFile("package.json", '{"name":"app"}')
		self.writeFile("pnpm-lock.yaml", "lockfileVersion: '9.0'")

		plan_scan = buildScanPlan(self.path_root)
		project_node = self.getProject(plan_scan, "node")

		self.assertEqual("pnpm", project_node["tool"])
		self.assertEqual(["pnpm", "audit", "--json"], project_node["command"])

	def testMarksPackageManagerLockfileMismatchAsInconclusive(self):
		self.writeFile("package.json", '{"packageManager":"npm@11.0.0"}')
		self.writeFile("pnpm-lock.yaml")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"packageManager does not match available lockfile",
			project_node["reason"],
		)

	def testMarksDifferentManagerLockfilesAsInconclusive(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("package-lock.json")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"lockfiles for multiple package managers are present",
			project_node["reason"],
		)

	def testTreatsNpmLockfilesAsSameManagerEvidence(self):
		self.writeFile("package.json", "{}")
		self.writeFile("package-lock.json")
		self.writeFile("npm-shrinkwrap.json")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("ready", project_node["status"])
		self.assertEqual("npm", project_node["tool"])
		self.assertEqual(["npm", "audit", "--json"], project_node["command"])
		licenses = [item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license"]
		self.assertEqual(["npm-shrinkwrap.json"], [item["command"][4] for item in licenses])

	def testAcceptsMatchingPackageManagerDeclaration(self):
		self.writeFile("package.json", '{"packageManager":"yarn@4.1.0+sha512.abc"}')
		self.writeFile("yarn.lock")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("ready", project_node["status"])
		self.assertEqual("yarn", project_node["tool"])
		self.assertEqual(
			["yarn", "npm", "audit", "--json", "--all", "--recursive"],
			project_node["command"],
		)

	def testMarksMatchingPackageManagerWithoutLockfileAsNotReady(self):
		self.writeFile("package.json", '{"packageManager":"pnpm@10.0.0"}')

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("needs-lockfile", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])

	def testMarksUnsupportedPackageManagerAsInconclusive(self):
		self.writeFile("package.json", '{"packageManager":"deno@1.2.3"}')

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"packageManager declaration is unsupported or malformed",
			project_node["reason"],
		)

	def testMarksMalformedPackageManagerAsInconclusive(self):
		self.writeFile("package.json", '{"packageManager":7}')

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"packageManager declaration is unsupported or malformed",
			project_node["reason"],
		)

	def testMarksYarnTagAsMalformedPackageManager(self):
		self.writeFile("package.json", '{"packageManager":"yarn@berry"}')
		self.writeFile("yarn.lock")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"packageManager declaration is unsupported or malformed",
			project_node["reason"],
		)

	def testMarksNpmTagAsMalformedPackageManager(self):
		self.writeFile("package.json", '{"packageManager":"npm@latest"}')
		self.writeFile("package-lock.json")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual(
			"packageManager declaration is unsupported or malformed",
			project_node["reason"],
		)

	def testMarksInvalidPackageJsonAsInconclusive(self):
		self.writeFile("package.json", "{")
		self.writeFile("package-lock.json")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual("package.json is invalid", project_node["reason"])

	def testMarksSymlinkedPackageJsonAsInconclusive(self):
		self.writeFile("package-lock.json")
		with tempfile.TemporaryDirectory() as name_external:
			path_external = Path(name_external) / "package.json"
			path_external.write_text("{}", encoding="utf-8")
			(self.path_root / "package.json").symlink_to(path_external)

			project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual("package.json is invalid", project_node["reason"])

	def testMarksNonStandardJsonConstantAsInvalid(self):
		self.writeFile("package.json", '{"name":NaN}')
		self.writeFile("package-lock.json")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual("package.json is invalid", project_node["reason"])

	def testMarksExcessivelyNestedPackageJsonAsInvalid(self):
		self.writeFile("package.json", '{"nested":' * 2000 + "0" + "}" * 2000)
		self.writeFile("package-lock.json")

		with patch("scripts.scan_plan.json.loads", side_effect=RecursionError):
			project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("inconclusive", project_node["status"])
		self.assertIsNone(project_node["tool"])
		self.assertIsNone(project_node["command"])
		self.assertEqual("package.json is invalid", project_node["reason"])

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

		self.assertEqual({".", "apps/web", "services/api"}, paths_project)

	def testExcludesRequestedPathsAndKeepsSibling(self):
		self.writeFile("apps/ignored/package.json", "{}")
		self.writeFile("apps/ignored/package-lock.json")
		self.writeFile("apps/kept/package.json", "{}")
		self.writeFile("apps/kept/package-lock.json")
		self.writeFile("generated/deep/ignored/go.mod", "module example.com/ignored")

		plan_scan = buildScanPlan(
			self.path_root,
			["generated/deep", "apps/ignored"],
		)

		self.assertEqual(["apps/ignored", "generated/deep"], plan_scan["excluded"])
		self.assertEqual(
			[".", "apps/kept", "apps/kept"],
			[item["path"] for item in plan_scan["projects"]],
		)

	def testReportsEmptyExclusionsByDefault(self):
		self.assertEqual([], buildScanPlan(self.path_root)["excluded"])

	def testCliAcceptsRepeatedExclusions(self):
		with patch(
			"sys.argv",
			["scan_plan.py", ".", "--exclude", "vendor", "--exclude", "fixtures"],
		):
			args_scan = parseArguments()

		self.assertEqual(["vendor", "fixtures"], args_scan.exclude)

	def testKeepsNestedProjectNotDeclaredAsWorkspace(self):
		self.writeFile("package.json", '{"name":"root"}')
		self.writeFile("package-lock.json", "{}")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testPackageJsonWorkspaceArrayCoversDeclaredMember(self):
		self.writeFile("package.json", '{"workspaces":["apps/*"]}')
		self.writeFile("package-lock.json", "{}")
		self.writeFile("apps/web/package.json", '{"name":"web"}')
		self.writeFile("examples/demo/package.json", '{"name":"demo"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "examples/demo"], [item["path"] for item in projects_node])

	def testWorkspaceGlobDoesNotCoverDeeperUndeclaredProject(self):
		self.writeFile("package.json", '{"workspaces":["*"]}')
		self.writeFile("package-lock.json")
		self.writeFile("app/package.json", '{"name":"app"}')
		self.writeFile("nested/app/package.json", '{"name":"nested-app"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "nested/app"], [item["path"] for item in projects_node])

	def testPackageJsonWorkspaceObjectCoversDeclaredMember(self):
		self.writeFile(
			"package.json",
			'{"workspaces":{"packages":["packages/*"]}}',
		)
		self.writeFile("yarn.lock")
		self.writeFile("packages/ui/package.json", '{"name":"ui"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual(["."], [item["path"] for item in projects_node])


if __name__ == "__main__":
	unittest.main()
