import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
		self.writeFile("package.json", '{"packageManager":"bun@1.2.3"}')

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

		self.assertEqual({"apps/web", "services/api"}, paths_project)

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

	def testPnpmWorkspaceIncludesMembersAndAppliesExclusionsLast(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile(
			"pnpm-workspace.yaml",
			"packages:\n  - '!apps/private'\n  - 'apps/*'\n",
		)
		self.writeFile("apps/web/package.json", '{"name":"web"}')
		self.writeFile("apps/private/package.json", '{"name":"private"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/private"], [item["path"] for item in projects_node])

	def testMalformedPackageJsonWorkspacesSuppressNoChildren(self):
		self.writeFile("package.json", '{"workspaces":["apps/*",7]}')
		self.writeFile("package-lock.json")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testUnsafePackageJsonWorkspacePathSuppressesNoChildren(self):
		self.writeFile("package.json", '{"workspaces":["apps/*","../shared/*"]}')
		self.writeFile("package-lock.json")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testUnsupportedPnpmWorkspaceYamlSuppressesNoChildren(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("pnpm-workspace.yaml", "packages: [apps/*]\n")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def assertMalformedPnpmWorkspaceSuppressesNoChildren(self, content_workspace: str) -> None:
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("pnpm-workspace.yaml", content_workspace)
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testPnpmDoubleQuotedEscapeSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			'packages:\n  - "apps\\/*"\n',
		)

	def testPnpmUnicodeWhitespaceSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			"packages:\n  - apps/*\n  - invalid\u00a0\n",
		)

	def testSymlinkedPnpmWorkspaceSuppressesNoChildren(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("apps/web/package.json", '{"name":"web"}')
		with tempfile.TemporaryDirectory() as name_external:
			path_external = Path(name_external) / "pnpm-workspace.yaml"
			path_external.write_text("packages:\n  - apps/*\n", encoding="utf-8")
			(self.path_root / "pnpm-workspace.yaml").symlink_to(path_external)

			projects_node = [
				item_project
				for item_project in buildScanPlan(self.path_root)["projects"]
				if item_project["kind"] == "node"
			]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testPnpmForbiddenControlCharacterSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			"packages:\n  - apps/*\n  - invalid\x00pattern\n",
		)

	def testPnpmHeaderCommentWithoutWhitespaceSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			"packages:#comment\n  - apps/*\n",
		)

	def testPnpmDoubleQuotedCommentWithoutWhitespaceSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			'packages:\n  - "apps/*"#comment\n',
		)

	def testPnpmSingleQuotedCommentWithoutWhitespaceSuppressesNoChildren(self):
		self.assertMalformedPnpmWorkspaceSuppressesNoChildren(
			"packages:\n  - 'apps/*'#comment\n",
		)

	def assertPnpmNonStringScalarSuppressesNoChildren(self, scalar_workspace: str) -> None:
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile(
			"pnpm-workspace.yaml",
			f"packages:\n  - apps/*\n  - {scalar_workspace}\n",
		)
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps/web"], [item["path"] for item in projects_node])

	def testPnpmHexadecimalScalarSuppressesNoChildren(self):
		self.assertPnpmNonStringScalarSuppressesNoChildren("0x10")

	def testPnpmExponentialScalarSuppressesNoChildren(self):
		self.assertPnpmNonStringScalarSuppressesNoChildren("1e3")

	def testPnpmNonFiniteScalarSuppressesNoChildren(self):
		self.assertPnpmNonStringScalarSuppressesNoChildren(".nan")

	def testPnpmTimestampScalarSuppressesNoChildren(self):
		value_timestamp = "2026-08-30T12:34:56Z"
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("pnpm-workspace.yaml", f"packages:\n  - {value_timestamp}\n")
		self.writeFile(f"{value_timestamp}/package.json", '{"name":"timestamp"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", value_timestamp], [item["path"] for item in projects_node])

	def testPnpmMappingEntrySuppressesNoChildren(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("pnpm-workspace.yaml", "packages:\n  - apps:\n")
		self.writeFile("apps:/package.json", '{"name":"mapping"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual([".", "apps:"], [item["path"] for item in projects_node])

	def testPnpmCommentOnlyListItemSuppressesNoChildren(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("pnpm-workspace.yaml", "packages:\n  - #member\n")
		self.writeFile("#member/package.json", '{"name":"member"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual(["#member", "."], [item["path"] for item in projects_node])

	def testMisindentedPnpmWorkspaceListSuppressesNoChildren(self):
		self.writeFile("package.json", "{}")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile(
			"pnpm-workspace.yaml",
			"packages:\n  - apps/*\n    - examples/*\n",
		)
		self.writeFile("apps/web/package.json", '{"name":"web"}')
		self.writeFile("examples/demo/package.json", '{"name":"demo"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual(
			[".", "apps/web", "examples/demo"],
			[item["path"] for item in projects_node],
		)

	def testInconclusiveParentSuppressesNoWorkspaceChildren(self):
		self.writeFile("package.json", '{"workspaces":["apps/*"]}')
		self.writeFile("package-lock.json")
		self.writeFile("pnpm-lock.yaml")
		self.writeFile("apps/web/package.json", '{"name":"web"}')

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual(
			[(".", "inconclusive"), ("apps/web", "needs-lockfile")],
			[(item["path"], item["status"]) for item in projects_node],
		)

	def testKeepsNestedInconclusiveNodeProjectVisible(self):
		self.writeFile("package.json", '{"name":"workspace","workspaces":["apps/*"]}')
		self.writeFile("package-lock.json")
		self.writeFile("apps/web/package.json", '{"packageManager":"npm@11.0.0"}')
		self.writeFile("apps/web/pnpm-lock.yaml")

		projects_node = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "node"
		]

		self.assertEqual(
			[(".", "ready"), ("apps/web", "inconclusive")],
			[
				(item_project["path"], item_project["status"])
				for item_project in projects_node
			],
		)

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
