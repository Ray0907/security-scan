import json
import tempfile
import unittest
from pathlib import Path

from scripts.scan_plan import buildScanPlan
from scripts.validate_report import loadSchema, validateDocument
from scan_plan_base import ScanPlanTestBase


class ScanPlanWorkspaceTest(ScanPlanTestBase):
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
			[
				"pip-audit", "--format", "json", "--no-deps", "--disable-pip",
				"-r", "requirements.txt",
			],
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

	def testUsesOsvScannerForUvLockAndKeepsExportNote(self):
		self.writeFile("pyproject.toml")
		self.writeFile("uv.lock")

		project_python = self.getProject(buildScanPlan(self.path_root), "python")

		self.assertEqual("ready", project_python["status"])
		self.assertEqual("osv-scanner", project_python["tool"])
		self.assertTrue(project_python["fallback"])
		self.assertIn("uv export --format requirements-txt", project_python["note"])

	def testUsesOsvScannerForPoetryLockAndKeepsExportNote(self):
		self.writeFile("pyproject.toml")
		self.writeFile("poetry.lock")

		project_python = self.getProject(buildScanPlan(self.path_root), "python")

		self.assertEqual("ready", project_python["status"])
		self.assertEqual("osv-scanner", project_python["tool"])
		self.assertIn(
			"poetry export -f requirements.txt --output requirements.txt",
			project_python["note"],
		)

	def testPythonEvidencePriorityRecordsIgnoredLockfiles(self):
		self.writeFile("pylock.toml")
		self.writeFile("requirements.txt")
		self.writeFile("uv.lock")

		project_python = self.getProject(buildScanPlan(self.path_root), "python")

		self.assertEqual(
			["pip-audit", "--format", "json", "--locked", "."],
			project_python["command"],
		)
		self.assertIn("requirements.txt", project_python["note"])
		self.assertIn("uv.lock", project_python["note"])

	def testSupportsBunLockfileAndPackageManager(self):
		self.writeFile("package.json", '{"packageManager":"bun@1.2.3"}')
		self.writeFile("bun.lock")

		project_node = self.getProject(buildScanPlan(self.path_root), "node")

		self.assertEqual("bun", project_node["tool"])
		self.assertEqual(["bun", "audit", "--json"], project_node["command"])

	def testUsesOsvScannerForUnsupportedLockfileEcosystems(self):
		files_kind = {
			"dart": "pubspec.lock",
			"elixir": "mix.lock",
			"swift": "Package.resolved",
			"dotnet": "packages.lock.json",
			"deno": "deno.lock",
		}
		for kind_project, name_file in files_kind.items():
			self.writeFile(f"{kind_project}/{name_file}")

		plan_scan = buildScanPlan(self.path_root)

		for kind_project, name_file in files_kind.items():
			with self.subTest(kind_project=kind_project):
				project_scan = self.getProject(plan_scan, kind_project)
				self.assertEqual("osv-scanner", project_scan["tool"])
				self.assertTrue(project_scan["fallback"])
				self.assertEqual(name_file, project_scan["command"][4])

	def testDetectsIacEvidenceAndKubernetesContent(self):
		self.writeFile("terraform/main.tf")
		self.writeFile("compose/docker-compose.dev.yaml")
		self.writeFile("k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
		self.writeFile("not-k8s/config.yaml", "apiVersion: v1\nmetadata: {}\n")

		projects_iac = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "iac"
		]

		self.assertEqual(
			[("compose", ["docker-compose.dev.yaml"]), ("k8s", ["deployment.yaml"]),
			 ("terraform", ["main.tf"])],
			[(item["path"], item["evidence"]) for item in projects_iac],
		)

	def testMergesIacEvidenceIntoContainerRecord(self):
		self.writeFile("service/Containerfile")
		self.writeFile("service/compose.yml")

		plan_scan = buildScanPlan(self.path_root)
		project_container = self.getProject(plan_scan, "container")

		self.assertEqual(["compose.yml"], project_container["evidence"])
		self.assertFalse(any(item["kind"] == "iac" for item in plan_scan["projects"]))

	def testAlwaysPlansOneRootSecretsScan(self):
		plan_scan = buildScanPlan(self.path_root, ["fixtures"])
		projects_secret = [
			item for item in plan_scan["projects"] if item["kind"] == "secrets"
		]

		self.assertEqual(1, len(projects_secret))
		self.assertEqual(".", projects_secret[0]["path"])
		self.assertEqual("filesystem-only", projects_secret[0]["coverage"])
		self.assertEqual("-", projects_secret[0]["command"][-1])
		self.assertIn("does not honor planner exclusions", projects_secret[0]["note"])

	def testPlansOfflineCiWorkflowAudit(self):
		self.writeFile(".github/workflows/validate.yml", "name: Validate")

		project_ci = self.getProject(buildScanPlan(self.path_root), "ci")

		self.assertEqual("zizmor", project_ci["tool"])
		self.assertEqual("offline-audits-only", project_ci["coverage"])
		self.assertEqual(".", project_ci["path"])

	def testUsesPlanSchemaVersionTwo(self):
		self.assertEqual(2, buildScanPlan(self.path_root)["schema_version"])

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

	def testContainerfilesPlanMisconfigurationScans(self):
		self.writeFile("base/Containerfile", "FROM alpine:3.22")
		self.writeFile("variant/Containerfile.dev", "FROM alpine:3.22")

		projects_container = [
			item_project
			for item_project in buildScanPlan(self.path_root)["projects"]
			if item_project["kind"] == "container"
		]

		self.assertEqual(["base", "variant"], [item["path"] for item in projects_container])

	def testPlansLicenseScansForSupportedLockfiles(self):
		self.writeFile("node/package.json", '{}')
		self.writeFile("node/package-lock.json", '{}')
		self.writeFile("python/requirements.txt", "requests==2.31.0\n")
		self.writeFile("rust/Cargo.toml", '[package]\nname = "rust"\n')
		self.writeFile("rust/Cargo.lock", "")
		licenses = [item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license"]
		self.assertEqual({"node", "python", "rust"}, {item["path"] for item in licenses})
		for item in licenses:
			self.assertEqual("osv-scanner-license", item["tool"])
			self.assertEqual("ready", item["status"])
			self.assertEqual(["osv-scanner", "scan", "source", "--lockfile"], item["command"][:4])
			self.assertEqual(["--all-packages", "--no-resolve", "--licenses=", "--format", "json"],
				item["command"][5:])
		self.assertEqual([], validateDocument(buildScanPlan(self.path_root),
			loadSchema(Path(__file__).parents[1] / "schema" / "scan-plan.schema.json")))

	def testDoesNotSendSymlinkedLockfileToLicenseService(self):
		self.writeFile("package.json", "{}")
		with tempfile.TemporaryDirectory() as external:
			lockfile = Path(external) / "package-lock.json"
			lockfile.write_text("{}")
			(self.path_root / "package-lock.json").symlink_to(lockfile)
			license_item = next(item for item in buildScanPlan(self.path_root)["projects"]
				if item["kind"] == "license")
		self.assertEqual("inconclusive", license_item["status"])
		self.assertIsNone(license_item["command"])

	def testDoesNotQueryLocalPythonReferences(self):
		self.writeFile("requirements.txt", "flask==3.0.0\n-e .\n")
		license_item = next(item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license")
		self.assertEqual("inconclusive", license_item["status"])
		self.assertIsNone(license_item["command"])
		self.assertIn("license not scanned", license_item["reason"])

	def testPlansUnsupportedAndMissingLicenseCoverage(self):
		self.writeFile("go/go.mod", "module example.org/app\n")
		self.writeFile("node/package.json", '{}')
		licenses = [item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license"]
		self.assertEqual(2, len(licenses))
		self.assertTrue(all(item["status"] != "ready" for item in licenses))
		self.assertIn("license scanning not supported for this ecosystem",
			next(item for item in licenses if item["path"] == "go")["reason"])

	def testRejectsMissingScanRoot(self):
		path_missing = self.path_root / "missing"

		with self.assertRaises(FileNotFoundError):
			buildScanPlan(path_missing)


if __name__ == "__main__":
	unittest.main()
