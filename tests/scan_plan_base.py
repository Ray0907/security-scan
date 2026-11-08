import tempfile
import unittest
from pathlib import Path

from scripts.scan_plan import buildScanPlan





class ScanPlanTestBase(unittest.TestCase):
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
