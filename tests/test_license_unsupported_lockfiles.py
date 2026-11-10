from scan_plan_base import ScanPlanTestBase
from scripts.license_records import normalizeLicenseRecord
from scripts.scan_plan import buildScanPlan


class LicensePlannerRegressionTests(ScanPlanTestBase):
	def testUnsupportedLockfilesHaveNoLicenseCommand(self):
		cases_lock = (("package.json", "pnpm-lock.yaml"), ("package.json", "yarn.lock"),
			("package.json", "bun.lock"), ("package.json", "bun.lockb"),
			("pyproject.toml", "uv.lock"), ("pyproject.toml", "poetry.lock"),
			("Pipfile", "Pipfile.lock"), ("pyproject.toml", "pylock.toml"),
			("pyproject.toml", "pylock.dev.toml"))
		for index, (manifest, lockfile) in enumerate(cases_lock):
			self.writeFile(f"case-{index}/{manifest}", "{}" if manifest == "package.json" else "")
			self.writeFile(f"case-{index}/{lockfile}")
		items_license = [item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license"]
		self.assertEqual(len(cases_lock), len(items_license))
		for index, (_, lockfile) in enumerate(cases_lock):
			with self.subTest(lockfile=lockfile):
				item = next(item for item in items_license if item["path"] == f"case-{index}")
				self.assertEqual("osv-scanner-license", item["tool"])
				self.assertEqual("inconclusive", item["status"])
				self.assertIsNone(item["command"])
				self.assertEqual("license scanning not supported for this lockfile", item["reason"])

	def testSupportedLockfilesKeepReadyLicenseCommands(self):
		cases_lock = (("package.json", "package-lock.json"),
			("package.json", "npm-shrinkwrap.json"), ("Cargo.toml", "Cargo.lock"),
			("pyproject.toml", "requirements.txt"), ("pyproject.toml", "requirements-dev.txt"))
		for index, (manifest, lockfile) in enumerate(cases_lock):
			self.writeFile(f"case-{index}/{manifest}", "{}" if manifest == "package.json" else "")
			self.writeFile(f"case-{index}/{lockfile}", "flask==3.0.0\n"
				if lockfile.startswith("requirements") else "")
		items_license = [item for item in buildScanPlan(self.path_root)["projects"]
			if item["kind"] == "license"]
		self.assertEqual(len(cases_lock), len(items_license))
		for index, (_, lockfile) in enumerate(cases_lock):
			with self.subTest(lockfile=lockfile):
				item = next(item for item in items_license if item["path"] == f"case-{index}")
				self.assertEqual("osv-scanner-license", item["tool"])
				self.assertEqual("ready", item["status"])
				self.assertEqual(["osv-scanner", "scan", "source", "--lockfile", lockfile,
					"--all-packages", "--no-resolve", "--licenses=", "--format", "json"], item["command"])

	def testNormalizerStillRejectsUnsupportedLicenseLockfiles(self):
		self.writeFile("uv.lock")
		path_stdout = self.path_root / "stdout.txt"
		self.writeFile("stderr.txt")
		meta = {"exit_code": 0, "path": ".", "command": [
			"osv-scanner", "scan", "source", "--lockfile", "uv.lock"]}
		self.assertEqual(([], "inconclusive", "license scanning not supported for this lockfile"),
			normalizeLicenseRecord("{}", meta, str(self.path_root), path_stdout))
