import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.run_plan import getGitMetadata, parseArguments, runPlan


class RunPlanTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name)
		self.path_plan = self.path_root / "plan.json"
		self.path_out = self.path_root / "evidence"

	def tearDown(self):
		self.temp_dir.cleanup()

	def writePlan(self, projects: list[dict]) -> None:
		self.path_plan.write_text(
			json.dumps({"schema_version": 2, "root": str(self.path_root), "projects": projects}),
			encoding="utf-8",
		)

	def project(self, kind: str = "node", tool: str = "npm") -> dict:
		return {
			"kind": kind,
			"path": ".",
			"status": "ready",
			"tool": tool,
			"command": [tool, "audit", "--json"],
		}

	def readRun(self) -> dict:
		return json.loads((self.path_out / "run.json").read_text(encoding="utf-8"))

	@patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None})
	@patch("scripts.run_plan.getToolVersion", return_value="npm 11")
	@patch("scripts.run_plan.shutil.which", return_value="/usr/bin/npm")
	@patch("scripts.run_plan.subprocess.run")
	def testRunsAndRedactsEvidence(self, run_mock, _which, _version, _git):
		self.writePlan([self.project()])
		run_mock.return_value = subprocess.CompletedProcess(
			["npm"], 1, stdout="token=abcdefghijk\n", stderr="custom-secret",
		)

		exit_code = runPlan(
			self.path_plan,
			self.path_out,
			quiet=True,
			patterns_redact=[r"custom-secret"],
		)

		self.assertEqual(0, exit_code)
		meta_run = self.readRun()["records"][0]
		self.assertEqual("ran", meta_run["state"])
		self.assertEqual(1, meta_run["exit_code"])
		self.assertEqual(2, meta_run["redactions"])
		path_record = next(path for path in self.path_out.iterdir() if path.is_dir())
		self.assertNotIn("abcdefghijk", (path_record / "stdout.txt").read_text())
		self.assertEqual("[REDACTED]", (path_record / "stderr.txt").read_text())

	@patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None})
	@patch("scripts.run_plan.shutil.which", return_value=None)
	def testSkipsMissingTool(self, _which, _git):
		self.writePlan([self.project()])

		self.assertEqual(0, runPlan(self.path_plan, self.path_out, quiet=True))

		meta_run = self.readRun()["records"][0]
		self.assertEqual("skipped", meta_run["state"])
		self.assertEqual("tool unavailable", meta_run["reason"])

	@patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None})
	@patch("scripts.run_plan.getToolVersion", return_value=None)
	@patch("scripts.run_plan.shutil.which", return_value="/usr/bin/npm")
	@patch("scripts.run_plan.subprocess.run", side_effect=subprocess.TimeoutExpired(["npm"], 3))
	def testTimeoutFailsRun(self, _run, _which, _version, _git):
		self.writePlan([self.project()])

		self.assertEqual(1, runPlan(self.path_plan, self.path_out, timeout_seconds=3, quiet=True))
		self.assertEqual("failed", self.readRun()["records"][0]["state"])

	@patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None})
	@patch("scripts.run_plan.getToolVersion", return_value="semgrep 1")
	@patch("scripts.run_plan.shutil.which", return_value="/usr/bin/semgrep")
	@patch("scripts.run_plan.subprocess.run")
	def testAppendsSemgrepRecord(self, run_mock, _which, _version, _git):
		self.writePlan([])
		run_mock.return_value = subprocess.CompletedProcess(
			["semgrep"], 0, stdout='{"results":[]}', stderr="",
		)

		runPlan(self.path_plan, self.path_out, semgrep=True, quiet=True)

		meta_semgrep = self.readRun()["records"][0]
		self.assertEqual("code", meta_semgrep["kind"])
		self.assertEqual("semgrep", meta_semgrep["tool"])
		self.assertEqual(
			["semgrep", "scan", "--config", "p/owasp-top-ten", "--json", "--metrics=off", "."],
			meta_semgrep["command"],
		)

	@patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None})
	@patch("scripts.run_plan.shutil.which", return_value=None)
	def testOnlyAndSkipFilterKinds(self, _which, _git):
		self.writePlan([self.project(), self.project("python", "pip-audit")])

		runPlan(
			self.path_plan,
			self.path_out,
			kinds_only=["node", "python"],
			kinds_skip=["python"],
			quiet=True,
		)

		self.assertEqual(["node"], [item["kind"] for item in self.readRun()["records"]])

	def testRefusesNonEmptyOutputUnlessForced(self):
		self.writePlan([])
		self.path_out.mkdir()
		(self.path_out / "existing").write_text("keep", encoding="utf-8")

		with self.assertRaisesRegex(ValueError, "non-empty"):
			runPlan(self.path_plan, self.path_out, quiet=True)

		with patch("scripts.run_plan.getGitMetadata", return_value={"commit": None, "branch": None, "dirty": None}):
			self.assertEqual(0, runPlan(self.path_plan, self.path_out, force=True, quiet=True))

	@patch("scripts.run_plan.subprocess.run")
	def testReadsGitMetadata(self, run_mock):
		run_mock.side_effect = [
			subprocess.CompletedProcess([], 0, stdout="abc123\n", stderr=""),
			subprocess.CompletedProcess([], 0, stdout="main\n", stderr=""),
			subprocess.CompletedProcess([], 0, stdout=" M file\n", stderr=""),
		]

		self.assertEqual(
			{"commit": "abc123", "branch": "main", "dirty": True},
			getGitMetadata(self.path_root),
		)

	def testParsesAllCommandLineOptions(self):
		with patch(
			"sys.argv",
			[
				"run_plan.py", "-", "--out", "evidence", "--timeout", "5",
				"--only", "node", "--skip", "ci", "--redact-pattern", "secret",
				"--quiet", "--force", "--semgrep",
			],
		):
			args_run = parseArguments()

		self.assertEqual("-", args_run.plan)
		self.assertEqual(5, args_run.timeout)
		self.assertEqual(["node"], args_run.only)
		self.assertEqual(["ci"], args_run.skip)
		self.assertTrue(args_run.quiet)
		self.assertTrue(args_run.force)
		self.assertTrue(args_run.semgrep)


if __name__ == "__main__":
	unittest.main()
