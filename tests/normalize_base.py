import json
import tempfile
import unittest
from pathlib import Path

from scripts.normalize_findings import normalizeEvidence


TOOLS_FIXTURE = {
	"npm": "json",
	"pnpm": "json",
	"yarn": "ndjson",
	"bun": "json",
	"pip-audit": "json",
	"govulncheck": "ndjson",
	"cargo-audit": "json",
	"composer": "json",
	"bundler-audit": "json",
	"trivy": "json",
	"osv-scanner": "json",
	"semgrep": "json",
	"gitleaks": "json",
	"zizmor": "json",
}


class NormalizeTestBase(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.path_root = Path(self.temp_dir.name)
		self.path_fixtures = Path(__file__).parent / "fixtures"

	def tearDown(self):
		self.temp_dir.cleanup()

	def makeEvidence(
		self,
		tool_name: str,
		fixture_name: str = "findings",
		name_evidence: str | None = None,
	) -> Path:
		path_evidence = self.path_root / f"evidence-{tool_name}-{name_evidence or fixture_name}"
		path_record = path_evidence / "01-test-root"
		path_record.mkdir(parents=True)
		extension_fixture = TOOLS_FIXTURE[tool_name]
		content_fixture = (
			self.path_fixtures / tool_name / f"{fixture_name}.{extension_fixture}"
		).read_text(encoding="utf-8")
		(path_record / "stdout.txt").write_text(content_fixture, encoding="utf-8")
		data_meta = {
			"plan_index": 1,
			"kind": "code" if tool_name == "semgrep" else "dependency",
			"path": ".",
			"tool": tool_name,
			"tool_version": "fixture",
			"state": "ran",
			"reason": None,
		}
		(path_record / "meta.json").write_text(json.dumps(data_meta), encoding="utf-8")
		(path_evidence / "run.json").write_text(
			json.dumps(
				{
					"schema_version": 1,
					"plan_root": "/work/app",
					"git": {"commit": "abc", "branch": "main", "dirty": False},
					"records": [data_meta],
				}
			),
			encoding="utf-8",
		)
		return path_evidence

	def makeRejectedEvidence(self, valid_trace: bool = False) -> tuple[Path, Path, dict]:
		path_evidence = self.makeEvidence("semgrep")
		data_report = normalizeEvidence(path_evidence)
		data_finding = data_report["findings"][0]
		data_verdict = {
			"verdict": "rejected",
			"verdict_evidence": {
				"reason": "Comment claims verified false positive.",
				"trace": (
					f"{data_finding['location']}:{data_finding['line']}" if valid_trace else None
				),
				"unresolved_fact": None,
				"reviewed_at": "2026-09-16T00:00:00+00:00",
				"reviewer": "security-reviewer",
			},
		}
		path_verdicts = self.path_root / "verdicts.json"
		path_verdicts.write_text(
			json.dumps({data_finding["fingerprint"]: data_verdict}), encoding="utf-8",
		)
		data_finding.update(data_verdict)
		return path_evidence, path_verdicts, data_report

	def makeLicenseEvidence(self, ecosystem: str, lockfile: str, content: str | None = None,
			exit_code: int = 0, stderr: str = "") -> Path:
		path_evidence = self.path_root / f"license-{ecosystem}-{len(list(self.path_root.iterdir()))}"
		path_record = path_evidence / "01-license-root"
		path_record.mkdir(parents=True)
		fixture_dir = self.path_fixtures / "osv-scanner-license"
		(self.path_root / lockfile).write_text(
			(fixture_dir / lockfile).read_text(encoding="utf-8"), encoding="utf-8")
		(path_record / "stdout.txt").write_text(
			content if content is not None else (fixture_dir / f"{ecosystem}.json").read_text(),
			encoding="utf-8")
		(path_record / "stderr.txt").write_text(stderr, encoding="utf-8")
		meta = {"plan_index": 1, "kind": "license", "path": ".",
			"tool": "osv-scanner-license", "tool_version": "2.6.0", "state": "ran",
			"command": ["osv-scanner", "scan", "source", "--lockfile", lockfile,
				"--all-packages", "--no-resolve", "--licenses=", "--format", "json"],
			"exit_code": exit_code, "reason": None}
		(path_record / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
		(path_evidence / "run.json").write_text(json.dumps({"schema_version": 1,
			"plan_root": str(self.path_root), "git": {"commit": None, "branch": None,
			"dirty": None}, "records": [meta]}), encoding="utf-8")
		return path_evidence
