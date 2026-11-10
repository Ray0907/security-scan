import json
import random
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.normalize_findings import PARSERS, normalizeEvidence, redactValue
from scripts.redaction import redactText
from scripts.run_plan import runRecord
from normalize_base import TOOLS_FIXTURE


class RedactionJsonTest(unittest.TestCase):
	def setUp(self):
		self.temp_dir = tempfile.TemporaryDirectory()
		self.addCleanup(self.temp_dir.cleanup)
		self.path_root = Path(self.temp_dir.name)

	def saveStdout(self, content, patterns=None, stderr="", tool="semgrep"):
		path_record = self.path_root / "01-test-root"
		path_record.mkdir(exist_ok=True)
		record = {
			"runnable": True, "command_scan": [tool], "path_cwd": self.path_root,
			"version_tool": None, "item_plan": {"kind": "code", "path": "."},
			"plan_index": 1, "name_tool": tool, "path_record": path_record,
		}
		with patch("scripts.run_plan.executeScan", return_value={
			"state": "ran", "reason": None, "exit_code": 0,
			"stdout": content, "stderr": stderr,
		}):
			meta = runRecord(record, 30, patterns)
		return (path_record / "stdout.txt").read_text(encoding="utf-8"), meta

	def testEscapedDelimitersDoNotHideLaterAssignments(self):
		for delimiter in (r"\,", "\\ "):
			with self.subTest(delimiter=delimiter):
				content = 'password=abcdef' + delimiter + 'token="FAKE_SECRET"'
				redacted, count = redactText(content)
				self.assertNotIn("abcdef", redacted)
				self.assertNotIn("FAKE_SECRET", redacted)
				self.assertEqual(2, count)

	def testEscapedJsonQuoteDoesNotHideLaterAssignment(self):
		content = json.dumps({'m': 'password=abcdef"token=\'FAKE_SECRET\''})
		redacted, count = redactText(content)
		self.assertNotIn("FAKE_SECRET", redacted)
		self.assertEqual(2, count)
		json.loads(redacted)

	def testTerminalBackslashIsFullyRedacted(self):
		for content, expected in (
			('password=abcde\\', 'password=[REDACTED]'),
			('password=abcdef\\\n', 'password=[REDACTED]\n'),
		):
			with self.subTest(content=content):
				self.assertEqual((expected, 1), redactText(content))

	def testJsonEscapedBackslashPairIsFullyRedacted(self):
		redacted, count = redactText(r'{"a":"token=abcdefg\\"}')
		self.assertEqual({"a": "token=[REDACTED]"}, json.loads(redacted))
		self.assertEqual(1, count)

	def testEscapedOpeningQuoteDoesNotSwallowLaterAssignment(self):
		content = r"""password=\"api_key='FAKE_SECRET'"""
		self.assertEqual(
			(r"""password=\"api_key=[REDACTED]'""", 1), redactText(content),
		)

	def testLargeKeywordValueUnderOneSecond(self):
		content = "password=" + "a" * 1_000_000
		started = time.monotonic()
		redacted = redactText(content)
		elapsed = time.monotonic() - started
		self.assertEqual(("password=[REDACTED]", 1), redacted)
		self.assertLess(elapsed, 1)

	def testSeededKeywordFuzzDoesNotLeakSecretsRemovedByMain(self):
		reference = re.compile(
			r"\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
			r"\s*([=:])\s*[\"']?[^\s\"',;]{6,}",
			re.IGNORECASE,
		)
		rng = random.Random(421904)
		alphabet = tuple("abcde\\\"',; \t\n") + ("token=", "api_key=", "password:", r'\"')
		checked = 0
		for index in range(5000):
			secret = f"FAKE_SECRET_{index:04d}"
			prefix = "".join(rng.choices(alphabet, k=rng.randrange(25)))
			keyword = rng.choice(("token", "password", "api_key", "authorization"))
			quote = rng.choice(("", '"', "'", r'\"', r"\'"))
			content = (
				rng.choice(("password=", r'password=\"'))
				+ prefix + rng.choice((r"\,", "\\ ", r'\"', "'", ";"))
				+ keyword + rng.choice(("=", ":", " = ")) + quote + secret + quote
			)
			mode = rng.randrange(3)
			if mode == 1:
				content = json.dumps(content)
			elif mode == 2:
				content = json.dumps({"m": content})
			if secret not in reference.sub(r"\1\2[REDACTED]", content):
				with self.subTest(index=index, content=content):
					self.assertNotIn(secret, redactText(content)[0])
				checked += 1
		self.assertGreater(checked, 2000)

	def testMinimumLengthBackslashSecretsAreRedacted(self):
		for content, expected in (
			(r"password=abc\de", "password=[REDACTED]"),
			(r"password=abcd\e", "password=[REDACTED]"),
			(r'password="abc\de"', 'password=[REDACTED]"'),
		):
			with self.subTest(content=content):
				saved, meta = self.saveStdout(content)
				self.assertEqual(expected, saved)
				self.assertEqual(1, meta["redactions"])
				self.assertEqual((expected, 1), redactText(content))
			with self.subTest(json_content=content):
				saved, meta = self.saveStdout(json.dumps({"message": content}))
				self.assertEqual({"message": expected}, json.loads(saved))
				self.assertEqual(1, meta["redactions"])

	def testCompactJsonCustomRedactionsAreNotRestored(self):
		content = json.dumps({
			"message": 'abcdef" suffix', "customer_secret": "FAKE_CUSTOM_VALUE",
		}, separators=(",", ":"))
		patterns = [r"abcdef.?", r'(?<="customer_secret":")[^"]+']
		saved, meta = self.saveStdout(content, patterns=patterns)
		self.assertNotIn("FAKE_CUSTOM_VALUE", saved)
		self.assertNotIn("abcdef", saved)
		self.assertEqual(redactText(content, patterns)[0], saved)
		self.assertEqual(2, meta["redactions"])

	def testBackslashSecretsAreFullyRedacted(self):
		for value in (r"abc\defghijkl", r"abcd\efghijkl", r"abcdef\ghijkl"):
			for content in (
				"password=" + value, json.dumps("password=" + value),
				json.dumps({"message": "password=" + value}),
			):
				with self.subTest(content=content):
					saved, meta = self.saveStdout(content)
					self.assertNotIn(value.split("\\")[1], saved)
					self.assertIn("password=[REDACTED]", saved)
					self.assertGreaterEqual(meta["redactions"], 1)
					if content.startswith("{"):
						self.assertEqual({"message": "password=[REDACTED]"}, json.loads(saved))
					elif content.startswith('"'):
						self.assertEqual("password=[REDACTED]", json.loads(saved))

	def testCustomPatternsKeepRawNumbersAndJsonContext(self):
		cases = (
			('{"value":1234567890123456}', [r"1234567890123456"], "1234567890123456"),
			('1234567890123456', [r"1234567890123456"], "1234567890123456"),
			(
				'{"nested":[1234567890123456]}', [r"1234567890123456"], "1234567890123456",
			),
			(
				'{"value":1234567890123456}\n\n{"ok":true}\n',
				[r"1234567890123456"], "1234567890123456",
			),
			(
				'{"customer_secret": "FAKE_CUSTOM_VALUE"}',
				[r'(?<="customer_secret": ")[^"]+'], "FAKE_CUSTOM_VALUE",
			),
			(
				'{"custom_secret": "SECRET123"}',
				[r'"custom_secret"\s*:\s*"[^"\\n]+"'], "SECRET123",
			),
		)
		for content, patterns, secret in cases:
			with self.subTest(content=content):
				saved, meta = self.saveStdout(content, patterns=patterns)
				self.assertNotIn(secret, saved)
				self.assertIn("[REDACTED]", saved)
				self.assertGreaterEqual(meta["redactions"], 1)

	def testPrivateKeyAcrossJsonStringsIsRedacted(self):
		parts = [
			"-----BEGIN RSA PRIVATE KEY-----", "QUFBQUFBQUFBQUFBQUFBQUFB",
			"-----END RSA PRIVATE KEY-----",
		]
		for content in (
			json.dumps({"pem_lines": parts}), "\n".join(map(json.dumps, parts)),
			json.dumps({"header": parts[0], "nested": {"body": parts[1], "end": parts[2]}}),
		):
			with self.subTest(content=content):
				saved, meta = self.saveStdout(content)
				self.assertNotIn(parts[1], saved)
				self.assertNotIn("PRIVATE KEY", saved)
				self.assertGreaterEqual(meta["redactions"], 1)

	def testDeepJsonKeepsRawRedactionWithoutCrashing(self):
		for depth in (500, 1100):
			with self.subTest(depth=depth):
				content = "[" * depth + '"password=abcdefgh"' + "]" * depth
				saved, meta = self.saveStdout(content)
				self.assertNotIn("abcdefgh", saved)
				self.assertEqual("[" * depth + '"password=[REDACTED]"' + "]" * depth, saved)
				self.assertGreaterEqual(meta["redactions"], 1)

	def testRawJsonFormattingIsPreserved(self):
		content = '{\n  "z": "password=abcdefgh",\n  "a": 2\n}\n'
		saved, meta = self.saveStdout(content)
		self.assertEqual(content.replace("password=abcdefgh", "password=[REDACTED]"), saved)
		self.assertEqual(1, meta["redactions"])

	def testEscapedQuoteSecretRemovedFromSavedStdout(self):
		content = json.dumps({"lines": 'password = "hunter2secretvalue"'})
		saved, meta = self.saveStdout(content)
		self.assertNotIn("hunter2secretvalue", saved)
		self.assertIn("[REDACTED]", json.loads(saved)["lines"])
		self.assertEqual(1, meta["redactions"])

	def testQuotedValueDoesNotCorruptJson(self):
		content = json.dumps({"m": 'see api_key=abcdefgh"quoted" more'})
		saved, meta = self.saveStdout(content)
		self.assertEqual({"m": 'see api_key=[REDACTED]"quoted" more'}, json.loads(saved))
		self.assertEqual(1, meta["redactions"])

	def testUnterminatedPrivateKeyHeadersUnderOneSecond(self):
		# A subprocess deadline prevents the original quadratic regex hanging the suite.
		program = """
import time
from scripts.redaction import redactText
chunk = '-----BEGIN RSA PRIVATE KEY-----' + 'A' * 224 + '\\n'
content = (chunk * (5_000_000 // len(chunk) + 1))[:5_000_000]
content += '\\n-----END EC PRIVATE KEY-----\\n'
started = time.monotonic()
assert redactText(content) == (content, 0)
elapsed = time.monotonic() - started
assert elapsed < 1, elapsed
print(elapsed)
"""
		try:
			result = subprocess.run(
				[sys.executable, "-c", program], capture_output=True, text=True,
				cwd=Path(__file__).resolve().parents[1], timeout=1, check=True,
			)
		except subprocess.TimeoutExpired:
			self.fail("5 MB of unterminated private-key headers took at least 1 second")
		self.assertLess(float(result.stdout), 1)

	def testNdjsonYarnRemainsParseableAndRedacted(self):
		content = (Path(__file__).parent / "fixtures/yarn/findings.ndjson").read_text()
		content += json.dumps({"type": "info", "data": 'password = "fake-yarn-secret"'}) + "\n"
		for trailing_newline in (True, False):
			with self.subTest(trailing_newline=trailing_newline):
				source = content if trailing_newline else content.rstrip("\n")
				saved, meta = self.saveStdout(source, tool="yarn")
				self.assertNotIn("fake-yarn-secret", saved)
				self.assertEqual(1, meta["redactions"])
				self.assertEqual(trailing_newline, saved.endswith("\n"))
				self.assertEqual(len(content.splitlines()), len(saved.splitlines()))
				self.assertEqual(PARSERS["yarn"](content), PARSERS["yarn"](saved))

	def testRealSizeFakePemStillRedacted(self):
		# Synthetic base64-shaped padding, not usable key material (~3.3 KB).
		pem = "-----BEGIN RSA PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 50
		pem += "-----END RSA PRIVATE KEY-----"
		self.assertEqual(("[REDACTED]", 1), redactText(pem))
		saved, meta = self.saveStdout(json.dumps({"nested": [pem]}))
		self.assertEqual({"nested": ["[REDACTED]"]}, json.loads(saved))
		self.assertEqual(1, meta["redactions"])

	def testPrivateKeyMatchingKeepsNestedTypesCaseAndLargeBodies(self):
		for content, expected in (
			("-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\n"
			 "fake-body\n-----END EC PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----", "[REDACTED]"),
			("-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\n"
			 "fake-body\n-----END EC PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n[REDACTED]"),
			("-----begin rsa private key-----\n" + "A" * 20000
			 + "\n-----END RSA PRIVATE KEY-----", "[REDACTED]"),
			("-----END EC PRIVATE KEY-----BEGIN RSA PRIVATE KEY-----\nfake\n"
			 "-----END RSA PRIVATE KEY-----", "-----END EC PRIVATE KEY[REDACTED]"),
			("-----BEGIN RSA PRIVATE KEY-----END RSA PRIVATE KEY-----\nfake\n"
			 "-----END RSA PRIVATE KEY-----", "[REDACTED]"),
			("-----BEGIN RİA PRIVATE KEY-----\nfake\n-----END RIA PRIVATE KEY-----", "[REDACTED]"),
		):
			with self.subTest(content=content[:80]):
				self.assertEqual((expected, 1), redactText(content))

	def testExistingTextPatternsAndCountsPreserved(self):
		values = [
			"AKIA" + "A" * 16, "ghp_" + "a" * 36,
			"github_pat_" + "a" * 80, "xoxb-" + "a" * 10,
			"sk-" + "a" * 20, "eyJ" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10,
			"https://fake-user:fake-pass@example.test", 'password = "fake-password"',
			"passwd:fake-password", "pwd=fake-password", "secret=fake-secret",
			"token=fake-token", "api_key=fake-api-key", "authorization=fake-auth",
		]
		for value in values:
			with self.subTest(value=value):
				expected, count = redactText(value)
				self.assertEqual(1, count)
				saved, meta = self.saveStdout("log: " + value + "\n")
				self.assertEqual("log: " + expected + "\n", saved)
				self.assertEqual(count, meta["redactions"])
				saved, meta = self.saveStdout(json.dumps({"value": value}))
				self.assertEqual(redactText(json.dumps({"value": value}))[0], saved)
				json.loads(saved)
				self.assertEqual(count, meta["redactions"])

	def testTextRedactionStopsBeforeEscapedQuotes(self):
		content = r'log: password = \"fake-password\" trailing'
		self.assertEqual(
			(r'log: password=[REDACTED]\" trailing', 1), redactText(content),
		)
		self.assertEqual(
			(r'api_key=[REDACTED]\"quoted\" more', 1),
			redactText(r'api_key=abcdefgh\"quoted\" more'),
		)

	def testCustomPatternsAppliedToNestedJsonAndNdjson(self):
		for content in (
			json.dumps({"items": ["fake-custom-one", {"value": "fake-custom-two"}]}),
			'{"value": "fake-custom-one"}\n\n{"value": "fake-custom-two"}\n',
		):
			with self.subTest(content=content):
				saved, meta = self.saveStdout(content, [r"fake-custom-\w+"])
				self.assertNotIn("fake-custom", saved)
				self.assertEqual(2, saved.count("[REDACTED]"))
				self.assertEqual(2, meta["redactions"])

	def testScannerParsersAcceptRawRedactedFixtures(self):
		for tool, extension in TOOLS_FIXTURE.items():
			for name in ("clean", "findings"):
				with self.subTest(tool=tool, fixture=name):
					content = (Path(__file__).parent / "fixtures" / tool / f"{name}.{extension}").read_text()
					saved, _meta = self.saveStdout(content, tool=tool)
					self.assertEqual(redactValue(PARSERS[tool](content)), PARSERS[tool](saved))

	def testJsonTypesUnicodeKeyOrderAndTrailingNewlinePreserved(self):
		data = {"z": ["雪 😀", 2**60 + 1, 1.25, True, False, None], "a": "no secret"}
		for trailing in ("", "\n"):
			with self.subTest(trailing=trailing):
				saved, meta = self.saveStdout(json.dumps(data, ensure_ascii=False) + trailing)
				parsed = json.loads(saved)
				self.assertEqual(data, parsed)
				self.assertEqual(list(data), list(parsed))
				self.assertIsInstance(parsed["z"][1], int)
				self.assertIsInstance(parsed["z"][2], float)
				self.assertEqual(bool(trailing), saved.endswith("\n"))
				self.assertEqual(0, meta["redactions"])

	def testJsonScalarAndSecretKeysRedacted(self):
		for data in ('password = "fake-scalar-secret"', {"ghp_" + "a" * 36: "ok"}):
			with self.subTest(data=data):
				saved, meta = self.saveStdout(json.dumps(data))
				self.assertIn("[REDACTED]", saved)
				self.assertEqual(1, meta["redactions"])
				json.loads(saved)

	def testInvalidNdjsonAndWhitespaceKeepTextFallback(self):
		for content in ("", " \n\t", '{"value": "token=fake-token"}\nnot json\n'):
			with self.subTest(content=content):
				saved, meta = self.saveStdout(content)
				expected, count = redactText(content)
				self.assertEqual(expected, saved)
				self.assertEqual(count, meta["redactions"])

	def testStderrStillUsesTextRedaction(self):
		stderr = r'{"m": "api_key=abcdefgh\"quoted\" more"}'
		saved, meta = self.saveStdout("{}", stderr=stderr)
		self.assertEqual({}, json.loads(saved))
		self.assertEqual(redactText(stderr)[0], (self.path_root / "01-test-root/stderr.txt").read_text())
		self.assertEqual(redactText(stderr)[1], meta["redactions"])

	def testNormalizedScannerNotFailedAfterRedaction(self):
		content = json.dumps({"results": [{
			"check_id": "fake-rule", "path": "fake.py", "start": {"line": 1},
			"extra": {"severity": "WARNING", "message": 'see api_key=abcdefgh"quoted" more',
				"lines": 'password = "hunter2secretvalue"'},
		}]})
		_saved, meta = self.saveStdout(content)
		(self.path_root / "run.json").write_text(json.dumps({
			"schema_version": 1, "plan_root": str(self.path_root), "records": [meta],
			"git": {"commit": None, "branch": None, "dirty": None},
		}))
		report = normalizeEvidence(self.path_root)
		self.assertEqual("findings", report["scanners"][0]["state"])
		self.assertNotIn("hunter2secretvalue", json.dumps(report))
		self.assertNotIn("abcdefgh", json.dumps(report))
		self.assertEqual(2, meta["redactions"])
