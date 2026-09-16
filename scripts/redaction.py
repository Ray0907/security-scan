"""Redact common secret formats before evidence is persisted."""

import re

PATTERNS_REDACT = [
	(
		re.compile(
			r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END \1-----",
			re.IGNORECASE | re.DOTALL,
		),
		"[REDACTED]",
	),
	(re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED]"),
	(re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}", re.IGNORECASE), "[REDACTED]"),
	(re.compile(r"github_pat_[A-Za-z0-9_]{80,}", re.IGNORECASE), "[REDACTED]"),
	(re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}", re.IGNORECASE), "[REDACTED]"),
	(re.compile(r"sk-[A-Za-z0-9_-]{20,}", re.IGNORECASE), "[REDACTED]"),
	(
		re.compile(
			r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
		),
		"[REDACTED]",
	),
	(re.compile(r"://[^/\s:]+:[^@\s]+@"), "://[REDACTED]@"),
	(
		re.compile(
			r"\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
			r"\s*([=:])\s*[\"']?[^\s\"',;]{6,}",
			re.IGNORECASE,
		),
		r"\1\2[REDACTED]",
	),
]


def redactText(text_value: str, patterns_custom: list[str] | None = None) -> tuple[str, int]:
	count_redaction = 0
	for pattern_redact, replacement_redact in PATTERNS_REDACT:
		text_value, count_pattern = pattern_redact.subn(replacement_redact, text_value)
		count_redaction += count_pattern
	for value_pattern in patterns_custom or ():
		text_value, count_pattern = re.subn(value_pattern, "[REDACTED]", text_value)
		count_redaction += count_pattern
	return text_value, count_redaction
