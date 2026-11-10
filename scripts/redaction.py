"""Redact common secret formats before evidence is persisted."""

import re

PATTERN_PRIVATE_KEY = re.compile(
	r"(?=(-----(BEGIN|END) ([A-Z ]*PRIVATE KEY)-----))", re.IGNORECASE,
)

PATTERNS_REDACT = [
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
			r"\s*([=:])\s*(?:\\?[\"'])?(?=[^\s\"',;]{6})"
			r"(?:(?!\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)"
			r"\s*[=:]\s*(?:\\?[\"'])?[^\s\"',;]{6})"
			r"(?:\\\\|[^\s\"',;\\]|\\(?![\"'])))+",
			re.IGNORECASE,
		),
		r"\1\2[REDACTED]",
	),
]


def redactPrivateKeys(text_value: str) -> tuple[str, int]:
	# Reverse indexing finds each header's nearest matching footer without rescanning bodies.
	markers_key = list(PATTERN_PRIVATE_KEY.finditer(text_value))
	index_end = len(markers_key) - 1
	ends_key = {}
	spans_key = []
	for match_key in reversed(markers_key):
		if match_key.group(2).lower() == "end":
			continue
		while index_end >= 0 and markers_key[index_end].start() >= match_key.end(1):
			match_end = markers_key[index_end]
			if match_end.group(2).lower() == "end":
				type_key = match_end.group(3).lower().replace("i\u0307", "i")
				ends_key[type_key] = match_end.end(1)
			index_end -= 1
		# Python's case-insensitive backreferences equate dotted I with ASCII i.
		type_key = match_key.group(3).lower().replace("i\u0307", "i")
		if type_key in ends_key:
			spans_key.append((match_key.start(), ends_key[type_key]))
	parts = []
	offset = 0
	count_redaction = 0
	for start, end in reversed(spans_key):
		if start >= offset:
			parts.extend((text_value[offset:start], "[REDACTED]"))
			offset = end
			count_redaction += 1
	parts.append(text_value[offset:])
	return "".join(parts), count_redaction


def redactText(text_value: str, patterns_custom: list[str] | None = None) -> tuple[str, int]:
	text_value, count_redaction = redactPrivateKeys(text_value)
	for pattern_redact, replacement_redact in PATTERNS_REDACT:
		text_value, count_pattern = pattern_redact.subn(replacement_redact, text_value)
		count_redaction += count_pattern
	for value_pattern in patterns_custom or ():
		text_value, count_pattern = re.subn(value_pattern, "[REDACTED]", text_value)
		count_redaction += count_pattern
	return text_value, count_redaction
