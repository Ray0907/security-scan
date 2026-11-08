import re
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


def getRelativePath(path_project: Path, path_root: Path) -> str:
	path_relative = path_project.relative_to(path_root)
	return "." if not path_relative.parts else path_relative.as_posix()


def rejectJsonConstant(value_constant: str) -> None:
	raise ValueError(f"non-standard JSON constant: {value_constant}")


def isSafeWorkspacePattern(pattern_workspace: str) -> bool:
	if not pattern_workspace or pattern_workspace != pattern_workspace.strip(" \t"):
		return False
	pattern_path = pattern_workspace[1:] if pattern_workspace.startswith("!") else pattern_workspace
	if not pattern_path or "\\" in pattern_path or pattern_path.startswith("/"):
		return False
	if re.match(r"^[A-Za-z]:", pattern_path):
		return False
	parts_path = pattern_path.split("/")
	return all(part_path not in ("", ".", "..") for part_path in parts_path)


def matchesWorkspacePattern(path_workspace: PurePosixPath, pattern_workspace: str) -> bool:
	parts_path = path_workspace.parts
	parts_pattern = tuple(pattern_workspace.split("/"))
	states_match = [(0, 0)]
	states_seen = set()
	while states_match:
		index_path, index_pattern = states_match.pop()
		state_match = (index_path, index_pattern)
		if state_match in states_seen:
			continue
		states_seen.add(state_match)
		if index_pattern == len(parts_pattern):
			if index_path == len(parts_path):
				return True
			continue
		if parts_pattern[index_pattern] == "**":
			states_match.append((index_path, index_pattern + 1))
			if index_path < len(parts_path):
				states_match.append((index_path + 1, index_pattern))
		elif index_path < len(parts_path) and fnmatchcase(
			parts_path[index_path], parts_pattern[index_pattern]
		):
			states_match.append((index_path + 1, index_pattern + 1))
	return False


def getPackageWorkspacePatterns(data_package: dict) -> tuple[str, ...] | None:
	if "workspaces" not in data_package:
		return ()
	value_workspaces = data_package["workspaces"]
	if isinstance(value_workspaces, dict):
		value_workspaces = value_workspaces.get("packages")
	if not isinstance(value_workspaces, list):
		return None
	if not all(
		isinstance(pattern_workspace, str) and isSafeWorkspacePattern(pattern_workspace)
		for pattern_workspace in value_workspaces
	):
		return None
	return tuple(value_workspaces)


def isYamlNonStringPlainScalar(value_scalar: str) -> bool:
	if value_scalar.lower() in {
		"~",
		"null",
		"true",
		"false",
		"yes",
		"no",
		"on",
		"off",
		"y",
		"n",
		".nan",
		".inf",
		"+.inf",
		"-.inf",
	}:
		return True
	if re.fullmatch(
		r"[-+]?(?:"
		r"0[bB][01_]+|"
		r"0[oO][0-7_]+|"
		r"0[xX][0-9a-fA-F_]+|"
		r"[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|"
		r"(?:(?:[0-9][0-9_]*)?\.[0-9_]+|[0-9][0-9_]*\.)"
		r"(?:[eE][-+]?[0-9]+)?|"
		r"[0-9][0-9_]*(?:[eE][-+]?[0-9]+)?"
		r")",
		value_scalar,
	):
		return True
	return (
		re.fullmatch(
			r"[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}"
			r"(?:"
			r"(?:[Tt]|[ \t]+)"
			r"[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
			r"(?:\.[0-9]+)?"
			r"(?:[ \t]*(?:[Zz]|[-+][0-9]{1,2}(?::[0-9]{2})?))?"
			r")?",
			value_scalar,
		)
		is not None
	)


def parsePnpmWorkspaceScalar(value_scalar: str) -> str | None:
	if value_scalar.startswith("'"):
		match_scalar = re.fullmatch(
			r"'((?:[^']|'')*)'(?:[ \t]+(?:#.*)?)?",
			value_scalar,
		)
		if match_scalar is None:
			return None
		return match_scalar.group(1).replace("''", "'")
	if value_scalar.startswith('"'):
		return None

	value_unquoted = re.split(r"[ \t]+#", value_scalar, maxsplit=1)[0].rstrip(" \t")
	if not value_unquoted or value_unquoted[0] in "-?:,[]{}#&*!|>'\"%@`":
		return None
	if re.search(r":(?:[ \t]|$)", value_unquoted):
		return None
	if isYamlNonStringPlainScalar(value_unquoted):
		return None
	return value_unquoted


def hasForbiddenYamlSourceCharacter(content_workspace: str) -> bool:
	for character_workspace in content_workspace:
		value_character = ord(character_workspace)
		if value_character in (0x09, 0x0A, 0x0D, 0x85):
			continue
		if 0x20 <= value_character <= 0x7E:
			continue
		if 0xA0 <= value_character <= 0xD7FF:
			continue
		if 0xE000 <= value_character <= 0xFFFD:
			continue
		if 0x10000 <= value_character <= 0x10FFFF:
			continue
		return True
	return False


def getPnpmWorkspacePatterns(path_project: Path) -> tuple[str, ...] | None:
	path_workspace = path_project / "pnpm-workspace.yaml"
	if path_workspace.is_symlink():
		return None
	if not path_workspace.exists():
		return ()
	try:
		content_workspace = path_workspace.read_text(encoding="utf-8")
	except (OSError, UnicodeError):
		return None
	if hasForbiddenYamlSourceCharacter(content_workspace):
		return None
	if any(
		character_workspace.isspace() and character_workspace not in " \t\r\n"
		for character_workspace in content_workspace
	):
		return None
	lines_workspace = [
		line_workspace[:-1] if line_workspace.endswith("\r") else line_workspace
		for line_workspace in content_workspace.split("\n")
	]

	indexes_packages = []
	for index_line, line_workspace in enumerate(lines_workspace):
		if line_workspace.startswith((" ", "\t")):
			continue
		if re.fullmatch(r"packages:(?:[ \t]+(?:#.*)?)?", line_workspace):
			indexes_packages.append(index_line)
		elif re.match(r"packages[ \t]*:", line_workspace):
			return None
	if not indexes_packages:
		return ()
	if len(indexes_packages) != 1:
		return None
	if any(
		line_workspace.strip(" \t")
		and not line_workspace.lstrip(" \t").startswith("#")
		for line_workspace in lines_workspace[: indexes_packages[0]]
	):
		return None

	patterns_workspace = []
	indent_list: int | None = None
	for line_workspace in lines_workspace[indexes_packages[0] + 1 :]:
		if not line_workspace.strip(" \t") or line_workspace.lstrip(" \t").startswith("#"):
			continue
		if not line_workspace.startswith((" ", "\t")):
			return None
		if "\t" in line_workspace:
			return None
		match_item = re.fullmatch(r"( +)-[ \t]+(.+?)[ \t]*", line_workspace)
		if match_item is None:
			return None
		indent_item = len(match_item.group(1))
		if indent_list is None:
			indent_list = indent_item
		elif indent_item != indent_list:
			return None
		pattern_workspace = parsePnpmWorkspaceScalar(match_item.group(2))
		if pattern_workspace is None or not isSafeWorkspacePattern(pattern_workspace):
			return None
		patterns_workspace.append(pattern_workspace)
	return tuple(patterns_workspace)
