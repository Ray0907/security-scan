"""Treat repository tool configuration as untrusted scan input."""

import re
from pathlib import Path


SUPPRESSION_FILES = {
	"gitleaks": (".gitleaksignore", ".gitleaks.toml"),
	"trivy": (".trivyignore", "trivy.yaml"),
	"semgrep": (".semgrepignore",),
}


def addSuppressionNote(item_project: dict, names_file: set[str]) -> None:
	files_config = [name for name in SUPPRESSION_FILES.get(item_project.get("tool"), ())
		if name in names_file]
	if not files_config:
		return
	note_config = ("repository suppression config present: " + ", ".join(files_config)
		+ "; results may omit findings")
	item_project["note"] = "; ".join(
		note for note in (item_project.get("note"), note_config) if note)
	item_project["evidence"] = sorted(set(item_project.get("evidence", [])) | set(files_config))


def isPlainYarnConfig(content_config: str) -> bool:
	if re.search(r"""yarnPath|plugins|injectEnvironmentFiles|\.env|[\\&*!]|<<|"""
		r"""["'][^\n]*?["'][ \t]*:""",
		content_config, re.IGNORECASE):
		return False
	lines_config = [line for line in content_config.splitlines()
		if line.strip() and not line.lstrip().startswith("#")]
	if lines_config and lines_config[0] == "---":
		lines_config = lines_config[1:]
	has_plain_key = False
	for line_config in lines_config:
		if line_config.lstrip().startswith(("{", "[", "---", "...")):
			return False
		if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*:(?:[ \t].*)?", line_config):
			has_plain_key = True
		elif not line_config[0].isspace() or not has_plain_key:
			return False
	return True


def getExecutionConfigReason(path_project: Path, path_root: Path, tool: str) -> str | None:
	configs = (".yarnrc.yml", ".yarnrc", ".env.yarn") if tool == "yarn" else (
		".cargo/config.toml", ".cargo/config", "rust-toolchain.toml", "rust-toolchain")
	try:
		path_home = Path.home().resolve()
	except (OSError, RuntimeError):
		path_home = Path.home()
	for path_directory in (path_project, *path_project.parents):
		if path_directory == path_home:
			continue
		for name_config in configs:
			path_config = path_directory / name_config
			name_relative = (path_config.relative_to(path_root).as_posix()
				if path_config.is_relative_to(path_root) else path_config.as_posix())
			if path_config.parent.is_symlink() or path_config.is_symlink():
				return (f"repository {name_relative} is symlinked; "
					f"running {tool} could execute repository code")
			if not path_config.exists():
				continue
			if name_config == ".env.yarn":
				return f"repository {name_relative} is present; running yarn could execute repository code"
			try:
				content_config = path_config.read_text(encoding="utf-8-sig")
			except (OSError, UnicodeError):
				return f"repository {name_relative} is unreadable; cannot safely run {tool}"
			content_lower = content_config.lower()
			if name_config.startswith("rust-toolchain"):
				is_unsafe = any(token in content_lower for token in ("path", "/", "\\"))
				reason_config = "contains a possible local toolchain path"
			elif tool == "cargo":
				is_unsafe = any(token in content_lower for token in ("audit", "include", "\\u"))
				reason_config = "contains audit, include or Unicode escapes that could define an audit alias"
			elif name_config == ".yarnrc":
				is_unsafe = any(token in content_lower for token in ("yarn-path", "yarnpath", "\\"))
				reason_config = "contains yarn-path, yarnPath or a backslash that could conceal them"
			else:
				is_unsafe = not isPlainYarnConfig(content_config)
				reason_config = "is not plain YAML; cannot rule out yarnPath/plugins/environment injection"
			if is_unsafe:
				return (f"repository {name_relative} {reason_config}; "
					f"running {tool} could execute repository code")
	return None


def guardRepositoryCommand(item_project: dict, path_project: Path, path_root: Path) -> None:
	command_scan = item_project.get("command")
	if not command_scan or command_scan[0] not in ("yarn", "cargo"):
		return
	reason_config = getExecutionConfigReason(path_project, path_root, command_scan[0])
	if reason_config:
		item_project.update(status="inconclusive", command=None, reason=reason_config)
