import re
from pathlib import Path


def getLicenseProjects(item_project: dict, path_project: Path, names_file: set[str]) -> list[dict]:
	kind_project = item_project["kind"]
	if kind_project not in {"node", "python", "rust", "go", "php", "ruby", "java",
		"dart", "elixir", "swift", "dotnet", "deno"}:
		return []
	data_base = {"kind": "license", "path": item_project["path"]}
	if kind_project not in {"node", "python", "rust"}:
		return [{**data_base, "tool": None, "command": None, "status": "inconclusive",
			"reason": "license scanning not supported for this ecosystem"}]
	if item_project["status"] != "ready":
		return [{**data_base, "tool": "osv-scanner-license", "command": None,
			"status": item_project["status"], "reason": item_project.get("reason", "missing lockfile")}]
	if kind_project == "node":
		files_lock = {
			"npm": ("npm-shrinkwrap.json",) if "npm-shrinkwrap.json" in names_file
				else ("package-lock.json",),
			"pnpm": ("pnpm-lock.yaml",), "yarn": ("yarn.lock",),
			"bun": ("bun.lock", "bun.lockb"),
		}[item_project["tool"]]
	elif kind_project == "python":
		files_lock = tuple(
			item_project["command"][index + 1]
			for index, arg in enumerate(item_project["command"][:-1]) if arg == "-r"
		) or tuple(sorted(name for name in names_file if name.startswith("pylock."))) or (
			item_project["command"][4],
		)
	else:
		files_lock = ("Cargo.lock",)
	items_license = []
	for name_lock in files_lock:
		if name_lock not in names_file:
			continue
		item_license = {**data_base, "tool": "osv-scanner-license", "status": "ready",
			"command": ["osv-scanner", "scan", "source", "--lockfile", name_lock,
				"--all-packages", "--no-resolve", "--licenses=", "--format", "json"]}
		path_lock = path_project / name_lock
		if path_lock.is_symlink():
			item_license.update(status="inconclusive", command=None,
				reason="symlinked lockfile, license not scanned")
		elif name_lock not in {"Cargo.lock", "package-lock.json", "npm-shrinkwrap.json"} and not \
				re.fullmatch(r"requirements.*\.txt", name_lock):
			item_license.update(status="inconclusive", command=None,
				reason="license scanning not supported for this lockfile")
		elif kind_project == "python" and re.fullmatch(r"requirements.*\.txt", name_lock):
			try:
				lines_lock = path_lock.read_text(encoding="utf-8").splitlines()
			except (OSError, UnicodeError):
				item_license.update(status="inconclusive", command=None,
					reason="lockfile unreadable as UTF-8, license not scanned")
			else:
				if any(line.strip() and not line.lstrip().startswith("#")
					and not re.fullmatch(r"\s*[a-zA-Z0-9_.-]+==[^\s;]+.*", line)
					for line in lines_lock):
					item_license.update(status="inconclusive", command=None,
						reason="unpinned or local dependency, license not scanned")
		items_license.append(item_license)
	return items_license
