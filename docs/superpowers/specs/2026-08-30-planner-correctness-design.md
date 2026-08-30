# Planner Correctness Design

## Goal

Prevent silent Node.js coverage gaps and incorrect package-manager selection while keeping the dependency planner deterministic, read-only, and dependency-free. Align the skill description with its current scanner coverage by removing the unsupported secrets claim.

## Package-manager evidence

For each Node.js project, collect the lockfile candidates for pnpm, Yarn, and npm and read the optional `packageManager` field from `package.json`.

A project is `ready` only when the evidence selects exactly one package manager:

- One supported lockfile and no conflicting `packageManager` value selects that lockfile's manager.
- `package-lock.json` and `npm-shrinkwrap.json` are both npm evidence, not a cross-manager conflict.
- A supported `packageManager` value with its matching lockfile is ready only when no other manager's lockfile exists.
- A supported `packageManager` value with no lockfile remains `needs-lockfile`; with only another manager's lockfile it is `inconclusive`.
- Lockfiles for two or more different managers, an unsupported or malformed `packageManager` value, invalid `package.json`, or any `packageManager`/lockfile mismatch produces `status: "inconclusive"`, no command, and a stable reason.
- A project with no `packageManager` declaration and no supported lockfile remains `needs-lockfile`.

The planner will not guess from a fixed lockfile priority. `references/SCANNERS.md` and `SKILL.md` will document planner-level `inconclusive` records and require them to be reported as incomplete coverage.

## Workspace coverage

A parent lockfile covers a nested Node.js package only when the nested package is explicitly selected by a workspace declaration owned by that parent project.

Supported declarations:

- `package.json#workspaces` as an array of strings.
- `package.json#workspaces.packages` as an array of strings.
- A top-level block-style `packages:` list in `pnpm-workspace.yaml`, with string entries and exclusions prefixed by `!`.

Patterns support relative path segments plus `*`, `?`, character classes, and `**`. Absolute paths, parent traversal, YAML anchors/tags, inline YAML collections, non-string entries, and other ambiguous forms invalidate the whole declaration for coverage purposes. Exclusions are applied after all inclusions regardless of source order. If any declaration or entry cannot be parsed safely—including an exclusion—the planner fails closed and suppresses no nested project from that declaration.

Workspace patterns are resolved relative to the declaring project and cannot escape it. A nested package is suppressed only when it resolves to an included workspace directory, is not excluded, and the parent Node.js project is `ready`. An inconclusive parent never suppresses children. Malformed, unsupported, or uncertain declarations do not suppress the nested project. This favors visible `needs-lockfile` coverage over silent omission.

The implementation remains in the Python standard library. It does not invoke package-manager CLIs or add a YAML dependency.

## Skill description

Remove `secrets` from the `SKILL.md` description because the current workflow has no dedicated secret scanner. Keep the reporting redaction requirements because scanner output and snippets may still expose credentials.

## Tests

Add regression tests before implementation for:

1. An unrelated nested Node.js project beneath a locked root remains visible.
2. A declared workspace package is covered by the ready root project.
3. A `packageManager`/lockfile mismatch is inconclusive, with no command and a stable reason.
4. Lockfiles for different managers are inconclusive, while both npm lockfile names are same-manager evidence.
5. A matching `packageManager` and lockfile remains ready; a matching manager without a lockfile remains `needs-lockfile`.
6. Unsupported or malformed `packageManager` values and invalid `package.json` are inconclusive.
7. A pnpm workspace include covers a member while an exclusion keeps a package visible.
8. Malformed or unsupported workspace declarations suppress no children.
9. An inconclusive parent suppresses no children.

Run the full unit suite, Python compilation, Markdown lint where available, and Agent Skills validation after implementation.
