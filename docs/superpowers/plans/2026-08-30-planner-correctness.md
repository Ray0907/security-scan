# Planner Correctness Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent silent Node.js monorepo omissions and package-manager guessing, and remove the unsupported secrets trigger.

**Architecture:** Keep planning deterministic and dependency-free. `scan_plan.py` will classify Node package-manager evidence before creating commands, then resolve only safely parsed workspace declarations to decide whether a ready parent lockfile covers an unlocked child package. Ambiguous evidence fails closed as `inconclusive`.

**Tech Stack:** Python 3.10+ standard library, `unittest`, Markdown, Agent Skills validator.

---

## File map

- Modify `scripts/scan_plan.py`: classify Node lockfile/packageManager evidence and resolve workspace membership.
- Modify `tests/test_scan_plan.py`: regression coverage for conflicts and workspace behavior.
- Modify `SKILL.md`: remove unsupported secrets trigger and handle planner-inconclusive records.
- Modify `references/SCANNERS.md`: document the planner's `inconclusive` state and conflict behavior.

## Chunk 1: Node package-manager evidence

### Task 1: Reject ambiguous package-manager evidence

**Files:**

- Modify: `tests/test_scan_plan.py`
- Modify: `scripts/scan_plan.py`

- [ ] **Step 1: Write failing tests**

Add tests asserting:

```python
def testMarksPackageManagerLockfileMismatchAsInconclusive(self):
    self.writeFile("package.json", '{"packageManager":"npm@11.0.0"}')
    self.writeFile("pnpm-lock.yaml")
    project = self.getProject(buildScanPlan(self.path_root), "node")
    self.assertEqual("inconclusive", project["status"])
    self.assertIsNone(project["command"])
    self.assertEqual("packageManager does not match available lockfile", project["reason"])


def testMarksDifferentManagerLockfilesAsInconclusive(self):
    self.writeFile("package.json", '{}')
    self.writeFile("pnpm-lock.yaml")
    self.writeFile("package-lock.json")
    project = self.getProject(buildScanPlan(self.path_root), "node")
    self.assertEqual("inconclusive", project["status"])
    self.assertIsNone(project["command"])


def testTreatsNpmLockfilesAsSameManagerEvidence(self):
    self.writeFile("package.json", '{}')
    self.writeFile("package-lock.json")
    self.writeFile("npm-shrinkwrap.json")
    project = self.getProject(buildScanPlan(self.path_root), "node")
    self.assertEqual("ready", project["status"])
    self.assertEqual("npm", project["tool"])
```

Also cover matching declaration, matching declaration without a lockfile, unsupported/non-string declarations, and invalid `package.json`.

- [ ] **Step 2: Verify RED**

Run:

```bash
python3 -m unittest tests.test_scan_plan.ScanPlanTest.testMarksPackageManagerLockfileMismatchAsInconclusive -v
python3 -m unittest tests.test_scan_plan.ScanPlanTest.testMarksDifferentManagerLockfilesAsInconclusive -v
```

Expected: failures showing the planner currently chooses a manager rather than returning `inconclusive`.

- [ ] **Step 3: Implement minimal evidence classification**

In `scripts/scan_plan.py`:

1. Read and validate `package.json` once per Node project.
2. Map lockfile names to manager identities; treat both npm lockfiles as `npm`.
3. Parse `packageManager` as `<npm|pnpm|yarn>@<version>`.
4. Return `inconclusive` with `tool: None`, `command: None`, and stable `reason` when JSON, declaration, or cross-manager evidence is ambiguous.
5. Preserve `needs-lockfile` when a supported declaration has no lockfile.
6. Pass parsed package data to Yarn command selection instead of re-reading the file.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
python3 -m unittest tests.test_scan_plan.ScanPlanTest -v
```

Expected: all Node evidence tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/scan_plan.py tests/test_scan_plan.py
git commit -m "fix: reject ambiguous node lockfiles"
```

## Chunk 2: Workspace coverage

### Task 2: Suppress only proven workspace members

**Files:**

- Modify: `tests/test_scan_plan.py`
- Modify: `scripts/scan_plan.py`

- [ ] **Step 1: Write failing tests**

Replace the blanket ancestor-lockfile expectation with tests asserting:

```python
def testKeepsNestedProjectNotDeclaredAsWorkspace(self):
    self.writeFile("package.json", '{"name":"root"}')
    self.writeFile("package-lock.json", '{}')
    self.writeFile("apps/web/package.json", '{"name":"web"}')
    projects = [p for p in buildScanPlan(self.path_root)["projects"] if p["kind"] == "node"]
    self.assertEqual([".", "apps/web"], [p["path"] for p in projects])


def testRootLockfileCoversDeclaredWorkspace(self):
    self.writeFile("package.json", '{"workspaces":["apps/*"]}')
    self.writeFile("package-lock.json", '{}')
    self.writeFile("apps/web/package.json", '{"name":"web"}')
    projects = [p for p in buildScanPlan(self.path_root)["projects"] if p["kind"] == "node"]
    self.assertEqual(["."], [p["path"] for p in projects])
```

Add tests for object-form workspaces, pnpm include/exclude patterns, malformed declarations, and an inconclusive parent not suppressing a child.

- [ ] **Step 2: Verify RED**

Run:

```bash
python3 -m unittest tests.test_scan_plan.ScanPlanTest.testKeepsNestedProjectNotDeclaredAsWorkspace -v
```

Expected: failure because the current ancestor check silently removes `apps/web`.

- [ ] **Step 3: Implement fail-closed workspace resolution**

Add focused helpers that:

1. Extract string patterns from package.json array/object workspace declarations.
2. Parse only the common top-level block `packages:` list from `pnpm-workspace.yaml`.
3. Reject absolute paths, parent traversal, malformed entries, unsupported YAML constructs, and unsafe matches.
4. Resolve include patterns relative to the ready parent and apply all `!` exclusions afterward.
5. Return no coverage when parsing is uncertain.

Change the final Node de-duplication pass to suppress only `needs-lockfile` children whose exact relative directory is in a ready parent's resolved workspace set. Never suppress children from an inconclusive parent.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
python3 -m unittest tests.test_scan_plan.ScanPlanTest -v
```

Expected: all workspace and existing ecosystem tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/scan_plan.py tests/test_scan_plan.py
git commit -m "fix: verify node workspace coverage"
```

## Chunk 3: Skill contract and final verification

### Task 3: Align documentation with implemented coverage

**Files:**

- Modify: `SKILL.md`
- Modify: `references/SCANNERS.md`

- [ ] **Step 1: Update the skill trigger**

Remove `secrets` from the frontmatter description while keeping secret-redaction requirements.

- [ ] **Step 2: Document planner inconclusive records**

Add `inconclusive` to the scanner planning states and explain that conflicting package-manager evidence produces no command and incomplete coverage. Update the workflow to explicitly record planner-inconclusive entries.

- [ ] **Step 3: Run complete verification**

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests
uvx --from skills-ref==0.1.1 agentskills validate "$(pwd)"
pnpm dlx markdownlint-cli2@0.23.2 "**/*.md"
git diff --check
```

Expected: all tests pass; compilation, validation, lint, and diff checks exit zero.

- [ ] **Step 4: Commit**

```bash
git add SKILL.md references/SCANNERS.md
git commit -m "docs: align security scan coverage"
```
