# ctf-event-watch CI Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only GitHub Actions quality checks and bounded weekly Dependabot updates to `KernelKittens/ctf-event-watch`.

**Architecture:** Use one pull request and main-branch workflow with a single quality job. The job installs the repository's locked Python dependency graph, installs Chromium for the existing browser suite, and runs every existing repository check. Keep dependency update policy in a separate Dependabot file so its limits and ecosystems remain easy to audit.

**Tech Stack:** GitHub Actions YAML, Python 3.13, uv 0.12.7, Ruff, mypy, pytest, Playwright, Axe, Dependabot v2, actionlint 1.7.12

## Global Constraints

- Work only in the task-owned AWS checkout at `/opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch`.
- Change only public repository configuration and implementation documentation.
- Do not change application behavior, deployment files, runtime settings, GitHub repository settings, or secrets.
- Do not add repository or environment secrets. The workflow may use only GitHub's ephemeral built-in `GITHUB_TOKEN`.
- Set workflow permissions to `contents: read` and disable persisted checkout credentials.
- Pin every third-party action to a full commit SHA with a version comment.
- Use `ubuntu-24.04`, Python 3.13, a 20-minute job timeout, and locked dependency installation.
- Do not add auto-merge, write permissions, release automation, deployment, scheduled application execution, or failure suppression.
- Preserve unrelated changes and inspect the exact staged file list before every commit.
- Keep all work private. Stop before any GitHub push, pull request, merge, or repository-setting change unless Moo separately approves that external action.

---

### Task 1: Add the read-only quality workflow

**Files:**

- Create: `.github/workflows/ci.yml`
- Verify: `pyproject.toml`
- Verify: `uv.lock`
- Verify: `tests/browser/test_dashboard.py`
- Verify: `tests/browser/test_public_calendar.py`

**Interfaces:**

- GitHub event input: `pull_request` targeting `main`, or `push` to `main`
- Repository input: `uv.lock`
- Test input: the existing `tests` tree, including Playwright and Axe cases
- Required output: one `quality` job whose exit status reflects all existing checks
- Security boundary: read-only `GITHUB_TOKEN`, no persisted checkout credentials, no secrets

- [ ] **Step 1: Confirm the workflow does not already exist**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
test -f .github/workflows/ci.yml
```

Expected: exit status 1 because the workflow is absent.

- [ ] **Step 2: Prepare independently verified validation tools**

Run:

```bash
set -euo pipefail
CI_TOOLS_DIR=/opt/dev/kk-ctf-watch-ci-impl-20260830/tools
mkdir -p "$CI_TOOLS_DIR"
curl --fail --location --output "$CI_TOOLS_DIR/uv.tar.gz" \
  https://github.com/astral-sh/uv/releases/download/0.12.7/uv-x86_64-unknown-linux-gnu.tar.gz
printf '%s  %s\n' \
  '788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21' \
  "$CI_TOOLS_DIR/uv.tar.gz" | sha256sum --check -
tar --extract --gzip --file "$CI_TOOLS_DIR/uv.tar.gz" --directory "$CI_TOOLS_DIR"
curl --fail --location --output "$CI_TOOLS_DIR/actionlint.tar.gz" \
  https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
printf '%s  %s\n' \
  '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8' \
  "$CI_TOOLS_DIR/actionlint.tar.gz" | sha256sum --check -
tar --extract --gzip --file "$CI_TOOLS_DIR/actionlint.tar.gz" --directory "$CI_TOOLS_DIR" actionlint
"$CI_TOOLS_DIR/uv-x86_64-unknown-linux-gnu/uv" --version
"$CI_TOOLS_DIR/actionlint" --version
```

Expected: both archives report `OK`, then uv reports `0.12.7` and actionlint reports `1.7.12`.

- [ ] **Step 3: Create the complete workflow**

Create `.github/workflows/ci.yml` with exactly:

```yaml
name: CI

on:
  pull_request:
    branches:
      - main
  push:
    branches:
      - main

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  quality:
    name: Quality
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Check out repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Set up Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"

      - name: Set up uv
        uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1
        with:
          enable-cache: true
          cache-dependency-glob: uv.lock

      - name: Install dependencies
        run: uv sync --locked --all-groups

      - name: Install Chromium
        run: uv run playwright install --with-deps chromium

      - name: Check lint
        run: uv run ruff check .

      - name: Check formatting
        run: uv run ruff format --check .

      - name: Check types
        run: uv run mypy src

      - name: Run tests
        run: uv run pytest
```

- [ ] **Step 4: Validate workflow syntax and security invariants**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
/opt/dev/kk-ctf-watch-ci-impl-20260830/tools/actionlint -no-color .github/workflows/ci.yml
! rg -n 'pull_request_target|continue-on-error|secrets:|permissions:.*write|persist-credentials:[[:space:]]*true' .github/workflows/ci.yml
! rg -n 'uses:[[:space:]]+[^[:space:]@]+@(main|master|v[0-9]+([.][0-9]+)*)[[:space:]]*(#.*)?$' .github/workflows/ci.yml
rg -n 'permissions:|contents: read|persist-credentials: false|ubuntu-24.04|timeout-minutes: 20|uv sync --locked --all-groups' .github/workflows/ci.yml
```

Expected: actionlint and both negative searches exit 0 without findings. The final search prints every required invariant.

- [ ] **Step 5: Prove the workflow commands match the existing project**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
UV=/opt/dev/kk-ctf-watch-ci-impl-20260830/tools/uv-x86_64-unknown-linux-gnu/uv
"$UV" sync --locked --all-groups
"$UV" run playwright install --with-deps chromium
"$UV" run ruff check .
"$UV" run ruff format --check .
"$UV" run mypy src
"$UV" run pytest --collect-only -q tests/browser
"$UV" run pytest
```

Expected:

- Ruff reports all checks passed.
- Ruff reports 95 files already formatted after this plan is tracked.
- mypy reports no issues in 33 source files.
- Browser collection lists 21 tests, including both dashboard and public-calendar Axe cases.
- pytest reports 191 passed.

- [ ] **Step 6: Inspect generated artifacts and commit only the workflow**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
git status --short
```

If tests changed any tracked browser screenshots, inspect those exact diffs first. Restore only the generated files below:

```bash
git restore -- \
  artifacts/flagwatch-dashboard-1440.png \
  artifacts/flagwatch-dashboard-320.png
```

Then run:

```bash
git add .github/workflows/ci.yml
git diff --cached --name-only
git diff --cached --check
git commit -m "ci: add locked quality checks"
```

Expected: the staged file list contains exactly `.github/workflows/ci.yml`; the whitespace check passes; the commit succeeds.

---

### Task 2: Add bounded weekly dependency updates

**Files:**

- Create: `.github/dependabot.yml`
- Verify: `.github/workflows/ci.yml`

**Interfaces:**

- Dependabot schema: version 2
- Package inputs: root `uv.lock` and GitHub Actions workflow references
- Schedule: weekly for both ecosystems
- Output bound: at most one open pull request per ecosystem
- Merge boundary: Dependabot may open pull requests, but no configuration may merge them

- [ ] **Step 1: Confirm the Dependabot configuration does not already exist**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
test -f .github/dependabot.yml
```

Expected: exit status 1 because the file is absent.

- [ ] **Step 2: Create the complete configuration**

Create `.github/dependabot.yml` with exactly:

```yaml
version: 2
updates:
  - package-ecosystem: "uv"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 1

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 1
```

- [ ] **Step 3: Validate syntax and exact policy semantics**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
/opt/dev/kk-ctf-watch-ci-impl-20260830/tools/uv-x86_64-unknown-linux-gnu/uv run \
  --with 'pyyaml==6.0.3' python - <<'PY'
from pathlib import Path

import yaml

actual = yaml.safe_load(Path(".github/dependabot.yml").read_text(encoding="utf-8"))
expected = {
    "version": 2,
    "updates": [
        {
            "package-ecosystem": "uv",
            "directory": "/",
            "schedule": {"interval": "weekly"},
            "open-pull-requests-limit": 1,
        },
        {
            "package-ecosystem": "github-actions",
            "directory": "/",
            "schedule": {"interval": "weekly"},
            "open-pull-requests-limit": 1,
        },
    ],
}
assert actual == expected, (actual, expected)
print("Dependabot policy matches the approved design.")
PY
! rg -n 'groups:|allow:|ignore:|assignees:|reviewers:|target-branch:|open-pull-requests-limit:[[:space:]]*[2-9]' .github/dependabot.yml
```

Expected: the assertion message prints and the negative policy search finds nothing. The transient PyYAML validator must not change `uv.lock`.

- [ ] **Step 4: Run the full quality gate again**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
UV=/opt/dev/kk-ctf-watch-ci-impl-20260830/tools/uv-x86_64-unknown-linux-gnu/uv
/opt/dev/kk-ctf-watch-ci-impl-20260830/tools/actionlint -no-color .github/workflows/ci.yml
"$UV" sync --locked --all-groups
"$UV" run ruff check .
"$UV" run ruff format --check .
"$UV" run mypy src
"$UV" run pytest
git diff --exit-code -- uv.lock
```

Expected: actionlint passes; all project checks pass; pytest reports 191 passed; `uv.lock` is unchanged.

- [ ] **Step 5: Inspect generated artifacts and commit only Dependabot**

Run:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
git status --short
```

If tests changed tracked screenshots, inspect and restore only the two exact generated files named in Task 1. Then run:

```bash
git add .github/dependabot.yml
git diff --cached --name-only
git diff --cached --check
git commit -m "chore: add bounded dependency updates"
```

Expected: the staged file list contains exactly `.github/dependabot.yml`; the whitespace check passes; the commit succeeds.

---

### Final private review and handoff

- [ ] Run the complete gate from Task 2 again with fresh output.
- [ ] Confirm the approved diff contains only the design, implementation plan, CI workflow, and Dependabot configuration:

```bash
cd /opt/dev/kk-ctf-watch-ci-impl-20260830/ctf-event-watch
git diff --check a8fec3972a42e2183addb3901bdc0c61a34c4937..HEAD
git diff --name-only a8fec3972a42e2183addb3901bdc0c61a34c4937..HEAD
git log --oneline --decorate a8fec3972a42e2183addb3901bdc0c61a34c4937..HEAD
git status --short
```

- [ ] Scan the documentation for placeholders and disallowed typography:

```bash
rg -n 'TB[D]|TO[D]O|implement[ ]later|appropriate[ ]error[ ]handling|similar[ ]to[ ]Task' \
  docs/superpowers/specs/2026-08-30-ctf-event-watch-ci-design.md \
  docs/superpowers/plans/2026-08-30-ctf-event-watch-ci-implementation.md
rg -n '\x{2013}|\x{2014}|\x{201c}|\x{201d}' \
  docs/superpowers/specs/2026-08-30-ctf-event-watch-ci-design.md \
  docs/superpowers/plans/2026-08-30-ctf-event-watch-ci-implementation.md
```

Expected: both scans produce no matches.

- [ ] Create a full private recovery bundle, verify it from inside the repository, calculate its SHA-256 digest, and copy it to the approved vault artifact directory.
- [ ] Stop before any push, pull request, merge, or GitHub repository-setting change.

Rollback is commit-based and happens in reverse order: revert the Dependabot commit, then revert the workflow commit. Reverting `.github/dependabot.yml` prevents future update runs but does not close Dependabot pull requests that already exist; closing those would be a separate external action requiring explicit approval.
