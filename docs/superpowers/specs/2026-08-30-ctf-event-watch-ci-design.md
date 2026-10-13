# ctf-event-watch CI baseline design

Date: 2026-08-30
Status: Approved for implementation planning

## Outcome

The public `ctf-event-watch` repository gets a dependable GitHub Actions quality gate and low-volume dependency tracking. Pull requests and pushes to `main` will run the checks already documented for contributors. The first implementation remains configuration-only.

This design does not alter application behavior, deployment, runtime data, repository permissions, branch protection, releases, or secrets.

## Problem

The repository documents Ruff, mypy, pytest, Playwright, and Axe checks, but GitHub does not run them. A contributor can therefore open or merge a change without a repository-owned result showing that the documented gate passed.

The repository also has a committed `uv.lock` but no dependency update configuration. Updates can go unnoticed, while adding broad or automated update behavior before CI exists would create avoidable noise and risk.

## Public and private boundary

This work belongs in the public Kernel Kittens repository because it changes only public build metadata and public contributor checks.

The workflow must not receive repository or environment secrets, CTF credentials, Discord credentials, model-provider credentials, Azure credentials, SMTP credentials, deployment credentials, private event data, or team data. GitHub may issue its built-in ephemeral `GITHUB_TOKEN`, limited to `contents: read`; checkout must not persist it in Git configuration. Tests use mocked HTTP transports, injected fixture fetchers, and local `127.0.0.1` servers. Setup requires public network access only for packages and the Chromium browser.

The branch stays in private remote staging through implementation and verification. Publishing a branch or pull request is a separate external action.

## Adopt, fork, or build

Adopt GitHub Actions and Dependabot directly.

- GitHub Actions already provides the repository event model, checks, logs, cancellation, and read-only token permissions needed here.
- Dependabot already understands GitHub Actions and uv lockfiles.
- Forking another repository's workflow would add assumptions without reducing the small configuration surface.
- Building a custom CI or dependency service would cost more and cover no unmet requirement.

## Workflow design

Add `.github/workflows/ci.yml` with one `quality` job.

The workflow runs for:

1. Pull requests targeting `main`.
2. Pushes to `main`.

The job uses:

- `ubuntu-24.04` as an explicit runner image.
- Python `3.13`, matching the repository requirement.
- A 20-minute job timeout.
- `contents: read` as the only GitHub token permission.
- Checkout with `persist-credentials: false`.
- Workflow and pull-request or ref based concurrency.
- Cancellation of superseded runs on the same pull request or ref.

A single job keeps setup and evidence easy to understand and avoids installing the same locked environment twice.

## Immutable actions

Every third-party action reference is pinned to a full commit SHA with its release version in a comment:

- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` for v7.0.1.
- `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97` for v7.0.0.
- `astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d` for v10.0.1.

The uv action cache is enabled and keyed from `uv.lock`. Dependabot may propose action updates later, but the committed workflow never follows a mutable tag.

## Quality gate

The job executes these commands in order:

1. `uv sync --locked --all-groups`
2. `uv run playwright install --with-deps chromium`
3. `uv run ruff check .`
4. `uv run ruff format --check .`
5. `uv run mypy src`
6. `uv run pytest`

Before accepting the workflow, `uv run pytest --collect-only -q tests/browser` must list the browser test module that imports `Axe` and its accessibility tests. This confirms the full pytest command includes the documented Playwright and Axe coverage.

A failing command fails the job. The workflow does not use `continue-on-error`, fallback commands, or result suppression.

The browser suite writes its two tracked dashboard screenshot paths in the ephemeral checkout. The workflow does not enforce a clean Git diff after tests because rendering differences could make that check flaky. It does not upload or commit screenshots.

## Event and trust flow

A GitHub pull request or push starts an isolated hosted runner. The runner checks out the public revision with a read-only token, installs the exact locked dependency set, installs Chromium, and runs the documented checks. GitHub records only the resulting check status and logs.

The workflow uses `pull_request`, not `pull_request_target`. Code from a fork cannot obtain repository or environment secrets, write repository content, or retain the ephemeral `GITHUB_TOKEN` in Git configuration through this job.

## Dependency tracking

After the CI baseline passes, add `.github/dependabot.yml` in a separate implementation commit.

Configure two weekly checks at the repository root:

1. `uv` dependencies.
2. `github-actions` dependencies.

Each ecosystem has `open-pull-requests-limit: 1`. There is no auto-merge, automatic approval, grouped major upgrade, or write-capable helper workflow. Each proposed update must pass the same CI and receive normal review.

Staging Dependabot after the baseline makes any update failure attributable to the proposed update instead of an unverified initial workflow.

## Failure behavior

- Dependency resolution drift fails at `uv sync --locked --all-groups`.
- Missing browser libraries fail during the Playwright install step.
- Lint, formatting, type, test, or accessibility regressions fail at their owning command.
- Stale runs are canceled only when a newer run supersedes the same pull request or ref.
- A Dependabot failure leaves its pull request open for review. Nothing merges automatically.
- No deployment or external notification runs on either success or failure.

## Implementation sequence

1. Record the clean baseline commit and repository state.
2. Add only the CI workflow.
3. Validate the YAML and run the full quality gate in the isolated AWS checkout.
4. Commit the workflow if all checks pass.
5. Add the bounded Dependabot configuration.
6. Validate both files and rerun the full quality gate.
7. Commit the dependency configuration if all checks pass.
8. Review the complete diff and verify no generated artifacts or unrelated changes are staged.
9. Stop for explicit approval before any GitHub push or pull request.

## Non-goals

This change does not:

- update Python or project dependencies;
- alter application source or test code;
- change tracked screenshots;
- deploy Flagwatch or touch a live service;
- add credentials, repository secrets, environments, releases, or branch rules;
- merge existing dependency pull requests in another repository;
- change any other Kernel Kittens repository.

## Rollback

Both changes are repository configuration commits. Reverting the Dependabot commit stops new scheduled proposals but does not close any pull requests it already opened; closing those requires a separate reviewed action. Reverting the workflow commit removes the new quality checks. No runtime or persisted application state needs restoration.

## Acceptance criteria

- The workflow triggers only for pull requests to `main` and pushes to `main`.
- The job receives no repository or environment secrets, uses only a read-only ephemeral `GITHUB_TOKEN`, and does not persist checkout credentials.
- Action references use the reviewed immutable SHAs.
- Python 3.13 and the committed uv lockfile define the environment.
- Ruff check, Ruff format check, mypy, pytest, Playwright, and Axe coverage run successfully.
- The full quality gate passes in a clean isolated checkout.
- Dependabot checks uv and GitHub Actions weekly with one open pull request per ecosystem.
- No auto-merge or write-capable automation is introduced.
- YAML validation, character scans, placeholder scans, and `git diff --check` pass.
- Only the intended configuration and design files differ from `main`.
- Nothing is pushed publicly without explicit approval.
