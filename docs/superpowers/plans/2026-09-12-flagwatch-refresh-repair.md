# Flagwatch Refresh Repair Implementation Plan

> **For Codex:** Execute each task with test-driven development and verify production before reporting completion.

**Goal:** Restore continuous Flagwatch refreshes, prevent malformed source conflicts from aborting a batch, enforce fail-closed matching, and give DeepSeek the already-approved official event-page evidence.

**Architecture:** Keep Azure Functions as the six-hour scheduler and Litterbox as the sole Discord notifier. Normalize untrusted conflict evidence at the domain boundary, reject alert eligibility when authoritative facts conflict, and aggregate text from pages already fetched through GuardedFetcher into the discovery evidence document. Deploy only the Function bundle, switch the existing Azure AI deployment to DeepSeek-V4-Flash-0731, trigger a bounded refresh, and verify the public snapshot and Litterbox logs.

**Tech Stack:** Python 3.13+, Pydantic, pytest, Azure Functions Flex Consumption, Azure AI Foundry, Discord Litterbox.

---

### Task 1: Bound source-conflict evidence

**Files:**
- Modify: `tests/test_composite_source.py`
- Modify: `src/flagwatch/sources/composite.py`

1. Add a regression test merging two same-identity events whose conflicting prize summaries exceed 500 characters, plus an unrelated healthy event.
2. Run the focused test and confirm it fails with Pydantic's 500-character validation boundary.
3. Update `_printable` to cap rendered conflict values at 500 characters with a visible ellipsis.
4. Run the focused and full composite-source tests.

### Task 2: Enforce fail-closed conflict matching

**Files:**
- Modify: `tests/test_matching.py`
- Modify: `src/flagwatch/matching.py`

1. Add a regression test for an otherwise eligible event containing a conflict marked `suppresses_alert=True`.
2. Run the focused test and confirm it fails because the current matcher ignores conflicts.
3. Reject the match when any event conflict suppresses alerts.
4. Run the focused and full matching tests.

### Task 3: Feed guarded event pages to DeepSeek discovery

**Files:**
- Modify: `tests/test_watch_page_source.py`
- Modify: `src/flagwatch/sources/watch_page.py`

1. Extend the discovery regression test so the needed date evidence exists only on a linked event page.
2. Run the focused test and confirm the model currently receives only homepage text and approved URL labels.
3. Build the model evidence document from the homepage plus successfully fetched linked pages. Keep the existing same-origin, redirect, response-size, and private-network protections in GuardedFetcher.
4. Run the focused and full watch-page tests.

### Task 4: Verify and package

**Files:**
- Verify: entire repository

1. Run formatting, lint, type, and full pytest checks defined by the project.
2. Review the final diff and recent commits for concurrent changes.
3. Build a Python 3.13 Linux Function bundle on the AWS development box.
4. Record the bundle digest and preserve the current Azure deployment configuration for rollback.

### Task 5: Deploy and backfill

**Files:**
- Deploy: `func-flagwatch-prod-8e2620`

1. Deploy only the verified Function bundle to the existing Flex Consumption app.
2. Change `FLAGWATCH_AI_MODEL` from `DeepSeek-V4-Pro` to the existing `DeepSeek-V4-Flash-0731` deployment. Do not claim this is local DeepSeek V4.1.
3. Trigger one refresh through the Function admin endpoint without exposing its key.
4. Verify a new `generated_at`, a 31-day lookback, a 90-day lookahead, policy evidence, and successful timer execution.
5. Verify Litterbox is still the only sender, is polling the fresh API, and targets only the configured Kernel Kittens channel.
6. Roll back the deployment or model setting if verification regresses.

### Task 6: Close out
