# Design: PR comment for Trivy scan results

**Date:** 2026-07-09
**Action:** `gha-trivy` (composite GitHub Action)
**Status:** Approved (design)

## Problem

The action already surfaces scan results as a job summary, an HTML report artifact,
an SBOM artifact, and a JUnit test report. None of these are visible directly on a
pull request — a reviewer has to open the run to see them. We want the vulnerability
summary, plus links to the run and artifacts, posted as a PR comment that updates in
place on re-runs so results are visible and comparable over time, without becoming
noisy when nothing changes.

## Goals

- Post a PR comment with the vulnerability severity summary and links to the workflow
  run, HTML report, and SBOM.
- On re-run, update the same comment in place (sticky comment).
- Keep the latest result prominent; retain prior results in a collapsed history for
  comparison.
- Avoid noise: only add to history when the severity counts actually change.
- Degrade gracefully when the action can't comment (missing permission / fork PR).

## Non-goals

- `pull_request_target` support (only `pull_request` events trigger commenting).
- A single aggregated comment across multiple scans — each report slug gets its own
  comment.
- Capping / pruning history (uncapped; grows only when counts change).

## Design

### 1. New input & activation

- Add input **`create-pr-comment`**, default `"true"`.
- The commenting step runs only when:
  - `inputs.create-pr-comment == 'true'`, **and**
  - `github.event_name == 'pull_request'`.
- The step uses `if: always() && …` so the comment is posted/updated even when
  vulnerabilities cause a later step (JUnit publish) to fail the job.
- Requires the calling workflow to grant `permissions: pull-requests: write`
  (and `contents: read`). Documented in README.

### 2. Failure handling

All octokit I/O is wrapped in `try/catch`. On failure (missing `pull-requests: write`,
fork PR with a read-only token, or any API error), the step:

- emits `::warning::` including a hint to grant `pull-requests: write`, and
- returns without failing the job.

The job summary and artifacts are unaffected.

### 3. Counts as embedded state (no external state file)

Extend `summary.tpl` so `trivy.md` ends with a hidden metadata marker carrying the
severity counts:

```
<!-- gha-trivy-meta:{"counts":{"critical":N,"high":N,"medium":N,"low":N,"unknown":N}} -->
```

The HTML comment is invisible in both the job summary and the PR comment. At runtime,
the commenting step parses these counts and enriches the marker it posts with:

- `run.number`, `run.url`
- `time` (ISO timestamp)
- `image` label (`inputs.image-ref` or `"fs"`)

Because the enriched marker is embedded in the posted comment, the **next** run reads
the previous run's counts and metadata directly from the existing comment — no
artifact, cache, or side state required.

### 4. Comment identity

Each comment carries a hidden identity marker:

```
<!-- gha-trivy:<slug> -->
```

where `<slug>` is the existing `REPORT_SLUG` (from `report-tag` or the job ID). The
step lists PR comments (paginated), finds the one whose body contains its slug marker,
and updates it; if none is found it creates a new comment. This yields one comment per
report slug, consistent with the existing per-slug artifact naming.

### 5. Links

- Add `id:` to the existing **Upload SBOM** and **Upload vulnerability report** steps.
- Read `steps.<id>.outputs.artifact-url` (provided by `actions/upload-artifact` v7).
- The comment includes links to:
  - the workflow run (`${github.server_url}/${github.repository}/actions/runs/${github.run_id}`),
  - the HTML report artifact,
  - the SBOM artifact (omitted when no SBOM was uploaded — i.e. `scan-ref` set and
    `upload-scan-ref` false).

### 6. Comment body & history behavior

Body layout:

```
<!-- gha-trivy:<slug> -->
### Vulnerability summary (<image|fs>) — latest: run #42

<current severity table>

Change since last run: Critical 2 (−1) · High 5 (=) · Medium 12 (+2) · Low 30 (=) · Unknown 4 (=)
Links: [workflow run](…) · [HTML report](…) · [SBOM](…)

<!-- gha-trivy-meta:{…current enriched…} -->

<details><summary>Previous runs (N)</summary>

#### run #41 · 2026-07-09T10:11:00Z
<severity table>

#### run #40 · 2026-07-08T14:02:00Z
<severity table>

</details>
```

Update rules:

- **First run (no existing comment):** create the comment with the latest block only;
  no delta line, no history section.
- **Counts changed vs previous latest:** render the previous latest block (its table +
  run link + timestamp, reconstructed from the previous marker) and prepend it to the
  collapsed history; set the current run as the new latest; show per-severity deltas.
- **Counts unchanged:** leave the history section untouched; refresh only the latest
  run link and timestamp; delta line reads `Change since last run: no change`.

Delta line format: per severity, `<Name> <count> (<±delta or =>)`, joined by ` · `.

History grows only when counts change; it is not capped.

### 7. Interaction with `create-summary`

`trivy.md` is required by the PR comment as well as the job summary. Adjust the gating:

- **Copy summary template** and **Create summary on vulnerabilities** (generating
  `trivy.md`): run when `create-summary == 'true'` **or** `create-pr-comment == 'true'`.
- **Add to job summary**: unchanged — still gated on `create-summary == 'true'`.

### 8. Tooling & testability

- Posting uses **`actions/github-script`** (latest release, SHA-pinned per repo
  convention).
- The pure logic is extracted into a module `scripts/pr-comment.cjs`:
  - `parseMeta(body)` — extract counts/metadata from a comment/`trivy.md` body.
  - `renderTable(counts)` — render a severity table.
  - `computeDeltaLine(current, previous)` — build the change-since-last-run line.
  - `buildBody({ slug, image, run, counts, links, existingBody })` — apply the update
    rules (§6) and return the full comment body.
- The github-script step is thin: it reads `trivy.md`, gathers run/link context, calls
  the module to build the body, then does octokit find + create/update, all inside
  `try/catch`.
- Add a `node --test` suite (`scripts/pr-comment.test.cjs`) covering: first run,
  changed counts (history prepend + deltas), unchanged counts (history preserved,
  timestamp refreshed), missing/omitted SBOM link, and malformed/absent marker.
- Add a `mise` task `test` running `node --test scripts/`, wired into CI so local and
  CI run the same command (local/CI parity convention).

### 9. Docs

- `README.md`: document the new input, the required `pull-requests: write` permission,
  the fork-PR caveat, and the sticky/history behavior.
- `action.yml`: input description for `create-pr-comment`.
- `CHANGELOG.md`: add an entry for the feature.

## Risks / edge cases

- **Fork PRs** get a read-only `GITHUB_TOKEN` on `pull_request`; the step will
  warn-and-continue (§2).
- **Concurrent runs** on the same PR could race on the same comment; acceptable —
  last write wins, and the embedded marker keeps state self-correcting on the next run.
- **Marker drift**: if the marker is missing/malformed (e.g. a user edited the
  comment), treat as "no previous state" — post a fresh latest block and start history
  anew rather than erroring.
```
