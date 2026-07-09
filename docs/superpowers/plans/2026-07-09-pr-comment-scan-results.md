# PR Comment for Trivy Scan Results — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Post a sticky PR comment with the Trivy vulnerability summary plus links to the workflow run and artifacts, updated in place on re-runs with a collapsed, change-only history.

**Architecture:** A small pure-JS module (`scripts/pr-comment.cjs`) owns all body-building/parsing/merge logic and is unit-tested with `node --test`. The composite action gains a new `create-pr-comment` input and an `actions/github-script` step that reads counts from the generated `trivy.md` (via an embedded metadata marker), gathers run/artifact links, calls the module to build the comment body, and creates-or-updates the PR comment — wrapped in `try/catch` that warns-and-continues.

**Tech Stack:** GitHub composite action (`action.yml`), `actions/github-script@v9`, Node.js (`node --test`), `mise` tasks, Trivy Go templates (`summary.tpl`).

## Global Constraints

- Conventional Commits for every commit; no `Co-authored-by` footer. No JIRA issue identifiable from branch `feat/pr-comment-scan-results` — omit the footer.
- Pin all third-party GitHub Actions to a commit SHA with a `# vX.Y.Z` comment (repo convention).
- Use latest releases: `actions/github-script` = **v9.0.0** SHA `3a2844b7e9c422d3c10d287c895573f7108da1b3`; `jdx/mise-action` = **v4.2.0** SHA `e6a8b3978addb5a52f2b4cd9d91eafa7f0ab959d`; `actions/checkout` = v7.0.0 SHA `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` (already used in repo).
- Node pinned in `mise.toml` to `24.14.1`.
- New input `create-pr-comment` defaults to `"true"`; commenting only runs on `github.event_name == 'pull_request'`.
- Inability to comment (missing `pull-requests: write`, fork PR read-only token, any API error) must `::warning::` and NOT fail the job.
- CI steps invoke logic via `mise run <task>` (local/CI parity).
- History entries are added only when severity counts change; history is uncapped.

## File Structure

- `scripts/pr-comment.cjs` (create) — pure logic: parse marker, render table, compute delta, merge history, build body. No I/O, no octokit.
- `scripts/pr-comment.test.cjs` (create) — `node --test` suite for the module.
- `summary.tpl` (modify) — append a hidden counts metadata marker.
- `action.yml` (modify) — new input; adjust `trivy.md` gating; add `id:` to two upload steps; add the github-script commenting step.
- `mise.toml` (modify) — add `node` tool and a `test` task.
- `.github/workflows/check.yml` (modify) — add a `unit-test` job (via `mise run test`); grant `pull-requests: write` to the integration job.
- `README.md`, `CHANGELOG.md` (modify) — document the feature.

---

### Task 1: Pure logic module `scripts/pr-comment.cjs` (+ tests, node/mise setup)

**Files:**

- Create: `scripts/pr-comment.cjs`
- Test: `scripts/pr-comment.test.cjs`
- Modify: `mise.toml`

**Interfaces:**

- Produces (all exported from `scripts/pr-comment.cjs`):
  - `SEVERITIES: Array<[key: string, label: string]>` — order: critical, high, medium, low, unknown.
  - `parseMeta(body: string|null|undefined): object|null` — returns the JSON parsed from the first `<!-- gha-trivy-meta:… -->` marker, or `null` if absent/malformed.
  - `renderTable(counts: {critical,high,medium,low,unknown}): string` — a GitHub markdown table (missing keys treated as 0).
  - `computeDeltaLine(current, previous): string|null` — `"Critical 2 (-1) · High 5 (=) · …"`; `null` when `previous` is falsy.
  - `countsEqual(a, b): boolean` — true iff all five severities match (missing = 0); false if either arg falsy.
  - `buildBody({ slug, image, run: {number, url}, time, counts, links: {run, report?, sbom?}, existingBody? }): string` — full comment body per §5/§6 of the spec.

- [ ] **Step 1: Add node tool and `test` task to `mise.toml`**

Modify `mise.toml` to read exactly:

```toml
[tools]
hk = "1.50.0"
pkl = "0.32.0"
node = "24.14.1"

[env]
# explicitly use pkl CLI instead of pklr library because the latter does not support all language features needed
HK_PKL_BACKEND = "pkl"

[hooks]
enter = "mise x -- hk install --mise"
postinstall = "mise x -- hk install --mise"

[tasks.test]
description = "Run unit tests"
run = "node --test scripts/"
```

- [ ] **Step 2: Write the failing tests**

Create `scripts/pr-comment.test.cjs`:

```js
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  parseMeta,
  renderTable,
  computeDeltaLine,
  countsEqual,
  buildBody,
} = require("./pr-comment.cjs");

const counts = (c, h, m, l, u) => ({
  critical: c,
  high: h,
  medium: m,
  low: l,
  unknown: u,
});

test("parseMeta reads the JSON from the marker", () => {
  const body = 'hi\n<!-- gha-trivy-meta:{"counts":{"critical":2}} -->\nbye';
  assert.deepEqual(parseMeta(body), { counts: { critical: 2 } });
});

test("parseMeta returns null when absent or malformed", () => {
  assert.equal(parseMeta("no marker here"), null);
  assert.equal(parseMeta(""), null);
  assert.equal(parseMeta(undefined), null);
  assert.equal(parseMeta("<!-- gha-trivy-meta:{bad json} -->"), null);
});

test("renderTable renders all severities, missing keys as 0", () => {
  const t = renderTable({ critical: 1, high: 2 });
  assert.match(t, /\| Critical \| High \| Medium \| Low \| Unknown \|/);
  assert.match(t, /\| 1 \| 2 \| 0 \| 0 \| 0 \|/);
});

test("computeDeltaLine shows signed deltas and equals", () => {
  const line = computeDeltaLine(
    counts(2, 5, 12, 30, 4),
    counts(3, 5, 10, 30, 4),
  );
  assert.equal(
    line,
    "Critical 2 (-1) · High 5 (=) · Medium 12 (+2) · Low 30 (=) · Unknown 4 (=)",
  );
});

test("computeDeltaLine returns null without previous", () => {
  assert.equal(computeDeltaLine(counts(1, 0, 0, 0, 0), null), null);
});

test("countsEqual compares all severities treating missing as 0", () => {
  assert.equal(
    countsEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, {}),
    true,
  );
  assert.equal(countsEqual({ critical: 1 }, { critical: 2 }), false);
  assert.equal(countsEqual(null, {}), false);
});

const baseOpts = {
  slug: "myslug",
  image: "myimage:tag",
  run: { number: 42, url: "https://run/42" },
  time: "2026-07-09T10:00:00Z",
  counts: counts(2, 5, 12, 30, 4),
  links: {
    run: "https://run/42",
    report: "https://artifact/report",
    sbom: "https://artifact/sbom",
  },
};

test("buildBody first run: markers, table, links, no delta, no history", () => {
  const body = buildBody({ ...baseOpts, existingBody: undefined });
  assert.match(body, /<!-- gha-trivy:myslug -->/);
  assert.match(
    body,
    /### Vulnerability summary \(myimage:tag\) — latest: run #42/,
  );
  assert.match(body, /\| 2 \| 5 \| 12 \| 30 \| 4 \|/);
  assert.match(
    body,
    /Links: \[workflow run\]\(https:\/\/run\/42\) · \[HTML report\]\(https:\/\/artifact\/report\) · \[SBOM\]\(https:\/\/artifact\/sbom\)/,
  );
  assert.doesNotMatch(body, /Change since last run/);
  assert.doesNotMatch(body, /Previous runs/);
  assert.match(body, /<!-- gha-trivy-meta:.*"number":42/);
});

test("buildBody omits SBOM link when not provided", () => {
  const body = buildBody({
    ...baseOpts,
    links: { run: "https://run/42", report: "https://artifact/report" },
    existingBody: undefined,
  });
  assert.doesNotMatch(body, /\[SBOM\]/);
  assert.match(body, /\[HTML report\]/);
});

test("buildBody changed counts: prepends previous latest to history, shows delta", () => {
  const prev = buildBody({
    ...baseOpts,
    counts: counts(3, 5, 10, 30, 4),
    run: { number: 41, url: "https://run/41" },
    time: "2026-07-08T09:00:00Z",
    existingBody: undefined,
  });
  const body = buildBody({ ...baseOpts, existingBody: prev });
  assert.match(
    body,
    /Change since last run: Critical 2 \(-1\) · High 5 \(=\) · Medium 12 \(\+2\)/,
  );
  assert.match(body, /<details><summary>Previous runs \(1\)<\/summary>/);
  assert.match(body, /#### run #41 · 2026-07-08T09:00:00Z/);
  assert.match(
    body,
    /### Vulnerability summary \(myimage:tag\) — latest: run #42/,
  );
});

test('buildBody unchanged counts: no history growth, refreshed run, "no change"', () => {
  const prev = buildBody({
    ...baseOpts,
    run: { number: 41, url: "https://run/41" },
    time: "2026-07-08T09:00:00Z",
    existingBody: undefined,
  });
  const body = buildBody({ ...baseOpts, existingBody: prev });
  assert.match(body, /Change since last run: no change/);
  assert.doesNotMatch(body, /Previous runs/);
  assert.match(body, /latest: run #42/);
});

test("buildBody with malformed existing marker treats as first run", () => {
  const body = buildBody({
    ...baseOpts,
    existingBody: "garbage <!-- gha-trivy-meta:{bad} -->",
  });
  assert.doesNotMatch(body, /Change since last run/);
  assert.doesNotMatch(body, /Previous runs/);
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `mise run test`
Expected: FAIL — `Cannot find module './pr-comment.cjs'`.

- [ ] **Step 4: Implement the module**

Create `scripts/pr-comment.cjs`:

```js
"use strict";

const SEVERITIES = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["unknown", "Unknown"],
];

const META_RE = /<!-- gha-trivy-meta:(.*?) -->/;
const HISTORY_RE =
  /<details><summary>Previous runs[^<]*<\/summary>\n\n([\s\S]*?)\n\n<\/details>/;

function parseMeta(body) {
  if (!body) return null;
  const m = body.match(META_RE);
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch {
    return null;
  }
}

function renderTable(counts) {
  const c = counts || {};
  const header = "| " + SEVERITIES.map(([, label]) => label).join(" | ") + " |";
  const sep = "| " + SEVERITIES.map(() => "---").join(" | ") + " |";
  const row = "| " + SEVERITIES.map(([key]) => c[key] ?? 0).join(" | ") + " |";
  return [header, sep, row].join("\n");
}

function computeDeltaLine(current, previous) {
  if (!previous) return null;
  return SEVERITIES.map(([key, label]) => {
    const cur = current[key] ?? 0;
    const prev = previous[key] ?? 0;
    const d = cur - prev;
    const tag = d === 0 ? "=" : d > 0 ? `+${d}` : `${d}`;
    return `${label} ${cur} (${tag})`;
  }).join(" · ");
}

function countsEqual(a, b) {
  if (!a || !b) return false;
  return SEVERITIES.every(([key]) => (a[key] ?? 0) === (b[key] ?? 0));
}

function extractHistoryInner(body) {
  if (!body) return "";
  const m = body.match(HISTORY_RE);
  return m ? m[1] : "";
}

function historyEntry(meta) {
  return `#### run #${meta.run.number} · ${meta.time}\n\n${renderTable(meta.counts)}`;
}

function buildBody({ slug, image, run, time, counts, links, existingBody }) {
  const prev = parseMeta(existingBody);
  const changed = !countsEqual(prev && prev.counts, counts);

  let historyInner = extractHistoryInner(existingBody);
  if (prev && changed) {
    const entry = historyEntry(prev);
    historyInner = historyInner ? `${entry}\n\n${historyInner}` : entry;
  }
  const historyCount = (historyInner.match(/#### run #/g) || []).length;
  const historySection = historyInner
    ? `<details><summary>Previous runs (${historyCount})</summary>\n\n${historyInner}\n\n</details>`
    : "";

  let deltaLine = null;
  if (prev) {
    deltaLine = changed
      ? `Change since last run: ${computeDeltaLine(counts, prev.counts)}`
      : "Change since last run: no change";
  }

  const linkParts = [`[workflow run](${links.run})`];
  if (links.report) linkParts.push(`[HTML report](${links.report})`);
  if (links.sbom) linkParts.push(`[SBOM](${links.sbom})`);

  const meta = { counts, run, time, image };
  const metaMarker = `<!-- gha-trivy-meta:${JSON.stringify(meta)} -->`;

  const lines = [
    `<!-- gha-trivy:${slug} -->`,
    `### Vulnerability summary (${image}) — latest: run #${run.number}`,
    "",
    renderTable(counts),
    "",
  ];
  if (deltaLine) lines.push(deltaLine);
  lines.push(`Links: ${linkParts.join(" · ")}`);
  lines.push("");
  lines.push(metaMarker);
  if (historySection) {
    lines.push("");
    lines.push(historySection);
  }
  return lines.join("\n");
}

module.exports = {
  SEVERITIES,
  parseMeta,
  renderTable,
  computeDeltaLine,
  countsEqual,
  buildBody,
};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `mise run test`
Expected: PASS — all tests green (`# pass 11`).

- [ ] **Step 6: Commit**

```bash
git add scripts/pr-comment.cjs scripts/pr-comment.test.cjs mise.toml
git commit -m "feat: add pr-comment body builder module with tests"
```

---

### Task 2: Embed counts metadata marker in `summary.tpl`

**Files:**

- Modify: `summary.tpl`

**Interfaces:**

- Produces: `trivy.md` now ends with `<!-- gha-trivy-meta:{"counts":{"critical":N,"high":N,"medium":N,"low":N,"unknown":N}} -->`, consumed by `parseMeta` (Task 1) in the action step (Task 3).

- [ ] **Step 1: Append the hidden marker to the template**

At the very end of `summary.tpl` (after the closing `</table>` on line 30), add a new line:

```gotemplate
<!-- gha-trivy-meta:{"counts":{"critical":{{ $critical }},"high":{{ $high }},"medium":{{ $medium }},"low":{{ $low }},"unknown":{{ $unknown }}}} -->
```

The full file tail should read:

```gotemplate
  </tr>
</table>
<!-- gha-trivy-meta:{"counts":{"critical":{{ $critical }},"high":{{ $high }},"medium":{{ $medium }},"low":{{ $low }},"unknown":{{ $unknown }}}} -->
```

- [ ] **Step 2: Sanity-check the marker shape with the module parser**

Run:

```bash
node -e 'const {parseMeta}=require("./scripts/pr-comment.cjs"); const s=`<table></table>\n<!-- gha-trivy-meta:{"counts":{"critical":1,"high":2,"medium":3,"low":4,"unknown":5}} -->`; console.log(JSON.stringify(parseMeta(s)))'
```

Expected output: `{"counts":{"critical":1,"high":2,"medium":3,"low":4,"unknown":5}}`

(The marker string here mirrors what Trivy renders; this verifies the literal format `parseMeta` expects.)

- [ ] **Step 3: Commit**

```bash
git add summary.tpl
git commit -m "feat: embed severity counts marker in vulnerability summary"
```

---

### Task 3: Wire the composite action (`action.yml`)

**Files:**

- Modify: `action.yml` (add input; adjust two `if:` gates; add `id:` to two upload steps; add commenting step)

**Interfaces:**

- Consumes: `scripts/pr-comment.cjs` (Task 1) via `require`; `trivy.md` marker (Task 2).
- Produces: PR comment behavior; no outputs consumed by later tasks.

- [ ] **Step 1: Add the `create-pr-comment` input**

In `action.yml`, after the `create-summary` input block (ends at line 41), add:

```yaml
create-pr-comment:
  description: If a sticky PR comment with the vulnerability summary should be created/updated (only on pull_request events; requires pull-requests:write)
  default: "true" # Note: Action inputs are always of type string
```

- [ ] **Step 2: Gate `trivy.md` generation on either summary or PR comment**

Change the `if:` on the **"Copy vulnerability summary template"** step (currently line 269) and the **"Create summary on vulnerabilities"** step (currently line 274) from:

```yaml
if: ${{ inputs.create-summary == 'true' }}
```

to:

```yaml
if: ${{ inputs.create-summary == 'true' || inputs.create-pr-comment == 'true' }}
```

Leave the **"Add to job summary"** step (line 293) gated on `inputs.create-summary == 'true'` unchanged.

- [ ] **Step 3: Add `id:` to the two upload-artifact steps**

On the **"Upload SBOM"** step (currently line 213, `uses: actions/upload-artifact...`) add an `id`:

```yaml
- name: Upload SBOM
  id: upload-sbom
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
```

On the **"Upload vulnerability report"** step (currently line 260) add an `id`:

```yaml
- name: Upload vulnerability report
  id: upload-report
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
  if: always()
```

- [ ] **Step 4: Add the commenting step**

Insert immediately after the **"Add to job summary"** step (after current line 297, before "Fix .trivy permissions"):

```yaml
- name: Post/update PR comment
  if: ${{ always() && inputs.create-pr-comment == 'true' && github.event_name == 'pull_request' }}
  uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0
  env:
    REPORT_URL: ${{ steps.upload-report.outputs.artifact-url }}
    SBOM_URL: ${{ steps.upload-sbom.outputs.artifact-url }}
    IMAGE_LABEL: ${{ inputs.image-ref != '' && inputs.image-ref || 'fs' }}
    REPORT_SLUG: ${{ env.REPORT_SLUG }}
  with:
    script: |
      const fs = require('fs');
      const path = require('path');
      const { parseMeta, buildBody } = require(path.join(process.env.GITHUB_ACTION_PATH, 'scripts', 'pr-comment.cjs'));

      try {
        if (!fs.existsSync('trivy.md')) {
          core.warning('trivy.md not found; skipping PR comment.');
          return;
        }
        const summary = fs.readFileSync('trivy.md', 'utf8');
        const parsed = parseMeta(summary);
        if (!parsed || !parsed.counts) {
          core.warning('No counts marker found in trivy.md; skipping PR comment.');
          return;
        }

        const slug = process.env.REPORT_SLUG;
        const marker = `<!-- gha-trivy:${slug} -->`;
        const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
        const links = { run: runUrl };
        if (process.env.REPORT_URL) links.report = process.env.REPORT_URL;
        if (process.env.SBOM_URL) links.sbom = process.env.SBOM_URL;

        const issueNumber = context.issue.number;

        const existing = await github.paginate(github.rest.issues.listComments, {
          owner: context.repo.owner,
          repo: context.repo.repo,
          issue_number: issueNumber,
          per_page: 100,
        });
        const mine = existing.find((c) => c.body && c.body.includes(marker));

        const body = buildBody({
          slug,
          image: process.env.IMAGE_LABEL,
          run: { number: context.runNumber, url: runUrl },
          time: new Date().toISOString(),
          counts: parsed.counts,
          links,
          existingBody: mine ? mine.body : undefined,
        });

        if (mine) {
          await github.rest.issues.updateComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            comment_id: mine.id,
            body,
          });
        } else {
          await github.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: issueNumber,
            body,
          });
        }
      } catch (err) {
        core.warning(`Could not post PR comment (grant 'pull-requests: write' if this is a permissions issue): ${err.message}`);
      }
```

- [ ] **Step 5: Validate action YAML parses**

Run: `node -e "const y=require('fs').readFileSync('action.yml','utf8'); require('child_process'); console.log('bytes',y.length)"` then confirm YAML validity with:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('action.yml')); print('action.yml OK')"
```

Expected: `action.yml OK` (no traceback).

- [ ] **Step 6: Commit**

```bash
git add action.yml
git commit -m "feat: post sticky PR comment with vulnerability summary and links"
```

---

### Task 4: CI — unit-test job and comment permissions (`.github/workflows/check.yml`)

**Files:**

- Modify: `.github/workflows/check.yml`

**Interfaces:**

- Consumes: `mise run test` (Task 1); the commenting step (Task 3) needs `pull-requests: write`.

- [ ] **Step 1: Add a `unit-test` job and grant PR-comment permission to the integration job**

Replace the contents of `.github/workflows/check.yml` with:

```yaml
name: Test gha-trivy Action

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  unit-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Set up mise
        uses: jdx/mise-action@e6a8b3978addb5a52f2b4cd9d91eafa7f0ab959d # v4.2.0

      - name: Run unit tests
        run: mise run test

  check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0

      - name: Create dummy file to scan
        run: |
          echo 'FROM alpine' > Dockerfile
          echo 'RUN apk add --no-cache curl' >> Dockerfile

      - name: Build test image
        run: |
          docker build -t test-gha-trivy:latest .

      - name: Run gha-trivy action
        uses: ./
        with:
          image-ref: test-gha-trivy:latest
          create-test-report: "true"
          create-summary: "true"
```

- [ ] **Step 2: Validate workflow YAML parses**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/check.yml')); print('check.yml OK')"
```

Expected: `check.yml OK`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/check.yml
git commit -m "ci: run pr-comment unit tests and grant PR comment permission"
```

---

### Task 5: Documentation (`README.md`, `CHANGELOG.md`)

**Files:**

- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:** none.

- [ ] **Step 1: Update `README.md`**

Replace the body of `README.md` with:

````markdown
# gha-trivy

Composite action for Trivy vulnerability scanning:

- add specific (default: CRITICAL) vulnerabilities to a JUnit test report
- create a HTML report on vulnerabilities and add it as artifact to the run
- add information to the run summary on types of vulnerabilities
- on pull requests, post a sticky PR comment with the vulnerability summary and links to the run and artifacts

## PR comment

When `create-pr-comment` is `true` (the default) and the workflow runs on a
`pull_request` event, the action posts a comment with the severity summary plus
links to the workflow run, the HTML report, and the SBOM. On re-runs the same
comment (one per report slug) is updated in place: the latest result stays on top,
a "change since last run" line shows per-severity deltas, and previous results are
kept in a collapsed history section that grows only when the counts change.

The calling workflow must grant the permission:

```yaml
permissions:
  contents: read
  pull-requests: write
```
````

If the token cannot write comments (permission not granted, or a pull request from a
fork where the token is read-only), the action emits a warning and continues without
failing. Set `create-pr-comment: "false"` to disable the comment entirely.

```

- [ ] **Step 2: Add a `CHANGELOG.md` entry**

Open `CHANGELOG.md`, read the existing top-of-file format, and add a new entry at the top matching that style (heading level, date format, bullet style) with text:

```

- feat: post a sticky PR comment with the vulnerability summary and links to the workflow run, HTML report, and SBOM; updated in place on re-runs with a change-only collapsed history (new input `create-pr-comment`, default `true`; requires `pull-requests: write`).

````

If the changelog is auto-generated from Conventional Commits (release-please/semantic-release style), skip manual editing and note in the commit body that the entry comes from the `feat:` commits instead.

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: document PR comment feature and required permission"
````

---

## Self-Review

**Spec coverage:**

- §1 new input & activation → Task 3 Step 1 (input), Step 4 (`if:` event+flag gate, `always()`).
- §2 warn-and-continue → Task 3 Step 4 (`try/catch` + `core.warning`).
- §3 counts marker / embedded state → Task 2 (template marker) + Task 3 Step 4 (parse + enrich into posted meta).
- §4 comment identity per slug → Task 1 `buildBody` slug marker + Task 3 find-by-marker.
- §5 links (run, report, SBOM; SBOM omitted when absent) → Task 3 Step 3 (`id:`s) + Step 4 (links object) + Task 1 (`buildBody` omits missing).
- §6 body & history rules (first/changed/unchanged, delta format) → Task 1 `buildBody` + tests.
- §7 `create-summary` interaction → Task 3 Step 2.
- §8 github-script + extracted tested module + `node --test` + mise task → Task 1 + Task 4.
- §9 docs → Task 5.
- Risks (fork PR, marker drift) → covered by warn-and-continue and `parseMeta` null-on-malformed (tested in Task 1).

**Placeholder scan:** No TBD/TODO; all code shown in full. Task 5 Step 2 intentionally defers to the existing changelog format (read-then-match) rather than guessing a header — this is a format-matching instruction, not a placeholder.

**Type consistency:** `buildBody` option shape, `parseMeta` return, and the `{counts, run:{number,url}, time, image}` meta object are consistent between Task 1 (module + tests), Task 2 (marker counts), and Task 3 (step usage). `REPORT_SLUG` env, `upload-sbom`/`upload-report` step ids, and `steps.*.outputs.artifact-url` names match between Task 3 steps.
