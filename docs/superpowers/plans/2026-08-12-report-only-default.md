# Report-Only Default Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change the action's default so it never fails the workflow unless a fail-for severity is explicitly configured via the `fail-for` input or a `.trivy-fail-for` file.

**Architecture:** All behavior lives in the composite action `action.yml`. Failure is driven by a JUnit report: a Trivy scan filtered to `FAIL_FOR_EFFECTIVE` writes JUnit XML, and `mikepenz/action-junit-report` with `fail_on_failure: true` fails the workflow on findings. We make the `FAIL_FOR_EFFECTIVE` fallback empty (= report-only mode), gate the JUnit scan and publish steps on it being non-empty, and write a placeholder JUnit file for external consumers in report-only mode.

**Tech Stack:** GitHub composite action (YAML), bash. No test harness exists for the composite action — verification is by targeted grep of the edited conditions, the repo's pre-commit prettier hook (runs automatically on `git commit` via hk), and a real workflow run after release.

**Spec:** `docs/superpowers/specs/2026-08-12-report-only-default-design.md`

## Global Constraints

- Commit messages follow conventional commits (checked by CI). The behavior change in Task 1 MUST be committed as `feat!:` with a `BREAKING CHANGE:` footer so the release workflow cuts a major version.
- Action inputs are strings; boolean inputs must be compared with `== 'true'`, never used as bare truthy values in `${{ }}` expressions (the string `'false'` is truthy).
- `env.FAIL_FOR_EFFECTIVE` is set via `$GITHUB_ENV` in the `Determine fail-for severity` step and is readable in later steps' `if:` conditions through the `env` context (the action already relies on this pattern for `env.REPORT_SLUG` etc.).
- Do not change behavior when `fail-for` or `.trivy-fail-for` IS configured — gating must work exactly as before.
- End every commit message with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Report-only gating in action.yml

The four spec changes that only make sense together: empty fallback, gated JUnit scan (incl. truthy-string fix on that line), placeholder JUnit file, gated publish step. Committing them separately would leave broken intermediate states (e.g. an empty `severity:` passed to trivy-action).

**Files:**

- Modify: `action.yml:76-107` (Determine fail-for severity)
- Modify: `action.yml:252-269` (JUnit scan step)
- Modify: `action.yml` (new placeholder step after the JUnit scan step)
- Modify: `action.yml:511-523` (Publish Test Report)

**Interfaces:**

- Produces: `env.FAIL_FOR_EFFECTIVE` — comma-separated severities, or empty string meaning report-only mode. Task 3's docs describe this resolution order; no other task consumes it in code.

- [ ] **Step 1: Change the fail-for fallback to empty (report-only mode)**

In the `Determine fail-for severity` step, replace the final else-branch:

```bash
          else
            # Default to CRITICAL (original behavior)
            echo "FAIL_FOR_EFFECTIVE=CRITICAL" >> $GITHUB_ENV
          fi
```

with:

```bash
          else
            # Default: report-only mode, the workflow is not failed for vulnerabilities
            echo "FAIL_FOR_EFFECTIVE=" >> $GITHUB_ENV
          fi
```

Leave the input branch and the `.trivy-fail-for` mapping (including the error on unrecognized content) unchanged.

- [ ] **Step 2: Gate the JUnit scan step and fix its truthy-string condition**

In the step `Scan for critical vulnerabilities (create JUnit report)`, replace:

```yaml
if: "${{ inputs.junit-test-output != '' || inputs.create-test-report }}"
```

with:

```yaml
if: "${{ env.FAIL_FOR_EFFECTIVE != '' && (inputs.junit-test-output != '' || inputs.create-test-report == 'true') }}"
```

Everything else in the step (severity filter `${{ env.FAIL_FOR_EFFECTIVE }}`, template, output path) stays unchanged.

- [ ] **Step 3: Add the placeholder JUnit step for report-only mode**

Insert directly after the `Scan for critical vulnerabilities (create JUnit report)` step (i.e. between it and `Create vulnerability report as HTML`):

```yaml
# In report-only mode, still provide a JUnit file for callers that consume
# it outside the action. A single passing test is used instead of an empty
# suite because some JUnit consumers treat "no tests found" as an error.
- name: Create placeholder JUnit report (report-only mode)
  if: "${{ env.FAIL_FOR_EFFECTIVE == '' && inputs.junit-test-output != '' }}"
  shell: bash
  run: |
    cat > "${{ inputs.junit-test-output }}" <<'EOF'
    <?xml version="1.0" encoding="UTF-8"?>
    <testsuites name="trivy" tests="1" failures="0" errors="0">
      <testsuite name="trivy" tests="1" failures="0" errors="0">
        <testcase classname="trivy" name="no fail-for severity configured (report-only mode)"/>
      </testsuite>
    </testsuites>
    EOF
```

Note on the heredoc: inside the YAML block scalar the script is de-indented to the block's base indentation, so `EOF` must be at the same YAML indentation as `cat` (as shown) to terminate the heredoc. The XML lines keep two extra spaces of leading whitespace, which is irrelevant to XML consumers.

- [ ] **Step 4: Gate the Publish Test Report step**

In the `Publish Test Report` step, replace:

```yaml
if: ${{ always() && inputs.create-test-report == 'true' }} # always run even if the previous step fails
```

with:

```yaml
if: ${{ always() && env.FAIL_FOR_EFFECTIVE != '' && inputs.create-test-report == 'true' }} # always run even if the previous step fails
```

- [ ] **Step 5: Verify the edited conditions**

Run:

```bash
grep -n "FAIL_FOR_EFFECTIVE" action.yml
```

Expected: matches in exactly these places — the two `$GITHUB_ENV` writes in `Determine fail-for severity` (input branch, file branch), the empty write in the else-branch, the JUnit scan `if:` and its `severity:`, the placeholder step `if:`, and the publish step `if:`. No remaining `FAIL_FOR_EFFECTIVE=CRITICAL` default.

Run:

```bash
grep -n "inputs.create-test-report" action.yml
```

Expected: every occurrence inside `${{ }}` expressions compares with `== 'true'` **except** the `Check Docker image user` step (line ~167), which is fixed in Task 2.

- [ ] **Step 6: Commit (breaking change)**

```bash
git add action.yml
git commit -m "feat!: report-only by default, fail only when fail-for is configured

The action no longer defaults to failing the workflow for CRITICAL
vulnerabilities. Failing is now opt-in via the fail-for input or a
.trivy-fail-for file. In report-only mode with junit-test-output set,
a placeholder JUnit file with a single passing test is written so
downstream consumers of the file keep working. Also fixes the JUnit
scan step condition treating the string 'false' as truthy.

BREAKING CHANGE: without the fail-for input or a .trivy-fail-for file,
the action only reports and never fails the workflow. Set fail-for:
CRITICAL (or add a .trivy-fail-for file) to restore the previous
gating behavior.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

The pre-commit hook (hk → prettier) validates that `action.yml` still parses as well-formed YAML. If prettier reports a formatting issue, fix the indentation it complains about and re-commit.

---

### Task 2: Fix truthy-string condition in the image-user check

Same `'false'`-is-truthy bug as in the JUnit scan step, in the `Check Docker image user` step. Separate commit because it is an independent fix a reviewer could judge on its own.

**Files:**

- Modify: `action.yml:165-173` (Check Docker image user)

**Interfaces:**

- Consumes: nothing from Task 1 (independent condition fix).
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Fix the condition**

In the `Check Docker image user` step, replace:

```yaml
if: "${{ inputs.check-image-user == 'true' && inputs.image-ref != '' && (inputs.junit-test-output != '' || inputs.create-test-report) }}"
```

with:

```yaml
if: "${{ inputs.check-image-user == 'true' && inputs.image-ref != '' && (inputs.junit-test-output != '' || inputs.create-test-report == 'true') }}"
```

- [ ] **Step 2: Verify no bare boolean-input usages remain**

Run:

```bash
grep -nE "inputs\.(create-test-report|check-image-user|upload-scan-ref|create-summary|create-pr-comment|grype-enabled)" action.yml | grep -v "== 'true'" | grep -v "description\|default"
```

Expected: no output (every boolean input comparison uses `== 'true'`).

- [ ] **Step 3: Commit**

```bash
git add action.yml
git commit -m "fix: image-user check condition treated string 'false' as truthy

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Documentation

Update the `fail-for` input description and the README for the new report-only default.

**Files:**

- Modify: `action.yml:27-29` (`fail-for` input description)
- Modify: `README.md:5` (feature bullet) and new section after the intro list

**Interfaces:**

- Consumes: the resolution order produced by Task 1 (input → `.trivy-fail-for` file → report-only).
- Produces: nothing consumed by other tasks.

- [ ] **Step 1: Update the fail-for input description in action.yml**

Replace:

```yaml
fail-for:
  description: Issue types for fail for if they are present (added to JUnit report)
  default: "" # e.g. CRITICAL,HIGH
```

with:

```yaml
fail-for:
  description: Severities to fail the workflow for if present (added to JUnit report). Falls back to a .trivy-fail-for file; if neither is set the action only reports and never fails
  default: "" # e.g. CRITICAL,HIGH
```

- [ ] **Step 2: Update the README feature bullet**

Replace:

```markdown
- add specific (default: CRITICAL) vulnerabilities to a JUnit test report
```

with:

```markdown
- optionally fail the workflow for configured vulnerability severities via a
  JUnit test report (report-only by default)
```

- [ ] **Step 3: Add a "Failing the workflow" section to the README**

Insert after the intro bullet list, before the `## PR comment` section:

```markdown
## Failing the workflow

By default the action is **report-only**: it creates reports, summaries, and
PR comments, but never fails the workflow. To fail the workflow when
vulnerabilities of certain severities are present, configure the severities
to fail for. They are resolved in this order:

1. the `fail-for` input, if set (a comma-separated list, e.g. `CRITICAL,HIGH`);
2. the content of a `.trivy-fail-for` file at the repository root, which holds
   a single lowest severity (e.g. `HIGH` means fail for `CRITICAL,HIGH`);
3. otherwise the action is report-only and does not fail the workflow.

Failing works via the JUnit test report, so it additionally requires
`junit-test-output` to be set or `create-test-report: "true"`.

In report-only mode with `junit-test-output` set, a placeholder JUnit file
containing a single passing test is written to that path, so workflow steps
that consume the file keep working.
```

- [ ] **Step 4: Verify no stale "default: CRITICAL" references remain**

Run:

```bash
grep -rn "default: CRITICAL\|Default to CRITICAL" README.md action.yml
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add action.yml README.md
git commit -m "docs: document report-only default and fail-for resolution order

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Post-implementation verification (manual, from the spec)

Not part of the tasks (requires a real workflow run in a consuming repository, after a release):

- No `fail-for` input, no `.trivy-fail-for` file: workflow passes even with CRITICAL findings; no JUnit gate check appears; reports/summary/PR comment still produced; with `junit-test-output` set, the placeholder JUnit file exists and contains one passing test.
- `fail-for: CRITICAL` (or a `.trivy-fail-for` file): fails on matching findings, as before.
- `create-test-report` left at default `'false'` and no `junit-test-output`: the gating scan does not run (bug fix), no test report is published.
