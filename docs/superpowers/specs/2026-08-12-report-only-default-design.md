# Design: Report-only default for vulnerability gating

**Date:** 2026-08-12
**Status:** Approved

## Goal

Change the action's default behavior so that it no longer fails the workflow
for CRITICAL vulnerabilities. By default the action only reports (HTML report,
job summary, PR comment, grype risk scan). Failing the workflow becomes
opt-in: it happens only when a fail-for severity is explicitly configured via
the `fail-for` input or a `.trivy-fail-for` file at the repository root.

This is a **breaking change** for consumers that rely on the implicit
CRITICAL gate.

## Background

Failure is currently driven entirely by the JUnit report path:

1. The `determine-fail-for` step resolves `FAIL_FOR_EFFECTIVE` in the order:
   `fail-for` input → `.trivy-fail-for` file → default `CRITICAL`.
2. A Trivy scan filtered to `FAIL_FOR_EFFECTIVE` writes a JUnit report
   (when `junit-test-output` is set or `create-test-report` is true).
3. The `Publish Test Report` step (`fail_on_failure: true`) fails the
   workflow when that JUnit report contains findings.

## Changes

### 1. Fail-for resolution (`determine-fail-for` step)

Resolution order stays: `fail-for` input → `.trivy-fail-for` file. The final
fallback changes from `CRITICAL` to empty. An empty `FAIL_FOR_EFFECTIVE`
means **report-only mode**. Unrecognized content in `.trivy-fail-for` still
errors (unchanged).

### 2. JUnit scan step (the gate)

The gating scan runs only when `FAIL_FOR_EFFECTIVE != ''` **and**
(`junit-test-output != ''` or `create-test-report == 'true'`). In report-only
mode no gating scan happens at all.

This also fixes an existing bug: the current condition
`inputs.junit-test-output != '' || inputs.create-test-report` treats the
string `'false'` as truthy, so the JUnit scan always ran. The comparison
becomes `inputs.create-test-report == 'true'`. The same truthy-string pattern
in the `Check Docker image user` step condition is fixed the same way.

### 3. Empty JUnit report for external consumers

New step: when in report-only mode and `junit-test-output != ''`, write a
minimal JUnit file to that path so callers that consume the file in their own
workflow steps do not break on a missing file.

The file contains one **passing** testcase named
`no fail-for severity configured (report-only mode)` rather than a zero-test
suite: some JUnit consumers treat "no tests found" as an error, and a named
passing test self-documents why nothing is gated.

### 4. Publish Test Report step

Additionally conditioned on `FAIL_FOR_EFFECTIVE != ''`. In report-only mode
there is nothing to publish; skipping keeps the run clean of a pointless
check.

### 5. Unchanged behavior

The HTML report, job summary, PR comment, and grype risk scan are already
severity-unfiltered reporting and keep working exactly as today. When
`fail-for` or `.trivy-fail-for` is configured, gating behaves exactly as
before.

### 6. Documentation and release

- Update the `fail-for` input description in `action.yml` (no longer
  "default: CRITICAL"; document report-only default and resolution order).
- Update the README accordingly (it currently states "default: CRITICAL").
- Commit as a breaking change (`feat!:` / `BREAKING CHANGE:` footer) so the
  release workflow cuts a major version.

## Error handling

- Invalid `.trivy-fail-for` content: unchanged, the step errors.
- Missing file / empty input: report-only mode (new default), not an error.

## Testing

The repository has no workflow-level test harness for the composite action;
verification is by review of the conditions and a real workflow run.
Checklist for verification:

- No `fail-for` input, no `.trivy-fail-for` file: workflow passes even with
  CRITICAL findings; no JUnit gate check appears; reports/summary/PR comment
  still produced; if `junit-test-output` is set, the placeholder JUnit file
  exists and contains one passing test.
- `fail-for: CRITICAL` (or a `.trivy-fail-for` file): behaves as today,
  failing on matching findings.
- `create-test-report` left at default `'false'`: the gating scan does not
  run (bug fix), no test report is published.
