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

Workflows that also set `create-test-report: "true"` additionally need `checks: write` for the JUnit annotations.

If the token cannot write comments (permission not granted, or a pull request from a
fork where the token is read-only), the action emits a warning and continues without
failing. Set `create-pr-comment: "false"` to disable the comment entirely.
