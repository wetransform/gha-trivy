# gha-trivy

Composite action for Trivy vulnerability scanning:

- add specific (default: CRITICAL) vulnerabilities to a JUnit test report
- create a HTML report on vulnerabilities and add it as artifact to the run
- add information to the run summary on types of vulnerabilities
- on pull requests, post a sticky PR comment with the vulnerability summary and links to the run and artifacts
- additionally scan the SBOM with [grype](https://github.com/anchore/grype) and
  report risk-based results (reporting only — grype never fails the build)

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

## Grype risk scan

In addition to the trivy scan, the action scans the same SBOM with
[grype](https://github.com/anchore/grype) for risk-based reporting. Grype's RISK
score (0–100, combining CVSS impact, EPSS exploit probability, and KEV / known
exploitation) is used to extend the summary and PR comment with:

- a count of vulnerabilities at or above a configurable risk threshold, and
- a table of the top 10 vulnerabilities by risk.

Grype is **reporting only** — it never fails the build. Trivy's `fail-for`
remains the sole gate. The full grype JSON and a plain-text findings table are
uploaded as an artifact.

The risk threshold defaults to `40` and is resolved in this order:

1. the `grype-risk-threshold` input, if set;
2. the content of a `.grype-risk-threshold` file at the repository root;
3. the default `40`.

Set `grype-enabled: "false"` to disable the grype scan entirely.
