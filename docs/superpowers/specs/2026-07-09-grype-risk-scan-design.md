# Design: add grype risk scanning to `gha-trivy`

Date: 2026-07-09
Status: approved (brainstorming) — ready for implementation plan

## Summary

Extend the `gha-trivy` composite action to additionally scan the CycloneDX SBOM
(already produced by trivy) with [grype](https://github.com/anchore/grype), for
**reporting only**. Grype's risk score (0–100, combining CVSS impact × EPSS
probability, with a KEV boost and a ransomware-campaign boost) is surfaced in the
job summary and PR comment, including a configurable **risk threshold** and a
count of vulnerabilities at or above it, plus a top-10-by-risk list.

Grype never fails the build; trivy's `fail-for` remains the sole gate.

## Goals

- Scan the existing trivy-produced SBOM with grype (no separate SBOM).
- Report grype's risk-based results: severity counts, a headline count of
  vulnerabilities with `risk >= threshold`, and the top 10 vulnerabilities by
  risk.
- Configurable risk threshold (input + file fallback), default `40`.
- On by default for all consumers, with an opt-out flag.
- Track the risk-threshold count over time in the sticky PR comment (delta +
  history), the same way severity counts are tracked today.
- Upload grype's full output (JSON + a human-readable table) as artifacts.

## Non-goals

- Gating / failing the build on grype results (reporting only).
- Replacing or changing trivy's role (SBOM creation, JUnit gating, HTML report,
  severity summary all unchanged).
- Making the top-N count configurable (fixed at 10 — convention over
  configuration).

## Context (current action)

`action.yml` is a composite action that:

1. Creates a CycloneDX SBOM with trivy (`${REPORT_SLUG}-sbom.json`), or uses an
   existing one (`scan-ref`).
2. Scans that SBOM with trivy to produce: a JUnit report (gated by `fail-for` /
   `.trivy-fail-for`), an HTML report artifact, and a severity-count summary via
   `summary.tpl`.
3. `summary.tpl` writes `trivy.md` containing a severity table and a
   `<!-- gha-trivy-meta:{"counts":{...}} -->` marker.
4. A `github-script` step reads `trivy.md`, parses the marker via
   `scripts/pr-comment.cjs` (`parseMeta`), and builds/updates a sticky PR comment
   via `buildBody` — latest counts on top, a "change since last run" delta line,
   and a collapsed history that grows only when counts change.

Conventions to follow:

- All third-party actions are pinned by commit SHA with a `# vX.Y.Z` comment.
- Config has an input + a repo-root file fallback (e.g. `fail-for` /
  `.trivy-fail-for`); reuse existing enable gates where possible; minimize new
  knobs.
- Node CJS scripts live in `scripts/` with co-located `*.test.cjs`; `mise run
test` runs `node --test "scripts/**/*.test.cjs"`.
- `.github/workflows/check.yml` runs the action end-to-end against a built test
  image on every push/PR.

## Design

### 1. Role & resilience

- Grype scans the same SBOM file the action already has
  (`${REPORT_SLUG}-sbom.json`), reporting only.
- On by default via a new `grype-enabled` input (default `"true"`). The entire
  grype block is gated on this flag.
- Grype steps are resilient: `continue-on-error: true`, `fail-build: false`, and
  the summary script tolerates a missing/empty grype JSON (emit a warning, skip
  the grype section) so a DB-download hiccup or scan error degrades gracefully
  rather than failing the security job.

### 2. New inputs & configuration

| Input                  | Default  | Meaning                                                                          |
| ---------------------- | -------- | -------------------------------------------------------------------------------- |
| `grype-enabled`        | `"true"` | Master switch for the grype block.                                               |
| `grype-risk-threshold` | `""`     | Risk threshold on grype's 0–100 scale; resolved by a dedicated step (see below). |

Threshold resolution (mirrors "Determine fail-for severity"):

1. If `grype-risk-threshold` input is non-empty → use it.
2. Else if `.grype-risk-threshold` file exists at repo root → read its numeric
   content (trimmed).
3. Else default **`40`**.

The resolved value is validated as a number and exported as
`GRYPE_RISK_THRESHOLD`. Non-numeric content is an error (`::error::`, exit 1),
matching the strictness of the fail-for step.

Grype's RISK scale is **0–100** (confirmed). Top-N is fixed at **10**.

### 3. New action steps

Inserted after the SBOM is created/used/uploaded (so the SBOM file exists), all
gated on `grype-enabled == 'true'`:

1. **Determine grype risk threshold** → exports `GRYPE_RISK_THRESHOLD`. Placed
   near "Determine fail-for severity".
2. **Scan SBOM with grype** — one `anchore/scan-action` step, pinned by commit
   SHA with a `# v7.4.0` comment:
   - `sbom: ${{ env.REPORT_SLUG }}-sbom.json`
   - `grype-version: v0.115.0`
   - `output-format: json`
   - `output-file: ${{ env.REPORT_SLUG }}-grype.json`
   - `fail-build: false`
   - `cache-db: true`
   - `continue-on-error: true`
3. **Summarize** — `node ${GITHUB_ACTION_PATH}/scripts/grype-summary.cjs`, reads
   the grype JSON and the `GRYPE_RISK_THRESHOLD` env var, writes:
   - `grype.md` — human markdown fragment (headline + severity table + top-10).
   - `grype-meta.json` — structured data for the PR comment.
   - `${REPORT_SLUG}-grype.txt` — full findings-by-risk table (derived from the
     JSON; provides the "table" artifact without a second scan).
4. **Upload grype artifacts** (`actions/upload-artifact`, same version/retention
   as existing uploads): `${REPORT_SLUG}-grype.json` and
   `${REPORT_SLUG}-grype.txt`. Capture the artifact URL as a step output for the
   PR-comment links.
5. **Append `grype.md`** to `$GITHUB_STEP_SUMMARY` under a heading, gated on
   `create-summary == 'true'` (and grype-enabled).

Dropped vs. the earlier draft: manual grype install (jaxxstorm) and manual
grype-DB cache restore/save — `anchore/scan-action` handles install (via
`grype-version`) and DB caching (via `cache-db: true`).

### 4. New component: `scripts/grype-summary.cjs`

Pure, testable module + thin CLI wrapper (same shape as `pr-comment.cjs`).

Reads the grype JSON `matches[]`. For each match extracts (exact field paths
confirmed against real grype v0.115.0 JSON during implementation — see Risks):

- vulnerability id (e.g. `match.vulnerability.id`)
- severity (`match.vulnerability.severity`)
- risk score (numeric, 0–100)
- EPSS score/percentile
- KEV status (boolean)
- package name + version, fix state

Computes:

- **Severity counts** across grype's severity set (Critical, High, Medium, Low,
  Negligible, Unknown — normalized to a fixed ordered set).
- **`atOrAbove`** = number of matches with `risk >= threshold`.
- **`top`** = up to 10 matches sorted by risk descending (ties broken
  deterministically, e.g. by id) — always the overall top 10, regardless of
  threshold.

Renders `grype.md`:

- Headline: `⚠️ N vulnerabilities at/above risk threshold X` (`✅` when N = 0).
- Grype severity table.
- Top-10 table: **Vulnerability · Package · Sev · Risk · EPSS · KEV**.

Writes `grype-meta.json`:

```json
{
  "threshold": 40,
  "atOrAbove": 3,
  "severities": {
    "critical": 1,
    "high": 3,
    "medium": 4,
    "low": 2,
    "negligible": 0,
    "unknown": 0
  },
  "top": [
    {
      "id": "...",
      "pkg": "...",
      "severity": "...",
      "risk": 9.2,
      "epss": 0.87,
      "kev": true
    }
  ]
}
```

Writes `${REPORT_SLUG}-grype.txt`: full findings sorted by risk desc, same
columns as the top-10 table, as a plain-text/markdown table for the artifact.

Robustness: if the JSON file is absent, empty, or unparseable, log a warning and
exit 0 without writing `grype.md`/`grype-meta.json` (the downstream steps treat
their absence as "no grype section").

### 5. Data flow into the PR comment (`scripts/pr-comment.cjs`)

The existing `github-script` PR-comment step additionally reads
`grype-meta.json` (if present) and passes a `grype` object into `buildBody`.

`buildBody` is extended to accept `grype = { threshold, atOrAbove, severities,
top }` and:

- Render a **Grype (risk-based)** section in the comment body: headline count +
  grype severity table + top-10 table.
- Add a grype link to the links line (grype artifact URL) when available.
- Store `grype: { threshold, atOrAbove }` in the meta marker JSON (top-10 list is
  NOT persisted, to keep the marker small — history tracks the count).
- Include the risk count in the **delta line**: e.g. `Risk≥40: 3 (+1)`.
- Include the grype count in each **history entry** alongside the severity table.
- Treat a change in `atOrAbove` as a `changed` trigger for history (so a
  risk-count change updates history even if severities are unchanged).

Backward compatibility: `grype` is optional. When absent (grype disabled, or an
older meta marker with no grype field), `buildBody` behaves exactly as today —
no grype section, no risk delta, severity-only `changed` detection. `parseMeta`
already tolerates missing fields.

### 6. Testing

- **`scripts/grype-summary.test.cjs`** (new) with a committed sample grype JSON
  fixture covering: multiple severities, KEV, varying risk/EPSS, more than 10
  findings, and an unfixed vuln. Asserts: severity counts, `atOrAbove` for a
  chosen threshold, top-10 ordering and cap, and the rendered markdown/headline
  (including the `✅` zero case via a second fixture or threshold above all
  risks). Also asserts graceful handling of missing/empty/unparseable input.
- **`scripts/pr-comment.test.cjs`** (extend): grype section rendering; risk-count
  delta line; history entry includes the grype count; `changed` triggered by
  `atOrAbove` change alone; meta marker round-trip includes `grype`; and the
  no-`grype` path is unchanged (existing assertions still pass).
- `mise run test` auto-includes the new test file.
- `.github/workflows/check.yml` already runs the action against a built test
  image, exercising grype (install + DB + scan + summary + artifacts) end-to-end.

### 7. Documentation

- **README**: new "Grype risk scan" section describing the grype scan, the
  `grype-enabled` and `grype-risk-threshold` inputs, the `.grype-risk-threshold`
  file fallback, the 0–100 risk scale, the default threshold (40), and that it is
  reporting-only.
- **CHANGELOG**: entry for the grype risk-scan feature.

## Risks / to confirm during implementation

- **Exact grype JSON field paths** for `risk`, `epss`, and `kev` in grype
  v0.115.0 output — verify by running grype and inspecting the JSON; adjust the
  extraction in `grype-summary.cjs` accordingly. The rest of the design is
  independent of the exact paths.
- **`anchore/scan-action` behavior**: confirm `cache-db: true` persists the DB
  across runs (uses `actions/cache`); confirm `output-format: json` writes
  grype's native JSON (with risk/EPSS/KEV) to `output-file`; confirm
  `fail-build: false` disables the default medium-severity gate. Pin the action
  by the commit SHA for tag `v7.4.0`.
- **Vulnerability id form**: grype ids may be GHSA rather than CVE; the top-N
  column header is "Vulnerability" and shows grype's id verbatim (no `by-cve`
  normalization, to avoid dropping non-CVE advisories).
