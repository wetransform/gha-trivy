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
