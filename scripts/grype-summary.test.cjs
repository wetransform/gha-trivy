const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { analyze, renderSummary, main } = require("./grype-summary.cjs");

// Build a grype match with only the fields grype-summary reads.
const mkMatch = ({
  id,
  sev,
  risk,
  pkg = "libx",
  ver = "1.0",
  epss = null,
  kev = false,
}) => ({
  vulnerability: {
    id,
    severity: sev,
    risk,
    epss:
      epss == null
        ? []
        : [{ cve: id, epss, percentile: 0.9, date: "2026-01-01" }],
    knownExploited: kev ? [{ cve: id }] : [],
    fix: { state: "fixed", versions: [] },
  },
  artifact: { name: pkg, version: ver },
});

const doc = {
  matches: [
    mkMatch({
      id: "CVE-1",
      sev: "Critical",
      risk: 92.0,
      epss: 0.87,
      kev: true,
    }),
    mkMatch({ id: "CVE-2", sev: "High", risk: 60.0, epss: 0.4 }),
    mkMatch({ id: "CVE-3", sev: "High", risk: 41.0 }),
    mkMatch({ id: "CVE-4", sev: "Medium", risk: 39.5 }),
    mkMatch({ id: "CVE-5", sev: "Medium", risk: 20.0 }),
    mkMatch({ id: "CVE-6", sev: "Low", risk: 10.0 }),
    mkMatch({ id: "CVE-7", sev: "Low", risk: 9.0 }),
    mkMatch({ id: "CVE-8", sev: "Negligible", risk: 5.0 }),
    mkMatch({ id: "CVE-9", sev: "Unknown", risk: 4.0 }),
    mkMatch({ id: "CVE-10", sev: "High", risk: 55.0 }),
    mkMatch({ id: "CVE-11", sev: "High", risk: 50.0 }),
    mkMatch({ id: "CVE-12", sev: "Medium", risk: 30.0 }),
  ],
};

test("analyze computes severity counts across grype's severity set", () => {
  const r = analyze(doc, 40);
  assert.deepEqual(r.severities, {
    critical: 1,
    high: 4,
    medium: 3,
    low: 2,
    negligible: 1,
    unknown: 1,
  });
});

test("analyze counts vulnerabilities at/above threshold (inclusive)", () => {
  assert.equal(analyze(doc, 40).atOrAbove, 5);
  assert.equal(analyze(doc, 92).atOrAbove, 1);
  assert.equal(analyze(doc, 100).atOrAbove, 0);
});

test("analyze returns top 10 by risk desc, capped and tie-broken by id", () => {
  const r = analyze(doc, 40);
  assert.equal(r.top.length, 10);
  assert.deepEqual(
    r.top.map((f) => f.id),
    [
      "CVE-1",
      "CVE-2",
      "CVE-10",
      "CVE-11",
      "CVE-3",
      "CVE-4",
      "CVE-12",
      "CVE-5",
      "CVE-6",
      "CVE-7",
    ],
  );
  assert.equal(r.top[0].kev, true);
  assert.equal(r.top[0].epss, 0.87);
  assert.equal(r.top[0].pkg, "libx 1.0");
});

test("renderSummary shows warning headline, severity table and top table", () => {
  const md = renderSummary(analyze(doc, 40));
  assert.match(md, /⚠️ 5 vulnerabilities at\/above risk threshold 40/);
  assert.match(
    md,
    /\| Critical \| High \| Medium \| Low \| Negligible \| Unknown \|/,
  );
  assert.match(
    md,
    /\| Vulnerability \| Package \| Sev \| Risk \| EPSS \| KEV \|/,
  );
  assert.match(
    md,
    /\| CVE-1 \| libx 1\.0 \| Critical \| 92\.0 \| 0\.87 \| ✓ \|/,
  );
});

test("renderSummary shows check headline when none at/above threshold", () => {
  const md = renderSummary(analyze(doc, 100));
  assert.match(md, /✅ 0 vulnerabilities at\/above risk threshold 100/);
});

test("analyze tolerates missing/empty matches", () => {
  const r = analyze({}, 40);
  assert.equal(r.atOrAbove, 0);
  assert.equal(r.top.length, 0);
  assert.deepEqual(r.severities, {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    negligible: 0,
    unknown: 0,
  });
});

test("main writes grype.md/grype-meta.json/txt, and skips gracefully on bad input", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grype-"));
  const cwd = process.cwd();
  process.chdir(dir);
  try {
    const jsonPath = path.join(dir, "in-grype.json");
    fs.writeFileSync(jsonPath, JSON.stringify(doc));

    const code = main(
      ["node", "grype-summary.cjs", jsonPath, "out-grype.txt"],
      {
        GRYPE_RISK_THRESHOLD: "40",
      },
    );
    assert.equal(code, 0);
    assert.match(fs.readFileSync(path.join(dir, "grype.md"), "utf8"), /⚠️ 5 /);
    const meta = JSON.parse(
      fs.readFileSync(path.join(dir, "grype-meta.json"), "utf8"),
    );
    assert.equal(meta.atOrAbove, 5);
    assert.equal(meta.threshold, 40);
    assert.equal(meta.top.length, 10);
    assert.ok(fs.existsSync(path.join(dir, "out-grype.txt")));

    // Bad input: no files written, returns 0 (resilient).
    // Use fresh temp dir to ensure nothing from first call is present.
    const badDir = fs.mkdtempSync(path.join(os.tmpdir(), "grype-"));
    const badCwd = process.cwd();
    process.chdir(badDir);
    try {
      // Stub stderr to capture diagnostic without printing it.
      const stderrWrites = [];
      const origWrite = process.stderr.write;
      process.stderr.write = function (chunk) {
        stderrWrites.push(chunk);
        return true;
      };
      try {
        const code2 = main(
          ["node", "grype-summary.cjs", "does-not-exist.json"],
          {
            GRYPE_RISK_THRESHOLD: "40",
          },
        );
        assert.equal(code2, 0);
        // Verify the diagnostic was emitted.
        assert.ok(
          stderrWrites.some((w) => /no usable grype JSON/.test(w)),
          "Expected stderr diagnostic about missing grype JSON",
        );
      } finally {
        process.stderr.write = origWrite;
      }
      // Verify no output files were created.
      assert.equal(fs.existsSync(path.join(badDir, "grype.md")), false);
      assert.equal(fs.existsSync(path.join(badDir, "grype-meta.json")), false);
      assert.equal(fs.existsSync(path.join(badDir, "grype.txt")), false);
    } finally {
      process.chdir(badCwd);
    }
  } finally {
    process.chdir(cwd);
  }
});
