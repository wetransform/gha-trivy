"use strict";

const fs = require("fs");

// Severity buckets in display order. Grype emits title-case severity strings.
const SEVERITIES = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["negligible", "Negligible"],
  ["unknown", "Unknown"],
];

const TOP_N = 10;

// Map a grype severity string to one of our bucket keys.
function severityKey(severity) {
  const s = String(severity || "").toLowerCase();
  return SEVERITIES.some(([k]) => k === s) ? s : "unknown";
}

// Extract a normalized finding from a grype match object.
function toFinding(match) {
  const v = (match && match.vulnerability) || {};
  const art = (match && match.artifact) || {};
  const epssArr = Array.isArray(v.epss) ? v.epss : [];
  const kevArr = Array.isArray(v.knownExploited) ? v.knownExploited : [];
  return {
    id: v.id || "",
    pkg: art.name ? `${art.name} ${art.version || ""}`.trim() : "",
    severity: v.severity || "Unknown",
    risk: typeof v.risk === "number" ? v.risk : 0,
    epss:
      epssArr.length && typeof epssArr[0].epss === "number"
        ? epssArr[0].epss
        : null,
    kev: kevArr.length > 0,
  };
}

function findings(doc) {
  const matches = doc && Array.isArray(doc.matches) ? doc.matches : [];
  return matches.map(toFinding);
}

function byRiskDesc(a, b) {
  return b.risk - a.risk || a.id.localeCompare(b.id);
}

// Analyze a grype document against a numeric risk threshold.
function analyze(doc, threshold) {
  const all = findings(doc);
  const severities = Object.fromEntries(SEVERITIES.map(([k]) => [k, 0]));
  for (const f of all) severities[severityKey(f.severity)] += 1;
  const atOrAbove = all.filter((f) => f.risk >= threshold).length;
  const top = [...all].sort(byRiskDesc).slice(0, TOP_N);
  return { threshold, atOrAbove, severities, top };
}

function renderSeverityTable(severities) {
  const s = severities || {};
  const header = "| " + SEVERITIES.map(([, l]) => l).join(" | ") + " |";
  const sep = "| " + SEVERITIES.map(() => "---").join(" | ") + " |";
  const row = "| " + SEVERITIES.map(([k]) => s[k] ?? 0).join(" | ") + " |";
  return [header, sep, row].join("\n");
}

function fmtRisk(risk) {
  return (typeof risk === "number" ? risk : 0).toFixed(1);
}

function fmtEpss(epss) {
  return epss == null ? "-" : epss.toFixed(2);
}

function renderTopTable(list) {
  if (!list || !list.length) return "_No vulnerabilities found._";
  const header = "| Vulnerability | Package | Sev | Risk | EPSS | KEV |";
  const sep = "| --- | --- | --- | --- | --- | --- |";
  const rows = list.map(
    (f) =>
      `| ${f.id} | ${f.pkg} | ${f.severity} | ${fmtRisk(f.risk)} | ${fmtEpss(
        f.epss,
      )} | ${f.kev ? "✓" : ""} |`,
  );
  return [header, sep, ...rows].join("\n");
}

function renderSummary({ threshold, atOrAbove, severities, top }) {
  const headline =
    atOrAbove > 0
      ? `⚠️ ${atOrAbove} vulnerabilities at/above risk threshold ${threshold}`
      : `✅ 0 vulnerabilities at/above risk threshold ${threshold}`;
  return [
    headline,
    "",
    renderSeverityTable(severities),
    "",
    `**Top ${TOP_N} by risk**`,
    "",
    renderTopTable(top),
    "",
  ].join("\n");
}

// Full findings table (all findings by risk) for the uploaded text artifact.
function renderFullTable(doc) {
  return renderTopTable([...findings(doc)].sort(byRiskDesc));
}

function readDoc(inputPath) {
  if (!inputPath || !fs.existsSync(inputPath)) return null;
  const raw = fs.readFileSync(inputPath, "utf8").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// CLI: node grype-summary.cjs <input.json> [output.txt]
// Writes grype.md + grype-meta.json to cwd, and the full table to output.txt.
// Missing/empty/unparseable input is not an error: warn and skip (resilience).
function main(argv, env) {
  const doc = readDoc(argv[2]);
  if (!doc) {
    process.stderr.write(
      "grype-summary: no usable grype JSON; skipping grype section\n",
    );
    return 0;
  }
  const threshold = Number(env.GRYPE_RISK_THRESHOLD);
  const result = analyze(doc, threshold);
  fs.writeFileSync("grype.md", renderSummary(result));
  fs.writeFileSync(
    "grype-meta.json",
    JSON.stringify({
      threshold: result.threshold,
      atOrAbove: result.atOrAbove,
      severities: result.severities,
      top: result.top,
    }),
  );
  fs.writeFileSync(argv[3] || "grype.txt", renderFullTable(doc));
  return 0;
}

if (require.main === module) {
  process.exit(main(process.argv, process.env));
}

module.exports = {
  SEVERITIES,
  TOP_N,
  severityKey,
  toFinding,
  analyze,
  renderSeverityTable,
  renderTopTable,
  renderSummary,
  renderFullTable,
  main,
};
