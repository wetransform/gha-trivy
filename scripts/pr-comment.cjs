"use strict";

const grypeSummary = require("./grype-summary.cjs");

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
  const parts = [
    `#### run #${meta.run.number} · ${meta.time}`,
    "",
    renderTable(meta.counts),
  ];
  if (meta.grype) {
    parts.push("", `Risk≥${meta.grype.threshold}: ${meta.grype.atOrAbove}`);
  }
  return parts.join("\n");
}

function grypeDeltaLine(cur, prev) {
  const c = cur.atOrAbove ?? 0;
  const p = prev.atOrAbove ?? 0;
  const d = c - p;
  const tag = d === 0 ? "=" : d > 0 ? `+${d}` : `${d}`;
  return `Risk≥${cur.threshold}: ${c} (${tag})`;
}

function renderGrypeSection(grype) {
  if (!grype) return null;
  const headline =
    (grype.atOrAbove ?? 0) > 0
      ? `⚠️ ${grype.atOrAbove} at/above risk threshold ${grype.threshold}`
      : `✅ 0 at/above risk threshold ${grype.threshold}`;
  return [
    "**Grype (risk-based)**",
    "",
    headline,
    "",
    grypeSummary.renderSeverityTable(grype.severities || {}),
    "",
    "**Top by risk**",
    "",
    grypeSummary.renderTopTable(grype.top || []),
  ].join("\n");
}

// A previous marker is only usable if it carries everything buildBody needs to
// render a delta and a history entry. A marker that parses as JSON but is
// missing these fields (e.g. a hand-edited comment) is treated as marker drift:
// no previous state, start fresh — never throw.
function isUsablePrev(meta) {
  return !!(
    meta &&
    meta.counts &&
    meta.run &&
    meta.run.number != null &&
    meta.time
  );
}

function buildBody({
  slug,
  image,
  run,
  time,
  counts,
  links,
  existingBody,
  grype,
}) {
  const parsedPrev = parseMeta(existingBody);
  const prev = isUsablePrev(parsedPrev) ? parsedPrev : null;

  const severitiesChanged = !countsEqual(prev && prev.counts, counts);
  const grypeChanged =
    !!(grype && prev && prev.grype) &&
    (prev.grype.atOrAbove ?? 0) !== (grype.atOrAbove ?? 0);
  const changed = severitiesChanged || grypeChanged;

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
    deltaLine = severitiesChanged
      ? `Change since last run: ${computeDeltaLine(counts, prev.counts)}`
      : "Change since last run: no change";
  }
  let grypeDeltaStr = null;
  if (prev && prev.grype && grype) {
    grypeDeltaStr = grypeDeltaLine(grype, prev.grype);
  }

  const linkParts = [`[workflow run](${links.run})`];
  if (links.report) linkParts.push(`[HTML report](${links.report})`);
  if (links.sbom) linkParts.push(`[SBOM](${links.sbom})`);
  if (links.grype) linkParts.push(`[Grype report](${links.grype})`);

  const meta = { counts, run, time, image };
  if (grype) {
    meta.grype = { threshold: grype.threshold, atOrAbove: grype.atOrAbove };
  }
  const metaMarker = `<!-- gha-trivy-meta:${JSON.stringify(meta)} -->`;

  const lines = [
    `<!-- gha-trivy:${slug} -->`,
    `### Vulnerability summary (${image}) — latest: run #${run.number}`,
    "",
    renderTable(counts),
    "",
  ];
  if (deltaLine) lines.push(deltaLine);
  if (grypeDeltaStr) lines.push(grypeDeltaStr);
  const grypeSection = renderGrypeSection(grype);
  if (grypeSection) {
    lines.push("");
    lines.push(grypeSection);
  }
  lines.push("");
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
