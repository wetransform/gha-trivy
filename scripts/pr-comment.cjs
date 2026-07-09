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
