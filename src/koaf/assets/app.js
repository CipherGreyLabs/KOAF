"use strict";

const state = {
  report: null,
  category: "All",
  severity: "ALL",
  query: "",
  redacted: true
};

const severityOrder = ["HIGH", "MEDIUM", "LOW", "INFO"];
const categoryIcons = {
  Network: "⌁", DNS: "◎", External: "↗", Browser: "◈", Host: "▣", Engine: "!"
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function countSeverities(items) {
  const counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0};
  for (const item of items) {
    if (Object.hasOwn(counts, item.severity)) counts[item.severity] += 1;
  }
  return counts;
}

function setText(id, value) {
  document.getElementById(id).textContent = String(value);
}

function renderOverview() {
  const report = state.report;
  const findings = report.findings || [];
  const counts = countSeverities(findings);

  setText("versionLabel", "KOAF / v" + report.version);
  setText("highCount", counts.HIGH);
  setText("mediumCount", counts.MEDIUM);
  setText("lowCount", counts.LOW);
  setText("infoCount", counts.INFO);
  setText("totalNavCount", findings.length);
  setText("scopeLabel", report.external_enabled ? "EXTERNAL LOOKUPS ENABLED" : "LOCAL-FIRST CHECK");
  setText("externalBadge", report.external_enabled
    ? "External lookups explicitly enabled"
    : "External checks disabled");
  setText("privacyState", report.redacted ? "Sensitive values hidden" : "Sensitive values revealed");

  if (!findings.length) {
    setText("heroTitle", "No findings returned");
    setText("heroDescription", "No checks produced results. Review the terminal for errors.");
  } else if (counts.HIGH) {
    setText("heroTitle", "High-priority signals need review");
    setText("heroDescription", "Some checks identified potential exposure indicators. Read each finding before taking action.");
  } else if (counts.MEDIUM) {
    setText("heroTitle", "A few settings need attention");
    setText("heroDescription", "The scan completed. Review medium-priority findings and verify your expected network model.");
  } else {
    setText("heroTitle", "Audit completed successfully");
    setText("heroDescription", "No high- or medium-priority findings were reported by the checks performed.");
  }

  const bars = document.getElementById("severityBars");
  bars.replaceChildren();
  const highest = Math.max(1, ...Object.values(counts));
  for (const severity of severityOrder) {
    const row = element("div", "bar-row");
    const top = element("div", "bar-top");
    top.append(element("span", "", severity[0] + severity.slice(1).toLowerCase()));
    top.append(element("strong", "", counts[severity]));
    const track = element("div", "bar-track");
    const fill = element("div", "bar-fill bar-" + severity.toLowerCase());
    fill.style.width = ((counts[severity] / highest) * 100).toFixed(1) + "%";
    track.append(fill);
    row.append(top, track);
    bars.append(row);
  }

  const categories = [...new Set(findings.map((f) => f.category))];
  const ordered = ["Network", "DNS", "External", "Host", "Browser", "Engine"];
  categories.sort((a, b) => {
    const ai = ordered.indexOf(a);
    const bi = ordered.indexOf(b);
    return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || a.localeCompare(b);
  });
  const nav = document.getElementById("categoryNav");
  nav.replaceChildren();
  for (const category of ["All", ...categories]) {
    const button = element("button", "nav-link" + (state.category === category ? " active" : ""));
    button.type = "button";
    button.dataset.category = category;
    button.append(element("span", "nav-symbol", category === "All" ? "▦" : (categoryIcons[category] || "·")));
    button.append(document.createTextNode(category === "All" ? "Overview" : category));
    const count = category === "All"
      ? findings.length
      : findings.filter((finding) => finding.category === category).length;
    button.append(element("span", "nav-count", count));
    button.addEventListener("click", () => {
      state.category = category;
      renderOverview();
      renderFindings();
    });
    nav.append(button);
  }

  const alerts = (report.correlation_alerts || []).filter((item) => item.category !== "Summary");
  setText("alertCount", "(" + alerts.length + ")");
  const alertList = document.getElementById("alertList");
  alertList.replaceChildren();
  if (!alerts.length) {
    alertList.append(element("p", "helper-text", "No correlation alerts were generated."));
  } else {
    for (const alert of alerts) {
      const card = element("div", "alert");
      card.append(element("strong", "", alert.title));
      card.append(element("p", "", alert.details));
      alertList.append(card);
    }
  }

  const reveal = document.getElementById("revealButton");
  reveal.disabled = Boolean(report.redaction_locked);
  reveal.setAttribute("aria-pressed", String(!report.redacted));
  reveal.title = report.redaction_locked ? "Redaction locked by --redact" : "Toggle sensitive value visibility";
  setText("revealLabel", report.redaction_locked
    ? "Redaction locked" : report.redacted ? "Reveal values" : "Hide values");
}

function renderFindings() {
  const all = state.report.findings || [];
  const query = state.query.trim().toLowerCase();
  const visible = all.filter((item) => (
    (state.category === "All" || item.category === state.category) &&
    (state.severity === "ALL" || item.severity === state.severity) &&
    (!query || [item.title, item.category, item.status, item.details]
      .join(" ").toLowerCase().includes(query))
  )).sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) ||
    a.category.localeCompare(b.category) ||
    a.title.localeCompare(b.title)
  );

  setText("findingCount", "(" + visible.length + ")");
  const list = document.getElementById("findingsList");
  list.replaceChildren();

  if (!visible.length) {
    list.append(element("p", "empty-state", "No findings match your filters."));
    return;
  }

  for (const item of visible) {
    const row = element("article", "finding");
    const top = element("div", "finding-top");
    top.append(element("div", "finding-glyph", categoryIcons[item.category] || "•"));

    const main = element("div", "finding-main");
    main.append(element("div", "finding-category", item.category.toUpperCase()));
    main.append(element("div", "finding-title", item.title));
    main.append(element("div", "finding-status", item.status));
    top.append(main);
    const tag = element("span", "severity-tag severity-" + item.severity.toLowerCase(), item.severity);
    top.append(tag);
    row.append(top);

    if (item.details || item.evidence) {
      const detail = element("details");
      detail.append(element("summary", "", "Details & interpretation"));
      const body = element("div", "detail-body", item.details || "No explanation provided.");
      if (item.evidence) {
        body.append(element("div", "detail-evidence", "Evidence: " + item.evidence));
      }
      detail.append(body);
      row.append(detail);
    }
    list.append(row);
  }
}

async function loadReport(redacted) {
  const resource = new URL("api/report", window.location.href);
  resource.searchParams.set("redact", redacted ? "1" : "0");
  const response = await fetch(resource, {cache: "no-store", credentials: "omit"});
  if (!response.ok) throw new Error("The local report could not be loaded (" + response.status + ").");
  const report = await response.json();
  if (!Array.isArray(report.findings) || !Array.isArray(report.correlation_alerts)) {
    throw new Error("Unexpected KOAF report structure.");
  }
  state.report = report;
  state.redacted = report.redacted;
  renderOverview();
  renderFindings();
}

let toastTimer;
function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3600);
}

document.querySelectorAll(".filter").forEach((button) => {
  button.addEventListener("click", () => {
    state.severity = button.dataset.filter;
    document.querySelectorAll(".filter").forEach((b) => b.classList.toggle("active", b === button));
    if (state.report) renderFindings();
  });
});

document.getElementById("searchInput").addEventListener("input", (event) => {
  state.query = event.target.value;
  if (state.report) renderFindings();
});

document.getElementById("revealButton").addEventListener("click", async () => {
  if (!state.report || state.report.redaction_locked) return;
  const reveal = state.report.redacted;
  try {
    await loadReport(!reveal);
    showToast(reveal ? "Sensitive values are visible on this device." : "Sensitive values hidden.");
  } catch (error) {
    showToast(error.message);
  }
});

document.getElementById("exportButton").addEventListener("click", () => {
  if (!state.report) return;
  if (!state.report.redacted && !window.confirm(
    "This JSON contains sensitive identifiers. Export an unredacted copy?"
  )) return;
  const filename = "koaf-report-" + (state.report.redacted ? "redacted" : "sensitive") + ".json";
  const blob = new Blob([JSON.stringify(state.report, null, 2)], {type: "application/json"});
  const address = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = address;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(address), 1000);
  showToast("Report exported locally as " + filename);
});

loadReport(true).catch((error) => {
  setText("heroTitle", "Dashboard could not load");
  setText("heroDescription", error.message);
  showToast(error.message);
});
