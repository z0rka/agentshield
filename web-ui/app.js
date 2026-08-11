/**
 * AgentShield dashboard.
 *
 * Renders a scan report. No framework, no build step, no dependencies - see README.md for the
 * argument. The whole app is one module because it is one screen.
 *
 * Everything here treats the report as untrusted input. It is a document describing what an
 * attacker got an agent to do, and it contains attacker-authored strings verbatim: injected
 * document text, tool arguments, the agent's own output. Every value reaches the DOM through
 * `textContent`, never `innerHTML`. A dashboard that renders its own findings as markup is an
 * XSS vector wearing a security-tool costume.
 */

const SEVERITIES = ["critical", "high", "medium", "low"];

const state = {
  report: null,
  findings: [],
  selected: null,
  filter: "",
};

// -- loading ----------------------------------------------------------------------

async function load() {
  try {
    const response = await fetch("report.json", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`report.json returned ${response.status}`);
    }
    render(await response.json());
  } catch (error) {
    fail(
      error instanceof TypeError
        // `file://` cannot fetch a sibling. This is the whole reason `agentshield ui` exists,
        // so say so. A raw network error sends the reader looking in the wrong place.
        ? "The page could not read report.json. Opening index.html directly does not work: a browser refuses to fetch local files."
        : String(error.message || error),
    );
  }
}

function fail(message) {
  document.getElementById("loading").hidden = true;
  const panel = document.getElementById("error");
  panel.hidden = false;
  document.getElementById("error-message").textContent = message;
}

// -- top level --------------------------------------------------------------------

function render(report) {
  state.report = report;
  state.findings = (report.findings || []).slice().sort(bySeverityThenCode);

  document.getElementById("loading").hidden = true;
  document.getElementById("layout").hidden = false;

  renderMeta();
  renderGate();
  renderCounts();
  renderCoverage();
  renderList();

  if (state.findings.length > 0) {
    select(state.findings[0]);
  } else {
    document.getElementById("detail").replaceChildren(
      el("p", { class: "empty" }, "No findings. The scan ran and reported nothing."),
    );
  }
}

function bySeverityThenCode(a, b) {
  const rank = SEVERITIES.indexOf(String(a.severity).toLowerCase())
    - SEVERITIES.indexOf(String(b.severity).toLowerCase());
  return rank !== 0 ? rank : String(a.code).localeCompare(String(b.code));
}

function renderMeta() {
  const r = state.report;
  const counts = r.counts || {};
  const meta = document.getElementById("scan-meta");
  meta.replaceChildren(
    field("target", r.target),
    field("scenarios", `${counts.scenarios_executed ?? 0}/${counts.scenarios_selected ?? 0}`),
    field("dataset", r.dataset_version),
    field("policy", r.policy_hash),
  );
}

function field(label, value) {
  return el("span", {}, `${label} `, el("b", {}, String(value ?? "-")));
}

function renderGate() {
  const gate = state.report.gate || {};
  const node = document.getElementById("gate");
  const passed = gate.passed === true;
  node.className = `gate ${passed ? "passed" : "failed"}`;
  node.textContent = passed
    ? `PASSED · exit ${gate.exit_code ?? 0}`
    : `FAILED · exit ${gate.exit_code ?? 1}`;
  node.title = `Gate: fail on ${gate.fail_on ?? "HIGH"} or above`;
}

function renderCounts() {
  const counts = state.report.counts || {};
  document.getElementById("counts").replaceChildren(
    ...SEVERITIES.map((severity) => {
      const n = counts[severity] ?? 0;
      return el("div", { class: `count ${severity}${n === 0 ? " zero" : ""}` },
        el("span", { class: "n" }, String(n)),
        el("span", { class: "label" }, severity),
      );
    }),
  );
}

/**
 * What was *not* tested.
 *
 * The most useful panel on the page and the least exciting one. A scan that quietly narrowed
 * its own scope and reported no findings looks exactly like a clean one, so the skipped
 * scenarios and their reasons are shown next to the counts, never buried in the JSON.
 */
function renderCoverage() {
  const coverage = state.report.coverage || {};
  const counts = state.report.counts || {};
  const skipped = coverage.skipped || [];

  const dl = el("dl", {},
    el("dt", {}, "executed"), el("dd", {}, String(counts.scenarios_executed ?? 0)),
    el("dt", {}, "skipped"), el("dd", {}, String(counts.scenarios_skipped ?? skipped.length)),
    el("dt", {}, "errored"), el("dd", {}, String(counts.scenarios_errored ?? 0)),
    el("dt", {}, "suites"), el("dd", {}, String((coverage.suites || []).length)),
  );

  const section = el("section", { class: "coverage" }, el("h2", {}, "Coverage"), dl);

  if (coverage.threat_model) {
    section.append(el("p", { class: "note" }, coverage.threat_model));
  }

  if (skipped.length > 0) {
    const list = el("ul", { class: "skipped-list" });
    for (const entry of skipped) {
      list.append(el("li", {}, `${entry.template}: ${entry.reason}`));
    }
    section.append(
      el("details", {},
        el("summary", {}, `${skipped.length} scenario(s) not applicable to this target`),
        list,
      ),
    );
  }

  document.getElementById("coverage").replaceWith(section);
  section.id = "coverage";
}

// -- findings list ----------------------------------------------------------------

function renderList() {
  const container = document.getElementById("findings");
  const needle = state.filter.trim().toLowerCase();

  const matches = state.findings.filter((finding) => {
    if (!needle) return true;
    return searchText(finding).includes(needle);
  });

  if (matches.length === 0) {
    container.replaceChildren(el("p", { class: "no-matches" }, "Nothing matches that filter."));
    return;
  }

  container.replaceChildren(...matches.map(listItem));
}

function searchText(finding) {
  const tools = (finding.evidence && finding.evidence.tool_names) || [];
  return [finding.code, finding.title, finding.category, ...tools].join(" ").toLowerCase();
}

function listItem(finding) {
  const severity = String(finding.severity).toLowerCase();
  const button = el("button", {
    class: `finding ${severity}`,
    type: "button",
    "aria-current": String(state.selected === finding),
  },
    el("span", { class: "bar" }),
    el("span", { class: "body" },
      el("span", { class: "code" }, finding.code),
      el("p", { class: "title" }, finding.title),
    ),
  );
  button.addEventListener("click", () => select(finding));
  return button;
}

// -- detail -----------------------------------------------------------------------

function select(finding) {
  state.selected = finding;
  renderList();
  renderDetail(finding);
  document.getElementById("detail").scrollTop = 0;
}

function renderDetail(finding) {
  const severity = String(finding.severity).toLowerCase();
  const evidence = finding.evidence || {};
  const nodes = [
    el("h1", {}, finding.title),
    el("div", { class: "subhead" },
      el("span", { class: `severity-tag ${severity}` }, severity.toUpperCase()),
      el("span", {}, finding.code),
      el("span", {}, finding.category),
      el("span", {}, `${finding.occurrences ?? 1} occurrence(s)`),
      el("span", {}, `detected by ${(finding.detected_by || []).join(", ") || "-"}`),
    ),
  ];

  if (finding.description) {
    nodes.push(el("section", {}, el("h2", {}, "What happened"), el("p", {}, finding.description)));
  }

  nodes.push(evidenceSection(evidence));

  if (finding.reproduction) {
    nodes.push(reproductionSection(finding.reproduction));
  }
  if (finding.remediation) {
    nodes.push(remediationSection(finding.remediation));
  }

  document.getElementById("detail").replaceChildren(...nodes);
}

/**
 * The evidence chain.
 *
 * The reason this dashboard exists. A finding is a sequence - a document retrieved, a value
 * lifted out of it, a tool called with that value - and reading it as a timeline with the
 * implicated steps marked is meaningfully better than reading it as a fenced block in Markdown.
 *
 * The excerpts are already redacted by the engine. `AGEN***[len=24]` is enough to confirm the
 * match and not enough to use, and the mask is highlighted so nobody mistakes it for the
 * value.
 */
function evidenceSection(evidence) {
  const section = el("section", {}, el("h2", {}, "Evidence"));

  if (evidence.summary) {
    section.append(el("p", {}, evidence.summary));
  }

  const excerpts = Object.entries(evidence.excerpts || {});
  const cited = evidence.step_indices || [];

  if (excerpts.length > 0) {
    const chain = el("div", { class: "chain" });
    excerpts.forEach(([kind, text], index) => {
      chain.append(
        el("div", { class: "chain-step cited" },
          el("div", { class: "rail" },
            el("span", { class: "dot" }, String(cited[index] ?? index)),
            el("span", { class: "line" }),
          ),
          el("div", { class: "content" },
            el("span", { class: "kind" }, kind.replace(/_/g, " ")),
            maskedExcerpt(text),
          ),
        ),
      );
    });
    section.append(chain);
  }

  const meta = el("dl", { class: "meta-grid" });
  if (cited.length > 0) {
    meta.append(el("dt", {}, "steps"), el("dd", {}, cited.join(" → ")));
  }
  if ((evidence.tool_names || []).length > 0) {
    meta.append(el("dt", {}, "tools"), el("dd", {}, evidence.tool_names.join(", ")));
  }
  if (evidence.policy_path) {
    meta.append(el("dt", {}, "policy"), el("dd", {}, evidence.policy_path));
  }
  if (meta.childElementCount > 0) {
    section.append(meta);
  }

  section.append(el("p", { class: "note" },
    "Excerpts are redacted at the source. The full trajectory is available from the control "
    + "plane at /api/findings/{id}/trajectory; a report file carries evidence, not raw steps."));

  return section;
}

/** Splits a redacted excerpt so the `***[len=N]` masks are visible as masks, not as content. */
function maskedExcerpt(text) {
  const node = el("p", { class: "excerpt" });
  const pattern = /\*\*\*\[len=\d+\]|\[REDACTED:[^\]]*\]/g;
  let cursor = 0;
  for (const match of String(text).matchAll(pattern)) {
    if (match.index > cursor) {
      node.append(document.createTextNode(String(text).slice(cursor, match.index)));
    }
    node.append(el("span", { class: "redaction" }, match[0]));
    cursor = match.index + match[0].length;
  }
  node.append(document.createTextNode(String(text).slice(cursor)));
  return node;
}

/**
 * The minimised payload and how to re-run it.
 *
 * `minimized: false` is reported, never hidden. The report never shows a short payload it
 * did not verify, so a finding whose minimisation ran out of budget keeps the full one and
 * says so.
 */
function reproductionSection(repro) {
  const section = el("section", {}, el("h2", {}, "Reproduction"));

  if (repro.note) {
    section.append(el("p", { class: "note" }, repro.note));
  }

  const payload = [];
  payload.push(repro.prompt ? repro.prompt : "(no user prompt needed)");
  for (const injection of repro.injections || []) {
    payload.push(`--- planted in ${injection.channel} ---`);
    payload.push(injection.content || "");
  }
  section.append(el("pre", {}, el("code", {}, payload.join("\n"))));

  if (!repro.prompt && (repro.injections || []).length > 0) {
    section.append(el("p", { class: "note" },
      "No user input at all. Everything the agent did came out of content it retrieved."));
  }

  if (repro.command) {
    section.append(el("pre", {}, el("code", {}, repro.command)));
  }

  const meta = el("dl", { class: "meta-grid" },
    el("dt", {}, "scenario"), el("dd", {}, repro.scenario_id ?? "-"),
    el("dt", {}, "seed"), el("dd", {}, String(repro.seed ?? "-")),
    el("dt", {}, "minimised"), el("dd", {}, repro.minimized ? `yes (${repro.probes} probes)` : "no"),
  );
  section.append(meta);

  return section;
}

function remediationSection(remediation) {
  const section = el("section", {}, el("h2", {}, "Remediation"));

  if (remediation.summary) {
    section.append(el("p", {}, remediation.summary));
  }

  const controls = remediation.controls || [];
  if (controls.length > 0) {
    section.append(el("ul", { class: "controls" }, ...controls.map((c) => el("li", {}, c))));
  }

  return section;
}

// -- helpers ----------------------------------------------------------------------

/**
 * Element builder.
 *
 * Children are appended as text nodes unless they are already nodes, which is what keeps
 * attacker-authored strings out of the parser. There is no `html` helper here to reach for
 * on a deadline.
 */
function el(tag, attributes, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes || {})) {
    node.setAttribute(name, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

document.getElementById("filter").addEventListener("input", (event) => {
  state.filter = event.target.value;
  renderList();
});

load();
