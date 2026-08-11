# Web UI

A dashboard for reading a scan: findings ranked by severity, the evidence chain behind each
one, the minimised payload that reproduces it, and what was *not* tested.

```bash
agentshield scan --target http://127.0.0.1:8090 \
  --policy ./datasets/policies/support-agent.yml \
  --suite owasp-agentic \
  --json artifacts/report.json

agentshield ui --report artifacts/report.json
```

## What it shows

**Counts and the gate.** Severity totals, the exit code, and the severity the gate was set to.
The exit code is on screen because it is the contract - 0 clean, 1 findings at or above the
gate, 2 the scan could not be completed.

**Coverage.** Scenarios executed, skipped and errored, the threat model that selected them, and
every skipped scenario with its reason. This panel is the least exciting thing on the page and
the most important: a scan that quietly narrowed its own scope and reported nothing looks
exactly like a clean one.

**The evidence chain.** The reason a browser is worth having here. A finding is a sequence - a
document retrieved, a value lifted out of it, a tool called with that value - and reading it as
a timeline with the implicated steps marked beats reading it as a fenced block in Markdown. The
excerpts are redacted at the source, and the masks (`***[len=21]`) are highlighted so nobody
mistakes one for the value.

**The reproduction.** The minimised payload, and the `agentshield replay` command that re-runs
it. When minimisation could not reduce the payload it says so, because the report never
shows a payload it did not re-verify. `(no user prompt needed)` is the line to stop on:
the finding reproduces with no user input at all.

## No build step

No `package.json`, no bundler, no framework, no `node_modules`. Three files: `index.html`,
`app.js`, `styles.css`.

A real decision, not laziness about tooling. A dependency tree inside the tool that
renders your security findings is a supply chain nobody audited, and the page is one screen
with no state to manage - the case for a framework is that it saves you from the DOM, and there
are about three hundred lines of DOM here. `test_the_dashboard_ships_with_no_build_step` fails
the build if a lockfile appears.

The cost is real too: no type checking, no component tests, and hand-rolled rendering. If the
dashboard grows a scan history, filters that persist, and live editing, that trade flips.

## Report content is attacker-authored

The dashboard renders strings an attacker chose. Injected article text, tool arguments, the
agent's own answer - all of it is quoted verbatim in the report, because a scanner that
summarises the payload cannot prove anything about it.

So every value reaches the DOM through `textContent` and never as markup. There is one element
builder, `el()`, and it wraps non-Node children in a text node; there is no `html` helper to
reach for on a deadline. A security dashboard that renders its own findings as markup
would be the most reliable XSS vector in the deployment: the payload arrives already stored,
already reviewed, and already trusted by whoever opens the page.

`security-engine-python/tests/test_web_ui.py` asserts the unsafe sinks are absent from the
source and that the builder still appends text nodes. That is a structural check, not an
executed one - weaker than driving a browser, stronger than a comment.

## Why `agentshield ui` exists

The files are static and need no server. A browser refuses to `fetch` a sibling file over
`file://`, though, so opening `index.html` directly leaves the page unable to load the report
next to it. The command serves the directory and the report, read-only, bound to loopback, on
the standard library alone.

## Live mode is not built

Today the dashboard reads a report file. Against a running control plane it would also show:

| | Endpoint |
|---|---|
| Scan list | `GET /api/projects/{id}/scans` |
| Live progress | `GET /api/scans/{id}/events` (server-sent events) |
| Findings | `GET /api/scans/{id}/findings` |
| **Full step timeline** | `GET /api/findings/{id}/trajectory` |

That last one was added for this: the API returns the server-redacted steps a finding's
evidence indices point at. A report file carries evidence and reproductions, not raw
trajectories, so the timeline is the one view that genuinely needs the control plane - and
wiring it up is a fetch and a render function, not a redesign.

It is not built because the file-backed view is what a reader can actually run: the control
plane needs PostgreSQL and Kafka, and a screenshot of something nobody can start is worth less
than a page they can open in thirty seconds.
