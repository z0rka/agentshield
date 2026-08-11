"""`agentshield ui` - serve the dashboard over a JSON report.

The dashboard is static files and needs no server to render. This exists anyway, for one
reason: a browser will not `fetch` a sibling file over `file://`, so opening `index.html`
directly leaves the page unable to load the report next to it. Rather than teach the page a
second loading path that only works in one browser, the CLI serves the directory.

Read-only, bound to loopback, no dependencies beyond the standard library. It serves a
directory of static files and one JSON document; anything more would be a second web
application to secure, and the control plane already exists for that.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import webbrowser
from functools import partial
from pathlib import Path

#: Where the shipped dashboard lives, relative to the repository root.
WEB_UI_DIRNAME = "web-ui"


def locate_web_ui(explicit: str | None = None) -> Path:
    """Find the dashboard directory.

    Walks up from this file looking for `web-ui/index.html`, so the command works from a source
    checkout regardless of the working directory. An installed wheel has no dashboard, and the
    error says so; quietly serving an empty directory would be worse.
    """
    if explicit:
        path = Path(explicit).resolve()
        if not (path / "index.html").is_file():
            raise FileNotFoundError(f"no index.html in {path}")
        return path

    for parent in Path(__file__).resolve().parents:
        candidate = parent / WEB_UI_DIRNAME
        if (candidate / "index.html").is_file():
            return candidate

    raise FileNotFoundError(
        "could not find the web-ui directory. Pass --web-ui, or run from a source checkout."
    )


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Static files, plus `/report.json` served from wherever the report actually is.

    The report is usually outside the served directory - `artifacts/report.json` next to a
    scan - and serving its parent instead would publish whatever else is in there.
    """

    report_path: Path

    def do_GET(self) -> None:
        if self.path.split("?")[0] == "/report.json":
            self._serve_report()
            return
        super().do_GET()

    def _serve_report(self) -> None:
        try:
            body = self.report_path.read_bytes()
        except OSError as exc:
            self.send_error(404, f"report unavailable: {exc}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Re-read on every request, so `agentshield scan` in another terminal shows up on
        # refresh. Caching it would freeze the page on whichever scan ran first.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence. A request log for a local static server is noise over the scan output."""


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(
    report: Path,
    *,
    web_ui: Path,
    host: str = "127.0.0.1",
    port: int = 8099,
    open_browser: bool = True,
) -> None:
    """Serve the dashboard until interrupted."""
    report = report.resolve()
    if not report.is_file():
        raise FileNotFoundError(f"report not found: {report}")

    # Validated here, not in the browser: "unexpected token < in JSON" is a worse error
    # message than this one, and pointing the command at the Markdown report is an easy slip.
    try:
        json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{report} is not valid JSON: {exc}") from exc

    handler = partial(_Handler, directory=str(web_ui))
    handler.report_path = report  # type: ignore[attr-defined]
    _Handler.report_path = report

    with _Server((host, port), handler) as httpd:
        url = f"http://{host}:{port}/"
        print(f"AgentShield dashboard: {url}")
        print(f"Report: {report}")
        print("Ctrl-C to stop.")

        if open_browser:
            threading.Timer(0.5, webbrowser.open, args=[url]).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
