#!/usr/bin/env python3
"""
N2 - GHOST IN THE WIRE
Participant evidence portal.

A deliberately tiny static-file server built on Python's standard library
(http.server). No Flask, no external runtime dependencies, no build step.

Serves:
  - /                      -> briefing + objectives + evidence links (index.html)
  - /evidence/<name>       -> the four evidence files (read-only, allowlist only)

Security:
  - Only an allowlist of evidence filenames may be served. Anything else is
    404. There is no directory listing and no path that escapes evidence/.
  - Organizer files are not present in this image (Dockerfile COPYs only
    evidence/ and portal/).
  - No flag values, secrets, or organizer scripts are reachable.
  - Runs as a non-root user inside the container.

The portal does NOT validate flags. CTFd (or the shared VVV platform) handles
submission; the briefing links participants to the configured CTFd URL.
"""

from __future__ import annotations

import html
import http.server
import os
import socketserver
import sys
from pathlib import Path

PORTAL_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = PORTAL_DIR / "templates"
STATIC_DIR = PORTAL_DIR / "static"

# Evidence directory. Mounted read-only from ../evidence at runtime, but also
# baked into the image for local runs.
EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", PORTAL_DIR.parent / "evidence"))

# Allowlist of evidence files participants may download. Anything else is 404,
# which closes the path-traversal / dot-segment class of attacks by design.
EVIDENCE_FILES = {
    "network_capture.pcap": "application/vnd.tcpdump.pcap",
    "dns_resolver.log": "text/plain; charset=utf-8",
    "dhcp_leases.csv": "text/csv; charset=utf-8",
    "repository_audit.log": "text/plain; charset=utf-8",
}

CTFD_URL = os.environ.get("CTFD_URL", "").strip()  # e.g. https://ctfd.parsec.iith...

INDEX_HTML = (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "N2Portal/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers -----------------------------------------------------------
    def _send_bytes(self, code: int, body: bytes, ctype: str,
                    extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_text(self, code: int, text: str, ctype: str = "text/html; charset=utf-8") -> None:
        self._send_bytes(code, text.encode("utf-8"), ctype)

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        # Normalize: no dot-segments ever reach the filesystem unvalidated.
        if path == "/" or path == "/index.html":
            body = INDEX_HTML
            if CTFD_URL:
                body = body.replace("{{CTFD_URL}}", html.escape(CTFD_URL))
            else:
                body = body.replace("{{CTFD_URL}}", "#")
            self._send_text(200, body)
            return

        if path.startswith("/evidence/"):
            name = path[len("/evidence/"):]
            # Hard allowlist. Reject anything containing path separators, dots
            # used for traversal, or anything not in the set.
            if name not in EVIDENCE_FILES:
                self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")
                return
            fpath = EVIDENCE_DIR / name
            if not fpath.is_file():
                self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")
                return
            ctype = EVIDENCE_FILES[name]
            data = fpath.read_bytes()
            extra = {"Content-Disposition": f'attachment; filename="{name}"'}
            self._send_bytes(200, data, ctype, extra)
            return

        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            # allowlist static assets by extension; no traversal
            if "/" in rel or ".." in rel or rel == "":
                self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")
                return
            allowed_ext = {".css", ".svg", ".png", ".ico", ".js"}
            ext = os.path.splitext(rel)[1].lower()
            if ext not in allowed_ext:
                self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")
                return
            fpath = STATIC_DIR / rel
            if not fpath.is_file():
                self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")
                return
            ctype = {
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
                ".png": "image/png", ".ico": "image/x-icon", ".js": "text/javascript",
            }[ext]
            self._send_bytes(200, fpath.read_bytes(), ctype)
            return

        self._send_text(404, "Not Found\n", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:
        # reuse GET logic but suppress body via _send_bytes when GET not invoked
        self.do_GET()

    def do_POST(self) -> None:  # no flag submission here
        self._send_text(405, "Method Not Allowed\n", "text/plain; charset=utf-8")

    def do_PUT(self) -> None:
        self._send_text(405, "Method Not Allowed\n", "text/plain; charset=utf-8")

    def do_DELETE(self) -> None:
        self._send_text(405, "Method Not Allowed\n", "text/plain; charset=utf-8")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    if not EVIDENCE_DIR.is_dir():
        sys.stderr.write(f"[portal] WARNING: evidence dir not found: {EVIDENCE_DIR}\n")
    srv = Server((host, port), Handler)
    sys.stderr.write(f"[portal] N2 evidence portal listening on {host}:{port}\n"
                     f"[portal] evidence dir: {EVIDENCE_DIR}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
