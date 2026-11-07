
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

HOST = "0.0.0.0"
PORT = 8080


class ResearchAPI(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data, separators=(",", ":")).encode()

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):
        # Ignore query parameters when routing.
        path = self.path.split("?", 1)[0]

        if path == "/":
            return self.send_json({
                "service": "research-api",
                "status": "operational"
            })

        if path == "/diagnostics/":
            return self.send_json({
                "service": "research-api",
                "environment": "development",
                "version": "2.7.14-dev",
                "debug": True,
                "upstream": "research-api:8080"
            })

        if path == "/diagnostics/status":
            return self.send_json({
                "service": "research-api",
                "status": "healthy",
                "deployment": "MRS-DEV-042",
                "last_deployment": "2026-09-28",
                "debug_artifacts": True
            })

        if path == "/diagnostics/artifacts/latest":
            return self.send_json({
                "name": "deployment-verification",
                "environment": "development",
                "verification": "passed",
                "token": "VVVFLAG{2af20e1c0eedbdc1f829fc1cef86f30881038189896d4bdcf67ee545a81bf7cf}"
            })

        return self.send_json({
            "error": "not found"
        }, status=404)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), ResearchAPI)
    print(f"Research API listening on {HOST}:{PORT}")
    server.serve_forever()
