#!/usr/bin/env python3
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

METRICS_FILE = Path("reports/metrics.prom")

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            if METRICS_FILE.exists():
                content = METRICS_FILE.read_text(encoding="utf-8").encode("utf-8")
            else:
                content = b"# No metrics yet\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return  # Suppress request spam

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9101), MetricsHandler)
    print("[+] [PROMETHEUS EXPORTER DAEMON] Serving metrics on http://0.0.0.0:9101/metrics...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
