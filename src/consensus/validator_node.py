"""
Task P06-002: Local AVS Validator Node Microservice.
Coursework simulation service representing an individual AVS validator node.
Exposes /health and /vote endpoints to simulate PoC execution and issue signed votes.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import json
import os
import sys
from typing import Any, Dict

from src.consensus.avs_gate import VoteDecision


class ValidatorRequestHandler(BaseHTTPRequestHandler):
    validator_id: str = "validator-1"

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "validator_id": self.validator_id,
                "role": "avs_simulation_validator",
                "network": "local_coursework_simulation",
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self) -> None:
        if self.path == "/vote":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Invalid JSON body"})
                return

            finding_digest = payload.get("finding_digest", "")
            target_contract = payload.get("target_contract", "")

            # Deterministic simulation of local Anvil PoC replay
            receipt_hash = hashlib.sha256(f"{self.validator_id}:{finding_digest}:{target_contract}".encode("utf-8")).hexdigest()
            signature = hashlib.sha256(f"{self.validator_id}:SIG:{receipt_hash}".encode("utf-8")).hexdigest()

            self._send_json(200, {
                "validator_id": self.validator_id,
                "decision": VoteDecision.VALIDATED.value,
                "execution_receipt_hash": receipt_hash,
                "signature": signature,
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logging in production/tests
        pass


def run_node(port: int = 8081, validator_id: str = "validator-1") -> None:
    ValidatorRequestHandler.validator_id = validator_id
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, ValidatorRequestHandler)
    print(f"[+] Validator node '{validator_id}' listening on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    v_id = os.environ.get("VALIDATOR_ID", "validator-1")
    v_port = int(os.environ.get("VALIDATOR_PORT", "8081"))
    run_node(port=v_port, validator_id=v_id)
