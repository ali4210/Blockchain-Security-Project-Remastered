import json
import hashlib
from typing import Dict, Any

class SafeEmergencyPauseBuilder:
    """Constructs Gnosis Safe multisig transaction proposal payloads to trigger emergency contract pause."""

    def __init__(self, target_contract: str = "0x5FbDB2315678afecb367f032d93F642f64180aa3"):
        self.target_contract = target_contract

    def build_pause_calldata(self) -> Dict[str, Any]:
        # Function signature: pause() -> keccak256("pause()")[0:4] = 0x8456cb59
        func_sig = "pause()"
        method_id = "0x8456cb59"

        payload = {
            "to": self.target_contract,
            "value": "0",
            "data": method_id,
            "operation": 0, # Call
            "safeTxGas": 50000,
            "baseGas": 0,
            "gasPrice": 0,
            "gasToken": "0x0000000000000000000000000000000000000000",
            "refundReceiver": "0x0000000000000000000000000000000000000000",
            "nonce": 1
        }
        
        # Calculate mock SafeTxHash digest
        raw_repr = f"{payload['to']}:{payload['data']}:{payload['nonce']}"
        tx_hash = "0x" + hashlib.sha256(raw_repr.encode()).hexdigest()
        payload["safeTxHash"] = tx_hash

        return payload

if __name__ == "__main__":
    builder = SafeEmergencyPauseBuilder()
    tx = builder.build_pause_calldata()
    print(f"[+] Safe Emergency Proposal built: to={tx['to']} calldata={tx['data']} hash={tx['safeTxHash'][:18]}...")
