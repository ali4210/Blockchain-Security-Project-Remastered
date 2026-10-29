#!/usr/bin/env python3
"""
One-time key-ceremony script for the Stage 5 k-of-n quorum-approval layer
(src/wallet/quorum_signer.py). Run ONCE per environment, same role as
`softhsm2-util --init-token` for the HSM layer -- NOT re-run at pipeline
signing time.

Generates one real 32-byte quorum-approval secret, splits it via
src/wallet/shamir_engine.py's real Shamir Secret Sharing into
QUORUM_THRESHOLD-of-QUORUM_TOTAL_SHARES shares, writes each share to its own
file under ~/.local/state/soc-quorum/, and immediately zeroes the original
secret from memory (shamir_engine.zero_buffer). The full secret is never
written to disk anywhere, by any of this script's code paths.

k-of-n choice (2-of-3): no numeric threshold convention already exists in
this project (checked wallet_policy.py, drill_relayer_key_compromise.py --
neither names one). wallet_policy.py DOES already define exactly two named
operator principals (soc_operator, lead_incident_commander) and already
lists "shamir_reconstruct" as an authorized-operator-only action. 2-of-3
is the smallest threshold ShamirSecretSharing allows (threshold >= 2) that
still tolerates one share becoming unavailable, and maps onto this
project's own two named operator roles plus one additional held share
(e.g. a designated compliance/backup holder) without inventing principals
that don't exist here.

Usage: python3 scripts/provision-quorum-shares.py [--force]
"""
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.wallet.shamir_engine import ShamirSecretSharing, zero_buffer  # noqa: E402

QUORUM_THRESHOLD = 2
QUORUM_TOTAL_SHARES = 3
SHARE_DIR = Path(os.getenv("QUORUM_SHARE_DIR", str(Path.home() / ".local/state/soc-quorum")))


def main():
    force = "--force" in sys.argv
    SHARE_DIR.mkdir(parents=True, exist_ok=True)
    existing = sorted(SHARE_DIR.glob("share-*.json"))
    if existing and not force:
        print(f"[!] {len(existing)} share file(s) already present under {SHARE_DIR} -- "
              "refusing to overwrite an existing ceremony. Pass --force to regenerate "
              "(this invalidates every previously-issued share).")
        return 1

    secret_buf = bytearray(secrets.token_bytes(32))
    engine = ShamirSecretSharing()
    shares = engine.split_secret(bytes(secret_buf), QUORUM_THRESHOLD, QUORUM_TOTAL_SHARES)
    zero_buffer(secret_buf)
    del secret_buf

    for share in shares:
        path = SHARE_DIR / f"share-{share.index}.json"
        path.write_text(json.dumps(share.to_dict(), indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)

    print(f"[+] Quorum ceremony complete: {QUORUM_THRESHOLD}-of-{QUORUM_TOTAL_SHARES} "
          f"real Shamir shares written to {SHARE_DIR}")
    for share in shares:
        print(f"    - share-{share.index}.json (checksum {share.checksum[:16]}...)")
    print("[+] The original secret was never written to disk and has been zeroed from memory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
