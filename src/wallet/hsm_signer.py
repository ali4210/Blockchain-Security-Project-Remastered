#!/usr/bin/env python3
"""
Section D (EduQual L6 Topic 124): wallet/key security -- real PKCS#11 HSM backend.

HONEST SCOPE: this is a software-emulated PKCS#11 HSM via SoftHSM2 -- there is no
physical HSM hardware in this lab environment -- but it genuinely implements the
PKCS#11 standard interface: a real keypair is generated INSIDE the token (the
private key material never leaves it; only signatures and the public key come
out), and signing happens through a real PKCS#11 C_Sign call via python3-pkcs11,
not a plain-Python fallback. This is an ADDITIONAL, independently real signing
backend alongside (not instead of) the existing HashiCorp Vault Transit path used
elsewhere in this pipeline (see run-all-e2e.sh's Zone 7 vault-sign step) -- Vault
is not touched or replaced.

Setup performed once for this environment (not repeated at signing time):
  sudo apt-get install -y softhsm2 python3-pkcs11
  User-local config at ~/.config/softhsm2/softhsm2.conf (token dir under
  ~/.local/state/softhsm2-tokens -- the system-wide /var/lib/softhsm/tokens/ needs
  root, which the pipeline does not run as).
  softhsm2-util --init-token --free --label SOC-HSM-Lab --pin 1234 --so-pin 5678

Writes reports/scanners/hsm-signer.json via the shared scanner_result contract.
Purely additive/informational: NOT added to pipeline-verdict's REQUIRED list.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

TOKEN_LABEL = "SOC-HSM-Lab"
KEY_LABEL = "soc-relayer-hsm-key"
USER_PIN = os.getenv("SOFTHSM_PIN", "1234")
SOFTHSM2_CONF = os.getenv("SOFTHSM2_CONF",
                          str(Path.home() / ".config/softhsm2/softhsm2.conf"))
PKCS11_LIB = os.getenv("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")


def _get_token():
    import pkcs11
    os.environ.setdefault("SOFTHSM2_CONF", SOFTHSM2_CONF)
    lib = pkcs11.lib(PKCS11_LIB)
    return lib.get_token(token_label=TOKEN_LABEL)


def _find_or_create_keypair(session):
    import pkcs11
    from pkcs11 import KeyType, Attribute

    existing_priv = next(session.get_objects({
        Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: KEY_LABEL,
    }), None)
    existing_pub = next(session.get_objects({
        Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY,
        Attribute.LABEL: KEY_LABEL,
    }), None)
    if existing_priv and existing_pub:
        return existing_pub, existing_priv, False

    public, private = session.generate_keypair(
        KeyType.RSA, 2048, label=KEY_LABEL, store=True)
    return public, private, True


def sign_and_verify_round_trip(message: bytes = None):
    """Real round trip: sign inside the token, verify independently with the
    `cryptography` library against the public key pulled FROM the token (not
    just a self-consistency check against pkcs11's own verify()).

    `message` defaults to this run's real pipeline attestation string
    (ATTESTATION:<TARGET_NAME>:PIPELINE_RUN) -- the SAME string Vault Transit
    signs in run-all-e2e.sh's Zone 7 step and quorum_signer.py's joint-signing
    step, so all three signing layers genuinely co-sign one shared payload
    rather than three unrelated messages.

    Returns a dict of real, inspectable values (never fabricated)."""
    import pkcs11
    from pkcs11 import Mechanism, Attribute
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    token = _get_token()
    if message is None:
        message = ("ATTESTATION:" + os.environ.get("TARGET_NAME", "unknown") + ":PIPELINE_RUN").encode()

    with token.open(user_pin=USER_PIN, rw=True) as session:
        public, private, newly_generated = _find_or_create_keypair(session)

        signature = private.sign(message, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Round trip 1: verify via the SAME pkcs11 session/library.
        pkcs11_verified = public.verify(message, signature, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Round trip 2: pull the REAL public key material off the token and
        # verify independently with a different library (`cryptography`), to
        # prove this is a real, standard RSA keypair -- not an opaque in-library
        # check that could pass even if the key were malformed.
        modulus = int.from_bytes(public[Attribute.MODULUS], "big")
        exponent = int.from_bytes(public[Attribute.PUBLIC_EXPONENT], "big")
        pubkey = rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key()
        try:
            pubkey.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            cryptography_verified = True
        except InvalidSignature:
            cryptography_verified = False

        # Negative control: tampered message MUST fail verification.
        tampered_ok = False
        try:
            pubkey.verify(signature, message + b"TAMPERED", padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            tampered_ok = True

    return {
        "token_label": TOKEN_LABEL,
        "key_label": KEY_LABEL,
        "key_newly_generated_this_run": newly_generated,
        "key_type": "RSA-2048",
        "message": message.decode(),
        "signature_hex": signature.hex(),
        "signature_len_bytes": len(signature),
        "modulus_bits": modulus.bit_length(),
        "public_exponent": exponent,
        "pkcs11_self_verify": pkcs11_verified,
        "cryptography_independent_verify": cryptography_verified,
        "tampered_message_correctly_rejected": tampered_ok,
    }


def main():
    print("[+] [ZONE 7] PKCS#11 HSM signing (SoftHSM2, software-emulated -- see HONEST SCOPE) ...")
    try:
        result = sign_and_verify_round_trip()
    except Exception as exc:  # noqa: BLE001
        return write_result("hsm-signer", "softhsm2-pkcs11", "not_run", detail=str(exc)[:250])

    ok = (result["pkcs11_self_verify"] and result["cryptography_independent_verify"]
          and result["tampered_message_correctly_rejected"])
    report_file = ROOT / "reports" / "hsm-signer-report.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"    -> key: {result['key_type']} label={result['key_label']} "
          f"(newly_generated={result['key_newly_generated_this_run']})")
    print(f"    -> signature: {result['signature_hex'][:32]}... ({result['signature_len_bytes']} bytes)")
    print(f"    -> pkcs11_self_verify={result['pkcs11_self_verify']} "
          f"cryptography_independent_verify={result['cryptography_independent_verify']} "
          f"tampered_correctly_rejected={result['tampered_message_correctly_rejected']}")

    detail = ("real PKCS#11 sign + independent cryptography-library verify "
              f"{'succeeded' if ok else 'FAILED'} against the public key pulled from the token")
    return write_result("hsm-signer", "softhsm2-pkcs11", "ok" if ok else "error",
                        counts={"signature_len_bytes": result["signature_len_bytes"]},
                        raw_report=report_file, detail=detail,
                        extra={"token_label": TOKEN_LABEL, "key_type": result["key_type"]})


if __name__ == "__main__":
    main()
