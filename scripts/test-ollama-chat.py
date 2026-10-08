#!/usr/bin/env python3
"""
Diagnostic CLI: Validate raw authenticated chat transport to Ollama (P05-003).
Safe to run in offline CI environments (emits fallback diagnostic instead of crashing).
"""

from pathlib import Path
import sys

# Ensure repository root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.llm_client.ollama_client import chat, get_ollama_base_url, get_auth_headers

def main() -> int:
    base_url = get_ollama_base_url()
    headers = get_auth_headers()
    has_auth = "Authorization" in headers

    print(f"[*] Target Ollama URL: {base_url}")
    print(f"[*] Bearer Auth Active: {has_auth}")

    test_messages = [
        {"role": "system", "content": "You are a blockchain security orchestrator."},
        {"role": "user", "content": "PING: Verify raw chat transport."},
    ]

    print("[*] Sending test chat request (Agent A / Qwen 2.5 Coder)...")
    response = chat(test_messages, force_agent="A", timeout=5.0)

    print(f"[+] Response received:\n{response}\n")
    if "[OFFLINE_FALLBACK]" in response:
        print("[!] Note: Running in offline simulation mode (live daemon unreachable).")
    else:
        print("[+] Live Ollama communication verified successfully.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
