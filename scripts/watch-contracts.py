#!/usr/bin/env python3
"""Phase 3c CLI: run the real standing contract monitor
(src/monitoring/contract_watcher.py) in the foreground.

Usage:
  python3 scripts/watch-contracts.py
  WATCHER_TRIGGER_CMD="python3 scripts/run-sast-symbolic.py" python3 scripts/watch-contracts.py

Ctrl+C (SIGINT) or `kill <pid>` (SIGTERM) both trigger a real, clean
shutdown: the poll loop stops, and if a real pipeline run is in progress,
its whole process group is signalled (SIGTERM; a second Ctrl+C/SIGTERM
escalates to SIGKILL) and this script waits for the real exit before it
exits itself -- never an orphan.

The signal handler itself only ever calls ContractWatcher.request_stop(),
which never blocks: it just signals the real child and sets a flag. The
real wait for that child happens in the ALREADY-blocked call inside the
main loop below (real_run_pipeline's own proc.wait(), interrupted by the
signal, naturally resumes and returns once the now-signalled child exits)
-- see request_stop()'s docstring for the real reentrant-wait bug this
avoids.
"""
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.monitoring.contract_watcher import ContractWatcher, POLL_INTERVAL_SEC, WATCH_DIR, TRIGGER_CMD, ROOT  # noqa: E402


def main() -> int:
    watcher = ContractWatcher()
    print(f"[+] [WATCH] Standing contract monitor starting.")
    print(f"    -> watching: {WATCH_DIR.relative_to(ROOT)}")
    print(f"    -> poll interval: {POLL_INTERVAL_SEC}s")
    print(f"    -> trigger command: {TRIGGER_CMD!r}")
    print(f"    -> {len(watcher._snapshot)} real .sol file(s) in initial snapshot")

    signal_count = [0]

    def handle_signal(signum, _frame):
        name = signal.Signals(signum).name
        signal_count[0] += 1
        if signal_count[0] == 1:
            print(f"\n[+] [WATCH] received {name}; requesting clean shutdown "
                  f"(finishing the current step if one is running; press again to force)...")
            watcher.request_stop()
        else:
            print(f"\n[+] [WATCH] received {name} again; forcing immediate shutdown...")
            watcher.request_stop(force=True)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not watcher._stopped:
        watcher.poll_once()
        if watcher._stopped:
            break
        time.sleep(POLL_INTERVAL_SEC)
    print("[+] [WATCH] stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
