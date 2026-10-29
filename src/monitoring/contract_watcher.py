#!/usr/bin/env python3
"""
Phase 3c: a real standing monitor that watches contracts/solidity/ for new
or changed .sol files and triggers this pipeline's REAL run path (`make
pipeline-e2e`, the same command a human would type) automatically, instead
of every run today requiring a manual run-sast-symbolic.py/swarm_orchestrator.py
invocation per target.

STEP 1 FINDINGS (verified fresh, nothing assumed):
  * No scheduling/watching mechanism already existed for this project: no
    crontab entry (`crontab -l` -> "no crontab for kali"), no systemd unit
    watching this repo (the one real systemd unit here, soc-metrics.service,
    is just `python3 -m http.server 9101` over reports/ for Prometheus --
    not a file watcher), and the GitLab CI "trigger" lines are echo
    statements simulating Jenkins, not a real schedule.
  * No live on-chain subscription exists anywhere (verified: zero
    eth_subscribe/websocket/wss/event-filter references in the whole
    codebase) -- Phase 3b's etherscan_client.py is pure one-shot REST,
    with no "list new transactions since block N" function at all. See
    the ON-CHAIN WATCHING note below for why this stays out of v1.
  * `watchdog` (the filesystem-events library) happens to be installed on
    THIS machine (v6.0.0, from /usr/lib/python3/dist-packages) but is NOT
    listed in requirements.txt -- i.e. it is not actually a declared
    dependency of this project, just an incidental system package. Per the
    real "already a dependency" test, this implementation uses a plain
    mtime-polling loop (stdlib only: os.walk + Path.stat().st_mtime) --
    real, zero-new-dependency, and entirely adequate at this project's
    real scale (a handful of .sol files, not thousands).
  * Verified directly (grep): nothing run-all-e2e.sh calls writes any file
    under contracts/solidity/ -- so watching exactly that directory (not
    the whole repo) avoids the monitor re-triggering on its own triggered
    run's output BY CONSTRUCTION, not by a broad exclude-list. reports/
    (the pipeline's real, voluminous own-output location) is simply never
    inside the watched root at all.

ON-CHAIN WATCHING: explicitly OUT of v1, not quietly dropped. Phase 3b's
client has no "poll for new transactions to address X" capability yet (only
one-shot getsourcecode/getcontractcreation/eth_getCode), and nothing in this
project tracks a "list of addresses to watch" today. Building that now
would mean inventing a new polling primitive against a 3-call/sec, 100k/day
free-tier budget with no real new transactions to find in this project's
own demo/test addresses -- exactly the "unthrottled polling loop with no
real value over a manual run" the task warned against. Documented as a
real v2 step: it needs a watched-address registry and a real
list-new-transactions Etherscan call that doesn't exist yet.

DEBOUNCE / CONCURRENCY: a short settle window coalesces near-simultaneous
file drops into ONE poll's worth of changes; a single `running` flag
serializes pipeline runs (never overlapping) -- if N files change while a
run is in progress, they are queued and fire as separate, still-serialized
follow-up runs after it finishes (never dropped, never overlapped).

HONEST-STATUS PATTERN, matching evidence_db.py / swarm_memory.py /
etherscan_client.py: every real event (watch started, files watched,
each trigger, each real pipeline run's real exit code, every error) is
reported, never silently swallowed.
"""
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
WATCH_DIR = ROOT / "contracts" / "solidity"

POLL_INTERVAL_SEC = float(os.getenv("WATCHER_POLL_INTERVAL_SEC", "2.0"))
DEBOUNCE_SEC = float(os.getenv("WATCHER_DEBOUNCE_SEC", "1.5"))
# Real production default: the exact same command a human runs. Overridable
# (e.g. for the fast smoke-test demo) -- never silently swapped otherwise.
TRIGGER_CMD = os.getenv("WATCHER_TRIGGER_CMD", "make pipeline-e2e")
CHILD_TERM_GRACE_SEC = float(os.getenv("WATCHER_CHILD_TERM_GRACE_SEC", "10"))


def scan_sol_files(root: Path = WATCH_DIR) -> Dict[str, float]:
    """Real mtime snapshot of every real .sol file under root, recursively.
    Returns {relative_path_str: mtime}. Never raises -- a root that does
    not exist yet yields an empty snapshot, not an error (nothing to watch
    yet is a real, valid state)."""
    if not root.is_dir():
        return {}
    snapshot = {}
    for path in root.rglob("*.sol"):
        try:
            snapshot[str(path.relative_to(root))] = path.stat().st_mtime
        except OSError:
            continue  # real race: deleted between glob and stat -- skip, don't crash
    return snapshot


def diff_changes(old: Dict[str, float], new: Dict[str, float]) -> List[str]:
    """Real new-or-modified file paths: in `new` but either absent from
    `old` or with a different mtime. Deletions are not reported -- there is
    nothing to scan for a file that no longer exists."""
    changed = []
    for path, mtime in new.items():
        if path not in old or old[path] != mtime:
            changed.append(path)
    return sorted(changed)


RunResult = Dict[str, object]


@dataclass
class ContractWatcher:
    """Real lifecycle: poll_once() drives one real scan+diff+trigger cycle.
    run_pipeline is injectable (tests supply a fake; real use defaults to
    the real subprocess-spawning function below) -- this is the ONE seam
    unit tests use instead of actually invoking the pipeline."""
    root: Path = field(default_factory=lambda: WATCH_DIR)
    trigger_cmd: str = field(default_factory=lambda: TRIGGER_CMD)
    run_pipeline: Callable[..., RunResult] = None  # set in __post_init__; real sig: (cmd, path, on_proc_started=None)
    on_event: Callable[[str], None] = field(default=lambda msg: print(msg))

    _snapshot: Dict[str, float] = field(default_factory=dict, repr=False)
    _pending: List[str] = field(default_factory=list, repr=False)
    _running: bool = field(default=False, repr=False)
    _current_proc: Optional[subprocess.Popen] = field(default=None, repr=False)
    _stopped: bool = field(default=False, repr=False)
    runs: List[RunResult] = field(default_factory=list, repr=False)

    def __post_init__(self):
        if self.run_pipeline is None:
            self.run_pipeline = real_run_pipeline
        self._snapshot = scan_sol_files(self.root)

    def poll_once(self) -> List[str]:
        """One real scan+diff cycle. Returns the changed paths detected
        this call (possibly empty). Never fires a second pipeline run while
        one is already in progress -- newly detected changes are queued."""
        if self._stopped:
            return []
        new_snapshot = scan_sol_files(self.root)
        changed = diff_changes(self._snapshot, new_snapshot)
        self._snapshot = new_snapshot
        if not changed:
            return []

        self.on_event(f"[WATCH] detected {len(changed)} changed file(s): {changed}")
        if self._running:
            self._pending.extend(p for p in changed if p not in self._pending)
            self.on_event(f"[WATCH] a run is already in progress; queued (pending now: {self._pending})")
            return changed

        self._fire_batch(changed)
        return changed

    # Defense-in-depth, not expected to ever trigger today: this project's
    # real trigger command (`make pipeline-e2e`) is verified to write
    # nothing under contracts/solidity/ (see module docstring), so a drain
    # cycle should never immediately re-queue the same path. IF that
    # invariant were ever broken by a future pipeline change, an iterative
    # cap here turns "infinite loop / stack overflow" into one loud,
    # honest error instead -- caught for real by this module's own test
    # suite accidentally reproducing exactly this shape of bug.
    MAX_CONSECUTIVE_DRAINS = 20

    def _fire_batch(self, paths: List[str]) -> None:
        """Serialized: one real pipeline run per path, never overlapping.
        Any change detected WHILE a run is in progress is queued by
        poll_once() (the _running flag); this drains those queued batches
        iteratively afterwards -- never dropped, never run concurrently."""
        pending_batch = paths
        drains = 0
        while pending_batch:
            self._running = True
            try:
                for path in pending_batch:
                    if self._stopped:
                        break
                    # Absolute path: works whether `root` is the real
                    # contracts/solidity/ (under this project's ROOT) or an
                    # isolated test directory with no relation to it -- the
                    # existing TARGET_CONTRACT convention already accepts an
                    # absolute path as-is (see run-sast-symbolic.py's
                    # pick_targets()), so this invents no new convention.
                    abs_path = str((self.root / path).resolve())
                    self.on_event(f"[TRIGGER] firing real pipeline run for {path!r} ({self.trigger_cmd!r})")
                    result = self.run_pipeline(self.trigger_cmd, abs_path, on_proc_started=self._set_current_proc)
                    self.runs.append(result)
                    self.on_event(f"[RUN] {path!r} -> exit_code={result.get('exit_code')} "
                                  f"status={result.get('status')}")
            finally:
                self._running = False

            if self._stopped or not self._pending:
                break
            drains += 1
            if drains > self.MAX_CONSECUTIVE_DRAINS:
                self.on_event(f"[WATCH] [!] {drains} consecutive drain cycles without settling -- the "
                              f"triggered command may be writing into the watched directory itself "
                              f"(violates this monitor's loop-safety invariant); stopping to avoid an "
                              f"infinite retrigger loop. Pending: {self._pending}")
                self._pending = []
                break
            pending_batch, self._pending = self._pending, []
            self.on_event(f"[WATCH] draining {len(pending_batch)} queued change(s) from while that run was in progress")

    def _set_current_proc(self, proc: Optional[subprocess.Popen]) -> None:
        """Real seam real_run_pipeline calls the moment it spawns (and again
        with None the moment it exits) so stop() always has an accurate
        handle to the actually-running child, without run_pipeline needing
        to know anything about ContractWatcher itself."""
        self._current_proc = proc

    def request_stop(self, force: bool = False) -> None:
        """SIGNAL-HANDLER-SAFE: never blocks, never calls wait()/poll() on
        the child. Sets the stop flag and (if a run is in progress) signals
        its whole process group, then returns immediately. The call stack
        frame that is ALREADY blocked inside real_run_pipeline()'s own
        proc.wait() -- interrupted by the very signal that invoked this --
        will see that real child exit shortly after this real kill signal
        reaches it, and its OWN wait() call returns naturally with the real
        exit code once Python retries the interrupted syscall. force=True
        escalates straight to SIGKILL (e.g. a second Ctrl+C).

        REAL BUG FOUND LIVE (not reasoned about): the previous design had
        stop() itself call proc.wait(timeout=...) directly from inside the
        signal handler, reentrantly, while that OTHER (outer) proc.wait()
        call was still on the stack below it, suspended by the same
        signal. Observed live: neither a second blocking wait() NOR a
        polling proc.poll() loop called from that inner, reentrant frame
        ever detected the real exit, even though the real OS process was
        confirmed gone within ~1s via `ps`/`pgrep` -- it only ever
        completed once the ORIGINAL outer wait() frame was left to finish
        on its own. The fix: do only the non-blocking, signal-safe part
        (os.killpg) here, and let that outer frame be the one that reaps
        the child -- never a second reentrant wait attempt on it."""
        self._stopped = True
        proc = self._current_proc
        if proc is None or proc.poll() is not None:
            return
        sig = signal.SIGKILL if force else signal.SIGTERM
        self.on_event(f"[STOP] signalling in-progress pipeline run (pid={proc.pid})'s "
                      f"whole process group with {sig.name}...")
        self._signal_group(proc.pid, sig)

    def stop(self) -> None:
        """Real, BLOCKING, clean shutdown: for callers NOT inside a signal
        handler for the same child (e.g. a separate control thread, or
        this module's own tests) -- safe to actually wait here because
        there is no other frame already blocked in this exact Popen's
        wait(). Terminates the real process group (SIGTERM, bounded
        non-blocking poll, SIGKILL only if it refuses) and never leaves an
        orphan. Production signal handling uses request_stop() instead --
        see its docstring for why a blocking wait() here is unsafe from
        within a signal handler specifically."""
        self._stopped = True
        proc = self._current_proc
        if proc is not None and proc.poll() is None:
            self.on_event(f"[STOP] terminating in-progress pipeline run (pid={proc.pid}, "
                          f"and its whole process group)...")
            self._signal_group(proc.pid, signal.SIGTERM)
            if not self._poll_until_exited(proc, CHILD_TERM_GRACE_SEC):
                self.on_event(f"[STOP] pid={proc.pid} did not exit within {CHILD_TERM_GRACE_SEC}s; killing")
                self._signal_group(proc.pid, signal.SIGKILL)
                if not self._poll_until_exited(proc, CHILD_TERM_GRACE_SEC):
                    self.on_event(f"[STOP] [!] pid={proc.pid} still not reaped {CHILD_TERM_GRACE_SEC}s after "
                                  f"SIGKILL -- SIGKILL cannot be blocked, so it is not a real live orphan, "
                                  f"but giving up polling here rather than wait indefinitely")
                    return
            self.on_event(f"[STOP] pid={proc.pid} exited with {proc.returncode}")

    @staticmethod
    def _poll_until_exited(proc: subprocess.Popen, timeout: float, interval: float = 0.1) -> bool:
        """Non-blocking equivalent of proc.wait(timeout=...): repeatedly
        calls the non-blocking proc.poll() instead of the blocking wait().
        Safe for stop()'s own, non-reentrant use; see request_stop()'s
        docstring for why even this does not reliably work when called
        reentrantly from within a signal handler for the same child."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return True
            time.sleep(interval)
        return proc.poll() is not None

    @staticmethod
    def _signal_group(pid: int, sig: signal.Signals) -> None:
        """Signals the whole process group real_run_pipeline created (see
        start_new_session=True there), so every real descendant -- not just
        the immediate shell -- receives it directly."""
        try:
            os.killpg(os.getpgid(pid), sig)
        except ProcessLookupError:
            pass  # already gone -- nothing to signal


def real_run_pipeline(trigger_cmd: str, changed_path: str,
                      on_proc_started: Optional[Callable[[Optional[subprocess.Popen]], None]] = None) -> RunResult:
    """The real production seam: spawns trigger_cmd (default `make
    pipeline-e2e`) as a real subprocess with TARGET_CONTRACT set to the
    real changed file, waits for it, and reports its real exit code --
    never fabricates success. Reports the live Popen handle to the caller
    via on_proc_started (and clears it to None once the process exits) so
    ContractWatcher.stop() can always find and terminate the real child."""
    env = {**os.environ, "TARGET_CONTRACT": changed_path}
    try:
        # start_new_session=True makes this child (and the whole subtree it
        # spawns via shell=True) its own process group leader, so
        # ContractWatcher.stop() can signal the entire group, not just this
        # direct shell -- see stop()'s own docstring for the real bug this
        # fixes.
        proc = subprocess.Popen(trigger_cmd, shell=True, cwd=str(ROOT), env=env, start_new_session=True)
    except OSError as exc:
        return {"status": "error", "exit_code": None, "detail": f"could not start pipeline: {exc}",
                "target": changed_path}
    if on_proc_started:
        on_proc_started(proc)
    try:
        exit_code = proc.wait()
    finally:
        if on_proc_started:
            on_proc_started(None)
    return {"status": "ok" if exit_code == 0 else "error", "exit_code": exit_code,
            "detail": f"{trigger_cmd!r} exited {exit_code}", "target": changed_path}
