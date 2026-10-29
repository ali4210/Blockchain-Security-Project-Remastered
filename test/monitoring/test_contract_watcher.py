"""Real tests for src/monitoring/contract_watcher.py (Phase 3c standing monitor).

The pure scan/diff functions and the debounce/concurrency/queueing logic in
ContractWatcher are tested with a FAKE run_pipeline (never spawns the real
pipeline -- that's the smoke test's job). real_run_pipeline() itself is
tested with real, trivial subprocesses (`true`/`false`/`sleep`) so its
process-lifecycle code (spawn, report handle, wait, terminate) is exercised
for real without needing the actual multi-minute pipeline.
"""
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from src.monitoring import contract_watcher as cw


# ---- scan_sol_files / diff_changes: pure, real filesystem logic -----------

def test_scan_sol_files_nonexistent_root_is_empty(tmp_path):
    assert cw.scan_sol_files(tmp_path / "does-not-exist") == {}


def test_scan_sol_files_only_matches_sol_extension(tmp_path):
    (tmp_path / "A.sol").write_text("contract A {}")
    (tmp_path / "notes.txt").write_text("not solidity")
    snapshot = cw.scan_sol_files(tmp_path)
    assert list(snapshot.keys()) == ["A.sol"]


def test_scan_sol_files_recurses_into_subdirectories(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "B.sol").write_text("contract B {}")
    snapshot = cw.scan_sol_files(tmp_path)
    assert "sub/B.sol" in snapshot


def test_diff_changes_detects_new_file():
    old = {"A.sol": 100.0}
    new = {"A.sol": 100.0, "B.sol": 200.0}
    assert cw.diff_changes(old, new) == ["B.sol"]


def test_diff_changes_detects_modified_mtime():
    old = {"A.sol": 100.0}
    new = {"A.sol": 150.0}
    assert cw.diff_changes(old, new) == ["A.sol"]


def test_diff_changes_ignores_unchanged_file():
    old = {"A.sol": 100.0}
    new = {"A.sol": 100.0}
    assert cw.diff_changes(old, new) == []


def test_diff_changes_ignores_deletions():
    old = {"A.sol": 100.0, "B.sol": 200.0}
    new = {"A.sol": 100.0}
    assert cw.diff_changes(old, new) == []


# ---- own-output-exclusion: watching exactly `root`, by construction -------

def test_files_outside_watched_root_are_never_detected(tmp_path):
    """A sibling directory (standing in for reports/, which is never inside
    contracts/solidity/ in the real layout) must have zero effect, since
    scan_sol_files only ever looks under the given root."""
    watched = tmp_path / "contracts_solidity"
    watched.mkdir()
    sibling_output = tmp_path / "reports"
    sibling_output.mkdir()

    events = []
    w = cw.ContractWatcher(root=watched, run_pipeline=lambda *a, **k: {"status": "ok", "exit_code": 0},
                          on_event=events.append)
    w.poll_once()
    (sibling_output / "run-output.sol").write_text("not a real contract, just proving scope")
    changed = w.poll_once()
    assert changed == []
    assert w.runs == []


# ---- ContractWatcher: debounce / serialized concurrency / queueing -------

def _watcher(tmp_path, run_pipeline=None, **kw):
    events = []
    w = cw.ContractWatcher(root=tmp_path, run_pipeline=run_pipeline, on_event=events.append, **kw)
    return w, events


def test_poll_once_does_nothing_when_no_changes(tmp_path):
    w, events = _watcher(tmp_path, run_pipeline=lambda *a, **k: pytest.fail("must not fire"))
    assert w.poll_once() == []
    assert w.runs == []


def test_poll_once_fires_one_real_run_per_new_file(tmp_path):
    calls = []

    def fake_run(cmd, path, on_proc_started=None):
        calls.append((cmd, path))
        return {"status": "ok", "exit_code": 0, "detail": "fake", "target": path}

    w, events = _watcher(tmp_path, run_pipeline=fake_run)
    (tmp_path / "A.sol").write_text("contract A {}")
    (tmp_path / "B.sol").write_text("contract B {}")
    changed = w.poll_once()

    assert changed == ["A.sol", "B.sol"]
    assert len(calls) == 2
    assert calls[0][1].endswith("A.sol") and calls[1][1].endswith("B.sol")
    assert all(cmd == cw.TRIGGER_CMD for cmd, _ in calls)
    assert len(w.runs) == 2


def test_runs_are_never_concurrent_new_change_is_queued_not_fired_immediately(tmp_path):
    """While the fake 'pipeline run' for A.sol is in progress, a second
    file (B.sol) appears and a poll happens -- it must be queued, not
    trigger a second, overlapping run."""
    order = []

    def fake_run(cmd, path, on_proc_started=None):
        order.append(("start", path))
        # Simulate a change landing WHILE this run is still "in progress" --
        # the watcher's _running flag must be true right now. Only do this
        # once, while processing A.sol -- otherwise B.sol's own (drained)
        # run would re-trigger the same simulation forever.
        if Path(path).name == "A.sol":
            (tmp_path / "B.sol").write_text("contract B {}")
            nested_changed = w.poll_once()
            order.append(("nested_poll_result", nested_changed))
        order.append(("end", path))
        return {"status": "ok", "exit_code": 0, "detail": "fake", "target": path}

    w, events = _watcher(tmp_path, run_pipeline=fake_run)
    (tmp_path / "A.sol").write_text("contract A {}")
    w.poll_once()

    # B.sol was detected by the nested poll but queued, not run concurrently.
    assert ("nested_poll_result", ["B.sol"]) in order
    starts = [p for kind, p in order if kind == "start"]
    assert len(starts) == 2  # A.sol's run, then B.sol's queued run drained afterwards
    assert starts[0].endswith("A.sol")
    assert starts[1].endswith("B.sol")
    assert any("queued" in e for e in events)
    assert any("draining" in e for e in events)


def test_multiple_queued_changes_all_drain_eventually(tmp_path):
    seen = []

    def fake_run(cmd, path, on_proc_started=None):
        name = Path(path).name
        seen.append(name)
        if name == "A.sol":
            (tmp_path / "B.sol").write_text("b")
            (tmp_path / "C.sol").write_text("c")
            w.poll_once()
        return {"status": "ok", "exit_code": 0}

    w, events = _watcher(tmp_path, run_pipeline=fake_run)
    (tmp_path / "A.sol").write_text("a")
    w.poll_once()

    assert seen[0] == "A.sol"
    assert sorted(seen[1:]) == ["B.sol", "C.sol"]
    assert len(w.runs) == 3


def test_pathological_self_retriggering_is_capped_not_infinite(tmp_path):
    """Defense-in-depth: if the triggered command ever did write into the
    watched directory (it doesn't today -- verified in the module
    docstring), this proves the watcher gives up loudly after
    MAX_CONSECUTIVE_DRAINS instead of looping/recursing forever."""
    call_count = [0]

    def fake_run(cmd, path, on_proc_started=None):
        call_count[0] += 1
        (tmp_path / "A.sol").write_text(f"contract A {{ /* {call_count[0]} */ }}")
        w.poll_once()
        return {"status": "ok", "exit_code": 0}

    w, events = _watcher(tmp_path, run_pipeline=fake_run)
    (tmp_path / "A.sol").write_text("contract A {}")
    w.poll_once()

    assert call_count[0] == cw.ContractWatcher.MAX_CONSECUTIVE_DRAINS + 1
    assert any("consecutive drain cycles" in e for e in events)
    assert w._pending == []


def test_stopped_watcher_does_not_fire_new_runs(tmp_path):
    calls = []
    w, events = _watcher(tmp_path, run_pipeline=lambda *a, **k: calls.append(1) or {"status": "ok"})
    w.stop()
    (tmp_path / "A.sol").write_text("a")
    changed = w.poll_once()
    assert changed == []
    assert calls == []


# ---- stop(): real process termination, no orphan -------------------------

def test_stop_terminates_a_real_in_progress_child_process(tmp_path):
    """Uses a REAL `sleep 30` subprocess (via real_run_pipeline) to prove
    stop() actually terminates a real running child rather than just
    flipping a flag. Runs the blocking _fire_batch call on a background
    thread so the main thread can call stop() while it's genuinely in
    progress, exactly like a signal handler would."""
    w = cw.ContractWatcher(root=tmp_path, trigger_cmd="sleep 30", run_pipeline=cw.real_run_pipeline,
                           on_event=lambda m: None)
    (tmp_path / "A.sol").write_text("a")

    thread = threading.Thread(target=w.poll_once)
    thread.start()

    # Give the real subprocess a moment to actually start.
    for _ in range(50):
        if w._current_proc is not None:
            break
        time.sleep(0.05)
    assert w._current_proc is not None, "real child process never started"
    pid = w._current_proc.pid

    start = time.monotonic()
    w.stop()
    stop_duration = time.monotonic() - start
    thread.join(timeout=5)

    assert not thread.is_alive()
    # A 30s sleep terminated via stop() must take nowhere near 30s.
    assert stop_duration < 5
    # The real OS process must actually be gone.
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_stop_terminates_the_whole_shell_process_group_not_just_the_shell(tmp_path):
    """Regression test for a real bug found live in the Phase 3c smoke
    test: trigger_cmd runs via shell=True, so the leaf command (here, a
    real `sleep`) is a GRANDCHILD of the tracked Popen, not the direct
    child. Signalling only the direct shell is not enough to guarantee the
    leaf dies promptly. start_new_session=True + os.killpg() in stop() must
    take down the whole real process group."""
    w = cw.ContractWatcher(root=tmp_path, trigger_cmd="echo start && sleep 30 && echo end",
                           run_pipeline=cw.real_run_pipeline, on_event=lambda m: None)
    (tmp_path / "A.sol").write_text("a")

    thread = threading.Thread(target=w.poll_once)
    thread.start()
    for _ in range(50):
        if w._current_proc is not None:
            break
        time.sleep(0.05)
    assert w._current_proc is not None
    shell_pid = w._current_proc.pid
    pgid = os.getpgid(shell_pid)

    # Find the real `sleep 30` grandchild via this exact process GROUP only
    # (not a system-wide cmdline substring scan -- this environment has an
    # unrelated, always-running `while true; do ...; sleep 30; done` real
    # service that would otherwise false-positive-match).
    import subprocess as sp
    sleep_pid = None
    for _ in range(50):
        members = sp.run(["pgrep", "-g", str(pgid)], capture_output=True, text=True).stdout.split()
        for pid_str in members:
            if int(pid_str) == shell_pid:
                continue
            try:
                cmdline = (Path("/proc") / pid_str / "cmdline").read_bytes().decode(errors="replace")
            except OSError:
                continue
            if "sleep" in cmdline:
                sleep_pid = int(pid_str)
                break
        if sleep_pid is not None:
            break
        time.sleep(0.05)
    assert sleep_pid is not None, "real sleep grandchild never appeared"

    start = time.monotonic()
    w.stop()
    duration = time.monotonic() - start
    thread.join(timeout=5)

    assert duration < 5  # nowhere near the real 30s sleep duration
    with pytest.raises(ProcessLookupError):
        os.kill(shell_pid, 0)
    with pytest.raises(ProcessLookupError):
        os.kill(sleep_pid, 0)  # the real regression: this used to still be alive


def test_request_stop_lets_the_real_blocked_wait_reap_the_child(tmp_path):
    """The actual production shape: Python always runs signal handlers on
    the MAIN thread, so to faithfully reproduce the real bug (a handler
    firing while THAT SAME thread is already blocked inside
    real_run_pipeline()'s own proc.wait()), poll_once() itself must run on
    the main thread here -- a background Timer just sends the real signal
    asynchronously, matching exactly how a real Ctrl+C/SIGTERM arrives in
    scripts/watch-contracts.py. request_stop() (never a blocking wait of
    its own) is all the handler does; proves the already-blocked outer
    wait() reaps the now-signalled child on its own."""
    w = cw.ContractWatcher(root=tmp_path, trigger_cmd="sleep 30", run_pipeline=cw.real_run_pipeline,
                           on_event=lambda m: None)
    (tmp_path / "A.sol").write_text("a")

    import signal as sig_mod
    pid_holder = []

    def watch_for_proc_then_signal():
        for _ in range(50):
            if w._current_proc is not None:
                pid_holder.append(w._current_proc.pid)
                break
            time.sleep(0.05)
        os.kill(os.getpid(), sig_mod.SIGUSR1)  # simulates the real Ctrl+C/SIGTERM delivery

    old_handler = sig_mod.signal(sig_mod.SIGUSR1, lambda signum, frame: w.request_stop())
    try:
        timer_thread = threading.Thread(target=watch_for_proc_then_signal)
        timer_thread.start()

        start = time.monotonic()
        w.poll_once()  # runs on THIS (the main) thread -- exactly like the real script
        duration = time.monotonic() - start
        timer_thread.join(timeout=5)
    finally:
        sig_mod.signal(sig_mod.SIGUSR1, old_handler)

    assert pid_holder, "real child process never started"
    pid = pid_holder[0]
    assert duration < 5  # real reap happened promptly, not after a 30s sleep
    assert w._stopped is True
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert len(w.runs) == 1
    assert w.runs[0]["exit_code"] != 0  # really killed, not a natural 0 exit


# ---- real_run_pipeline(): real subprocess lifecycle ------------------------

def test_real_run_pipeline_reports_and_clears_the_live_handle():
    handles = []
    result = cw.real_run_pipeline("true", "/tmp/fake-target.sol", on_proc_started=handles.append)
    assert result["status"] == "ok"
    assert result["exit_code"] == 0
    assert len(handles) == 2
    assert handles[0] is not None and handles[0].pid > 0
    assert handles[1] is None


def test_real_run_pipeline_reports_real_nonzero_exit():
    result = cw.real_run_pipeline("false", "/tmp/fake-target.sol")
    assert result["status"] == "error"
    assert result["exit_code"] == 1


def test_real_run_pipeline_sets_target_contract_env_for_the_child(tmp_path):
    marker = tmp_path / "seen_target.txt"
    result = cw.real_run_pipeline(f'echo "$TARGET_CONTRACT" > {marker}', "/real/changed/Path.sol")
    assert result["exit_code"] == 0
    assert marker.read_text().strip() == "/real/changed/Path.sol"


def test_real_run_pipeline_honest_error_when_command_cannot_start():
    with patch.object(cw.subprocess, "Popen", side_effect=OSError("no such command")):
        result = cw.real_run_pipeline("definitely-not-a-real-binary", "/tmp/x.sol")
    assert result["status"] == "error"
    assert result["exit_code"] is None
    assert "could not start pipeline" in result["detail"]
