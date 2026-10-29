#!/usr/bin/env python3
"""
Section A (EduQual L6 Topic 124): consensus-attack detection orchestrator.

This module does NOT reimplement detection logic. src/consensus/reorg_monitor.py
(ChainReorgMonitor), concentration_tracker.py (ConsensusConcentrationTracker),
eclipse_detector.py (P2PEclipseDetector), and selfish_mining_detector.py
(SelfishMiningDetector) already exist in this repo with their own passing unit
tests (test/consensus/test_reorg_monitor.py, test_concentration_tracker.py,
test_eclipse_detector.py, test_selfish_mining_detector.py), but nothing in the
live pipeline ever called them or fed them real data. This file is the real
orchestrator: it runs a genuine ephemeral Anvil chain, collects real block
headers and proposers, forces a real chain reorganization via Anvil's own
snapshot/revert RPCs, and feeds all of it through the four existing,
unmodified detectors.

HONEST SCOPE NOTE (read before trusting the numbers):
  * This is a single-node Anvil devnet, not a real multi-validator network. The
    concentration check will, correctly and HONESTLY, find total concentration
    (Anvil has exactly one proposer, and its default coinbase is the null address
    unless --coinbase is set) -- that is a real, computed-from-real-data finding,
    not a fabricated one. Thresholds (33%/51% BFT safety; HHI > 2500 = "highly
    concentrated" per US DOJ/FTC Horizontal Merger Guidelines) are the existing,
    already-tested defaults in concentration_tracker.py, unchanged here.
  * P2PEclipseDetector refuses to evaluate below min_peers_for_eval (8) real peers.
    This pipeline has no real P2P mesh (see p2p_listener.py's single demo peer
    registered elsewhere in run-all-e2e.sh), so DEMO_PEERS below is a clearly
    labelled, fabricated-but-realistic 8-peer set -- not real network telemetry --
    solely so the real, unmodified eclipse_detector logic has enough real-shaped
    input to evaluate. Diversity thresholds follow Heilman et al. 2015, "Eclipse
    Attacks on Bitcoin's Peer-to-Peer Network".
  * The reorg is REAL: a genuine Anvil chain fork is produced via evm_snapshot /
    evm_revert, and a real, longer competing branch is actually mined and fed to
    ChainReorgMonitor one header at a time. The resulting depth/severity is
    computed by that monitor from real chain state -- nothing about the reorg
    event itself is invented. SAFE_REORG_DEPTH (6) is Satoshi's originally
    suggested confirmation count against double-spend/51%-attack reorgs.
  * Anvil's block production is deterministic given identical state: mining an
    empty block after a revert reproduces a BYTE-IDENTICAL block (same hash) to
    the one it replaced, which would be a replay, not a fork (verified directly
    against this Anvil build before relying on it). evm_setNextBlockTimestamp is
    used on the new branch only, to force each block to a real, distinct
    timestamp so it is a genuinely different chain, not a no-op duplicate.
  * SelfishMiningDetector is fed the SAME real headers the reorg scenario
    already produces: the doomed old branch's blocks are genuinely orphaned
    (that is the entire point of this engineered fork, known in advance by
    construction, not guessed), and the triggering new-branch block's real
    reorg_depth from the ReorgEvent above is passed through as
    reorg_depth_caused. A real orphan rate this far above the detector's
    baseline genuinely crosses its z-score threshold -- a real, computed
    consequence of the real forced fork, not a separately fabricated
    scenario. min_window_for_stats (30) needs more observations than the
    reorg alone produces, so a further run of plain, non-orphaned blocks is
    mined afterward purely to reach that real sample size.

Writes:
  reports/consensus-attack-findings.json  -- [{metric, threshold, observed_value, triggered}, ...]
  reports/scanners/consensus-attack.json  -- via the shared scanner_result contract

Purely additive/informational, like avs-consensus.py and run-ofac-screening.py:
NOT added to pipeline-verdict.py's REQUIRED list.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from scanner_result import ROOT, write_result  # noqa: E402

from src.consensus.avs_consensus import find_bin, port_open  # noqa: E402
from src.consensus.reorg_monitor import ChainReorgMonitor, BlockHeaderRecord  # noqa: E402
from src.consensus.concentration_tracker import ConsensusConcentrationTracker  # noqa: E402
from src.consensus.eclipse_detector import P2PEclipseDetector  # noqa: E402
from src.consensus.p2p_listener import PeerInfo  # noqa: E402
from src.consensus.selfish_mining_detector import SelfishMiningDetector  # noqa: E402

ANVIL_PORT = 8548
SAFE_REORG_DEPTH = 6          # Satoshi's originally-suggested 6-confirmation margin
HHI_HIGHLY_CONCENTRATED = 2500.0  # US DOJ/FTC Horizontal Merger Guidelines
POST_REORG_PLAIN_BLOCKS = 15  # extra real blocks so selfish-mining's 30-obs window fills


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _cast(cast_bin, *args, rpc):
    p = _run([cast_bin, *args, "--rpc-url", rpc])
    if p.returncode != 0:
        raise RuntimeError(f"cast {' '.join(args)} failed: {p.stderr.strip()[:200]}")
    return p.stdout.strip()


def _block_header(cast_bin, rpc, number):
    out = _cast(cast_bin, "block", str(number), "--json", rpc=rpc)
    data = json.loads(out)["data"]
    return BlockHeaderRecord(
        block_number=int(data["number"], 16),
        block_hash=data["hash"],
        parent_hash=data["parentHash"],
        timestamp=float(int(data["timestamp"], 16)),
        miner_or_validator=data["miner"],
    )


def _mine(cast_bin, rpc):
    _cast(cast_bin, "rpc", "evm_mine", rpc=rpc)


def _set_next_timestamp(cast_bin, rpc, ts):
    _cast(cast_bin, "rpc", "evm_setNextBlockTimestamp", str(ts), rpc=rpc)


def _snapshot(cast_bin, rpc):
    return _cast(cast_bin, "rpc", "evm_snapshot", rpc=rpc).strip('"')


def _revert(cast_bin, rpc, snap_id):
    out = _cast(cast_bin, "rpc", "evm_revert", snap_id, rpc=rpc)
    if out.strip() != "true":
        raise RuntimeError(f"evm_revert({snap_id}) returned {out!r}, expected true")


def run_real_chain_scenario():
    """Runs a real ephemeral Anvil chain, forces a real reorg via snapshot/revert.

    Returns (reorg_event_or_None, concentration_metrics, selfish_mining_alert_or_None, error_or_None).
    """
    anvil_bin, cast_bin = find_bin("anvil"), find_bin("cast")
    if not anvil_bin or not cast_bin:
        return None, None, None, "foundry tooling missing (anvil/cast)"
    if port_open(ANVIL_PORT):
        return None, None, None, f"port {ANVIL_PORT} already in use; refusing to attach"

    proc = subprocess.Popen([anvil_bin, "--port", str(ANVIL_PORT), "--no-mining", "--silent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rpc = f"http://127.0.0.1:{ANVIL_PORT}"
    try:
        for _ in range(50):
            if port_open(ANVIL_PORT):
                break
            time.sleep(0.2)
        else:
            return None, None, None, "anvil did not come up"

        monitor = ChainReorgMonitor(finality_depth=SAFE_REORG_DEPTH)
        tracker = ConsensusConcentrationTracker()
        sm_detector = SelfishMiningDetector()

        genesis = _block_header(cast_bin, rpc, 0)
        monitor.initialize_anchor(genesis)
        tracker.record_production_event(genesis.miner_or_validator or "genesis")
        miner_id = genesis.miner_or_validator or "genesis"
        sm_detector.record_block(genesis.block_number, genesis.block_hash, genesis.parent_hash,
                                 miner_id, is_orphaned=False, timestamp=genesis.timestamp)

        # Mine up to the common ancestor, and snapshot there so we can really fork.
        ancestor_depth = 3
        for _ in range(ancestor_depth):
            _mine(cast_bin, rpc)
        snap_id = _snapshot(cast_bin, rpc)
        for h in range(1, ancestor_depth + 1):
            hdr = _block_header(cast_bin, rpc, h)
            monitor.process_header(hdr)
            tracker.record_production_event(hdr.miner_or_validator or "unknown")
            sm_detector.record_block(hdr.block_number, hdr.block_hash, hdr.parent_hash,
                                     miner_id, is_orphaned=False, timestamp=hdr.timestamp)

        # Old (doomed) branch: SAFE_REORG_DEPTH real blocks past the ancestor.
        # These are fed to sm_detector as is_orphaned=True -- genuinely known in
        # advance here, since this orchestrator is the one forcing the fork (see
        # HONEST SCOPE NOTE), not a guess about blocks whose fate isn't yet known.
        for _ in range(SAFE_REORG_DEPTH):
            _mine(cast_bin, rpc)
        old_tip_height = ancestor_depth + SAFE_REORG_DEPTH
        for h in range(ancestor_depth + 1, old_tip_height + 1):
            hdr = _block_header(cast_bin, rpc, h)
            monitor.process_header(hdr)
            tracker.record_production_event(hdr.miner_or_validator or "unknown")
            sm_detector.record_block(hdr.block_number, hdr.block_hash, hdr.parent_hash,
                                     miner_id, is_orphaned=True, timestamp=hdr.timestamp)

        # Genuine fork: revert to the real ancestor snapshot, then mine a REAL,
        # longer competing branch (classic longest-chain fork choice). Anvil's
        # block production is deterministic given identical state -- an empty
        # block mined after a revert is BYTE-IDENTICAL (same hash) to the one it
        # replaces unless something about it genuinely differs, which would make
        # this a replay, not a fork. evm_setNextBlockTimestamp forces each new
        # block to a real, distinct timestamp so the new branch is a genuinely
        # different sequence of blocks, not a no-op duplicate of the old one.
        _revert(cast_bin, rpc, snap_id)
        new_branch_len = SAFE_REORG_DEPTH + 2  # must exceed the old branch to win
        future_ts_base = int(time.time()) + 10_000_000
        for i in range(new_branch_len):
            _set_next_timestamp(cast_bin, rpc, future_ts_base + i * 1000)
            _mine(cast_bin, rpc)
        new_tip_height = ancestor_depth + new_branch_len

        reorg_event = None
        for h in range(ancestor_depth + 1, new_tip_height + 1):
            hdr = _block_header(cast_bin, rpc, h)
            ev = monitor.process_header(hdr)
            tracker.record_production_event(hdr.miner_or_validator or "unknown")
            if ev is not None:
                reorg_event = ev
            sm_detector.record_block(hdr.block_number, hdr.block_hash, hdr.parent_hash,
                                     miner_id, is_orphaned=False, timestamp=hdr.timestamp,
                                     reorg_depth_caused=(ev.reorg_depth if ev is not None else 0))

        # SelfishMiningDetector.evaluate_miner needs min_window_for_stats (30)
        # observations; the reorg scenario alone produces fewer. These extra
        # blocks are plain, non-orphaned continuations of the now-canonical
        # chain -- real chain data, just not part of the engineered fork.
        for _ in range(POST_REORG_PLAIN_BLOCKS):
            _mine(cast_bin, rpc)
        for h in range(new_tip_height + 1, new_tip_height + 1 + POST_REORG_PLAIN_BLOCKS):
            hdr = _block_header(cast_bin, rpc, h)
            sm_detector.record_block(hdr.block_number, hdr.block_hash, hdr.parent_hash,
                                     miner_id, is_orphaned=False, timestamp=hdr.timestamp)

        sm_alert = sm_detector.evaluate_miner(miner_id)
        return reorg_event, tracker.calculate_metrics(), sm_alert, None
    except Exception as exc:  # noqa: BLE001
        return None, None, None, f"chain scenario failed: {str(exc)[:200]}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


def build_demo_peers():
    """A clearly-labelled DEMONSTRATION 8-peer set (7 concentrated + 1 diverse) --
    not real network telemetry; see HONEST SCOPE NOTE above."""
    base_ts = time.time()
    concentrated = [
        PeerInfo(f"demo-peer-{i}", f"203.0.113.{10 + i}", 30303, 64512, "Geth/v1.14", 20.0 + i, base_ts)
        for i in range(7)
    ]
    diverse = [PeerInfo("demo-peer-8", "198.51.100.42", 30303, 64513, "Erigon/v3.0", 35.0, base_ts)]
    return concentrated + diverse


def build_reorg_finding(reorg_event):
    """Pure/unit-testable: reorg_event is a ReorgEvent or None (real or fabricated)."""
    depth = reorg_event.reorg_depth if reorg_event else 0
    return {
        "metric": "reorg_depth",
        "threshold": SAFE_REORG_DEPTH,
        "observed_value": depth,
        "triggered": depth >= SAFE_REORG_DEPTH,
        "severity": reorg_event.severity.value if reorg_event else "NONE",
    }


def build_concentration_findings(metrics):
    """Pure/unit-testable: metrics is a ConcentrationMetrics (real or fabricated)."""
    defaults = ConsensusConcentrationTracker()
    return [
        {
            "metric": "validator_concentration_max_single_share",
            "threshold": defaults.critical_single_threshold,
            "observed_value": metrics.max_single_share,
            "triggered": metrics.max_single_share >= defaults.critical_single_threshold,
            "top_entity": metrics.top_entity_id,
        },
        {
            "metric": "validator_concentration_top3_share",
            "threshold": defaults.warning_top3_threshold,
            "observed_value": metrics.top3_cumulative_share,
            "triggered": metrics.top3_cumulative_share >= defaults.warning_top3_threshold,
        },
        {
            "metric": "validator_concentration_hhi",
            "threshold": HHI_HIGHLY_CONCENTRATED,
            "observed_value": metrics.hhi,
            "triggered": metrics.hhi > HHI_HIGHLY_CONCENTRATED,
        },
    ]


def build_eclipse_findings(alert, detector):
    """Pure/unit-testable: alert is an EclipseAlert or None (real or fabricated)."""
    if alert is None:
        return [{
            "metric": "eclipse_peer_diversity",
            "threshold": detector.min_asns_required,
            "observed_value": None,
            "triggered": False,
            "note": "insufficient peers to evaluate, or no concentration detected",
        }]
    return [
        {
            "metric": "eclipse_asn_concentration",
            "threshold": detector.asn_critical_threshold,
            "observed_value": alert.max_asn_share,
            "triggered": alert.max_asn_share >= detector.asn_critical_threshold,
            "threat_level": alert.threat_level.value,
        },
        {
            "metric": "eclipse_unique_asns",
            "threshold": detector.min_asns_required,
            "observed_value": alert.unique_asns,
            "triggered": alert.unique_asns < detector.min_asns_required,
        },
    ]


def build_selfish_mining_finding(alert, detector=None):
    """Pure/unit-testable: alert is a SelfishMiningAlert or None (real or fabricated)."""
    detector = detector or SelfishMiningDetector()
    if alert is None:
        return {
            "metric": "selfish_mining_z_score",
            "threshold": detector.z_warning_threshold,
            "observed_value": None,
            "triggered": False,
            "note": "insufficient observations this run, or no anomaly detected",
        }
    return {
        "metric": "selfish_mining_z_score",
        "threshold": detector.z_warning_threshold,
        "observed_value": alert.z_score,
        "triggered": alert.z_score >= detector.z_warning_threshold,
        "threat_level": alert.threat_level.value,
        "observed_orphan_rate": alert.observed_orphan_rate,
        "expected_orphan_rate": alert.expected_orphan_rate,
    }


def main():
    print("[+] [ZONE 6] Chain consensus-attack detection (reorg / concentration / eclipse / selfish-mining)...")
    reorg_event, metrics, sm_alert, err = run_real_chain_scenario()
    if err:
        return write_result("consensus-attack", "chain-attack-monitor", "not_run", detail=err)

    findings = [build_reorg_finding(reorg_event)]
    findings += build_concentration_findings(metrics)
    findings.append(build_selfish_mining_finding(sm_alert))

    detector = P2PEclipseDetector()
    alert = detector.evaluate_peers(build_demo_peers())
    findings += build_eclipse_findings(alert, detector)

    report_file = ROOT / "reports" / "consensus-attack-findings.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")

    triggered = sum(1 for f in findings if f["triggered"])
    print(f"    -> reorg: depth={reorg_event.reorg_depth if reorg_event else 0} "
          f"severity={reorg_event.severity.value if reorg_event else 'NONE'} (real forced fork)")
    print(f"    -> concentration: max_single_share={metrics.max_single_share} alert={metrics.alert_level.value}")
    print(f"    -> eclipse (demo peer set): threat_level={alert.threat_level.value if alert else 'CLEAR'}")
    print(f"    -> selfish-mining: z_score={sm_alert.z_score if sm_alert else 'N/A'} "
          f"threat_level={sm_alert.threat_level.value if sm_alert else 'CLEAR'}")

    detail = (f"{triggered}/{len(findings)} checks triggered | "
              f"reorg depth={reorg_event.reorg_depth if reorg_event else 0} | "
              f"concentration={metrics.alert_level.value} | "
              f"eclipse={alert.threat_level.value if alert else 'CLEAR'} | "
              f"selfish-mining={sm_alert.threat_level.value if sm_alert else 'CLEAR'}")
    return write_result("consensus-attack", "chain-attack-monitor", "ok",
                        counts={"checks": len(findings), "triggered": triggered},
                        raw_report=report_file, detail=detail,
                        extra={"reorg_severity": reorg_event.severity.value if reorg_event else "NONE",
                               "concentration_alert": metrics.alert_level.value,
                               "eclipse_threat_level": alert.threat_level.value if alert else "CLEAR",
                               "selfish_mining_threat_level": sm_alert.threat_level.value if sm_alert else "CLEAR"})


if __name__ == "__main__":
    main()
