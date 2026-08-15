"""Corrections gate + envelope end-to-end + eval harness.

Proves: only verified-by-execution corrections publish; agreement alone never
does; the full session lifecycle corrects a confidently-wrong hemisphere via
evidence (sycophancy ratio 0.0) and flags a sycophant (ratio > 0); hot swap
preserves envelope identity and memory; the kill drill detects, elects,
absorbs, degrades, and fences; the whole ledger verifies after a session;
the five-config eval report carries pair-vs-best-single and drill metrics.
"""
import os

import pytest

from callosum.adapter import MockHemisphere
from callosum.corrections import CorrectionStore
from callosum.crypto import Signer
from callosum.envelope import BrainEnvelope
from callosum.eval import demo_tasks, run_eval
from callosum.evidence import make_evidence
from callosum.ledger import Ledger
from callosum.util import read_json


def _task(subtask="concurrency", grounded="left"):
    other = "right" if grounded == "left" else "left"
    return {
        "id": "tX", "subtask": subtask, "truth": "the verified answer",
        "prompt": "resolve tX",
        "positions": {grounded: "the verified answer", other: "a confident wrong answer"},
        "evidence_file": "tX_proof.json",
    }


def _env(tmp_path, left_behavior, right_behavior, task):
    ev_root = tmp_path / "env" / "evidence"
    os.makedirs(ev_root, exist_ok=True)
    (ev_root / task["evidence_file"]).write_bytes(b'{"cmd":"pytest","exit_code":0}')
    left = MockHemisphere("left", left_behavior, evidence_root=str(ev_root))
    right = MockHemisphere("right", right_behavior, evidence_root=str(ev_root))
    return BrainEnvelope(str(tmp_path / "env"), left, right, hb_interval=0.05)


# --------------------------------------------------------------- corrections
@pytest.fixture
def cstore(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    (ev / "proof.json").write_bytes(b'{"exit_code":0}')
    led = Ledger(tmp_path / "ledger", Signer.generate())
    return ev, CorrectionStore(tmp_path, led, ev)


def test_agreement_alone_never_publishes(cstore):
    ev, cs = cstore
    rec = cs.submit({"claim": "X", "status": "collaborative_agreement", "environment": {}})
    assert rec["publishable"] is False
    assert cs.publishable() == []


def test_verified_with_evidence_publishes(cstore):
    ev, cs = cstore
    rec = cs.submit({"claim": "X", "status": "verified_correction", "environment": {},
                     "evidence": [make_evidence(ev, "proof.json")]})
    assert rec["publishable"] is True
    assert len(cs.publishable()) == 1


def test_verified_without_evidence_rejected(cstore):
    ev, cs = cstore
    with pytest.raises(ValueError, match="requires evidence"):
        cs.submit({"claim": "X", "status": "verified_correction", "environment": {}})


def test_forged_evidence_rejected_at_submit(cstore):
    ev, cs = cstore
    bad = make_evidence(ev, "proof.json")
    bad["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="evidence rejected"):
        cs.submit({"claim": "X", "status": "refuted", "environment": {}, "evidence": [bad]})


def test_bad_status_and_missing_fields_rejected(cstore):
    ev, cs = cstore
    with pytest.raises(ValueError, match="invalid status"):
        cs.submit({"claim": "X", "status": "vibes", "environment": {}})
    with pytest.raises(ValueError, match="missing fields"):
        cs.submit({"status": "model_disagreement"})


# ------------------------------------------------------------------ envelope
def test_session_wrong_confident_corrected_by_evidence(tmp_path):
    task = _task()
    env = _env(tmp_path, "grounded", "wrong_confident", task)
    r = env.run_session(task, tripwire_window=0.0)
    assert r["agreed"] is True
    assert r["final"]["right"] == task["truth"]
    assert r["sycophancy_ratio"] == 0.0  # the flip was evidence-driven
    assert r["evidence_msgs"] >= 1
    # correction package emitted and publishable
    pubs = env.corrections.publishable()
    assert len(pubs) == 1 and pubs[0]["corrected_claim"] == task["truth"]
    # capability outcome recorded for the corrector
    assert env.cap.win_rate(task["subtask"], "left") == 1.0
    ok, reason = env.ledger.verify(trusted_pubs={env.signer.pub_hex})
    assert ok, reason


def test_session_sycophant_flagged(tmp_path):
    task = _task(grounded="left")
    # left stubborn asserts; right sycophant flips on the bare assertion
    env = _env(tmp_path, "stubborn", "sycophant", task)
    r = env.run_session(task, tripwire_window=0.0)
    assert r["agreed"] is True
    assert r["sycophancy_ratio"] == 1.0  # flipped with zero evidence
    assert env.ledger.last("sycophancy_flag") is not None


def test_fast_agreement_tripwire_in_session(tmp_path):
    task = _task()
    task["positions"] = {"left": "same", "right": "same"}
    env = _env(tmp_path, "wrong_confident", "wrong_confident", task)
    task["truth"] = "same"  # both start agreed -> instant evidence-free agreement
    task["positions"] = {"left": "same", "right": "same"}
    r = env.run_session(task, tripwire_window=30.0)
    assert r["agreed"] and r["tripwire"] is True
    assert env.ledger.last("fast_agreement_tripwire") is not None


def test_hot_swap_preserves_identity_and_memory(tmp_path):
    task = _task()
    env = _env(tmp_path, "grounded", "wrong_confident", task)
    eid = env.envelope_id
    env.remember({"fact": "callosum v1"})
    new_right = MockHemisphere("right-codex", "grounded",
                               evidence_root=str(tmp_path / "env" / "evidence"))
    env.hot_swap("right", new_right)
    assert env.envelope_id == eid  # identity is the envelope's, not the occupant's
    assert env.memory()["notes"][0]["fact"] == "callosum v1"
    assert env.occupants["right"].name == "right-codex"
    assert env.ledger.last("hot_swap")["payload"]["new"] == "right-codex"


def test_kill_drill_detect_elect_absorb_degrade(tmp_path):
    task = _task(subtask="concurrency", grounded="left")
    env = _env(tmp_path, "grounded", "wrong_confident", task)
    # give right a capability so absorb has something to flag
    env.cap.record_outcome("windows_crt", "right", "left")
    r = env.run_session(task, kill_side="right", kill_after_round=0)
    fo = r["failover"]
    assert fo is not None and fo["survivor"] == "left" and fo["dead"] == ["right"]
    assert fo["detection_latency_s"] <= env.monitor.budget * 3
    assert "windows_crt" in fo["unbacked"]
    assert r["epoch"] == 1
    d = read_json(os.path.join(env.root, "degraded.json"))
    assert d["evidence_required_all"] is True
    ok, reason = env.ledger.verify(trusted_pubs={env.signer.pub_hex})
    assert ok, reason


def test_checkpoint_contains_state(tmp_path):
    task = _task()
    env = _env(tmp_path, "grounded", "wrong_confident", task)
    env.run_session(task, tripwire_window=0.0)
    ck = env.checkpoint()
    assert ck["envelope_id"] == env.envelope_id
    assert ck["ledger_head"]["seq"] >= 0
    assert "subtasks" in ck["capability"]


def test_watchdog_halt_blocks_sessions(tmp_path):
    task = _task()
    env = _env(tmp_path, "grounded", "wrong_confident", task)
    env.watchdog.note_progress(ts=0.0)  # ancient progress
    env.watchdog.t_safe = 0.01
    assert env.watchdog.check(env.ledger) is True
    with pytest.raises(RuntimeError, match="HALT"):
        env.run_session(task)


# ---------------------------------------------------------------------- eval
def test_eval_five_configs_and_report(tmp_path):
    report = run_eval(str(tmp_path / "eval"), demo_tasks())
    s = report["summary"]
    for cfg in ("A_left_solo", "B_right_solo", "C_council", "D_collab", "E_kill_drill"):
        assert cfg in s
    # capability split: each solo wins exactly half
    assert s["A_left_solo"] == 0.5 and s["B_right_solo"] == 0.5
    # live collaboration resolves everything via evidence -> beats best single
    assert s["D_collab"] == 1.0
    assert s["pair_vs_best_single_pp"] > 0
    assert s["mean_sycophancy_ratio"] == 0.0  # every flip was evidence-driven
    assert s["mean_detection_latency_s"] is not None
    assert os.path.exists(tmp_path / "eval" / "eval_report.json")


def test_eval_council_frozen_no_exchanges(tmp_path):
    report = run_eval(str(tmp_path / "eval2"), demo_tasks()[:2])
    for row in report["tasks"]:
        assert row["C_exchanges"] == 0


def test_eval_kill_drill_metrics_present(tmp_path):
    report = run_eval(str(tmp_path / "eval3"), demo_tasks()[:2])
    for row in report["tasks"]:
        assert row["E_failover"] is not None
        assert row["E_failover"]["detection_latency_s"] >= 0
