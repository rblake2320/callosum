"""Independence, instrumentation, and capability-matrix suites.

Proves: reveal is blocked pre-commit; commit tamper is caught; evidence vs
assertion changes classify correctly; the fast-agreement tripwire fires and
demands validation; authority follows measured wins; ties inhibit no one;
matrix file poisoning is defeated by ledger rebuild; absorb reassigns and
flags unbacked capabilities.
"""
import os

import pytest

from callosum.capability import CapabilityMatrix
from callosum.crypto import Signer
from callosum.instrumentation import PositionTracker
from callosum.ledger import Ledger
from callosum.util import atomic_write_json, read_json


@pytest.fixture
def led(tmp_path):
    return Ledger(tmp_path / "ledger", Signer.generate())


# ------------------------------------------------------------- independence
def test_reveal_blocked_until_both_commit(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    t.commit_initial("left", "position A")
    with pytest.raises(RuntimeError, match="reveal blocked"):
        t.reveal()


def test_reveal_after_both_commits(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    t.commit_initial("left", "A")
    t.commit_initial("right", "B")
    assert t.reveal() == {"left": "A", "right": "B"}
    assert led.last("reveal") is not None


def test_commit_tamper_detected_at_reveal(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    t.commit_initial("left", "A")
    t.commit_initial("right", "B")
    # attacker edits the stored position after sealing
    p = os.path.join(tmp_path, "positions", "right.json")
    rec = read_json(p)
    rec["text"] = "B-modified"
    atomic_write_json(p, rec)
    with pytest.raises(RuntimeError, match="tamper"):
        t.reveal()
    assert led.last("tamper_detected") is not None


def test_commits_are_sealed_in_ledger(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    h = t.commit_initial("left", "A")
    e = led.last("position_commit")
    assert e["payload"] == {"hemi": "left", "sha256": h}
    assert led.verify()[0]


# ------------------------------------------------------------ classification
def test_evidence_change_classified_clean(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    rec = t.record_change("right", "wrong", "right-answer", "m1", cause_evidence_valid=True)
    assert rec["by"] == "evidence"
    assert t.sycophancy_ratio() == 0.0
    assert led.last("sycophancy_flag") is None


def test_assertion_change_flags_sycophancy(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    t.record_change("left", "A", "B", "m2", cause_evidence_valid=False)
    assert t.sycophancy_ratio() == 1.0
    assert led.last("sycophancy_flag")["payload"]["hemi"] == "left"


def test_ratio_math(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    t.record_change("l", "a", "b", None, True)
    t.record_change("l", "b", "c", None, False)
    t.record_change("r", "x", "y", None, True)
    t.record_change("r", "y", "z", None, True)
    assert t.sycophancy_ratio() == 0.25
    assert PositionTracker(tmp_path, led).sycophancy_ratio() is None  # fresh tracker, no changes


def test_fast_agreement_tripwire_fires_and_ledgers(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    assert t.check_fast_agreement(contact_ts=100.0, agree_ts=101.0, evidence_msgs=0, window=30) is True
    e = led.last("fast_agreement_tripwire")
    assert e["payload"]["action"] == "independent_validation_required"


def test_no_tripwire_when_evidence_flowed(tmp_path, led):
    t = PositionTracker(tmp_path, led)
    assert t.check_fast_agreement(100.0, 101.0, evidence_msgs=2, window=30) is False
    assert led.last("fast_agreement_tripwire") is None


# ---------------------------------------------------------------- capability
def test_authority_follows_wins_and_flips(tmp_path, led):
    c = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    c.record_outcome("s", "left", "right")
    assert c.authority("s") == "left"
    c.record_outcome("s", "right", "left")
    assert c.authority("s") is None  # tie: nobody inhibits
    c.record_outcome("s", "right", "left")
    assert c.authority("s") == "right"


def test_priority_score_reflects_breadth(tmp_path, led):
    c = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    c.record_outcome("a", "left", "right")
    c.record_outcome("b", "left", "right")
    c.record_outcome("c", "right", "left")
    assert c.priority_score("left") > c.priority_score("right")


def test_absorb_reassigns_and_flags_unbacked(tmp_path, led):
    c = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    for _ in range(3):
        c.record_outcome("windows_crt", "right", "left")  # right dominates
    c.record_outcome("crypto", "left", "right")
    unbacked = c.absorb("right", "left", margin=0.15)
    assert "windows_crt" in unbacked  # survivor can't back this guarantee
    assert c.authority("windows_crt") == "left"  # but owns it now
    assert "crypto" not in unbacked


def test_matrix_poisoning_defeated_by_ledger_rebuild(tmp_path, led):
    """Attacker edits capability.json directly to steal authority: rebuild wins."""
    c = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    c.record_outcome("s", "left", "right")
    c.record_outcome("s", "left", "right")
    poisoned = read_json(tmp_path / "cap.json")
    poisoned["subtasks"]["s"]["right"] = {"wins": 100, "total": 100}
    poisoned["subtasks"]["s"]["left"] = {"wins": 0, "total": 2}
    atomic_write_json(tmp_path / "cap.json", poisoned)
    assert CapabilityMatrix(str(tmp_path / "cap.json"), led).authority("s") == "right"  # poison took
    c2 = CapabilityMatrix(str(tmp_path / "cap.json"), led).rebuild_from_ledger()
    assert c2.authority("s") == "left"  # truth restored from the sealed chain


def test_rebuild_refuses_tampered_ledger(tmp_path):
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    c = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    c.record_outcome("s", "left")
    # truncate the tail
    lines = open(led.path, "rb").read().splitlines()
    open(led.path, "wb").write(b"")
    with pytest.raises(RuntimeError, match="ledger failed verification"):
        c.rebuild_from_ledger()
