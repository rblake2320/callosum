"""Evidence + bridge adversarial suite.

Proves: sha-forged, missing, traversal, absolute-path, and mixed-poisoned
evidence are rejected; non-authoritative assertions are suppressed AND ledgered;
valid counterexamples cross; authority passes without evidence; quarantine
dampens even the authority holder; stale epochs are fenced; degraded mode
requires evidence from everyone; suppression never erases dissent.
"""
import os

import pytest

from callosum.bridge import Callosum
from callosum.capability import CapabilityMatrix
from callosum.crypto import Signer
from callosum.evidence import make_evidence, make_msg, validate_ref
from callosum.failover import Quarantine
from callosum.ledger import Ledger
from callosum.transport import FileDropBus, bump_epoch
from callosum.util import atomic_write_json


@pytest.fixture
def rig(tmp_path):
    root = tmp_path
    ev = root / "evidence"
    ev.mkdir()
    (ev / "proof.json").write_bytes(b'{"cmd":"pytest","exit_code":0}')
    signer = Signer.generate()
    ledger = Ledger(root / "ledger", signer)
    cap = CapabilityMatrix(str(root / "capability.json"), ledger)
    # left holds authority on 'concurrency' (2-0)
    cap.record_outcome("concurrency", "left", "right")
    cap.record_outcome("concurrency", "left", "right")
    bus = FileDropBus(root)
    q = Quarantine(root)
    bridge = Callosum(root, ledger, cap, bus, ev, q)
    return root, ev, ledger, cap, bus, q, bridge


def _kinds(ledger, kind):
    return [e for e in ledger.entries() if e["kind"] == kind]


# ---------------------------------------------------------------- evidence
def test_valid_evidence_ok(rig):
    root, ev, *_ = rig
    ref = make_evidence(ev, "proof.json")
    assert validate_ref(ref, ev) == (True, "ok")


def test_sha_forgery_rejected(rig):
    root, ev, *_ = rig
    ref = make_evidence(ev, "proof.json")
    ref["sha256"] = "a" * 64
    ok, reason = validate_ref(ref, ev)
    assert not ok and "mismatch" in reason


def test_missing_artifact_rejected(rig):
    root, ev, *_ = rig
    ok, reason = validate_ref({"path": "ghost.json", "sha256": "a" * 64}, ev)
    assert not ok and "missing" in reason


def test_path_traversal_rejected(rig, tmp_path):
    root, ev, *_ = rig
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"loot")
    from callosum.util import sha256_file

    ref = {"path": "../secret.txt", "sha256": sha256_file(outside)}
    ok, reason = validate_ref(ref, ev)
    assert not ok and "escapes" in reason


def test_absolute_path_rejected(rig):
    root, ev, *_ = rig
    ok, reason = validate_ref({"path": str(ev / "proof.json"), "sha256": "a" * 64}, ev)
    assert not ok and "absolute" in reason


def test_mixed_poisoned_evidence_rejected(rig):
    """One real artifact must not launder a forged one across the bridge."""
    root, ev, ledger, cap, bus, q, bridge = rig
    good = make_evidence(ev, "proof.json")
    bad = {"etype": "artifact", "path": "proof.json", "sha256": "b" * 64, "meta": {}}
    msg = make_msg("right", "left", "concurrency", "counterexample", "x", evidence=[good, bad])
    res = bridge.transmit(msg)
    assert res["status"] == "suppressed"


# ------------------------------------------------------------------ bridge
def test_authority_influence_passes_without_evidence(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    msg = make_msg("left", "right", "concurrency", "objection", "left speaks", evidence=[])
    res = bridge.transmit(msg)
    assert res["status"] == "delivered"
    assert bus.poll("right")[0]["body"] == "left speaks"


def test_nonauthoritative_assertion_suppressed_and_ledgered(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    msg = make_msg("right", "left", "concurrency", "objection", "trust me", evidence=[])
    res = bridge.transmit(msg)
    assert res["status"] == "suppressed"
    assert bus.pending("left") == 0
    sup = _kinds(ledger, "bridge_suppressed")
    assert sup and sup[-1]["payload"]["msg_id"] == msg["msg_id"]  # dissent damped, never erased


def test_nonauthoritative_counterexample_with_evidence_crosses(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    ref = make_evidence(ev, "proof.json")
    msg = make_msg("right", "left", "concurrency", "counterexample", "proof attached", evidence=[ref])
    res = bridge.transmit(msg)
    assert res["status"] == "delivered" and res["evidence_valid"]
    assert bridge.delivered_evidence[msg["msg_id"]] is True


def test_status_messages_always_pass(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    msg = make_msg("right", "left", "concurrency", "status", "heartbeat note")
    assert bridge.transmit(msg)["status"] == "delivered"


def test_untracked_subtask_passes_flagged_unadjudicated(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    msg = make_msg("right", "left", "brand_new_subtask", "delta", "novel area")
    res = bridge.transmit(msg)
    assert res["status"] == "delivered" and res["reason"] == "unadjudicated subtask"


def test_quarantined_authority_still_needs_evidence(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    q.quarantine("left", 2, ledger, reason="contradicted by execution")
    msg = make_msg("left", "right", "concurrency", "objection", "I am still the boss")
    assert bridge.transmit(msg)["status"] == "suppressed"
    # with evidence it crosses AND earns a release credit
    ref = make_evidence(ev, "proof.json")
    msg2 = make_msg("left", "right", "concurrency", "counterexample", "here is proof", evidence=[ref])
    assert bridge.transmit(msg2)["status"] == "delivered"
    assert q._load()["left"] == 1


def test_stale_epoch_fenced(rig):
    """Split-brain guard: falsely-dead hemisphere returns on the old epoch -> rejected."""
    root, ev, ledger, cap, bus, q, bridge = rig
    old_epoch_msg = make_msg("right", "left", "concurrency", "status", "I never died", epoch=0)
    bump_epoch(root)  # election happened while it was 'dead'
    res = bridge.transmit(old_epoch_msg)
    assert res["status"] == "rejected" and res["reason"] == "stale_epoch"
    assert _kinds(ledger, "bridge_rejected")


def test_degraded_mode_requires_evidence_from_everyone(rig):
    root, ev, ledger, cap, bus, q, bridge = rig
    atomic_write_json(os.path.join(root, "degraded.json"), {"active": True, "evidence_required_all": True})
    msg = make_msg("left", "right", "concurrency", "objection", "authority speaking")
    assert bridge.transmit(msg)["status"] == "suppressed"  # even the authority holder
    ref = make_evidence(ev, "proof.json")
    msg2 = make_msg("left", "right", "concurrency", "objection", "with proof", evidence=[ref])
    assert bridge.transmit(msg2)["status"] == "delivered"
