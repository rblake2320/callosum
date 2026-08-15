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


def test_quarantine_credit_requires_novel_evidence(rig):
    """A quarantined sender resubmitting the SAME evidence artifact repeatedly
    must not fully self-release quarantine -- each credit has to come with
    proof the sender hasn't already presented, or quarantine's 're-earn trust'
    intent is meaningless (it'd be a fixed 'wait K messages' timer, not a
    validated-evidence gate)."""
    root, ev, ledger, cap, bus, q, bridge = rig
    q.quarantine("left", 3, ledger, reason="contradicted by execution")
    ref = make_evidence(ev, "proof.json")
    for _ in range(5):
        msg = make_msg("left", "right", "concurrency", "counterexample", "same proof again", evidence=[ref])
        assert bridge.transmit(msg)["status"] == "delivered"
    # 5 deliveries of the SAME artifact must earn at most 1 credit, not 5+.
    assert q._load()["left"] == 2
    assert q.active("left")


def test_quarantine_novelty_tracking_does_not_outlive_its_term(rig):
    """Evidence-novelty tracking for credit() must be scoped to the CURRENT
    quarantine term, not accumulate forever. Otherwise a hemisphere that
    legitimately re-cites the same real artifact from a past, resolved
    incident -- in a brand new, unrelated quarantine term -- gets starved of
    credit it has earned all over again."""
    root, ev, ledger, cap, bus, q, bridge = rig
    ref = make_evidence(ev, "proof.json")

    # First term: earn a credit citing `ref`, then let the term end (released).
    q.quarantine("left", 1, ledger, reason="first incident")
    msg1 = make_msg("left", "right", "concurrency", "counterexample", "proof", evidence=[ref])
    assert bridge.transmit(msg1)["status"] == "delivered"
    assert not q.active("left")  # released after 1 credit

    # Second, unrelated term: citing the SAME artifact again must still count,
    # because it's the first citation of THIS term, not a replay within it.
    q.quarantine("left", 1, ledger, reason="second, unrelated incident")
    msg2 = make_msg("left", "right", "concurrency", "counterexample", "proof", evidence=[ref])
    assert bridge.transmit(msg2)["status"] == "delivered"
    assert not q.active("left")  # released again -- not starved by term 1's history


def test_unrecognized_kind_rejected_not_delivered_unconditionally(rig):
    """The bridge is documented as the sole inhibitory checkpoint -- it must
    fail closed on a kind it doesn't recognize, not silently fall through to
    the 'non-influence, always passes' branch (which is only correct because
    make_msg() at the shipped call sites already rejects bad kinds; the
    bridge itself shouldn't rely on that)."""
    root, ev, ledger, cap, bus, q, bridge = rig
    q.quarantine("left", 2, ledger, reason="test")
    msg = dict(
        msg_id="m1", sender="left", recipient="right", subtask="concurrency",
        kind="objection ", body="trailing space makes this an unrecognized kind",
        evidence=[], epoch=0,
    )
    res = bridge.transmit(msg)
    assert res["status"] == "rejected" and res["reason"] == "unrecognized_kind"
    assert _kinds(ledger, "bridge_rejected")


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
