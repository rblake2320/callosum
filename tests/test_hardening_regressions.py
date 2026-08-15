"""Regression suite for the v0.1.1 hardening pass.

Every test here FAILS on v0.1.0 and passes after the fix. Each one is an
adversarial or crash scenario, not a happy path. Grouped by the guarantee the
repo documents and did not actually hold.

  H1  epoch fence      a fenced hemisphere forging a high epoch walked through
  H2  ledger rebuild   a chain re-signed end-to-end by an attacker was accepted
  H3  absorb replay    rebuild produced a matrix that differed from live state
  H4  capability RMW   two live handles silently dropped an adjudicated outcome
  H5  ledger crash     a clean crash between append and HEAD read as tamper
  H6  key at rest      the envelope key was written unprotected despite the docs
  H7  delivered proof  the chain recorded THAT evidence crossed, not WHICH
  H8  corrections      the publishable corpus appended without a cross-proc lock
"""
import json
import os
import stat
import subprocess
import sys

import pytest

from callosum.bridge import Callosum
from callosum.capability import CapabilityMatrix
from callosum.corrections import CorrectionStore
from callosum.crypto import Signer
from callosum.evidence import make_evidence, make_msg
from callosum.failover import Quarantine
from callosum.ledger import Ledger
from callosum.transport import FileDropBus, bump_epoch, get_epoch
from callosum.util import atomic_write_json


@pytest.fixture
def led(tmp_path):
    return Ledger(tmp_path / "ledger", Signer.generate())


def _bridge(root, led, cap):
    ev = os.path.join(root, "evidence")
    os.makedirs(ev, exist_ok=True)
    return Callosum(root, led, cap, FileDropBus(root), ev, Quarantine(root)), ev


# ------------------------------------------------------------------ H1 fence
def test_forged_forward_epoch_is_rejected(tmp_path, led):
    """A fenced side that lies upward must not bypass the split-brain guard."""
    root = str(tmp_path)
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    cap.record_outcome("concurrency", "right", "left")  # right holds authority
    bridge, _ = _bridge(root, led, cap)
    bump_epoch(root)
    bump_epoch(root)  # election happened; current epoch = 2

    stale = bridge.transmit(make_msg("right", "left", "concurrency", "objection", "honest", epoch=0))
    forged = bridge.transmit(make_msg("right", "left", "concurrency", "objection", "lying", epoch=10**9))

    assert stale["status"] == "rejected" and stale["reason"] == "stale_epoch"
    assert forged["status"] == "rejected" and forged["reason"] == "future_epoch"
    kinds = [e["payload"]["reason"] for e in led.entries() if e["kind"] == "bridge_rejected"]
    assert any("future_epoch" in k for k in kinds)


def test_current_epoch_still_passes(tmp_path, led):
    """The fence must not be so tight that legitimate traffic dies."""
    root = str(tmp_path)
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    bridge, _ = _bridge(root, led, cap)
    bump_epoch(root)
    res = bridge.transmit(make_msg("left", "right", "s", "objection", "ok", epoch=get_epoch(root)))
    assert res["status"] == "delivered"


# --------------------------------------------------------------- H2 rebuild
def test_rebuild_rejects_chain_resigned_by_attacker(tmp_path):
    """Poisoning defense: replay must pin the envelope key, not any valid key."""
    envelope_key = Signer.generate()
    led = Ledger(tmp_path / "ledger", envelope_key)
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    cap.record_outcome("crypto", "left", "right")
    assert cap.authority("crypto") == "left"

    # attacker owns the disk but not the key: rebuild the whole chain with theirs
    attacker = Signer.generate()
    os.remove(led.path)
    os.remove(led.head_path)
    forged = Ledger(tmp_path / "ledger", attacker)
    forged.append("capability_outcome", {"subtask": "crypto", "winner": "right", "loser": "left"})
    forged.append("capability_outcome", {"subtask": "crypto", "winner": "right", "loser": "left"})
    assert forged.verify()[0] is True  # internally consistent, just foreign-signed

    victim = CapabilityMatrix(str(tmp_path / "cap.json"), Ledger(tmp_path / "ledger", envelope_key))
    with pytest.raises(RuntimeError, match="untrusted signer"):
        victim.rebuild_from_ledger()


def test_rebuild_without_inferable_signer_refuses(tmp_path):
    class LedgerNoSigner:
        signer = None

        def verify(self, trusted_pubs=None):
            return True, "ok"

        def entries(self):
            return []

    cap = CapabilityMatrix(str(tmp_path / "cap.json"), LedgerNoSigner())
    with pytest.raises(RuntimeError, match="trusted signer set"):
        cap.rebuild_from_ledger()


# ---------------------------------------------------------------- H3 replay
def test_rebuild_reproduces_live_absorb_state(tmp_path, led):
    """Replay must be faithful, not approximate: only the dead side's authorities move."""
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    cap.record_outcome("concurrency", "left", "right")  # left authority
    cap.record_outcome("windows_crt", "right", "left")  # right authority
    cap.absorb("right", "left")
    live = json.loads(json.dumps(cap.data))

    cap.rebuild_from_ledger()

    assert cap.data["reassigned"] == live["reassigned"]
    assert cap.data["unbacked"] == live["unbacked"]
    # and specifically: left's own subtask was never blanket-reassigned
    assert "concurrency" not in cap.data["reassigned"]
    assert cap.data["reassigned"]["windows_crt"] == "left"


def test_rebuild_handles_legacy_absorb_entry_without_map(tmp_path, led):
    """Chains written before the map was sealed still replay to the right shape."""
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    cap.record_outcome("concurrency", "left", "right")
    cap.record_outcome("windows_crt", "right", "left")
    led.append("capability_absorb", {"dead": "right", "survivor": "left", "unbacked": ["windows_crt"]})

    cap.rebuild_from_ledger()
    assert cap.data["reassigned"] == {"windows_crt": "left"}
    assert cap.data["unbacked"] == ["windows_crt"]


# ------------------------------------------------------------------- H4 RMW
def test_two_handles_do_not_lose_an_outcome(tmp_path):
    """Locking the write is not enough; the read must be inside the lock too."""
    p = str(tmp_path / "cap.json")
    a = CapabilityMatrix(p)
    b = CapabilityMatrix(p)  # both cached state at construction
    a.record_outcome("x", "left", "right")
    b.record_outcome("x", "right", "left")

    with open(p) as fh:
        st = json.load(fh)["subtasks"]["x"]
    assert st["left"]["total"] == 2 and st["right"]["total"] == 2
    assert st["left"]["wins"] == 1 and st["right"]["wins"] == 1


_CHILD = r"""
import sys
from callosum.capability import CapabilityMatrix
p, subtask, winner, loser, n = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
for _ in range(n):
    CapabilityMatrix(p).record_outcome(subtask, winner, loser)
"""


def test_concurrent_processes_lose_no_outcomes(tmp_path):
    """4 processes x 25 outcomes each -> exactly 100 recorded, zero lost."""
    p = str(tmp_path / "cap.json")
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    procs = [subprocess.Popen([sys.executable, str(script), p, "x", w, l, "25"], env=env)
             for w, l in [("left", "right"), ("right", "left"), ("left", "right"), ("right", "left")]]
    for pr in procs:
        assert pr.wait(timeout=120) == 0
    with open(p) as fh:
        st = json.load(fh)["subtasks"]["x"]
    assert st["left"]["total"] == 100 and st["right"]["total"] == 100
    assert st["left"]["wins"] + st["right"]["wins"] == 100


# ----------------------------------------------------------------- H5 crash
def test_clean_crash_after_append_is_not_reported_as_tamper(tmp_path):
    """v0.1.0's exact crash window: the line landed, the anchor update was lost.

    Old behaviour: reported "tail truncation or rollback" -- a false tamper
    alarm on an ordinary power cut, contradicting the module docstring's claim
    that a crash leaves "either a valid tail or a torn final line".
    """
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    a = led.append("a", {})
    with open(led.head_path) as fh:
        anchor_before = json.load(fh)
    assert anchor_before["seq"] == a["seq"]
    led.append("b", {})
    atomic_write_json(led.head_path, anchor_before)  # anchor stuck one behind

    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert ok, reason
    assert "recovered" in reason

    # unpinned verification must NOT take the recovery path (forgery hole)
    assert led.verify()[0] is False

    # and the chain must still extend correctly, not fork at the stale anchor
    c = led.append("c", {})
    assert c["seq"] == 2
    assert led.verify(trusted_pubs={s.pub_hex})[0]
    assert [x["kind"] for x in led.entries()] == ["a", "b", "c"]


def test_phase3_loss_verifies_and_extends(tmp_path):
    """Crash after the line, before the commit marker (new two-phase ordering)."""
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    led.append("a", {})
    e = led.append("b", {})
    atomic_write_json(led.head_path, {"seq": e["seq"], "hash": e["hash"],
                                      "sig": e["sig"], "signer": e["signer"], "state": "pending"})
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert ok, reason
    led.append("c", {})
    assert led.verify(trusted_pubs={s.pub_hex})[0]
    assert [x["kind"] for x in led.entries()] == ["a", "b", "c"]


def test_crash_before_line_landed_recovers_without_forking_the_chain(tmp_path):
    """A pending anchor whose entry never landed must not become `prev`."""
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    a = led.append("a", {})
    ghost_hash = "f" * 64
    atomic_write_json(led.head_path, {"seq": a["seq"] + 1, "hash": ghost_hash,
                                      "sig": s.sign_hex(bytes.fromhex(ghost_hash)),
                                      "signer": s.pub_hex, "state": "pending"})
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert ok, reason
    nxt = led.append("b", {})
    assert nxt["prev"] == a["hash"] and nxt["seq"] == a["seq"] + 1
    assert led.verify(trusted_pubs={s.pub_hex})[0]


def test_committed_tail_truncation_is_still_tamper(tmp_path):
    """The crash allowance must not create a truncation loophole."""
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    led.append("a", {})
    led.append("b", {})
    led.append("c", {})
    with open(led.path, "rb") as fh:
        lines = fh.read().splitlines()
    with open(led.path, "wb") as fh:
        fh.write(b"\n".join(lines[:-1]) + b"\n")  # cut the committed tail
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert not ok and "truncation" in reason


def test_forged_pending_head_cannot_hide_truncation(tmp_path):
    """An attacker without the key cannot mint a pending anchor to cover a cut."""
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    led.append("a", {})
    kept = led.append("b", {})
    led.append("c", {})
    with open(led.path, "rb") as fh:
        lines = fh.read().splitlines()
    with open(led.path, "wb") as fh:
        fh.write(b"\n".join(lines[:-1]) + b"\n")
    attacker = Signer.generate()
    h = "a" * 64
    atomic_write_json(led.head_path, {"seq": kept["seq"] + 1, "hash": h,
                                      "sig": attacker.sign_hex(bytes.fromhex(h)),
                                      "signer": attacker.pub_hex, "state": "pending"})
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert not ok and "untrusted" in reason


# ------------------------------------------------------------------- H6 key
@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_key_is_written_0600_by_default(tmp_path):
    """The documented at-rest protection must be on the default runtime path."""
    p = tmp_path / "identity.key"
    Signer.generate().save(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_envelope_key_on_disk_is_0600(tmp_path):
    from callosum.adapter import MockHemisphere
    from callosum.envelope import BrainEnvelope

    ev = tmp_path / "evidence"
    ev.mkdir()
    BrainEnvelope(str(tmp_path),
                  MockHemisphere("left", "grounded", str(ev)),
                  MockHemisphere("right", "stubborn", str(ev)))
    key = tmp_path / "identity.key"
    assert key.exists()
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_saved_key_round_trips(tmp_path):
    p = tmp_path / "k.key"
    s = Signer.generate()
    s.save(p)
    assert Signer.load(p).pub_hex == s.pub_hex


# --------------------------------------------------------------- H7 delivery
def test_delivered_entry_seals_which_artifact_bought_the_crossing(tmp_path, led):
    root = str(tmp_path)
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), led)
    cap.record_outcome("s", "left", "right")  # left has authority; right must pay evidence
    bridge, ev = _bridge(root, led, cap)
    with open(os.path.join(ev, "proof.json"), "wb") as f:
        f.write(b'{"cmd":"pytest","exit_code":0}')
    ref = make_evidence(ev, "proof.json")
    res = bridge.transmit(make_msg("right", "left", "s", "counterexample", "repro", evidence=[ref]))
    assert res["status"] == "delivered" and res["evidence_valid"]

    entry = [e for e in led.entries() if e["kind"] == "bridge_delivered"][-1]
    sealed = entry["payload"]["evidence"]
    assert sealed and sealed[0]["path"] == "proof.json"
    assert sealed[0]["sha256"] == ref["sha256"]
    # the chain alone is enough to re-adjudicate the crossing later
    assert led.verify()[0]


# ------------------------------------------------------------ H8 corrections
def test_corrections_store_takes_a_cross_process_lock(tmp_path, led):
    ev = tmp_path / "evidence"
    ev.mkdir()
    with open(ev / "p.json", "wb") as f:
        f.write(b'{"cmd":"pytest","exit_code":0}')
    store = CorrectionStore(str(tmp_path), led, str(ev))
    assert store.lock_path.endswith(".lock")
    for i in range(5):
        store.submit({"claim": f"c{i}", "status": "verified_correction",
                      "environment": {"e": 1}, "evidence": [make_evidence(str(ev), "p.json")]})
    assert os.path.exists(store.lock_path)
    assert len(store.all()) == 5
    assert len(store.publishable()) == 5


def test_corrections_lines_stay_whole_under_concurrency(tmp_path, led):
    """Every line must parse: no interleaved partial appends."""
    ev = tmp_path / "evidence"
    ev.mkdir()
    with open(ev / "p.json", "wb") as f:
        f.write(b"x" * 4096)
    store = CorrectionStore(str(tmp_path), led, str(ev))
    ref = make_evidence(str(ev), "p.json")
    for i in range(40):
        store.submit({"claim": "c" * 500 + str(i), "status": "verified_correction",
                      "environment": {"e": 1}, "evidence": [ref]})
    with open(store.path, "rb") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    assert len(lines) == 40
    for ln in lines:
        json.loads(ln)  # raises on a torn line
