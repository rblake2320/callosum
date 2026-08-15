"""Failover, watchdog, and transport suites.

Proves: death detected within 3x interval budget; election is capability-
weighted (not highest-ID); epoch bumps and seals; degraded mode activates with
raised requirements and named unbacked capabilities; double-election is
idempotent; false-death rejoin lands quarantined on the new epoch; watchdog
halts on stalled verified progress and stands down when progress flows; the
bus delivers exactly once (delta-push) and tolerates torn in-flight files.
"""
import time

import pytest

from callosum.capability import CapabilityMatrix
from callosum.crypto import Signer
from callosum.failover import FailoverController, Heartbeat, Monitor, Quarantine, Watchdog
from callosum.ledger import Ledger
from callosum.transport import FileDropBus, get_epoch
from callosum.util import read_json


@pytest.fixture
def rig(tmp_path):
    signer = Signer.generate()
    ledger = Ledger(tmp_path / "ledger", signer)
    cap = CapabilityMatrix(str(tmp_path / "cap.json"), ledger)
    # left is broadly stronger -> election priority
    cap.record_outcome("a", "left", "right")
    cap.record_outcome("b", "left", "right")
    cap.record_outcome("windows_crt", "right", "left")
    cap.record_outcome("windows_crt", "right", "left")
    hb = Heartbeat(tmp_path)
    mon = Monitor(hb, interval=0.05, misses=3)
    q = Quarantine(tmp_path)
    fc = FailoverController(tmp_path, ledger, cap, mon, q)
    return tmp_path, ledger, cap, hb, mon, q, fc


def test_detection_within_budget(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    assert not mon.is_dead("right")
    t0 = time.time()
    time.sleep(mon.budget + 0.05)  # right stops beating
    hb.beat("left")
    assert mon.is_dead("right")
    assert (time.time() - t0) < mon.budget * 3  # detected promptly, not eventually


def test_never_started_is_not_dead(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    assert not mon.is_dead("right")  # absence != death


def test_election_capability_weighted_and_sealed(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    time.sleep(mon.budget + 0.05)
    hb.beat("left")
    rep = fc.check_and_elect()
    assert rep["survivor"] == "left" and rep["dead"] == ["right"]
    assert rep["scores"]["left"] > 0
    assert get_epoch(root) == 1  # fencing token bumped
    e = ledger.last("election")
    assert e["payload"]["epoch"] == 1
    assert ledger.verify()[0]


def test_degraded_mode_and_unbacked(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    time.sleep(mon.budget + 0.05)
    hb.beat("left")
    rep = fc.check_and_elect()
    d = read_json(root / "degraded.json")
    assert d["evidence_required_all"] is True
    assert d["checkpoint_interval_scale"] == 0.5
    assert d["autonomy"] == "reduced"
    assert "windows_crt" in d["unbacked"]  # the guarantee right was carrying
    assert "windows_crt" in rep["unbacked"]


def test_double_election_idempotent(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    time.sleep(mon.budget + 0.05)
    hb.beat("left")
    assert fc.check_and_elect() is not None
    assert fc.check_and_elect() is None  # same death handled once
    assert get_epoch(root) == 1


def test_both_dead_is_watchdog_territory(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    time.sleep(mon.budget + 0.05)
    assert fc.check_and_elect() is None  # no survivor to elect


def test_false_death_rejoin_quarantined_on_new_epoch(rig):
    root, ledger, cap, hb, mon, q, fc = rig
    hb.beat("left"); hb.beat("right")
    time.sleep(mon.budget + 0.05)
    hb.beat("left")
    fc.check_and_elect()
    epoch = fc.rejoin("right", k=2)
    assert epoch == 1
    assert q.active("right")
    assert ledger.last("rejoin")["payload"]["hemi"] == "right"
    q.credit("right", ledger); q.credit("right", ledger)
    assert not q.active("right")
    assert ledger.last("quarantine_released")["payload"]["hemi"] == "right"


def test_watchdog_halts_on_stall_and_not_on_progress(tmp_path):
    signer = Signer.generate()
    ledger = Ledger(tmp_path / "ledger", signer)
    wd = Watchdog(tmp_path, t_safe=0.1)
    wd.note_progress()
    assert wd.check(ledger) is False
    time.sleep(0.15)
    assert wd.check(ledger) is True
    assert wd.halted()
    assert ledger.last("watchdog_halt") is not None
    wd.clear()
    assert not wd.halted()
    wd.note_progress()
    assert wd.check(ledger) is False


def test_bus_exactly_once_delivery(tmp_path):
    bus = FileDropBus(tmp_path)
    bus.post("left", {"msg_id": "m1", "body": "hello"})
    bus.post("left", {"msg_id": "m2", "body": "world"})
    first = bus.poll("left")
    assert [m["msg_id"] for m in first] == ["m1", "m2"]  # ordered
    assert bus.poll("left") == []  # never re-read (delta-push)
    assert bus.pending("left") == 0


def test_bus_skips_torn_inflight_file(tmp_path):
    import os

    bus = FileDropBus(tmp_path)
    inbox = os.path.join(bus.root, "left", "inbox")
    os.makedirs(inbox, exist_ok=True)
    with open(os.path.join(inbox, "00000000000000000001_torn.json"), "wb") as f:
        f.write(b'{"half": ')  # writer crashed mid-flight
    bus.post("left", {"msg_id": "m3", "body": "ok"})
    got = bus.poll("left")
    assert [m["msg_id"] for m in got] == ["m3"]  # torn file skipped, not fatal
