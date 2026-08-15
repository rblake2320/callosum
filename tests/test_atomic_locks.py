"""Atomic write + FileLock adversarial suite.

Proves: writes are all-or-nothing (simulated crash leaves the original intact),
no tmp litter, byte-exact CRLF safety, cross-PROCESS mutual exclusion under
contention, and deterministic lock timeouts.
"""
import multiprocessing as mp
import os

import pytest

from callosum.util import FileLock, atomic_write_bytes, atomic_write_json, read_json


def test_atomic_write_content_and_no_tmp_litter(tmp_path):
    p = tmp_path / "f.json"
    atomic_write_json(p, {"a": 1})
    assert read_json(p) == {"a": 1}
    assert [f for f in os.listdir(tmp_path) if f.startswith(".tmp.")] == []


def test_atomic_write_overwrite_is_replace(tmp_path):
    p = tmp_path / "f.bin"
    atomic_write_bytes(p, b"old")
    atomic_write_bytes(p, b"new")
    assert p.read_bytes() == b"new"


def test_crash_before_replace_leaves_original(tmp_path, monkeypatch):
    """Kill the write between fsync and os.replace: original must be untouched."""
    p = tmp_path / "f.bin"
    atomic_write_bytes(p, b"original")
    real_replace = os.replace

    def boom(src, dst):
        raise OSError("simulated crash before replace")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        atomic_write_bytes(p, b"halfway")
    monkeypatch.setattr(os, "replace", real_replace)
    assert p.read_bytes() == b"original"


def test_crlf_bytes_preserved(tmp_path):
    """Binary writes must never newline-translate (Windows text-mode hazard)."""
    p = tmp_path / "f.bin"
    payload = b"line1\r\nline2\nline3\r\n"
    atomic_write_bytes(p, payload)
    assert p.read_bytes() == payload


def _locked_increment(lock_path, counter_path, n):
    for _ in range(n):
        with FileLock(lock_path, timeout=30):
            with open(counter_path) as fh:
                v = int(fh.read())
            with open(counter_path, "w") as fh:
                fh.write(str(v + 1))


def test_cross_process_mutual_exclusion(tmp_path):
    lock_path = str(tmp_path / "l.lock")
    counter = str(tmp_path / "c.txt")
    with open(counter, "w") as fh:
        fh.write("0")
    procs = [mp.Process(target=_locked_increment, args=(lock_path, counter, 50)) for _ in range(4)]
    [pr.start() for pr in procs]
    [pr.join() for pr in procs]
    with open(counter) as fh:
        assert int(fh.read()) == 200  # zero lost updates


def _hold(lock_path, hold_evt, done_evt):
    with FileLock(lock_path):
        hold_evt.set()
        done_evt.wait(10)


def test_lock_timeout_is_deterministic(tmp_path):
    lock_path = str(tmp_path / "l.lock")
    hold_evt, done_evt = mp.Event(), mp.Event()
    pr = mp.Process(target=_hold, args=(lock_path, hold_evt, done_evt))
    pr.start()
    assert hold_evt.wait(5)
    with pytest.raises(TimeoutError):
        FileLock(lock_path, timeout=0.3).acquire()
    done_evt.set()
    pr.join()


def test_lock_reacquire_after_release(tmp_path):
    lp = str(tmp_path / "l.lock")
    l1 = FileLock(lp, timeout=1).acquire()
    l1.release()
    l2 = FileLock(lp, timeout=1).acquire()
    l2.release()
