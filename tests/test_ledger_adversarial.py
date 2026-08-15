"""Ledger adversarial suite.

Proves the chain detects: payload tampering, entry reordering, mid-chain
deletion, TAIL TRUNCATION (via HEAD anchor -- a pure hash chain misses this),
signature forgery, untrusted signers, HEAD corruption, torn final lines, and
that concurrent multi-process appends still verify.
"""
import json
import multiprocessing as mp
import os

from callosum.crypto import Signer
from callosum.ledger import Ledger
from callosum.util import atomic_write_json, canonical, read_json


def _mk(tmp_path, n=5):
    s = Signer.generate()
    led = Ledger(tmp_path / "ledger", s)
    for i in range(n):
        led.append("event", {"i": i})
    return s, led


def _lines(led):
    with open(led.path, "rb") as f:
        return [l for l in f.read().splitlines() if l.strip()]


def _write_lines(led, lines):
    with open(led.path, "wb") as f:
        f.write(b"\n".join(lines) + b"\n")


def test_clean_chain_verifies(tmp_path):
    s, led = _mk(tmp_path)
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert ok, reason


def test_payload_tamper_detected(tmp_path):
    s, led = _mk(tmp_path)
    lines = _lines(led)
    e = json.loads(lines[2])
    e["payload"]["i"] = 999  # rewrite history
    lines[2] = canonical(e)
    _write_lines(led, lines)
    ok, reason = led.verify()
    assert not ok and "hash mismatch" in reason


def test_reorder_detected(tmp_path):
    s, led = _mk(tmp_path)
    lines = _lines(led)
    lines[1], lines[2] = lines[2], lines[1]
    _write_lines(led, lines)
    assert not led.verify()[0]


def test_mid_chain_deletion_detected(tmp_path):
    s, led = _mk(tmp_path)
    lines = _lines(led)
    del lines[2]
    _write_lines(led, lines)
    assert not led.verify()[0]


def test_tail_truncation_detected_by_head_anchor(tmp_path):
    """A clean tail cut yields a perfectly valid shorter chain -- HEAD catches it."""
    s, led = _mk(tmp_path)
    lines = _lines(led)
    _write_lines(led, lines[:-2])
    ok, reason = led.verify()
    assert not ok and "HEAD mismatch" in reason


def test_signature_forgery_detected(tmp_path):
    s, led = _mk(tmp_path)
    attacker = Signer.generate()
    lines = _lines(led)
    e = json.loads(lines[3])
    e["sig"] = attacker.sign_hex(bytes.fromhex(e["hash"]))  # wrong key, right hash
    lines[3] = canonical(e)
    _write_lines(led, lines)
    ok, reason = led.verify()
    assert not ok and "bad signature" in reason


def test_attacker_full_rewrite_fails_trusted_set(tmp_path):
    """Attacker re-signs the whole chain with their own key: trusted set rejects."""
    s, led = _mk(tmp_path, n=2)
    attacker = Signer.generate()
    evil = Ledger(tmp_path / "ledger2", attacker)
    evil.append("event", {"i": 0})
    ok, reason = evil.verify(trusted_pubs={s.pub_hex})
    assert not ok and "untrusted" in reason


def test_head_corruption_detected(tmp_path):
    s, led = _mk(tmp_path)
    head = read_json(led.head_path)
    head["hash"] = "f" * 64
    atomic_write_json(led.head_path, head)
    assert not led.verify()[0]


def test_torn_final_line_detected(tmp_path):
    s, led = _mk(tmp_path)
    with open(led.path, "ab") as f:
        f.write(b'{"seq": 99, "truncat')  # crash mid-append
    ok, reason = led.verify()
    assert not ok and "torn" in reason


def _worker(dirpath, key_hex, n):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    s = Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex)))
    led = Ledger(dirpath, s)
    for i in range(n):
        led.append("worker_event", {"pid": os.getpid(), "i": i})


def test_concurrent_multiprocess_appends_verify(tmp_path):
    s = Signer.generate()
    key_hex = s._priv.private_bytes_raw().hex()
    d = str(tmp_path / "ledger")
    procs = [mp.Process(target=_worker, args=(d, key_hex, 15)) for _ in range(4)]
    [p.start() for p in procs]
    [p.join() for p in procs]
    led = Ledger(d, s)
    ok, reason = led.verify(trusted_pubs={s.pub_hex})
    assert ok, reason
    assert len(led.entries()) == 60  # no lost appends
