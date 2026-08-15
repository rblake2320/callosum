"""Tamper-evident evidence ledger.

Each entry: {seq, ts, kind, payload, prev} -> hash = sha256(canonical(core)),
sig = Ed25519(hash). HEAD.json anchors the last {seq, hash, sig} atomically so
tail truncation is detectable (a pure hash chain cannot detect a clean tail cut).

Concurrency: appends serialize on a cross-process FileLock; the JSONL append is
fsync'd, HEAD is written atomically. A crash mid-append leaves either a valid
tail or a torn final line -- verify() reports both.
"""
from __future__ import annotations

import json
import os
import time

from .crypto import Signer, verify_hex
from .util import GENESIS, FileLock, atomic_write_json, canonical, read_json


class Ledger:
    def __init__(self, dirpath, signer: Signer):
        self.dir = os.fspath(dirpath)
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "ledger.jsonl")
        self.head_path = os.path.join(self.dir, "HEAD.json")
        self.lock_path = os.path.join(self.dir, "ledger.lock")
        self.signer = signer

    # ------------------------------------------------------------------ write
    def append(self, kind: str, payload: dict) -> dict:
        with FileLock(self.lock_path):
            head = self._head()
            core = {
                "seq": head["seq"] + 1,
                "ts": time.time(),
                "kind": kind,
                "payload": payload,
                "prev": head["hash"],
            }
            h = self._entry_hash(core)
            entry = dict(core, hash=h, sig=self.signer.sign_hex(bytes.fromhex(h)), signer=self.signer.pub_hex)
            with open(self.path, "ab") as f:
                f.write(canonical(entry) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            atomic_write_json(
                self.head_path,
                {"seq": core["seq"], "hash": h, "sig": self.signer.sign_hex(bytes.fromhex(h)), "signer": self.signer.pub_hex},
            )
            return entry

    # ------------------------------------------------------------------- read
    def entries(self) -> list:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, "rb") as f:
            for line in f.read().splitlines():
                if line.strip():
                    out.append(json.loads(line.decode("utf-8")))
        return out

    def last(self, kind: str | None = None) -> dict | None:
        es = self.entries()
        if kind is not None:
            es = [e for e in es if e["kind"] == kind]
        return es[-1] if es else None

    # ----------------------------------------------------------------- verify
    def verify(self, trusted_pubs: set[str] | None = None) -> tuple[bool, str]:
        """Full-chain verification: linkage, hashes, signatures, HEAD anchor."""
        if not os.path.exists(self.path):
            return (not os.path.exists(self.head_path), "empty" if not os.path.exists(self.head_path) else "HEAD exists but ledger missing")
        prev = GENESIS
        last_entry = None
        with open(self.path, "rb") as f:
            for i, line in enumerate(f.read().splitlines()):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line.decode("utf-8"))
                except Exception:
                    return False, f"torn/corrupt line at index {i}"
                core = {k: e[k] for k in ("seq", "ts", "kind", "payload", "prev")}
                if e["seq"] != (last_entry["seq"] + 1 if last_entry else 0):
                    return False, f"seq break at {e.get('seq')}"
                if e["prev"] != prev:
                    return False, f"chain break at seq {e['seq']}"
                if self._entry_hash(core) != e["hash"]:
                    return False, f"hash mismatch at seq {e['seq']} (payload tampered)"
                if not verify_hex(e["signer"], bytes.fromhex(e["hash"]), e["sig"]):
                    return False, f"bad signature at seq {e['seq']}"
                if trusted_pubs is not None and e["signer"] not in trusted_pubs:
                    return False, f"untrusted signer at seq {e['seq']}"
                prev = e["hash"]
                last_entry = e
        if last_entry is None:
            if os.path.exists(self.head_path):
                return False, "HEAD mismatch (ledger emptied / rollback)"
            return True, "empty"
        if not os.path.exists(self.head_path):
            return False, "HEAD anchor missing"
        head = read_json(self.head_path)
        if head["seq"] != last_entry["seq"] or head["hash"] != last_entry["hash"]:
            return False, "HEAD mismatch (tail truncation or rollback)"
        if not verify_hex(head["signer"], bytes.fromhex(head["hash"]), head["sig"]):
            return False, "HEAD signature invalid"
        if trusted_pubs is not None and head["signer"] not in trusted_pubs:
            return False, "HEAD signer untrusted"
        return True, f"ok ({last_entry['seq'] + 1} entries)"

    # ---------------------------------------------------------------- helpers
    def _head(self) -> dict:
        if os.path.exists(self.head_path):
            return read_json(self.head_path)
        return {"seq": -1, "hash": GENESIS}

    @staticmethod
    def _entry_hash(core: dict) -> str:
        from .util import sha256_hex

        return sha256_hex(canonical(core))
