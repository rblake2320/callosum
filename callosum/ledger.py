"""Tamper-evident evidence ledger.

Each entry: {seq, ts, kind, payload, prev} -> hash = sha256(canonical(core)),
sig = Ed25519(hash). HEAD.json anchors the last {seq, hash, sig} atomically so
tail truncation is detectable (a pure hash chain cannot detect a clean tail cut).

Concurrency: appends serialize on a cross-process FileLock; the JSONL append is
fsync'd, HEAD is written atomically.

Crash semantics (two-phase HEAD). A single atomic HEAD write cannot distinguish
"clean crash between the JSONL append and the HEAD update" from "attacker cut
the tail" -- both present as HEAD-behind-by-one, and the old code reported the
clean crash as tamper. HEAD is therefore written twice:

    phase 1   HEAD <- {seq, hash, sig, state:"pending"}    (signed intent)
    phase 2   append line + fsync
    phase 3   HEAD <- {seq, hash, sig, state:"committed"}

verify() resolves exactly four states:
    committed and matches last entry             -> ok
    pending, seq == last.seq, hash matches       -> ok (crash after append)
    pending, seq == last.seq + 1                 -> ok (crash before line landed)
    anything else                                -> tamper (truncation/rollback)

Cutting a *committed* tail still fails closed: HEAD is Ed25519-signed over a
hash that is no longer in the chain, and the attacker cannot re-sign without the
envelope key. Only the single uncommitted entry in flight at crash time is
ambiguous, and by construction it was never committed.

Legacy HEAD records (written before two-phase, no "state" key) are read as
committed, so pre-existing ledgers verify exactly as they did before.
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
            head = self._resolve_head()
            core = {
                "seq": head["seq"] + 1,
                "ts": time.time(),
                "kind": kind,
                "payload": payload,
                "prev": head["hash"],
            }
            h = self._entry_hash(core)
            sig = self.signer.sign_hex(bytes.fromhex(h))
            anchor = {"seq": core["seq"], "hash": h, "sig": sig, "signer": self.signer.pub_hex}

            # phase 1: signed intent
            atomic_write_json(self.head_path, dict(anchor, state="pending"))
            # phase 2: durable line
            entry = dict(core, hash=h, sig=sig, signer=self.signer.pub_hex)
            with open(self.path, "ab") as f:
                f.write(canonical(entry) + b"\n")
                f.flush()
                os.fsync(f.fileno())
            # phase 3: commit
            atomic_write_json(self.head_path, dict(anchor, state="committed"))
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
            if not os.path.exists(self.head_path):
                return True, "empty"
            head = read_json(self.head_path)
            if (head.get("state") == "pending" and head.get("seq") == 0
                    and verify_hex(head["signer"], bytes.fromhex(head["hash"]), head["sig"])
                    and (trusted_pubs is None or head["signer"] in trusted_pubs)):
                return True, "ok (empty; crash before first entry landed)"
            return False, "HEAD exists but ledger missing"
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

        if not os.path.exists(self.head_path):
            return (False, "HEAD anchor missing") if last_entry else (True, "empty")
        head = read_json(self.head_path)
        pending = head.get("state", "committed") == "pending"

        # the anchor itself must be authentic before its seq/hash mean anything
        if not verify_hex(head["signer"], bytes.fromhex(head["hash"]), head["sig"]):
            return False, "HEAD signature invalid"
        if trusted_pubs is not None and head["signer"] not in trusted_pubs:
            return False, "HEAD signer untrusted"

        if last_entry is None:
            if pending and head["seq"] == 0:
                return True, "ok (empty; crash before first entry landed)"
            return False, "HEAD mismatch (ledger emptied / rollback)"

        if head["seq"] == last_entry["seq"] and head["hash"] == last_entry["hash"]:
            return True, f"ok ({last_entry['seq'] + 1} entries)"
        if pending and head["seq"] == last_entry["seq"] + 1:
            return True, f"ok ({last_entry['seq'] + 1} entries; crash before entry {head['seq']} landed)"
        if head["seq"] < last_entry["seq"] and trusted_pubs is not None:
            # HEAD behind a longer chain. Truncation moves HEAD *ahead* of the
            # chain, never behind, so this is the legacy single-phase crash
            # window (entries landed, the anchor update was lost). Safe to
            # accept only because every trailing entry is signed by a pinned
            # key -- an attacker without it cannot manufacture this state.
            # Requires trusted_pubs: with an unpinned signer set this would be
            # a forgery hole, so it stays closed there.
            return True, (f"ok ({last_entry['seq'] + 1} entries; uncommitted tail "
                          f"recovered: anchor at seq {head['seq']})")
        return False, "HEAD mismatch (tail truncation or rollback)"

    # ---------------------------------------------------------------- helpers
    def head(self) -> dict:
        """Chain-truthful anchor: what the next entry will link to."""
        return self._resolve_head()

    _head = head  # back-compat alias for callers written against the private name

    def _resolve_head(self) -> dict:
        """Chain-truthful head for the next append.

        A pending anchor whose entry never landed must NOT become `prev` -- doing
        so would fork the chain permanently. Reconcile against the actual tail.
        """
        tail = self._tail_entry()
        if not os.path.exists(self.head_path):
            return {"seq": tail["seq"], "hash": tail["hash"]} if tail else {"seq": -1, "hash": GENESIS}
        head = read_json(self.head_path)
        if tail is None:
            return {"seq": -1, "hash": GENESIS}
        if tail["seq"] == head["seq"] and tail["hash"] == head["hash"]:
            return head
        if tail["seq"] > head["seq"]:
            return {"seq": tail["seq"], "hash": tail["hash"]}  # anchor update was lost
        if head.get("state", "committed") == "pending":
            return {"seq": tail["seq"], "hash": tail["hash"]}  # intent never landed
        # committed anchor ahead of the chain: truncation. Do NOT silently heal --
        # leave the anchor in place so verify() keeps reporting the damage.
        return head

    def _tail_entry(self) -> dict | None:
        if not os.path.exists(self.path):
            return None
        with open(self.path, "rb") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        for ln in reversed(lines):
            try:
                return json.loads(ln.decode("utf-8"))
            except Exception:
                continue  # torn final line
        return None

    @staticmethod
    def _entry_hash(core: dict) -> str:
        from .util import sha256_hex

        return sha256_hex(canonical(core))
