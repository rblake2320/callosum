"""Callosum messages and evidence validation.

Evidence is the only currency that buys influence across the bridge. An evidence
ref binds to a real artifact by sha256 and must resolve INSIDE the evidence root
(realpath jail -- no traversal, no symlink escape). A test-run record is just an
artifact: a sealed JSON file containing {cmd, exit_code, output_sha256}.
"""
from __future__ import annotations

import os
import time
import uuid

from .util import sha256_file

INFLUENCE_KINDS = {"delta", "objection", "counterexample"}
ALL_KINDS = INFLUENCE_KINDS | {"status", "position"}


def make_evidence(evidence_root, rel_path: str, etype: str = "artifact", meta: dict | None = None) -> dict:
    full = os.path.join(evidence_root, rel_path)
    return {"etype": etype, "path": rel_path, "sha256": sha256_file(full), "meta": meta or {}}


def make_msg(sender: str, recipient: str, subtask: str, kind: str, body: str,
             evidence: list | None = None, epoch: int = 0) -> dict:
    if kind not in ALL_KINDS:
        raise ValueError(f"unknown message kind: {kind}")
    return {
        "msg_id": uuid.uuid4().hex,
        "sender": sender,
        "recipient": recipient,
        "subtask": subtask,
        "kind": kind,
        "body": body,
        "evidence": evidence or [],
        "epoch": epoch,
        "ts": time.time(),
    }


def validate_ref(ref: dict, evidence_root) -> tuple[bool, str]:
    root = os.path.realpath(os.fspath(evidence_root))
    rel = ref.get("path", "")
    if os.path.isabs(rel):
        return False, "absolute path rejected"
    full = os.path.realpath(os.path.join(root, rel))
    if not (full == root or full.startswith(root + os.sep)):
        return False, "escapes evidence root"
    if not os.path.isfile(full):
        return False, "artifact missing"
    if sha256_file(full) != ref.get("sha256"):
        return False, "sha256 mismatch (forged or stale evidence)"
    return True, "ok"


def validate_msg_evidence(msg: dict, evidence_root) -> tuple[bool, list]:
    """True iff the message carries at least one valid evidence ref AND no invalid ones.

    A single forged ref poisons the whole message: mixing one real artifact with
    forged ones must not launder the forged ones across the bridge.
    """
    refs = msg.get("evidence", [])
    if not refs:
        return False, [("none", "no evidence attached")]
    details = []
    ok_all = True
    for r in refs:
        ok, reason = validate_ref(r, evidence_root)
        details.append((r.get("path", "?"), reason))
        ok_all = ok_all and ok
    return ok_all, details
