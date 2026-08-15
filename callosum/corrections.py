"""Correction packages -- the propagation layer (PathBook / aihangout.ai feed).

Three statuses are structurally distinct and only one publishes:
  model_disagreement      -> recorded, never publishable
  collaborative_agreement -> recorded, never publishable ("two models agreed" != true)
  verified_correction     -> publishable, REQUIRES valid execution evidence
  refuted                 -> recorded with evidence, not published standalone

Every accepted package is sealed into the ledger and appended to
corrections/corrections.jsonl. Aggregated verified packages are a
clean-provenance corpus by construction.
"""
from __future__ import annotations

import json
import os
import time
import uuid

from .evidence import validate_ref
from .util import FileLock, canonical

STATUSES = {"model_disagreement", "collaborative_agreement", "verified_correction", "refuted"}
EVIDENCE_REQUIRED = {"verified_correction", "refuted"}
PUBLISHABLE = {"verified_correction"}
REQUIRED_FIELDS = {"claim", "status", "environment"}


class CorrectionStore:
    def __init__(self, root, ledger, evidence_root):
        self.dir = os.path.join(os.fspath(root), "corrections")
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, "corrections.jsonl")
        self.lock_path = self.path + ".lock"
        self.ledger = ledger
        self.evidence_root = os.fspath(evidence_root)

    def submit(self, pkg: dict) -> dict:
        missing = REQUIRED_FIELDS - set(pkg)
        if missing:
            raise ValueError(f"missing fields: {sorted(missing)}")
        if pkg["status"] not in STATUSES:
            raise ValueError(f"invalid status: {pkg['status']}")
        if pkg["status"] in EVIDENCE_REQUIRED:
            refs = pkg.get("evidence", [])
            if not refs:
                raise ValueError(f"status '{pkg['status']}' requires evidence")
            for r in refs:
                ok, reason = validate_ref(r, self.evidence_root)
                if not ok:
                    raise ValueError(f"evidence rejected ({r.get('path')}): {reason}")
        rec = dict(
            pkg,
            correction_id=pkg.get("correction_id", uuid.uuid4().hex),
            ts=time.time(),
            publishable=pkg["status"] in PUBLISHABLE,
            confidence="verified-in-specified-environment" if pkg["status"] in EVIDENCE_REQUIRED else "unverified",
            revision=pkg.get("revision", 1),
        )
        # Same cross-process discipline as the ledger: an unlocked "ab" append is
        # not atomic across processes on Windows, and this corpus is meant to be
        # provenance-clean by construction.
        with FileLock(self.lock_path), open(self.path, "ab") as f:
            f.write(canonical(rec) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        self.ledger.append("correction", {k: rec[k] for k in ("correction_id", "claim", "status", "publishable")})
        return rec

    def all(self) -> list:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "rb") as f:
            return [json.loads(ln) for ln in f.read().splitlines() if ln.strip()]

    def publishable(self) -> list:
        return [r for r in self.all() if r.get("publishable")]
