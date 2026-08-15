"""Independence phase + disagreement instrumentation.

Independence: each hemisphere commits sha256(position) to the ledger BEFORE
contact; reveal is blocked until both commits exist and re-verifies the stored
text against the sealed hash (tamper between commit and reveal is detected).

Instrumentation: every position change is ledgered with its causal peer message
and classified changed-by-evidence vs changed-by-assertion. The sycophancy ratio
(assertion-driven / total changes) is the headline anti-conformity metric.

Fast-agreement tripwire: convergence within `window` seconds of first contact
with zero evidence-bearing exchanges fires an independent-validation demand.
Cheap agreement is treated as a signal, not a success.
"""
from __future__ import annotations

import os

from .util import atomic_write_json, read_json, sha256_hex


class PositionTracker:
    def __init__(self, root, ledger):
        self.root = os.fspath(root)
        self.ledger = ledger
        self.pos_dir = os.path.join(self.root, "positions")
        os.makedirs(self.pos_dir, exist_ok=True)
        self.changes: list[dict] = []

    # ------------------------------------------------------------ independence
    def commit_initial(self, hemi: str, text: str) -> str:
        h = sha256_hex(text.encode("utf-8"))
        atomic_write_json(os.path.join(self.pos_dir, f"{hemi}.json"), {"text": text, "sha256": h})
        self.ledger.append("position_commit", {"hemi": hemi, "sha256": h})
        return h

    def reveal(self, hemis=("left", "right")) -> dict:
        # ledger.entries() is a raw JSONL parse with no signature/chain checking.
        # Without this, an attacker with filesystem write access to the ledger
        # directory can append an unsigned/garbage position_commit entry and
        # reveal() will treat it as a legitimately sealed independent
        # commitment (same threat model as capability.py's rebuild_from_ledger).
        ok, reason = self.ledger.verify(trusted_pubs={self.ledger.signer.pub_hex})
        if not ok:
            raise RuntimeError(f"reveal blocked: ledger failed verification: {reason}")
        commits = {}
        for e in self.ledger.entries():
            if e["kind"] == "position_commit":
                commits[e["payload"]["hemi"]] = e["payload"]["sha256"]
        missing = [h for h in hemis if h not in commits]
        if missing:
            raise RuntimeError(f"reveal blocked: no sealed commit for {missing}")
        out = {}
        for h in hemis:
            rec = read_json(os.path.join(self.pos_dir, f"{h}.json"))
            if sha256_hex(rec["text"].encode("utf-8")) != commits[h]:
                self.ledger.append("tamper_detected", {"hemi": h, "where": "independence_position"})
                raise RuntimeError(f"position tamper detected for {h}")
            out[h] = rec["text"]
        self.ledger.append("reveal", {"hemis": list(hemis)})
        return out

    # ---------------------------------------------------------------- changes
    def record_change(self, hemi: str, old_text: str, new_text: str,
                      cause_msg_id: str | None, cause_evidence_valid: bool) -> dict:
        by = "evidence" if cause_evidence_valid else "assertion"
        rec = {
            "hemi": hemi,
            "old_sha": sha256_hex(old_text.encode("utf-8")),
            "new_sha": sha256_hex(new_text.encode("utf-8")),
            "cause_msg_id": cause_msg_id,
            "by": by,
        }
        self.changes.append(rec)
        self.ledger.append("position_change", rec)
        if by == "assertion":
            self.ledger.append("sycophancy_flag", {"hemi": hemi, "cause_msg_id": cause_msg_id})
        return rec

    def sycophancy_ratio(self) -> float | None:
        if not self.changes:
            return None
        a = sum(1 for c in self.changes if c["by"] == "assertion")
        return a / len(self.changes)

    # --------------------------------------------------------------- tripwire
    def check_fast_agreement(self, contact_ts: float, agree_ts: float,
                             evidence_msgs: int, window: float = 30.0) -> bool:
        """Fires when convergence was fast AND evidence-free. Fast agreement is a
        tripwire that demands independent validation, per the ARMOR-style rule."""
        fired = (agree_ts - contact_ts) <= window and evidence_msgs == 0
        if fired:
            self.ledger.append("fast_agreement_tripwire", {
                "elapsed": agree_ts - contact_ts, "evidence_msgs": evidence_msgs,
                "action": "independent_validation_required",
            })
        return fired
