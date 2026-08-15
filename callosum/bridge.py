"""The callosum: an INHIBITORY, evidence-gated bridge -- not a pipe.

Transmission rules (in order):
  1. Epoch fence: msg.epoch != current epoch -> REJECTED (split-brain guard).
     Equality, not `<`. A `<` test fences only honest stragglers: a fenced
     hemisphere could stamp an arbitrarily high epoch and walk straight through
     the guard. Epochs are envelope-assigned, so any deviation is illegitimate.
  2. Non-influence kinds (status, position) always pass, logged.
  3. Quarantined sender: ALL influence requires valid evidence, authority or not.
  4. Authority holder on the subtask: influence passes without evidence (logged,
     evidence still validated and recorded if present).
  5. Non-authoritative sender: influence is SUPPRESSED unless it carries valid
     evidence (counterexample-with-citation rule). Suppressions are ledgered --
     dissent is damped in-flight but never erased.
  6. Untracked subtask (authority None, no reassignment): pass, flagged
     'unadjudicated' -- there is no basis to inhibit yet.
  7. Degraded mode (post-failover): evidence required for ALL influence.

Every delivery/suppression/rejection is a sealed ledger entry. delivered_evidence
maps msg_id -> bool(valid evidence) so instrumentation can classify downstream
position changes as evidence-driven vs assertion-driven (sycophancy).
"""
from __future__ import annotations

import os

from .evidence import INFLUENCE_KINDS, validate_msg_evidence
from .transport import FileDropBus, get_epoch
from .util import read_json


class Callosum:
    def __init__(self, root, ledger, capmatrix, bus: FileDropBus, evidence_root, quarantine=None):
        self.root = os.fspath(root)
        self.ledger = ledger
        self.cap = capmatrix
        self.bus = bus
        self.evidence_root = os.fspath(evidence_root)
        self.quarantine = quarantine
        self.delivered_evidence: dict[str, bool] = {}

    # ------------------------------------------------------------------ rules
    def _degraded_requires_evidence(self) -> bool:
        p = os.path.join(self.root, "degraded.json")
        if os.path.exists(p):
            return bool(read_json(p).get("evidence_required_all", False))
        return False

    def transmit(self, msg: dict) -> dict:
        base = {
            "msg_id": msg["msg_id"], "sender": msg["sender"], "recipient": msg["recipient"],
            "subtask": msg["subtask"], "kind": msg["kind"],
        }
        # 1. epoch fence (equality: a forged-forward epoch must not bypass the guard)
        current = get_epoch(self.root)
        sent = msg.get("epoch", 0)
        if sent != current:
            reason = "stale_epoch" if sent < current else "future_epoch"
            self.ledger.append("bridge_rejected",
                               dict(base, reason=f"{reason}: msg epoch {sent} != current {current}"))
            return {"status": "rejected", "reason": reason, "evidence_valid": False}

        influence = msg["kind"] in INFLUENCE_KINDS
        ev_ok, ev_details = (validate_msg_evidence(msg, self.evidence_root)
                             if msg.get("evidence") else (False, [("none", "no evidence attached")]))

        # 2. non-influence always passes
        if not influence:
            return self._deliver(msg, base, ev_ok, note="non-influence")


        quarantined = bool(self.quarantine and self.quarantine.active(msg["sender"]))
        authority = self.cap.authority(msg["subtask"])
        degraded = self._degraded_requires_evidence()

        needs_evidence = (
            quarantined
            or degraded
            or (authority is not None and authority != msg["sender"])
        )

        if needs_evidence and not ev_ok:
            reason = ("quarantined sender" if quarantined else
                      "degraded mode" if degraded else
                      f"non-authoritative on '{msg['subtask']}' (authority={authority})")
            self.ledger.append("bridge_suppressed", dict(base, reason=reason, evidence=ev_details))
            return {"status": "suppressed", "reason": reason, "evidence_valid": False, "evidence": ev_details}

        note = "unadjudicated subtask" if (authority is None and not quarantined and not degraded) else "ok"
        result = self._deliver(msg, base, ev_ok, note=note)
        if quarantined and ev_ok and self.quarantine:
            self.quarantine.credit(msg["sender"], self.ledger)
        return result

    def _deliver(self, msg: dict, base: dict, ev_ok: bool, note: str) -> dict:
        self.bus.post(msg["recipient"], msg)
        self.delivered_evidence[msg["msg_id"]] = ev_ok
        # Seal WHICH artifact bought the crossing, not merely that one did.
        # Suppressions already recorded their evidence detail; deliveries did
        # not, so a delivered influence message could not be re-adjudicated
        # from the chain after the fact. Claim seed 1(e) needs both sides.
        self.ledger.append("bridge_delivered", dict(
            base,
            evidence_valid=ev_ok,
            note=note,
            evidence=[{"path": r.get("path"), "sha256": r.get("sha256"), "etype": r.get("etype")}
                      for r in msg.get("evidence", [])],
        ))
        return {"status": "delivered", "reason": note, "evidence_valid": ev_ok}
