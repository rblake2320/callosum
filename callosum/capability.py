"""Capability matrix -- the plasticity substrate.

Per-subtask win rates decide bridge authority; aggregate score is the election
priority; absorb() is competence-profile-driven reassignment on hemisphere loss
(NOT bare failover): the survivor inherits the dead side's authorities and every
subtask where the dead side out-performed the survivor by >= margin is flagged
UNBACKED so degraded mode knows exactly which guarantees are currently missing.

Outcome writes go through the ledger (kind='capability_outcome') so the matrix
is reconstructible and poisoning is tamper-evident: rebuild() ignores anything
not present in a verified chain.
"""
from __future__ import annotations

import os

from .util import FileLock, atomic_write_json, read_json


class CapabilityMatrix:
    def __init__(self, path, ledger=None):
        self.path = os.fspath(path)
        self.lock_path = self.path + ".lock"
        self.ledger = ledger
        self.data = read_json(self.path) if os.path.exists(self.path) else {
            "subtasks": {}, "reassigned": {}, "unbacked": []
        }

    # ------------------------------------------------------------------ write
    def record_outcome(self, subtask: str, winner: str, loser: str | None = None) -> None:
        with FileLock(self.lock_path):
            st = self.data["subtasks"].setdefault(subtask, {})
            st[winner] = st.get(winner, {"wins": 0, "total": 0})
            st[winner]["wins"] += 1
            st[winner]["total"] += 1
            if loser:
                st[loser] = st.get(loser, {"wins": 0, "total": 0})
                st[loser]["total"] += 1
            atomic_write_json(self.path, self.data)
        if self.ledger is not None:
            self.ledger.append("capability_outcome", {"subtask": subtask, "winner": winner, "loser": loser})

    # ------------------------------------------------------------------- read
    def win_rate(self, subtask: str, hemi: str) -> float:
        st = self.data["subtasks"].get(subtask, {})
        rec = st.get(hemi)
        return (rec["wins"] / rec["total"]) if rec and rec["total"] else 0.0

    def authority(self, subtask: str) -> str | None:
        """Higher win-rate side holds authority; reassignment overrides; tie -> None
        (no basis to inhibit: both sides must carry evidence)."""
        if subtask in self.data["reassigned"]:
            return self.data["reassigned"][subtask]
        st = self.data["subtasks"].get(subtask, {})
        if not st:
            return None
        best = sorted(st.items(), key=lambda kv: self.win_rate(subtask, kv[0]), reverse=True)
        if len(best) >= 2 and self.win_rate(subtask, best[0][0]) == self.win_rate(subtask, best[1][0]):
            return None
        return best[0][0]

    def priority_score(self, hemi: str) -> float:
        """Election priority: mean win rate across tracked subtasks (capability, not ID)."""
        rates = [self.win_rate(s, hemi) for s in self.data["subtasks"]]
        return sum(rates) / len(rates) if rates else 0.0

    # ------------------------------------------------------------- plasticity
    def absorb(self, dead: str, survivor: str, margin: float = 0.15) -> list:
        """Reassign the dead hemisphere's authorities to the survivor; flag unbacked."""
        unbacked = []
        with FileLock(self.lock_path):
            for subtask in self.data["subtasks"]:
                if self.authority(subtask) in (dead, None):
                    self.data["reassigned"][subtask] = survivor
                if self.win_rate(subtask, dead) - self.win_rate(subtask, survivor) >= margin:
                    unbacked.append(subtask)
            self.data["unbacked"] = sorted(set(self.data["unbacked"]) | set(unbacked))
            atomic_write_json(self.path, self.data)
        if self.ledger is not None:
            self.ledger.append("capability_absorb", {"dead": dead, "survivor": survivor, "unbacked": unbacked})
        return unbacked

    def rebuild_from_ledger(self) -> "CapabilityMatrix":
        """Discard file state; replay only verified ledger outcomes (anti-poisoning)."""
        if self.ledger is None:
            raise RuntimeError("no ledger bound")
        ok, reason = self.ledger.verify()
        if not ok:
            raise RuntimeError(f"ledger failed verification: {reason}")
        self.data = {"subtasks": {}, "reassigned": {}, "unbacked": []}
        for e in self.ledger.entries():
            if e["kind"] == "capability_outcome":
                p = e["payload"]
                st = self.data["subtasks"].setdefault(p["subtask"], {})
                st[p["winner"]] = st.get(p["winner"], {"wins": 0, "total": 0})
                st[p["winner"]]["wins"] += 1
                st[p["winner"]]["total"] += 1
                if p.get("loser"):
                    st[p["loser"]] = st.get(p["loser"], {"wins": 0, "total": 0})
                    st[p["loser"]]["total"] += 1
            elif e["kind"] == "capability_absorb":
                p = e["payload"]
                for subtask in self.data["subtasks"]:
                    self.data["reassigned"][subtask] = p["survivor"]
                self.data["unbacked"] = sorted(set(self.data["unbacked"]) | set(p["unbacked"]))
        atomic_write_json(self.path, self.data)
        return self
