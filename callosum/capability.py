"""Capability matrix -- the plasticity substrate.

Per-subtask win rates decide bridge authority; aggregate score is the election
priority; absorb() is competence-profile-driven reassignment on hemisphere loss
(NOT bare failover): the survivor inherits the dead side's authorities and every
subtask where the dead side out-performed the survivor by >= margin is flagged
UNBACKED so degraded mode knows exactly which guarantees are currently missing.

Outcome writes go through the ledger (kind='capability_outcome') so the matrix
is reconstructible and poisoning is tamper-evident: rebuild() ignores anything
not present in a verified chain.

Three integrity rules this module must hold, each with a regression test:

1. Read-modify-write happens INSIDE the lock. `self.data` loaded at construction
   is a cache, not the truth; two live handles mutating from stale caches used
   to silently drop outcomes even though the write itself was locked.
2. rebuild() pins the signer. Verifying a chain without `trusted_pubs` accepts a
   chain an attacker re-signed end-to-end with their own key -- which is exactly
   the poisoning rebuild() exists to defeat.
3. Replay is faithful. absorb() reassigns only the subtasks the dead side (or
   nobody) held; replay must apply that same recorded map, not blanket-assign
   every subtask to the survivor.
"""
from __future__ import annotations

import os

from .util import FileLock, atomic_write_json, read_json


class CapabilityMatrix:
    def __init__(self, path, ledger=None, trusted_pubs: set[str] | None = None):
        self.path = os.fspath(path)
        self.lock_path = self.path + ".lock"
        self.ledger = ledger
        self.trusted_pubs = trusted_pubs
        # Unlike record_outcome/absorb, this initial read had no lock -- a
        # concurrent atomic_write_json's os.replace() from another process
        # can transiently raise PermissionError to an unprotected reader on
        # Windows (confirmed: ~7.5% of runs under real concurrent
        # construction + writes). _load() itself must stay lock-free since
        # record_outcome/absorb/rebuild_from_ledger already call it from
        # inside their own FileLock and re-acquiring would deadlock.
        with FileLock(self.lock_path):
            self.data = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {"subtasks": {}, "reassigned": {}, "unbacked": []}
        d = read_json(self.path)
        d.setdefault("subtasks", {})
        d.setdefault("reassigned", {})
        d.setdefault("unbacked", [])
        return d

    # ------------------------------------------------------------------ write
    @staticmethod
    def _tally(data: dict, subtask: str, winner: str, loser: str | None) -> None:
        st = data["subtasks"].setdefault(subtask, {})
        st[winner] = st.get(winner, {"wins": 0, "total": 0})
        st[winner]["wins"] += 1
        st[winner]["total"] += 1
        if loser:
            st[loser] = st.get(loser, {"wins": 0, "total": 0})
            st[loser]["total"] += 1

    def record_outcome(self, subtask: str, winner: str, loser: str | None = None) -> None:
        with FileLock(self.lock_path):
            self.data = self._load()  # refresh under the lock: no lost updates
            self._tally(self.data, subtask, winner, loser)
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
        """Reassign the dead hemisphere's authorities to the survivor; flag unbacked.

        The exact reassignment map is sealed to the ledger so replay reproduces
        this state rather than approximating it.
        """
        unbacked = []
        with FileLock(self.lock_path):
            self.data = self._load()  # refresh under the lock
            reassigned = {}
            for subtask in self.data["subtasks"]:
                if self.authority(subtask) in (dead, None):
                    reassigned[subtask] = survivor
                if self.win_rate(subtask, dead) - self.win_rate(subtask, survivor) >= margin:
                    unbacked.append(subtask)
            self.data["reassigned"].update(reassigned)
            self.data["unbacked"] = sorted(set(self.data["unbacked"]) | set(unbacked))
            atomic_write_json(self.path, self.data)
        if self.ledger is not None:
            self.ledger.append("capability_absorb", {
                "dead": dead, "survivor": survivor,
                "unbacked": unbacked, "reassigned": reassigned,
            })
        return unbacked

    def rebuild_from_ledger(self, trusted_pubs: set[str] | None = None) -> CapabilityMatrix:
        """Discard file state; replay only verified ledger outcomes (anti-poisoning).

        The chain is verified against a PINNED signer set -- by default the
        envelope key bound to this ledger. Without pinning, a chain re-signed
        end-to-end by an attacker verifies cleanly and rebuild becomes a
        poisoning vector instead of the defense against one.
        """
        if self.ledger is None:
            raise RuntimeError("no ledger bound")
        pubs = trusted_pubs or self.trusted_pubs
        if pubs is None:
            signer = getattr(self.ledger, "signer", None)
            pub = getattr(signer, "pub_hex", None)
            if not pub:
                raise RuntimeError("rebuild requires a trusted signer set; none could be inferred")
            pubs = {pub}
        ok, reason = self.ledger.verify(trusted_pubs=set(pubs))
        if not ok:
            raise RuntimeError(f"ledger failed verification: {reason}")

        data = {"subtasks": {}, "reassigned": {}, "unbacked": []}
        for e in self.ledger.entries():
            if e["kind"] == "capability_outcome":
                p = e["payload"]
                self._tally(data, p["subtask"], p["winner"], p.get("loser"))
            elif e["kind"] == "capability_absorb":
                p = e["payload"]
                recorded = p.get("reassigned")
                if recorded is None:
                    # legacy entry (written before the map was sealed): recompute
                    # the map from replay state rather than blanket-assigning.
                    scratch = CapabilityMatrix.__new__(CapabilityMatrix)
                    scratch.data = data
                    recorded = {s: p["survivor"] for s in data["subtasks"]
                                if scratch.authority(s) in (p["dead"], None)}
                data["reassigned"].update(recorded)
                data["unbacked"] = sorted(set(data["unbacked"]) | set(p["unbacked"]))
        self.data = data
        with FileLock(self.lock_path):
            atomic_write_json(self.path, self.data)
        return self
