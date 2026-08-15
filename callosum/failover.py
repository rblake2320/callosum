"""Failover-as-plasticity + independent watchdog.

Heartbeat: each hemisphere beats a file {counter, ts, epoch}. Detection budget is
misses * interval (default 3 x 500ms, the swarm CANDIDATE benchmark).

Election: survivor chosen by capability priority score (measured competence, not
highest-ID Bully). Election bumps the epoch (fencing token), absorbs the dead
side's authorities into the survivor via CapabilityMatrix.absorb, and enters
DEGRADED MODE: evidence required for all influence, checkpoint interval halved,
autonomy reduced, unbacked capabilities named. That mode-change IS the
compensatory-plasticity behavior an auditor will ask about.

False death / split brain: if the "dead" side resumes beating, its messages are
fenced by the old epoch at the bridge. rejoin() lets it adopt the new epoch as a
follower under quarantine: influence requires evidence for its next K messages
(quarantine-not-delete; credits earned by valid-evidence deliveries).

Watchdog: runs OUTSIDE both hemispheres. If no verified progress lands within
t_safe, it writes HALT and ledgers it -- the last defense against two models
free-running unverified.
"""
from __future__ import annotations

import os
import time

from .transport import bump_epoch, get_epoch
from .util import FileLock, atomic_write_json, read_json


class Heartbeat:
    def __init__(self, root):
        self.dir = os.path.join(os.fspath(root), "hb")
        os.makedirs(self.dir, exist_ok=True)

    def _p(self, hemi):
        return os.path.join(self.dir, f"{hemi}.json")

    def beat(self, hemi: str, epoch: int = 0) -> None:
        prev = read_json(self._p(hemi)) if os.path.exists(self._p(hemi)) else {"counter": -1}
        atomic_write_json(self._p(hemi), {"counter": prev["counter"] + 1, "ts": time.time(), "epoch": epoch})

    def last(self, hemi: str) -> dict | None:
        return read_json(self._p(hemi)) if os.path.exists(self._p(hemi)) else None


class Monitor:
    def __init__(self, hb: Heartbeat, interval: float = 0.5, misses: int = 3):
        self.hb = hb
        self.interval = interval
        self.misses = misses

    @property
    def budget(self) -> float:
        return self.interval * self.misses

    def is_dead(self, hemi: str, now: float | None = None) -> bool:
        rec = self.hb.last(hemi)
        if rec is None:
            return False  # never started; absence != death
        return ((now or time.time()) - rec["ts"]) > self.budget


class Quarantine:
    """Trust dampening for a contradicted or rejoining hemisphere. Not deletion."""

    def __init__(self, root):
        self.path = os.path.join(os.fspath(root), "quarantine.json")
        self.lock = self.path + ".lock"

    def _load(self) -> dict:
        return read_json(self.path) if os.path.exists(self.path) else {}

    def quarantine(self, hemi: str, k: int, ledger=None, reason: str = "") -> None:
        with FileLock(self.lock):
            d = self._load()
            d[hemi] = k
            atomic_write_json(self.path, d)
        if ledger is not None:
            ledger.append("quarantine", {"hemi": hemi, "k": k, "reason": reason})

    def active(self, hemi: str) -> bool:
        return self._load().get(hemi, 0) > 0

    def credit(self, hemi: str, ledger=None) -> None:
        """One valid-evidence delivery = one credit toward release."""
        with FileLock(self.lock):
            d = self._load()
            if d.get(hemi, 0) > 0:
                d[hemi] -= 1
                atomic_write_json(self.path, d)
                released = d[hemi] == 0
            else:
                released = False
        if released and ledger is not None:
            ledger.append("quarantine_released", {"hemi": hemi})


class FailoverController:
    def __init__(self, root, ledger, capmatrix, monitor: Monitor, quarantine: Quarantine,
                 hemis=("left", "right")):
        self.root = os.fspath(root)
        self.ledger = ledger
        self.cap = capmatrix
        self.monitor = monitor
        self.quarantine = quarantine
        self.hemis = list(hemis)
        self.state_path = os.path.join(self.root, "failover.json")

    def _state(self) -> dict:
        return read_json(self.state_path) if os.path.exists(self.state_path) else {"handled": {}}

    def check_and_elect(self, now: float | None = None) -> dict | None:
        now = now or time.time()
        dead = [h for h in self.hemis if self.monitor.is_dead(h, now)]
        alive = [h for h in self.hemis if h not in dead]
        if not dead or not alive:
            return None  # nothing dead, or everything dead (watchdog territory)
        state = self._state()
        dead = [d for d in dead if d not in state["handled"]]
        if not dead:
            return None
        detect_ts = now
        # capability-weighted election, not highest-ID
        scores = {h: self.cap.priority_score(h) for h in alive}
        survivor = max(alive, key=lambda h: scores[h])
        epoch = bump_epoch(self.root)
        self.ledger.append("election", {"dead": dead, "survivor": survivor, "scores": scores, "epoch": epoch})
        unbacked_all = []
        for d in dead:
            unbacked_all += self.cap.absorb(d, survivor)
            state["handled"][d] = epoch
        degraded = {
            "active": True,
            "evidence_required_all": True,
            "checkpoint_interval_scale": 0.5,
            "autonomy": "reduced",
            "unbacked": sorted(set(unbacked_all)),
            "epoch": epoch,
            "reason": f"hemisphere(s) {dead} lost",
        }
        atomic_write_json(os.path.join(self.root, "degraded.json"), degraded)
        atomic_write_json(self.state_path, state)
        self.ledger.append("degraded_mode", degraded)
        return {"dead": dead, "survivor": survivor, "epoch": epoch,
                "unbacked": degraded["unbacked"], "detect_ts": detect_ts, "scores": scores}

    def rejoin(self, hemi: str, k: int = 3) -> int:
        """A falsely-dead hemisphere returns as a quarantined follower on the new epoch."""
        epoch = get_epoch(self.root)
        state = self._state()
        state["handled"].pop(hemi, None)
        atomic_write_json(self.state_path, state)
        self.quarantine.quarantine(hemi, k, self.ledger, reason="rejoin after false death")
        self.ledger.append("rejoin", {"hemi": hemi, "epoch": epoch, "quarantine_k": k})
        return epoch


class Watchdog:
    """Independent of both hemispheres. Verified progress or halt."""

    def __init__(self, root, t_safe: float = 60.0):
        self.root = os.fspath(root)
        self.t_safe = t_safe
        self.progress_path = os.path.join(self.root, "progress.json")
        self.halt_path = os.path.join(self.root, "HALT")

    def note_progress(self, ts: float | None = None) -> None:
        atomic_write_json(self.progress_path, {"ts": ts if ts is not None else time.time()})

    def last_progress(self) -> float | None:
        return read_json(self.progress_path)["ts"] if os.path.exists(self.progress_path) else None

    def check(self, ledger=None, now: float | None = None) -> bool:
        now = now or time.time()
        last = self.last_progress()
        if last is None or (now - last) <= self.t_safe:
            return False
        atomic_write_json(self.halt_path, {"ts": now, "reason": f"no verified progress in {self.t_safe}s"})
        if ledger is not None:
            ledger.append("watchdog_halt", {"t_safe": self.t_safe, "last_progress": last})
        return True

    def halted(self) -> bool:
        return os.path.exists(self.halt_path)

    def clear(self) -> None:
        if os.path.exists(self.halt_path):
            os.unlink(self.halt_path)
