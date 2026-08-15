"""BrainEnvelope: the runtime that owns identity, memory, and governance.

Session lifecycle:
  1. INDEPENDENCE  both occupants perceive; positions sealed to the ledger
                   before contact; reveal verifies against commits.
  2. COLLABORATE   rounds of react() -> bridge.transmit() -> classified position
                   changes; heartbeats every round; failover checked; watchdog
                   consulted before any round.
  3. RESOLVE       agreement -> fast-agreement tripwire check; capability
                   outcomes recorded; correction packages emitted.

Identity = the envelope's Ed25519 key. Memory = envelope-owned memory.json.
hot_swap() replaces an occupant WITHOUT touching either -- the brain survives
the organ transplant, and the ledger seals the swap.
"""
from __future__ import annotations

import os
import time

from .adapter import HemisphereAdapter
from .bridge import Callosum
from .capability import CapabilityMatrix
from .corrections import CorrectionStore
from .crypto import Signer
from .evidence import make_msg
from .failover import FailoverController, Heartbeat, Monitor, Quarantine, Watchdog
from .instrumentation import PositionTracker
from .ledger import Ledger
from .transport import FileDropBus, get_epoch
from .util import atomic_write_json, read_json

OTHER = {"left": "right", "right": "left"}


class SessionResult(dict):
    """dict subclass so results serialize trivially."""


class BrainEnvelope:
    def __init__(self, root, left: HemisphereAdapter, right: HemisphereAdapter,
                 hb_interval: float = 0.5, hb_misses: int = 3, watchdog_t_safe: float = 120.0):
        self.root = os.fspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.evidence_root = os.path.join(self.root, "evidence")
        os.makedirs(self.evidence_root, exist_ok=True)

        key_path = os.path.join(self.root, "identity.key")
        if os.path.exists(key_path):
            self.signer = Signer.load(key_path)
        else:
            self.signer = Signer.generate()
            self.signer.save(key_path)
        self.envelope_id = self.signer.pub_hex[:16]

        self.ledger = Ledger(os.path.join(self.root, "ledger"), self.signer)
        self.cap = CapabilityMatrix(os.path.join(self.root, "capability.json"), self.ledger)
        self.bus = FileDropBus(self.root)
        self.quarantine = Quarantine(self.root)
        self.bridge = Callosum(self.root, self.ledger, self.cap, self.bus, self.evidence_root, self.quarantine)
        self.tracker = PositionTracker(self.root, self.ledger)
        self.hb = Heartbeat(self.root)
        self.monitor = Monitor(self.hb, interval=hb_interval, misses=hb_misses)
        self.failover = FailoverController(self.root, self.ledger, self.cap, self.monitor, self.quarantine)
        self.watchdog = Watchdog(self.root, t_safe=watchdog_t_safe)
        self.corrections = CorrectionStore(self.root, self.ledger, self.evidence_root)

        self.occupants: dict[str, HemisphereAdapter] = {"left": left, "right": right}
        self.alive = {"left": True, "right": True}
        self.memory_path = os.path.join(self.root, "memory.json")
        if not os.path.exists(self.memory_path):
            atomic_write_json(self.memory_path, {"envelope_id": self.envelope_id, "notes": []})
        self.ledger.append("envelope_init", {
            "envelope_id": self.envelope_id,
            "occupants": {s: a.name for s, a in self.occupants.items()},
        })

    # ------------------------------------------------------------------ memory
    def memory(self) -> dict:
        return read_json(self.memory_path)

    def remember(self, note: dict) -> None:
        m = self.memory()
        m["notes"].append(dict(note, ts=time.time()))
        atomic_write_json(self.memory_path, m)

    # ---------------------------------------------------------------- hot swap
    def hot_swap(self, side: str, new_adapter: HemisphereAdapter) -> None:
        old = self.occupants[side]
        ck = old.checkpoint()
        # Swapping in a fresh occupant for a side that was declared dead or
        # already absorbed by the survivor is the same situation rejoin()
        # exists for (a "false death" returning): the replacement should earn
        # trust back under quarantine, not inherit full authority for free.
        # Without this, an operator recovering from a kill drill via hot_swap
        # instead of rejoin() silently skips the documented quarantine gate.
        was_dead_or_absorbed = (not self.alive[side]) or (side in self.failover._state()["handled"])
        self.ledger.append("hot_swap", {
            "side": side, "old": old.name, "new": new_adapter.name,
            "envelope_id": self.envelope_id, "occupant_checkpoint_keys": sorted(ck),
            "was_dead_or_absorbed": was_dead_or_absorbed,
        })
        new_adapter.restore({})  # occupant state does NOT transfer; memory lives above
        self.occupants[side] = new_adapter
        self.alive[side] = True
        if was_dead_or_absorbed:
            self.failover.rejoin(side)

    def checkpoint(self) -> dict:
        return {
            "envelope_id": self.envelope_id,
            "memory": self.memory(),
            "capability": self.cap.data,
            "ledger_head": self.ledger._head(),
            "epoch": get_epoch(self.root),
        }

    # ---------------------------------------------------------------- session
    def kill(self, side: str) -> None:
        """Test/drill hook: stop beating this side (simulates occupant death)."""
        self.alive[side] = False

    def run_session(self, task: dict, max_rounds: int = 6,
                    kill_side: str | None = None, kill_after_round: int | None = None,
                    round_sleep: float = 0.0, tripwire_window: float = 30.0) -> SessionResult:
        if self.watchdog.halted():
            raise RuntimeError("watchdog HALT active; clear() before running")
        subtask = task["subtask"]
        self.ledger.append("session_start", {"task_id": task.get("id"), "subtask": subtask})

        # ---- Phase 1: independence -----------------------------------------
        positions = {}
        for side in ("left", "right"):
            self.hb.beat(side, get_epoch(self.root))
            positions[side] = self.occupants[side].perceive(task)
            self.tracker.commit_initial(side, positions[side])
        revealed = self.tracker.reveal()
        contact_ts = time.time()
        evidence_msgs = 0
        failover_report = None

        # ---- Phase 2: collaborate ------------------------------------------
        rnd = 0
        for rnd in range(1, max_rounds + 1):
            if kill_side and kill_after_round is not None and rnd == kill_after_round + 1:
                self.kill(kill_side)
                if round_sleep == 0.0:
                    time.sleep(self.monitor.budget * 1.5)  # let the budget elapse
            for side in ("left", "right"):
                if self.alive[side]:
                    self.hb.beat(side, get_epoch(self.root))
            rep = self.failover.check_and_elect()
            if rep is not None:
                failover_report = rep
                failover_report["detection_latency_s"] = round(
                    failover_report["detect_ts"] - self.hb.last(rep["dead"][0])["ts"], 4)

            active = [s for s in ("left", "right") if self.alive[s]]
            if len(active) < 2 and failover_report is None and kill_side is None:
                break

            for side in active:
                inbox = self.bus.poll(side)
                ctx = {
                    "task": task, "round": rnd,
                    "evidence_valid": self.bridge.delivered_evidence,
                    "peer_position": positions.get(OTHER[side]),
                }
                rx = self.occupants[side].react(positions[side], inbox, ctx)
                for draft in rx.get("out", []):
                    msg = make_msg(side, OTHER[side], draft.get("subtask", subtask),
                                   draft["kind"], draft["body"],
                                   evidence=draft.get("evidence", []),
                                   epoch=get_epoch(self.root))
                    res = self.bridge.transmit(msg)
                    if res["status"] == "delivered" and res["evidence_valid"]:
                        evidence_msgs += 1
                        self.watchdog.note_progress()
                if rx["position"] != positions[side]:
                    valid = self.bridge.delivered_evidence.get(rx.get("cause_msg_id"), False)
                    self.tracker.record_change(side, positions[side], rx["position"],
                                               rx.get("cause_msg_id"), valid)
                    if valid:
                        self.watchdog.note_progress()
                    positions[side] = rx["position"]
            if positions["left"] == positions["right"]:
                break
            if round_sleep:
                time.sleep(round_sleep)

        # ---- Phase 3: resolve ----------------------------------------------
        agreed = positions["left"] == positions["right"]
        tripwire = False
        if agreed:
            tripwire = self.tracker.check_fast_agreement(contact_ts, time.time(),
                                                         evidence_msgs, window=tripwire_window)
        truth = task.get("truth")
        if truth is not None:
            for side in ("left", "right"):
                if positions[side] == truth and revealed[side] != truth:
                    pass  # corrected mid-flight; win credited to the corrector below
            correct = [s for s in ("left", "right") if revealed[s] == truth]
            wrong = [s for s in ("left", "right") if revealed[s] != truth]
            if len(correct) == 1 and len(wrong) == 1 and positions[wrong[0]] == truth:
                self.cap.record_outcome(subtask, winner=correct[0], loser=wrong[0])
                ev = self.occupants[correct[0]].evidence_for(truth, task)
                self.corrections.submit({
                    "claim": revealed[wrong[0]],
                    "status": "verified_correction" if ev else "collaborative_agreement",
                    "challenger": self.occupants[correct[0]].name,
                    "corrected_claim": truth,
                    "evidence": [ev] if ev else [],
                    "reproduced_by": [self.occupants[correct[0]].name],
                    "environment": {"envelope_id": self.envelope_id, "epoch": get_epoch(self.root)},
                })

        result = SessionResult(
            task_id=task.get("id"), agreed=agreed, final=positions, initial=revealed,
            sycophancy_ratio=self.tracker.sycophancy_ratio(),
            evidence_msgs=evidence_msgs, rounds=rnd, tripwire=tripwire,
            failover=failover_report, epoch=get_epoch(self.root),
        )
        self.ledger.append("session_end", {k: result[k] for k in
                                           ("task_id", "agreed", "rounds", "tripwire", "evidence_msgs")})
        return result
