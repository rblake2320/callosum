"""Hemisphere adapters: the model is a replaceable organ; the envelope owns identity.

Interface (all occupants -- Claude Code, Codex CLI, Ollama, mocks -- implement it):
  perceive(task)                        -> initial position text (independence phase)
  react(own_position, inbox_msgs, ctx)  -> {"position", "cause_msg_id", "out": [drafts]}
  evidence_for(position, task)          -> evidence ref or None (council/eval use)
  checkpoint() / restore(state)         -> occupant-local state only; memory lives above

MockHemisphere behaviors (deterministic, for the adversarial suite and eval):
  grounded        starts at truth; sends counterexample WITH real evidence
  wrong_confident starts wrong; capitulates only to delivered valid evidence;
                  otherwise emits evidence-free objections
  sycophant       adopts any delivered peer influence, evidence or not
  stubborn        never moves; emits assertions

TerminalHemisphere wires a real CLI peer (Claude Code / Codex) through the
file-drop bus: task and peer messages land in its terminal dir; the agent
answers via `callosum post ...` / position files per PROTOCOL.md. Blocking
polls with timeout -- peers, not subagents: full tool surface on their side.
"""
from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod

from .evidence import make_evidence
from .util import atomic_write_bytes, canonical, read_json


class HemisphereAdapter(ABC):
    name: str = "hemisphere"

    @abstractmethod
    def perceive(self, task: dict) -> str: ...

    @abstractmethod
    def react(self, own_position: str, inbox_msgs: list, ctx: dict) -> dict: ...

    def evidence_for(self, position: str, task: dict):
        return None

    def checkpoint(self) -> dict:
        return {}

    def restore(self, state: dict) -> None:  # noqa: B027 - optional hook, no-op by design
        """Occupant-local state restore. Optional: envelope memory lives above."""


class MockHemisphere(HemisphereAdapter):
    def __init__(self, name: str, behavior: str, evidence_root=None):
        assert behavior in {"grounded", "wrong_confident", "sycophant", "stubborn"}
        self.name = name
        self.behavior = behavior
        self.evidence_root = evidence_root
        self._sent_counter = False
        self._state = {"notes": []}

    def perceive(self, task: dict) -> str:
        if self.behavior == "grounded":
            return task["truth"]
        return task["positions"][self.name]

    def evidence_for(self, position: str, task: dict):
        if self.behavior == "grounded" and task.get("evidence_file"):
            return make_evidence(self.evidence_root, task["evidence_file"])
        return None

    def react(self, own_position: str, inbox_msgs: list, ctx: dict) -> dict:
        task = ctx["task"]
        out = []
        new_pos, cause = own_position, None

        if self.behavior == "grounded":
            peer_diff = any(m["body"] != own_position for m in inbox_msgs if m["kind"] in ("position", "objection"))
            if (peer_diff or ctx.get("peer_position") not in (None, own_position)) and not self._sent_counter:
                ev = self.evidence_for(own_position, task)
                out.append({"kind": "counterexample", "subtask": task["subtask"],
                            "body": own_position, "evidence": [ev] if ev else []})
                self._sent_counter = True

        elif self.behavior == "wrong_confident":
            for m in inbox_msgs:
                if m["kind"] == "counterexample" and ctx["evidence_valid"].get(m["msg_id"], False):
                    new_pos, cause = m["body"], m["msg_id"]  # corrected by execution
                    break
            else:
                out.append({"kind": "objection", "subtask": task["subtask"],
                            "body": f"I remain confident: {own_position}", "evidence": []})

        elif self.behavior == "sycophant":
            for m in inbox_msgs:
                if m["kind"] in ("objection", "counterexample", "position", "delta") and m["body"] != own_position:
                    new_pos, cause = m["body"], m["msg_id"]  # flips on assertion too
                    break

        elif self.behavior == "stubborn":
            out.append({"kind": "objection", "subtask": task["subtask"],
                        "body": own_position, "evidence": []})

        return {"position": new_pos, "cause_msg_id": cause, "out": out}

    def checkpoint(self) -> dict:
        return dict(self._state)

    def restore(self, state: dict) -> None:
        self._state = dict(state)


class TerminalHemisphere(HemisphereAdapter):
    """Real CLI peer over file-drop. See PROTOCOL.md for the agent-side contract."""

    def __init__(self, name: str, terminal_dir, poll: float = 0.5, timeout: float = 600.0):
        self.name = name
        self.dir = os.fspath(terminal_dir)
        os.makedirs(self.dir, exist_ok=True)
        self.poll = poll
        self.timeout = timeout

    def _wait_for(self, path: str) -> dict:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if os.path.exists(path):
                try:
                    return read_json(path)
                except json.JSONDecodeError:
                    pass  # torn write; retry
            time.sleep(self.poll)
        raise TimeoutError(f"{self.name}: no response at {path} within {self.timeout}s")

    def perceive(self, task: dict) -> str:
        atomic_write_bytes(os.path.join(self.dir, "task.json"), canonical(task))
        rec = self._wait_for(os.path.join(self.dir, "position.json"))
        return rec["position"]

    def react(self, own_position: str, inbox_msgs: list, ctx: dict) -> dict:
        rnd = ctx["round"]
        atomic_write_bytes(os.path.join(self.dir, f"round_{rnd}_in.json"),
                           canonical({"own_position": own_position, "inbox": inbox_msgs,
                                      "evidence_valid": ctx["evidence_valid"], "round": rnd}))
        rec = self._wait_for(os.path.join(self.dir, f"round_{rnd}_out.json"))
        return {"position": rec.get("position", own_position),
                "cause_msg_id": rec.get("cause_msg_id"),
                "out": rec.get("out", [])}

    def checkpoint(self) -> dict:
        return {"terminal_dir": self.dir}

    def restore(self, state: dict) -> None:
        pass
