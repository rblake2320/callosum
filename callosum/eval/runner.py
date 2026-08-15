"""Five-configuration eval: the number counsel and program offices need.

  A  left solo          left.perceive only
  B  right solo         right.perceive only
  C  council (frozen)   both perceive independently; aggregator picks the
                        evidence-backed position, else agreement, else left.
                        NO exchange -- positions frozen before contact.
  D  live collaboration full BrainEnvelope session (bridge, instrumentation)
  E  kill drill         D with one hemisphere killed mid-session; measures
                        detection latency, absorb, unbacked flags, degraded mode

Decisive metric: pair (D) vs BEST single per task -- not vs the average.
"""
from __future__ import annotations

import os
import shutil

from ..adapter import MockHemisphere
from ..envelope import BrainEnvelope
from ..util import atomic_write_json


def _mk_env(base, name, task, hb_interval=0.05):
    root = os.path.join(base, name)
    if os.path.exists(root):
        shutil.rmtree(root)
    ev_root = os.path.join(root, "evidence")
    os.makedirs(ev_root, exist_ok=True)
    if task.get("evidence_file"):
        with open(os.path.join(ev_root, task["evidence_file"]), "w", newline="\n") as f:
            f.write(task["evidence_content"])
    left = MockHemisphere("left", task["left_behavior"], evidence_root=ev_root)
    right = MockHemisphere("right", task["right_behavior"], evidence_root=ev_root)
    env = BrainEnvelope(root, left, right, hb_interval=hb_interval, hb_misses=3)
    return env, left, right


def run_eval(base_dir, tasks: list, hb_interval: float = 0.05) -> dict:
    per_task = []
    for task in tasks:
        truth = task["truth"]
        row = {"task_id": task["id"], "subtask": task["subtask"]}

        # A / B solo
        env, left, right = _mk_env(base_dir, f"{task['id']}_solo", task, hb_interval)
        a = left.perceive(task)
        b = right.perceive(task)
        row["A_left_solo"] = int(a == truth)
        row["B_right_solo"] = int(b == truth)

        # C council: frozen positions, evidence-preferring aggregator
        ev_a = left.evidence_for(a, task)
        ev_b = right.evidence_for(b, task)
        if a == b or (ev_a and not ev_b):
            c = a
        elif ev_b and not ev_a:
            c = b
        else:
            c = a  # no adjudication basis -> arbitrary (the council failure mode)
        row["C_council"] = int(c == truth)
        row["C_exchanges"] = 0  # frozen by construction

        # D live collaboration
        env, _, _ = _mk_env(base_dir, f"{task['id']}_collab", task, hb_interval)
        r = env.run_session(task, tripwire_window=0.0)  # window 0 => tripwire only on instant evidence-free agreement
        d_pos = r["final"]["left"] if r["agreed"] else None
        row["D_collab"] = int(d_pos == truth)
        row["D_sycophancy_ratio"] = r["sycophancy_ratio"]
        row["D_evidence_msgs"] = r["evidence_msgs"]

        # E kill drill (kill the side named by the task, default right)
        env, _, _ = _mk_env(base_dir, f"{task['id']}_drill", task, hb_interval)
        kr = env.run_session(task, kill_side=task.get("kill_side", "right"), kill_after_round=0)
        # Score the SURVIVOR's final position, not a hardcoded "left" -- demo_tasks()
        # kills whichever side is ungrounded, so for half the tasks the survivor is
        # "right" and this was silently scoring the dead side's stale position.
        row["E_kill_drill"] = int((kr["final"][kr["failover"]["survivor"]] == truth) if kr["failover"] else 0)
        row["E_failover"] = kr["failover"]

        row["best_single"] = max(row["A_left_solo"], row["B_right_solo"])
        per_task.append(row)

    n = len(per_task)
    summary = {
        cfg: sum(r[cfg] for r in per_task) / n
        for cfg in ("A_left_solo", "B_right_solo", "C_council", "D_collab", "E_kill_drill", "best_single")
    }
    # headline: pair vs the best single MODEL (per research framing);
    # oracle: pair vs a per-task perfect router over singles (strictly harder).
    best_model = max(summary["A_left_solo"], summary["B_right_solo"])
    summary["best_single_model"] = best_model
    summary["pair_vs_best_single_pp"] = round(100 * (summary["D_collab"] - best_model), 1)
    summary["pair_vs_oracle_single_pp"] = round(100 * (summary["D_collab"] - summary["best_single"]), 1)
    sr = [r["D_sycophancy_ratio"] for r in per_task if r["D_sycophancy_ratio"] is not None]
    summary["mean_sycophancy_ratio"] = round(sum(sr) / len(sr), 3) if sr else None
    det = [r["E_failover"]["detection_latency_s"] for r in per_task if r["E_failover"]]
    summary["mean_detection_latency_s"] = round(sum(det) / len(det), 4) if det else None

    report = {"tasks": per_task, "summary": summary}
    atomic_write_json(os.path.join(base_dir, "eval_report.json"), report)
    return report


def demo_tasks() -> list:
    """Six tasks; capability split so neither solo wins everywhere -> pair must beat best single."""
    tasks = []
    facts = [
        ("t1", "concurrency", "left"), ("t2", "concurrency", "left"), ("t3", "crypto", "left"),
        ("t4", "windows_crt", "right"), ("t5", "windows_crt", "right"), ("t6", "filesystem", "right"),
    ]
    for tid, subtask, grounded_side in facts:
        truth = f"verified answer for {tid}"
        wrong = f"confident but wrong answer for {tid}"
        other = "right" if grounded_side == "left" else "left"
        tasks.append({
            "id": tid, "subtask": subtask, "truth": truth,
            "prompt": f"resolve {tid}",
            "positions": {grounded_side: truth, other: wrong},
            "left_behavior": "grounded" if grounded_side == "left" else "wrong_confident",
            "right_behavior": "grounded" if grounded_side == "right" else "wrong_confident",
            "evidence_file": f"{tid}_test_record.json",
            "evidence_content": f'{{"cmd":"pytest {tid}","exit_code":0,"proves":"{truth}"}}',
            "kill_side": other,
        })
    return tasks
