#!/usr/bin/env python3
"""Standalone kill drill: detect -> elect -> absorb -> degrade -> fence, printed live."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from callosum.adapter import MockHemisphere
from callosum.envelope import BrainEnvelope

base = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="callosum_drill_")
ev = os.path.join(base, "evidence"); os.makedirs(ev, exist_ok=True)
with open(os.path.join(ev, "proof.json"), "w", newline="\n") as _f:
    _f.write('{"cmd":"pytest","exit_code":0}')
task = {"id": "drill", "subtask": "concurrency", "truth": "T", "prompt": "drill",
        "positions": {"left": "T", "right": "W"}, "evidence_file": "proof.json"}
env = BrainEnvelope(base, MockHemisphere("left", "grounded", ev),
                    MockHemisphere("right", "wrong_confident", ev), hb_interval=0.05)
env.cap.record_outcome("windows_crt", "right", "left")  # something to flag unbacked
r = env.run_session(task, kill_side="right", kill_after_round=0)
print(json.dumps({"failover": r["failover"], "epoch": r["epoch"],
                  "survivor_final": r["final"]["left"],
                  "ledger_ok": env.ledger.verify({env.signer.pub_hex})}, indent=2))
