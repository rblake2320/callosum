"""TerminalHemisphere adversarial suite.

Proves: react() tolerates a real CLI peer's malformed round_N_out.json (typo'd
or missing draft keys, invalid kind) by dropping the bad draft instead of
crashing the whole governed session with a raw KeyError/ValueError -- the same
tolerance already given to torn/malformed JSON in _wait_for.
"""
import json
import threading
import time

from callosum.adapter import TerminalHemisphere


def _write_after(path, payload, delay=0.05):
    def go():
        time.sleep(delay)
        with open(path, "w") as f:
            json.dump(payload, f)
    threading.Thread(target=go, daemon=True).start()


def test_react_drops_draft_missing_kind_key(tmp_path):
    t = TerminalHemisphere("right", tmp_path, poll=0.02, timeout=5.0)
    out_path = str(tmp_path / "round_1_out.json")
    _write_after(out_path, {
        "position": "same",
        "out": [{"type": "objection", "body": "typo'd key, not 'kind'"}],  # malformed
    })
    rx = t.react("same", [], {"round": 1, "evidence_valid": {}})
    assert rx["out"] == []  # malformed draft dropped, not raised


def test_react_drops_draft_with_invalid_kind_value(tmp_path):
    t = TerminalHemisphere("right", tmp_path, poll=0.02, timeout=5.0)
    out_path = str(tmp_path / "round_1_out.json")
    _write_after(out_path, {
        "position": "same",
        "out": [{"kind": "not_a_real_kind", "body": "x"}],  # would blow up make_msg()
    })
    rx = t.react("same", [], {"round": 1, "evidence_valid": {}})
    assert rx["out"] == []


def test_react_passes_through_well_formed_draft(tmp_path):
    t = TerminalHemisphere("right", tmp_path, poll=0.02, timeout=5.0)
    out_path = str(tmp_path / "round_1_out.json")
    _write_after(out_path, {
        "position": "same",
        "out": [{"kind": "objection", "body": "I disagree", "subtask": "s"}],
    })
    rx = t.react("same", [], {"round": 1, "evidence_valid": {}})
    assert len(rx["out"]) == 1 and rx["out"][0]["kind"] == "objection"
