"""`callosum` CLI -- the command surface real terminal occupants (Claude Code /
Codex CLI) use to speak on the bus. See PROTOCOL.md.

  callosum post   --root R --sender left --subtask X --kind counterexample \
                  --body "..." [--evidence rel/path ...]
  callosum beat   --root R --hemi left
  callosum verify --root R
  callosum status --root R
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .bridge import Callosum
from .capability import CapabilityMatrix
from .crypto import Signer
from .evidence import make_evidence, make_msg
from .failover import Heartbeat, Quarantine
from .ledger import Ledger
from .transport import FileDropBus, get_epoch
from .util import read_json

OTHER = {"left": "right", "right": "left"}


def _open(root):
    signer = Signer.load(os.path.join(root, "identity.key"))
    ledger = Ledger(os.path.join(root, "ledger"), signer)
    cap = CapabilityMatrix(os.path.join(root, "capability.json"), ledger)
    bus = FileDropBus(root)
    q = Quarantine(root)
    bridge = Callosum(root, ledger, cap, bus, os.path.join(root, "evidence"), q)
    return signer, ledger, cap, bus, bridge


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="callosum")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("post")
    sp.add_argument("--root", required=True)
    sp.add_argument("--sender", required=True, choices=["left", "right"])
    sp.add_argument("--subtask", required=True)
    sp.add_argument("--kind", required=True)
    sp.add_argument("--body", required=True)
    sp.add_argument("--evidence", nargs="*", default=[])

    sb = sub.add_parser("beat")
    sb.add_argument("--root", required=True)
    sb.add_argument("--hemi", required=True, choices=["left", "right"])

    sv = sub.add_parser("verify")
    sv.add_argument("--root", required=True)

    ss = sub.add_parser("status")
    ss.add_argument("--root", required=True)

    a = p.parse_args(argv)

    if a.cmd == "post":
        _, _, _, _, bridge = _open(a.root)
        refs = [make_evidence(os.path.join(a.root, "evidence"), rel) for rel in a.evidence]
        msg = make_msg(a.sender, OTHER[a.sender], a.subtask, a.kind, a.body,
                       evidence=refs, epoch=get_epoch(a.root))
        res = bridge.transmit(msg)
        print(json.dumps(res))
        return 0 if res["status"] == "delivered" else 2

    if a.cmd == "beat":
        Heartbeat(a.root).beat(a.hemi, get_epoch(a.root))
        print("ok")
        return 0

    if a.cmd == "verify":
        signer, ledger, _, _, _ = _open(a.root)
        ok, reason = ledger.verify(trusted_pubs={signer.pub_hex})
        print(json.dumps({"ok": ok, "reason": reason}))
        return 0 if ok else 3

    if a.cmd == "status":
        root = a.root
        out = {
            "epoch": get_epoch(root),
            "degraded": read_json(os.path.join(root, "degraded.json"))
            if os.path.exists(os.path.join(root, "degraded.json")) else None,
            "halt": os.path.exists(os.path.join(root, "HALT")),
        }
        print(json.dumps(out, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
