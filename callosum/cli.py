"""`callosum` CLI -- the command surface real terminal occupants (Claude Code /
Codex CLI) use to speak on the bus. See PROTOCOL.md.

  callosum init   --root R
  callosum post   --root R --sender left --subtask X --kind counterexample \
                  --body "..." [--evidence rel/path ...]
  callosum beat   --root R --hemi left
  callosum verify --root R
  callosum status --root R

`init` exists because every other subcommand requires an envelope root that
already holds an identity key, and the only way to create one was to write
Python by hand -- the documented "wire real terminals" path had no entry point.
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
from .util import atomic_write_json, read_json

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

    si = sub.add_parser("init", help="create an envelope root ready for two terminal occupants")
    si.add_argument("--root", required=True)
    si.add_argument("--force", action="store_true", help="reuse a root that already has an identity key")

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

    if a.cmd == "init":
        root = os.path.abspath(a.root)
        key_path = os.path.join(root, "identity.key")
        if os.path.exists(key_path) and not a.force:
            print(json.dumps({"ok": False,
                              "reason": f"identity.key already exists at {key_path}; "
                                        "refusing to overwrite an envelope identity (use --force to reuse)"}))
            return 4
        for d in ("evidence", "terminals/left", "terminals/right", "ledger", "bus"):
            os.makedirs(os.path.join(root, *d.split("/")), exist_ok=True)
        if not os.path.exists(key_path):
            Signer.generate().save(key_path)  # DPAPI on Windows, 0600 on POSIX
        signer = Signer.load(key_path)
        ledger = Ledger(os.path.join(root, "ledger"), signer)
        if not os.path.exists(os.path.join(root, "epoch.json")):
            atomic_write_json(os.path.join(root, "epoch.json"), {"epoch": 0})
        ledger.append("envelope_init_cli", {"envelope_id": signer.pub_hex[:16], "root": root})
        print(json.dumps({
            "ok": True,
            "root": root,
            "envelope_id": signer.pub_hex[:16],
            "epoch": get_epoch(root),
            "next": [
                f"open one agent in {os.path.join(root, 'terminals', 'left')} and one in "
                f"{os.path.join(root, 'terminals', 'right')}",
                "paste PROTOCOL.md into each agent",
                f"each agent starts its heartbeat: callosum beat --root {root} --hemi <left|right>",
                f"drop evidence artifacts under {os.path.join(root, 'evidence')}",
            ],
        }, indent=2))
        return 0

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
        qpath = os.path.join(root, "quarantine.json")
        out = {
            "epoch": get_epoch(root),
            "degraded": read_json(os.path.join(root, "degraded.json"))
            if os.path.exists(os.path.join(root, "degraded.json")) else None,
            "halt": os.path.exists(os.path.join(root, "HALT")),
            # PROTOCOL.md tells occupants to run `status` when confused, but
            # quarantine is precisely the state that silently changes what the
            # bridge demands of them. Surfacing it is not optional.
            "quarantine": {k: v for k, v in (read_json(qpath) if os.path.exists(qpath) else {}).items() if v > 0},
        }
        print(json.dumps(out, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
