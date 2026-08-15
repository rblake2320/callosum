"""File-drop bus: the honest cross-vendor channel.

Layout under <root>/bus/:
    <hemi>/inbox/       delivered messages awaiting the occupant
    <hemi>/processed/   consumed messages (delta-push: moved, never re-read)

Post = atomic write into inbox with a monotonic ns-timestamp filename. Poll =
read sorted, os.replace into processed. os.replace is atomic on NTFS + POSIX,
so a consumer never sees a half-written message and never reads twice.

Epoch fencing lives here too: epoch.json is the fencing token. Elections bump
it under lock; the bridge rejects any message stamped with an older epoch,
which is the split-brain guard for a falsely-declared-dead hemisphere.
"""
from __future__ import annotations

import json
import os
import time

from .util import FileLock, atomic_write_json, read_json


class FileDropBus:
    def __init__(self, root):
        self.root = os.path.join(os.fspath(root), "bus")
        os.makedirs(self.root, exist_ok=True)

    def _dirs(self, hemi: str) -> tuple[str, str]:
        inbox = os.path.join(self.root, hemi, "inbox")
        processed = os.path.join(self.root, hemi, "processed")
        os.makedirs(inbox, exist_ok=True)
        os.makedirs(processed, exist_ok=True)
        return inbox, processed

    def post(self, recipient: str, msg: dict) -> str:
        inbox, _ = self._dirs(recipient)
        fname = f"{time.time_ns():020d}_{msg['msg_id']}.json"
        from .util import atomic_write_bytes, canonical

        atomic_write_bytes(os.path.join(inbox, fname), canonical(msg))
        return fname

    def poll(self, hemi: str) -> list:
        """Consume all pending messages exactly once (delta-push semantics)."""
        inbox, processed = self._dirs(hemi)
        out = []
        for fname in sorted(os.listdir(inbox)):
            if not fname.endswith(".json"):
                continue
            src = os.path.join(inbox, fname)
            try:
                with open(src, "rb") as f:
                    msg = json.loads(f.read().decode("utf-8"))
            except (json.JSONDecodeError, OSError):
                continue  # torn write in-flight; next poll gets it
            os.replace(src, os.path.join(processed, fname))
            out.append(msg)
        return out

    def pending(self, hemi: str) -> int:
        inbox, _ = self._dirs(hemi)
        return len([f for f in os.listdir(inbox) if f.endswith(".json")])


# ------------------------------------------------------------------ epoch fence
def _epoch_paths(root):
    return os.path.join(os.fspath(root), "epoch.json"), os.path.join(os.fspath(root), "epoch.lock")


def get_epoch(root) -> int:
    p, _ = _epoch_paths(root)
    return read_json(p)["epoch"] if os.path.exists(p) else 0


def bump_epoch(root) -> int:
    p, lock = _epoch_paths(root)
    with FileLock(lock):
        e = (read_json(p)["epoch"] if os.path.exists(p) else 0) + 1
        atomic_write_json(p, {"epoch": e})
        return e
