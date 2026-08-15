"""Core primitives: canonical JSON, hashing, crash-safe atomic writes, cross-process locks.

Windows-first notes:
- Atomic write = tmp file + fsync + os.replace (atomic on NTFS and POSIX).
- FileLock uses msvcrt.locking with LK_NBLCK in an owned retry loop. We never use
  LK_LOCK because the Windows CRT retries it 10x internally (1/sec) and then raises,
  which makes timeout behavior non-deterministic. We own the retry loop instead.
- All JSON is written as bytes via canonical() -> no newline translation, CRLF-safe.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_bytes(path, data: bytes) -> None:
    """Crash-safe write: tmp in same dir -> flush -> fsync -> os.replace -> dir fsync (POSIX)."""
    path = os.fspath(path)
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def atomic_write_json(path, obj) -> None:
    atomic_write_bytes(path, canonical(obj))


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


if os.name == "nt":  # pragma: no cover - exercised on Windows only
    import msvcrt

    class FileLock:
        """Cross-process advisory lock. Non-blocking probe + owned retry loop."""

        def __init__(self, path, timeout: float = 10.0, poll: float = 0.02):
            self.path = os.fspath(path)
            self.timeout = timeout
            self.poll = poll
            self._f = None

        def acquire(self):
            deadline = time.monotonic() + self.timeout
            self._f = open(self.path, "a+b")  # noqa: SIM115 - the lock owns this handle for its lifetime
            if self._f.tell() == 0:
                self._f.write(b"\0")
                self._f.flush()
            while True:
                try:
                    self._f.seek(0)
                    msvcrt.locking(self._f.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError as exc:
                    if time.monotonic() > deadline:
                        self._f.close()
                        self._f = None
                        raise TimeoutError(f"lock timeout: {self.path}") from exc
                    time.sleep(self.poll)

        def release(self):
            if self._f is not None:
                try:
                    self._f.seek(0)
                    msvcrt.locking(self._f.fileno(), msvcrt.LK_UNLCK, 1)
                finally:
                    self._f.close()
                    self._f = None

        def __enter__(self):
            return self.acquire()

        def __exit__(self, *exc):
            self.release()

else:
    import fcntl

    class FileLock:
        """Cross-process advisory lock (flock). Non-blocking probe + owned retry loop."""

        def __init__(self, path, timeout: float = 10.0, poll: float = 0.02):
            self.path = os.fspath(path)
            self.timeout = timeout
            self.poll = poll
            self._f = None

        def acquire(self):
            deadline = time.monotonic() + self.timeout
            self._f = open(self.path, "a+b")  # noqa: SIM115 - the lock owns this handle for its lifetime
            while True:
                try:
                    fcntl.flock(self._f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except OSError as exc:
                    if time.monotonic() > deadline:
                        self._f.close()
                        self._f = None
                        raise TimeoutError(f"lock timeout: {self.path}") from exc
                    time.sleep(self.poll)

        def release(self):
            if self._f is not None:
                try:
                    fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
                finally:
                    self._f.close()
                    self._f = None

        def __enter__(self):
            return self.acquire()

        def __exit__(self, *exc):
            self.release()
