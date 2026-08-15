"""Ed25519 identity for the envelope. The KEY belongs to the envelope, not to any
model occupant -- swapping a hemisphere never rotates identity.

Windows hardening: wrap the saved key with DPAPI via protect()/unprotect() below
(CryptProtectData, CURRENT_USER scope). POSIX fallback is chmod 600.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Signer:
    def __init__(self, priv: Ed25519PrivateKey):
        self._priv = priv
        self._pub_hex = priv.public_key().public_bytes_raw().hex()

    @classmethod
    def generate(cls) -> Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path) -> Signer:
        with open(path, "rb") as f:
            raw = f.read()
        if raw[:4] == b"DPAP":  # pragma: no cover - windows only
            raw = dpapi_unprotect(raw[4:])
        else:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def save(self, path, use_dpapi: bool | None = None) -> None:
        """Persist the envelope key.

        `use_dpapi=None` (the default) means "protect it if the platform can":
        DPAPI-wrapped on Windows, 0600 on POSIX. It used to default to False,
        so every BrainEnvelope wrote a bare hex private key to disk while the
        README advertised DPAPI wrapping -- the documented hardening was never
        on the runtime path. Pass False explicitly to opt out.

        POSIX mode is set at create time via O_EXCL|0600, not chmod'd after the
        bytes are already on disk with the ambient umask.
        """
        if use_dpapi is None:
            use_dpapi = os.name == "nt"
        raw = self._priv.private_bytes_raw()
        if use_dpapi and os.name == "nt":  # pragma: no cover - windows only
            payload = b"DPAP" + dpapi_protect(raw)
        else:
            payload = raw.hex().encode("ascii")
        path = os.fspath(path)
        if os.name != "nt":
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            os.chmod(path, 0o600)  # idempotent when the file pre-existed
        else:  # pragma: no cover - windows only
            with open(path, "wb") as f:
                f.write(payload)

    @property
    def pub_hex(self) -> str:
        return self._pub_hex

    def sign_hex(self, msg: bytes) -> str:
        return self._priv.sign(msg).hex()


def verify_hex(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), msg)
        return True
    except Exception:
        return False


# --- Windows DPAPI (CNG-era user-scope wrap). No-op imports on POSIX. ---
if os.name == "nt":  # pragma: no cover - windows only
    import ctypes
    import ctypes.wintypes as wt

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> _BLOB:
        buf = ctypes.create_string_buffer(data, len(data))
        return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def _out(blob: _BLOB) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob.pbData)

    def dpapi_protect(data: bytes) -> bytes:
        out = _BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(_blob(data)), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptProtectData failed")
        return _out(out)

    def dpapi_unprotect(data: bytes) -> bytes:
        out = _BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(_blob(data)), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptUnprotectData failed")
        return _out(out)
else:
    def dpapi_protect(data: bytes) -> bytes:  # pragma: no cover
        raise OSError("DPAPI is Windows-only")

    def dpapi_unprotect(data: bytes) -> bytes:  # pragma: no cover
        raise OSError("DPAPI is Windows-only")
