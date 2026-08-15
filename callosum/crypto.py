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
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path) -> "Signer":
        with open(path, "rb") as f:
            raw = f.read()
        if raw[:4] == b"DPAP":  # pragma: no cover - windows only
            raw = dpapi_unprotect(raw[4:])
        else:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def save(self, path, use_dpapi: bool = False) -> None:
        raw = self._priv.private_bytes_raw()
        if use_dpapi and os.name == "nt":  # pragma: no cover - windows only
            blob = b"DPAP" + dpapi_protect(raw)
            with open(path, "wb") as f:
                f.write(blob)
        else:
            with open(path, "wb") as f:
                f.write(raw.hex().encode("ascii"))
            if os.name != "nt":
                os.chmod(path, 0o600)

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
