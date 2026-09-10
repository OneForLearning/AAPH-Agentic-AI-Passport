from __future__ import annotations

import base64
import binascii
import secrets
import struct
import time
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import AgentError

MARKER = "NON_PRODUCTION_DEMO"
ACTION_DOMAIN = b"AAPH-POC-ACTION-PROPOSAL-V1\0"
SESSION_DOMAIN = b"AAPH-POC-SESSION-REQUEST-V1\0"


def canonical(value: Any) -> bytes:
    return jcs.canonicalize(value)


def transcript(domain: bytes, value: Any) -> bytes:
    payload = canonical(value)
    return struct.pack(">I", len(domain)) + domain + struct.pack(">Q", len(payload)) + payload


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def uuid7() -> str:
    timestamp = int(time.time_ns() // 1_000_000)
    if not 0 <= timestamp < 1 << 48:
        raise AgentError("system time outside UUIDv7 range")
    value = bytearray(secrets.token_bytes(16))
    value[:6] = timestamp.to_bytes(6, "big")
    value[6] = (value[6] & 0x0F) | 0x70
    value[8] = (value[8] & 0x3F) | 0x80
    text = value.hex()
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"


def sign(value: dict[str, Any], domain: bytes, key: Ed25519PrivateKey) -> dict[str, Any]:
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"marker": MARKER, "artifact": value, "signer_public_key": b64(public), "signature": b64(key.sign(transcript(domain, value)))}


def signer_public(key: Ed25519PrivateKey) -> str:
    return b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def load_key(path: Path) -> Ed25519PrivateKey:
    try:
        encoded = path.read_text(encoding="ascii").strip()
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
    except (OSError, ValueError, binascii.Error) as error:
        raise AgentError("agent signing key unavailable or invalid") from error
    if len(raw) != 32 or b64(raw) != encoded:
        raise AgentError("agent signing key unavailable or invalid")
    return Ed25519PrivateKey.from_private_bytes(raw)
