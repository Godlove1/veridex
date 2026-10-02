"""Veridex protocol v1: hashing, event/config/checkpoint bodies, signatures.

Everything in this module is pure (no I/O) and must match the TypeScript
implementation byte-for-byte. Shared test vectors live in protocol/test-vectors.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .canonical import canonical_bytes

PROTOCOL_VERSION = 1
HASH_ALGORITHM = "SHA-256"
CANONICALIZATION = "vcf-1"
GENESIS_HASH = "0" * 64

OPS_RECORD = ("CREATE", "UPDATE", "DELETE")
OP_CONFIGURE = "CONFIGURE"


def tagged_hash(tag: str, value: Any) -> str:
    """SHA-256 over a domain-separated canonical encoding.

    H(tag, v) = SHA256( "veridex/v1/" || tag || 0x00 || VCF-1(v) )

    The tag prevents a record hash from ever being confused with an event,
    config or checkpoint hash (cross-type collisions by construction).
    """
    h = hashlib.sha256()
    h.update(b"veridex/v1/")
    h.update(tag.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_bytes(value))
    return h.hexdigest()


# ---------------------------------------------------------------- record ----


def record_hash(protected: dict[str, Any]) -> str:
    """Hash of the normalized protected fields of one record."""
    return tagged_hash("record", protected)


# ---------------------------------------------------------------- config ----


def config_body(
    *,
    resource: str,
    schema: str,
    table: str,
    primary_key: list[str],
    fields: list[str],
    version: int,
    prev_config_hash: Optional[str],
) -> dict[str, Any]:
    if not fields:
        raise ValueError("at least one protected field is required")
    if not primary_key:
        raise ValueError("primary key columns are required")
    return {
        "v": PROTOCOL_VERSION,
        "resource": resource,
        "schema": schema,
        "table": table,
        "primary_key": list(primary_key),
        "fields": sorted(set(fields)),
        "version": version,
        "prev_config_hash": prev_config_hash,
        "canonicalization": CANONICALIZATION,
        "hash_algorithm": HASH_ALGORITHM,
    }


def config_hash(body: dict[str, Any]) -> str:
    return tagged_hash("config", body)


# ----------------------------------------------------------------- event ----

EVENT_FIELDS = (
    "v",
    "seq",
    "op",
    "resource",
    "record_id",
    "version",
    "record_hash",
    "prev_event_hash",
    "prev_log_hash",
    "config_hash",
    "created_at",
)


def event_body(
    *,
    seq: int,
    op: str,
    resource: str,
    record_id: Optional[str],
    version: int,
    record_hash: Optional[str],
    prev_event_hash: Optional[str],
    prev_log_hash: str,
    config_hash: str,
    created_at: str,
) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "seq": seq,
        "op": op,
        "resource": resource,
        "record_id": record_id,
        "version": version,
        "record_hash": record_hash,
        "prev_event_hash": prev_event_hash,
        "prev_log_hash": prev_log_hash,
        "config_hash": config_hash,
        "created_at": created_at,
    }


def event_hash(body: dict[str, Any]) -> str:
    return tagged_hash("event", body)


# ------------------------------------------------------------ checkpoint ----


def checkpoint_body(*, log_id: str, seq: int, head: str, created_at: str) -> dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "log_id": log_id,
        "seq": seq,
        "head": head,
        "created_at": created_at,
    }


def checkpoint_hash(body: dict[str, Any]) -> str:
    return tagged_hash("checkpoint", body)


# ------------------------------------------------------------- signatures ---


def key_id(public_key_hex: str) -> str:
    """Short identifier for a public key: first 16 hex chars of SHA-256(raw key)."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


@dataclass(frozen=True)
class Signer:
    """Ed25519 signer. Signs the raw 32 bytes of an already domain-tagged hash."""

    _sk: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Signer":
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes (64 hex chars)")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_hex(self) -> str:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @property
    def key_id(self) -> str:
        return key_id(self.public_key_hex)

    def seed_hex(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            NoEncryption,
            PrivateFormat,
        )

        return self._sk.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ).hex()

    def sign(self, hash_hex: str) -> str:
        return self._sk.sign(bytes.fromhex(hash_hex)).hex()


class TrustedKeys:
    """Public keys the verifier trusts. MUST come from configuration outside the
    protected database; a key read from the same database proves nothing."""

    def __init__(self, public_keys_hex: Iterable[str]):
        self._keys: dict[str, Ed25519PublicKey] = {}
        for pk in public_keys_hex:
            pk = pk.strip().lower()
            if not pk:
                continue
            self._keys[key_id(pk)] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk))
        if not self._keys:
            raise ValueError("at least one trusted public key is required")

    def verify(self, kid: str, hash_hex: str, signature_hex: str) -> bool:
        pk = self._keys.get(kid)
        if pk is None:
            return False
        try:
            pk.verify(bytes.fromhex(signature_hex), bytes.fromhex(hash_hex))
            return True
        except (InvalidSignature, ValueError):
            return False

    def __contains__(self, kid: str) -> bool:
        return kid in self._keys
