"""Veridex protocol v1: hashing, event/config/checkpoint bodies, signatures.

Everything in this module is pure (no I/O) and must match the TypeScript
implementation byte-for-byte. Shared test vectors live in protocol/test-vectors.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence

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
MERKLE = "vmt-1"
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


# ---------------------------------------------------------------- merkle ----
#
# VMT-1: the RFC 6962 / RFC 9162 Merkle tree over the event hashes of one
# batch, in seq order. Leaves and interior nodes are domain-separated, and an
# odd node is promoted (never duplicated), so a root commits to exactly one
# ordered list of leaves.


def _hash32(hash_hex: str) -> bytes:
    if not isinstance(hash_hex, str) or len(hash_hex) != 64:
        raise ValueError("expected a 64-character hex hash")
    if hash_hex != hash_hex.lower():
        raise ValueError("hashes must be lowercase hex")
    return bytes.fromhex(hash_hex)


def _merkle_leaf(event_hash_hex: str) -> bytes:
    return hashlib.sha256(b"veridex/v1/merkle-leaf\x00" + _hash32(event_hash_hex)).digest()


def _merkle_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"veridex/v1/merkle-node\x00" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _subtree(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = _split(n)
    return _merkle_node(_subtree(leaves[:k]), _subtree(leaves[k:]))


def merkle_root(event_hashes: Sequence[str]) -> str:
    """Merkle root of a non-empty, ordered list of event hashes."""
    if not event_hashes:
        raise ValueError("a batch must contain at least one event")
    return _subtree([_merkle_leaf(h) for h in event_hashes]).hex()


def merkle_path(event_hashes: Sequence[str], index: int) -> list[str]:
    """Inclusion path (sibling hashes, leaf to root) for the leaf at ``index``."""
    if not 0 <= index < len(event_hashes):
        raise ValueError("leaf index out of range")
    leaves = [_merkle_leaf(h) for h in event_hashes]
    path: list[bytes] = []
    while len(leaves) > 1:
        k = _split(len(leaves))
        if index < k:
            path.append(_subtree(leaves[k:]))
            leaves = leaves[:k]
        else:
            path.append(_subtree(leaves[:k]))
            leaves, index = leaves[k:], index - k
    return [p.hex() for p in reversed(path)]


def verify_inclusion(
    event_hash_hex: str, leaf_index: int, tree_size: int, path: Sequence[str], root: str
) -> bool:
    """True iff ``event_hash_hex`` is leaf ``leaf_index`` of the ``tree_size``-leaf
    tree with root ``root`` (RFC 9162 section 2.1.3.2). Never raises."""
    try:
        if isinstance(leaf_index, bool) or isinstance(tree_size, bool):
            return False
        if not 0 <= leaf_index < tree_size:
            return False
        fn, sn = leaf_index, tree_size - 1
        r = _merkle_leaf(event_hash_hex)
        for p in path:
            sibling = _hash32(p)
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _merkle_node(sibling, r)
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                r = _merkle_node(r, sibling)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r == _hash32(root)
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------ checkpoint ----

CHECKPOINT_VERSION = 2  # v1 (stage 1) committed to the log head only


def checkpoint_body(
    *, log_id: str, batch: int, from_seq: int, seq: int, merkle_root: str, created_at: str
) -> dict[str, Any]:
    """A checkpoint commits to batch number ``batch``: events ``from_seq..seq``."""
    return {
        "v": CHECKPOINT_VERSION,
        "log_id": log_id,
        "batch": batch,
        "from_seq": from_seq,
        "seq": seq,
        "merkle_root": merkle_root,
        "created_at": created_at,
    }


def checkpoint_hash(body: dict[str, Any]) -> str:
    return tagged_hash("checkpoint", body)


def log_key(log_id: str) -> str:
    """32-byte key under which a log's batches are anchored on a blockchain."""
    return tagged_hash("log", log_id)


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
