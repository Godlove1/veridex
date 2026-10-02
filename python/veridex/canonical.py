"""Veridex Canonical Form, version 1 (VCF-1).

Deterministic JSON-like serialization that MUST produce byte-identical output
in every Veridex implementation. See protocol/SPEC.md section 2.

Accepted value types:  str, int (safe range), bool, None, list/tuple, dict with str keys.
Rejected:              float, NaN, out-of-range int, non-str keys, lone surrogates,
                       duplicate keys after NFC normalization, anything else.

Values coming out of a database must first pass through value normalization
(veridex.normalize) which converts Decimal, datetime, UUID, bytes, etc. into strings.
"""

from __future__ import annotations

import unicodedata
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented in VCF-1."""


def _nfc(s: str) -> str:
    try:
        s.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        raise CanonicalizationError("string contains a lone surrogate") from e
    return unicodedata.normalize("NFC", s)


def _encode_string(s: str) -> str:
    s = _nfc(s)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode(value: Any, depth: int) -> str:
    if depth > 64:
        raise CanonicalizationError("nesting deeper than 64 levels")
    # bool must be checked before int: bool is a subclass of int in Python.
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer {value} outside safe range; encode it as a string"
            )
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(
            "floats are not allowed in VCF-1; use a decimal string"
        )
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        items: dict[bytes, tuple[str, Any]] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"object key {k!r} is not a string")
            nk = _nfc(k)
            kb = nk.encode("utf-8")
            if kb in items:
                raise CanonicalizationError(
                    f"duplicate key after NFC normalization: {nk!r}"
                )
            items[kb] = (nk, v)
        parts = [
            _encode_string(items[kb][0]) + ":" + _encode(items[kb][1], depth + 1)
            for kb in sorted(items)
        ]
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(
        f"type {type(value).__name__} is not canonicalizable; normalize it first"
    )


def canonicalize(value: Any) -> str:
    """Return the VCF-1 canonical string for ``value``."""
    return _encode(value, 0)


def canonical_bytes(value: Any) -> bytes:
    """Return the UTF-8 bytes of the VCF-1 canonical string."""
    return canonicalize(value).encode("utf-8")
