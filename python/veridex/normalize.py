"""Value normalization: database driver values -> VCF-1 values.

This layer exists because the real cross-language risk is not JSON key order;
it is that two drivers return the same column as different native types
(e.g. Postgres NUMERIC as Decimal in Python, as string in node-postgres).

Every implementation MUST apply these rules before canonicalization.
See protocol/SPEC.md section 3.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from decimal import Decimal
from typing import Any

from .canonical import MAX_SAFE_INTEGER, CanonicalizationError


def _fmt_time(t: _dt.time) -> str:
    return t.strftime("%H:%M:%S.") + f"{t.microsecond:06d}"


def normalize_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        # Large integers (e.g. BIGINT ids) become decimal strings so every
        # language can represent them exactly.
        return value if abs(value) <= MAX_SAFE_INTEGER else str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError("NaN/Infinity decimals are not allowed")
        # Fixed-point notation, scale preserved: NUMERIC 5000.00 -> "5000.00".
        return format(value, "f")
    if isinstance(value, float):
        raise CanonicalizationError(
            "floating-point column values cannot be protected deterministically; "
            "use NUMERIC/DECIMAL or exclude the field"
        )
    if isinstance(value, _dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(_dt.timezone.utc)
            return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond:06d}Z"
        return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond:06d}"
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, _dt.time):
        if value.tzinfo is not None:
            raise CanonicalizationError("TIME WITH TIME ZONE is not supported")
        return _fmt_time(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [normalize_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize_value(v) for k, v in value.items()}
    raise CanonicalizationError(
        f"unsupported column value type {type(value).__name__}"
    )


def normalize_record(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    missing = [f for f in fields if f not in row]
    if missing:
        raise KeyError(f"protected fields missing from row: {missing}")
    return {f: normalize_value(row[f]) for f in fields}


def normalize_record_id(pk_values: list[Any]) -> str:
    """Single-column keys -> the normalized value as a string.
    Composite keys -> the VCF-1 canonical array string."""
    from .canonical import canonicalize

    vals = [normalize_value(v) for v in pk_values]
    if len(vals) == 1:
        v = vals[0]
        if v is None:
            raise ValueError("primary key value is null")
        return v if isinstance(v, str) else canonicalize(v)
    return canonicalize(vals)
