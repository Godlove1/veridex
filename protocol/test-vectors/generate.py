"""Generate protocol/test-vectors/vectors.json from the Python reference
implementation. Every other implementation must reproduce these outputs.

    python protocol/test-vectors/generate.py

Commit the result. If this script ever changes an existing vector, that is a
protocol break and needs a new protocol version.
"""

from __future__ import annotations

import json
from pathlib import Path

from veridex import protocol as P
from veridex.canonical import CanonicalizationError, canonicalize

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"  # RFC 8032 test 1 seed
OUT = Path(__file__).with_name("vectors.json")

CANONICAL_CASES = [
    ("spec example payment", {"id": 123, "amount": "5000.00", "currency": "XAF", "status": "completed"}),
    ("empty object", {}),
    ("empty array", []),
    ("scalars", {"t": True, "f": False, "n": None, "zero": 0, "neg": -42}),
    ("max safe integer", {"big": 9007199254740991, "small": -9007199254740991}),
    ("key order is by UTF-8 bytes, not insertion", {"b": 1, "a": 2, "B": 3, "aa": 4, "_": 5}),
    ("non-ASCII keys sort by UTF-8 bytes", {"é": 1, "z": 2, "€": 3, "😀": 4, "ÿ": 5}),
    ("NFC normalization of decomposed string", {"name": "école"}),
    ("NFC normalization of key", {"café": 1}),
    ("escapes", {"s": "quote\" backslash\\ nl\n tab\t cr\r bs\b ff\f"}),
    ("other control chars use lowercase \\u", {"s": "\u0000\u0001\u001f\u007f"}),
    ("non-ASCII output raw, not escaped", {"s": "Yaoundé – 東京 – 😀"}),
    ("slash is not escaped", {"url": "https://a/b"}),
    ("nested", {"outer": {"z": [3, {"y": None, "x": "1"}], "a": []}}),
    ("array order preserved", [3, 1, 2]),
    ("top-level string", "hello"),
]

INVALID_CASES = [
    ("float", {"amount": 1.5}),
    ("unsafe integer", {"id": 9007199254740993}),
    ("duplicate keys after NFC", {"é": 1, "é": 2}),
]

RECORDS = [
    {"amount": "500.00", "currency": "XAF", "id": 123, "recipient": "alice", "status": "completed"},
    {"amount": "9999999.00", "currency": "XAF", "id": 123, "recipient": "alice", "status": "completed"},
    {"id": "9007199254740993", "created": "2026-10-02T08:34:00.000000Z", "uuid": "0b6d1c2e-6f0a-4c8e-9a3b-1d2e3f4a5b6c",
     "blob": "0xdeadbeef", "tags": ["a", "b"], "meta": {"k": "v"}, "maybe": None},
]


def main() -> None:
    signer = P.Signer.from_seed_hex(SEED)
    canonical = [
        {"name": n, "input": v, "canonical": canonicalize(v), "record_hash": P.record_hash(v)}
        for n, v in CANONICAL_CASES
    ]
    invalid = []
    for n, v in INVALID_CASES:
        try:
            canonicalize(v)
        except CanonicalizationError:
            invalid.append({"name": n, "input": v})
        else:
            raise AssertionError(f"invalid case {n} was accepted")

    records = [{"input": r, "record_hash": P.record_hash(r)} for r in RECORDS]

    # A small, valid log: CONFIGURE, CREATE, UPDATE, DELETE, then a checkpoint.
    cfg = P.config_body(resource="public.payments", schema="public", table="payments",
                        primary_key=["id"], fields=["id", "amount", "currency", "recipient", "status"],
                        version=1, prev_config_hash=None)
    cfg_h = P.config_hash(cfg)
    log, prev_log, prev_rec = [], P.GENESIS_HASH, None
    steps = [
        ("CONFIGURE", None, 1, None),
        ("CREATE", "123", 1, records[0]["record_hash"]),
        ("UPDATE", "123", 2, records[1]["record_hash"]),
        ("DELETE", "123", 3, records[1]["record_hash"]),
    ]
    for i, (op, rid, ver, rh) in enumerate(steps, start=1):
        body = P.event_body(seq=i, op=op, resource="public.payments", record_id=rid, version=ver,
                            record_hash=rh, prev_event_hash=None if op in ("CONFIGURE", "CREATE") else prev_rec,
                            prev_log_hash=prev_log, config_hash=cfg_h,
                            created_at=f"2026-10-02T08:3{i}:00.000000Z")
        h = P.event_hash(body)
        log.append({"body": body, "canonical": canonicalize(body), "event_hash": h,
                    "key_id": signer.key_id, "signature": signer.sign(h)})
        prev_log = h
        if op != "CONFIGURE":
            prev_rec = h

    cp = P.checkpoint_body(log_id="7e1f0c4a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", seq=len(log), head=prev_log,
                           created_at="2026-10-02T08:40:00.000000Z")
    cp_h = P.checkpoint_hash(cp)

    out = {
        "protocol": {"version": P.PROTOCOL_VERSION, "hash_algorithm": P.HASH_ALGORITHM,
                     "canonicalization": P.CANONICALIZATION, "signature": "Ed25519"},
        "key": {"seed": SEED, "public_key": signer.public_key_hex, "key_id": signer.key_id},
        "canonical": canonical,
        "invalid": invalid,
        "records": records,
        "config": {"body": cfg, "canonical": canonicalize(cfg), "config_hash": cfg_h},
        "log": log,
        "checkpoint": {"body": cp, "checkpoint_hash": cp_h, "key_id": signer.key_id,
                       "signature": signer.sign(cp_h)},
    }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
