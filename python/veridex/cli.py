"""veridex command-line interface.

Configuration comes from environment variables (never hard-code keys):

  VERIDEX_DATABASE_URL    PostgreSQL connection string
  VERIDEX_SIGNING_KEY     Ed25519 seed, 64 hex chars (only for commands that write)
  VERIDEX_TRUSTED_KEYS    comma-separated Ed25519 public keys, hex
  VERIDEX_ANCHOR_FILE     path to the FileAnchor (stage 1 dev anchor)
  VERIDEX_SCHEMA          integrity schema name (default: veridex)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .adapters.postgres import PostgresAdapter
from .anchor import FileAnchor
from .core import Veridex
from .protocol import Signer
from .results import Status, VeridexError

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _env(name: str, required: bool = True) -> str | None:
    v = os.environ.get(name)
    if required and not v:
        raise SystemExit(f"error: environment variable {name} is required")
    return v


def _build(need_signer: bool) -> Veridex:
    seed = _env("VERIDEX_SIGNING_KEY", required=need_signer)
    signer = Signer.from_seed_hex(seed) if seed else None
    trusted = (_env("VERIDEX_TRUSTED_KEYS", required=False) or "").split(",")
    if signer is not None and not any(t.strip() for t in trusted):
        trusted = [signer.public_key_hex]
    anchor_path = _env("VERIDEX_ANCHOR_FILE", required=False)
    return Veridex(
        database=PostgresAdapter(_env("VERIDEX_DATABASE_URL"), integrity_schema=os.environ.get("VERIDEX_SCHEMA", "veridex")),
        trusted_keys=trusted,
        signer=signer,
        anchor=FileAnchor(anchor_path) if anchor_path else None,
    )


def _print(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
        return
    if isinstance(data, dict):
        width = max((len(k) for k in data), default=0)
        for k, v in data.items():
            if isinstance(v, list):
                v = ", ".join(str(x.get("reason", x)) if isinstance(x, dict) else str(x) for x in v) or "-"
            print(f"{k.replace('_', ' ').title():<{width + 2}} {v}")
    else:
        print(data)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="veridex", description="Tamper-evident integrity for relational databases")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="generate an Ed25519 signing key")
    sub.add_parser("init", help="create the integrity schema")

    pr = sub.add_parser("protect", help="protect fields of a table")
    pr.add_argument("table")
    pr.add_argument("fields", help="comma-separated field list")
    pr.add_argument("--pk", default="id", help="primary key column(s), comma-separated")

    v = sub.add_parser("verify", help="verify one record")
    v.add_argument("table")
    v.add_argument("record_id", nargs="+", help="primary key value(s)")

    h = sub.add_parser("history", help="show the evidence history of one record")
    h.add_argument("table")
    h.add_argument("record_id", nargs="+")

    sub.add_parser("checkpoint", help="sign the log head and publish it to the anchor")
    sub.add_parser("audit", help="verify the whole evidence log")
    sub.add_parser("status", help="show log and anchor status")

    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            s = Signer.generate()
            _print({"signing_key": s.seed_hex(), "public_key": s.public_key_hex, "key_id": s.key_id}, a.json)
            print("\nStore the signing key in a secret manager. Give verifiers only the public key.",
                  file=sys.stderr)
            return EXIT_OK

        vx = _build(need_signer=a.cmd in ("protect", "checkpoint"))

        if a.cmd == "init":
            _print({"log_id": vx.init()}, a.json)
        elif a.cmd == "protect":
            cfg = vx.protect(a.table, a.fields.split(","), primary_key=a.pk.split(","))
            _print({"resource": cfg.resource, "fields": ", ".join(cfg.fields),
                    "version": cfg.version, "config_hash": cfg.config_hash}, a.json)
        elif a.cmd == "verify":
            rid = a.record_id[0] if len(a.record_id) == 1 else a.record_id
            r = vx.verify(a.table, rid)
            _print(r.to_dict(), a.json)
            return EXIT_OK if r.ok else EXIT_FAIL
        elif a.cmd == "history":
            rid = a.record_id[0] if len(a.record_id) == 1 else a.record_id
            rows = vx.history(a.table, rid)
            if a.json:
                _print(rows, True)
            else:
                for e in rows:
                    print(f"seq={e['seq']:<6} v{e['version']:<3} {e['op']:<7} {e['created_at']}  {e['event_hash'][:16]}…")
        elif a.cmd == "checkpoint":
            cp = vx.checkpoint()
            _print(cp or {"result": "nothing new to anchor"}, a.json)
        elif a.cmd == "audit":
            rep = vx.audit()
            _print(rep.to_dict(), a.json)
            return EXIT_OK if rep.ok else EXIT_FAIL
        elif a.cmd == "status":
            rep = vx.audit()
            _print({"log_id": rep.log_id, "events": rep.event_count,
                    "anchored_through_seq": rep.anchored_through_seq,
                    "pending_events": rep.event_count - rep.anchored_through_seq,
                    "anchor_error": rep.anchor_error,
                    "log_status": "OK" if not rep.problems else Status.INVALID_PROOF.value}, a.json)
        return EXIT_OK
    except VeridexError as e:
        _print({"error": e.code, "message": str(e)}, a.json)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
