"""veridex command-line interface.

Configuration comes from environment variables (never hard-code keys):

  VERIDEX_DATABASE_URL    PostgreSQL connection string
  VERIDEX_SIGNING_KEY     Ed25519 seed, 64 hex chars (only for commands that write)
  VERIDEX_TRUSTED_KEYS    comma-separated Ed25519 public keys, hex
  VERIDEX_SCHEMA          integrity schema name (default: veridex)
  VERIDEX_LOG_ID          log id printed by `veridex init`; pins the verifier to that log
  VERIDEX_BATCH_SIZE      events per Merkle batch (default: 5000)
  VERIDEX_BATCH_INTERVAL  seconds before waiting events are due (default: 300)

Anchor, one of:

  VERIDEX_ANCHOR_FILE     path to a FileAnchor (development)

  VERIDEX_EVM_RPC_URL     JSON-RPC endpoint (Anvil, Base, any EVM chain)
  VERIDEX_EVM_CHAIN_ID    chain id the endpoint must serve (31337 Anvil, 8453 Base, 84532 Base Sepolia)
  VERIDEX_EVM_CONTRACT    address of the VeridexAnchor contract
  VERIDEX_EVM_PUBLISHER   account whose batches are trusted (verifiers)
  VERIDEX_EVM_PRIVATE_KEY key of the publishing account (only `checkpoint` and `deploy-anchor`)
  VERIDEX_EVM_BLOCK_TAG   latest | safe | finalized (default: finalized on Base, else latest)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .adapters.postgres import PostgresAdapter
from .anchor import AnchorError, FileAnchor
from .core import DEFAULT_BATCH_INTERVAL, DEFAULT_BATCH_SIZE, Veridex
from .protocol import Signer
from .results import ConfigurationError, Status, VeridexError

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _env(name: str, required: bool = True) -> str | None:
    v = os.environ.get(name)
    if required and not v:
        raise SystemExit(f"error: environment variable {name} is required")
    return v


def _evm_chain_id() -> int:
    try:
        return int(_env("VERIDEX_EVM_CHAIN_ID"))
    except ValueError:
        raise SystemExit("error: VERIDEX_EVM_CHAIN_ID must be an integer") from None


def _anchor(writer: bool) -> Any:
    path, rpc = _env("VERIDEX_ANCHOR_FILE", required=False), _env("VERIDEX_EVM_RPC_URL", required=False)
    if path and rpc:
        raise ConfigurationError("set VERIDEX_ANCHOR_FILE or VERIDEX_EVM_RPC_URL, not both")
    if path:
        return FileAnchor(path)
    if not rpc:
        return None
    from .evm import BASE_CHAIN_IDS, EvmAnchor

    chain_id = _evm_chain_id()
    default_tag = "finalized" if chain_id in BASE_CHAIN_IDS.values() else "latest"
    return EvmAnchor(
        rpc,
        _env("VERIDEX_EVM_CONTRACT"),
        publisher=_env("VERIDEX_EVM_PUBLISHER", required=False),
        # Read-only commands never load the key, even if it is in the environment.
        private_key=_env("VERIDEX_EVM_PRIVATE_KEY") if writer else None,
        chain_id=chain_id,
        block_tag=os.environ.get("VERIDEX_EVM_BLOCK_TAG", default_tag),
    )


def _build(need_signer: bool, anchor_writer: bool = False) -> Veridex:
    seed = _env("VERIDEX_SIGNING_KEY", required=need_signer)
    signer = Signer.from_seed_hex(seed) if seed else None
    trusted = (_env("VERIDEX_TRUSTED_KEYS", required=False) or "").split(",")
    if signer is not None and not any(t.strip() for t in trusted):
        trusted = [signer.public_key_hex]
    return Veridex(
        database=PostgresAdapter(_env("VERIDEX_DATABASE_URL"), integrity_schema=os.environ.get("VERIDEX_SCHEMA", "veridex")),
        trusted_keys=trusted,
        signer=signer,
        anchor=_anchor(anchor_writer),
        log_id=_env("VERIDEX_LOG_ID", required=False),
        batch_size=int(os.environ.get("VERIDEX_BATCH_SIZE", DEFAULT_BATCH_SIZE)),
        batch_interval=float(os.environ.get("VERIDEX_BATCH_INTERVAL", DEFAULT_BATCH_INTERVAL)),
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

    pf = sub.add_parser("proof", help="print the Merkle inclusion proof of a record's latest event (JSON)")
    pf.add_argument("table")
    pf.add_argument("record_id", nargs="+")

    c = sub.add_parser("checkpoint", help="batch the waiting events and anchor their Merkle root")
    c.add_argument("--if-due", action="store_true",
                   help="only if the batch size or batch interval has been reached (for cron)")
    sub.add_parser("deploy-anchor", help="deploy the VeridexAnchor contract (sends a transaction)")
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

        if a.cmd == "deploy-anchor":
            from eth_account import Account

            from .evm import EvmAnchor

            key, chain_id = _env("VERIDEX_EVM_PRIVATE_KEY"), _evm_chain_id()
            address = EvmAnchor.deploy(_env("VERIDEX_EVM_RPC_URL"), key, chain_id=chain_id)
            _print({"contract": address, "publisher": Account.from_key(key).address, "chain_id": chain_id}, a.json)
            print("\nSet VERIDEX_EVM_CONTRACT to the contract and give verifiers the publisher address.",
                  file=sys.stderr)
            return EXIT_OK

        vx = _build(need_signer=a.cmd in ("protect", "checkpoint"), anchor_writer=a.cmd == "checkpoint")

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
        elif a.cmd == "proof":
            rid = a.record_id[0] if len(a.record_id) == 1 else a.record_id
            _print(vx.prove(a.table, rid), True)
        elif a.cmd == "checkpoint":
            cp = vx.checkpoint(if_due=a.if_due)
            _print(cp or {"result": "nothing to anchor yet" if a.if_due else "nothing new to anchor"}, a.json)
        elif a.cmd == "audit":
            rep = vx.audit()
            _print(rep.to_dict(), a.json)
            return EXIT_OK if rep.ok else EXIT_FAIL
        elif a.cmd == "status":
            rep = vx.audit()
            _print({"log_id": rep.log_id, "events": rep.event_count,
                    "anchor": getattr(vx.anchor, "name", None),
                    "anchored_batches": len(rep.batches),
                    "anchored_through_seq": rep.anchored_through_seq,
                    "pending_events": rep.event_count - rep.anchored_through_seq,
                    "anchor_error": rep.anchor_error,
                    "log_status": "OK" if not rep.problems else Status.INVALID_PROOF.value}, a.json)
        return EXIT_OK
    except VeridexError as e:
        _print({"error": e.code, "message": str(e)}, a.json)
        return EXIT_ERROR
    except AnchorError as e:
        _print({"error": "ANCHOR_ERROR", "message": str(e)}, a.json)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
