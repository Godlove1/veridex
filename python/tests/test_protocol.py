"""Protocol tests: Python against the shared vectors, plus a live round-trip
where a log written to PostgreSQL by Python is verified by the TypeScript code."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from veridex import protocol as P
from veridex.canonical import CanonicalizationError, canonicalize
from veridex.normalize import normalize_value

from .conftest import create_payment, update_amount

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "protocol/test-vectors/vectors.json").read_text(encoding="utf-8"))


def test_canonical_vectors():
    for c in VECTORS["canonical"]:
        assert canonicalize(c["input"]) == c["canonical"], c["name"]
        assert P.record_hash(c["input"]) == c["record_hash"], c["name"]


def test_invalid_vectors():
    for c in VECTORS["invalid"]:
        with pytest.raises(CanonicalizationError):
            canonicalize(c["input"])
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": "\ud800"})


def test_log_and_checkpoint_vectors():
    s = P.Signer.from_seed_hex(VECTORS["key"]["seed"])
    assert s.public_key_hex == VECTORS["key"]["public_key"]
    for e in VECTORS["log"]:
        assert P.event_hash(e["body"]) == e["event_hash"]
        assert s.sign(e["event_hash"]) == e["signature"]
    cp = VECTORS["checkpoint"]
    assert P.checkpoint_hash(cp["body"]) == cp["checkpoint_hash"]
    assert P.config_hash(VECTORS["config"]["body"]) == VECTORS["config"]["config_hash"]


def test_domain_separation():
    v = {"a": "1"}
    assert len({P.tagged_hash(t, v) for t in ("record", "event", "config", "checkpoint")}) == 4


def test_normalization_rules():
    import datetime as dt
    import uuid
    from decimal import Decimal

    assert normalize_value(Decimal("5000.00")) == "5000.00"
    assert normalize_value(Decimal("1E+3")) == "1000"
    assert normalize_value(2**60) == str(2**60)
    assert normalize_value(dt.datetime(2026, 10, 2, 9, 34, tzinfo=dt.timezone(dt.timedelta(hours=1)))) \
        == "2026-10-02T08:34:00.000000Z"
    assert normalize_value(dt.date(2026, 10, 2)) == "2026-10-02"
    assert normalize_value(uuid.UUID("0B6D1C2E-6F0A-4C8E-9A3B-1D2E3F4A5B6C")) == "0b6d1c2e-6f0a-4c8e-9a3b-1d2e3f4a5b6c"
    assert normalize_value(b"\xde\xad") == "0xdead"
    with pytest.raises(CanonicalizationError):
        normalize_value(0.1)


def test_rich_postgres_types_roundtrip(vx, db_url):
    import psycopg

    with psycopg.connect(db_url, autocommit=True) as c:
        c.execute("""CREATE TABLE ledger (
            tenant uuid, entry bigint, amount numeric(30,8), at timestamptz, day date,
            tags text[], meta jsonb, raw bytea, PRIMARY KEY (tenant, entry))""")
        c.execute("""INSERT INTO ledger VALUES ('0b6d1c2e-6f0a-4c8e-9a3b-1d2e3f4a5b6c', 9007199254740993,
            123456789.12345678, '2026-10-02 09:34:00.123456+01', '2026-10-02', '{a,b}',
            '{"k": "v", "n": 1}', '\\xdeadbeef')""")
    vx.protect("ledger", ["amount", "at", "day", "tags", "meta", "raw"], primary_key=["tenant", "entry"])
    key = ("0b6d1c2e-6f0a-4c8e-9a3b-1d2e3f4a5b6c", 9007199254740993)
    vx.record("ledger", "CREATE", record_id=key)
    vx.checkpoint()
    assert vx.verify("ledger", key).status.value == "VERIFIED"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_typescript_verifies_python_written_log(vx, app, tmp_path):
    create_payment(vx, app)
    update_amount(vx, app, 123, "750.00")
    events = vx.db.load_events()
    export = [
        {
            "body": {**{k: e[k] for k in P.EVENT_FIELDS if k != "v"}, "v": 1},
            "event_hash": e["event_hash"],
            "key_id": e["key_id"],
            "signature": e["signature"],
        }
        for e in events
    ]
    f = tmp_path / "log.json"
    f.write_text(json.dumps({"events": export, "trusted": [vx.signer.public_key_hex]}))
    script = (
        "import {readFileSync} from 'node:fs';"
        f"import {{verifyLog, TrustedKeys}} from '{(ROOT / 'typescript/src/index.ts').as_posix()}';"
        "const d = JSON.parse(readFileSync(process.argv[1], 'utf8'));"
        "console.log(JSON.stringify(verifyLog(d.events, new TrustedKeys(d.trusted))));"
    )
    out = subprocess.run(["node", "--input-type=module", "-e", script, str(f)],
                         capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == []
