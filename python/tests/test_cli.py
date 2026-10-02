"""CLI and defense-in-depth checks."""

from __future__ import annotations

import json

import psycopg
import pytest

from veridex.cli import main

from .conftest import TEST_SEED, create_payment


def test_append_only_trigger_blocks_ordinary_mutation(vx, app, db_url):
    create_payment(vx, app)
    with psycopg.connect(db_url, autocommit=True) as c:
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            c.execute("UPDATE veridex.events SET record_hash = 'x'")
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            c.execute("DELETE FROM veridex.configurations")


def test_cli_end_to_end(vx, app, db_url, anchor_path, monkeypatch, capsys):
    monkeypatch.setenv("VERIDEX_DATABASE_URL", db_url)
    monkeypatch.setenv("VERIDEX_SIGNING_KEY", TEST_SEED)
    monkeypatch.setenv("VERIDEX_ANCHOR_FILE", str(anchor_path))
    create_payment(vx, app)

    assert main(["--json", "verify", "payments", "123"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "PENDING_ANCHOR"

    monkeypatch.setenv("VERIDEX_BATCH_INTERVAL", "3600")
    assert main(["--json", "checkpoint", "--if-due"]) == 0  # 2 fresh events: not due yet
    assert "result" in json.loads(capsys.readouterr().out)
    assert main(["--json", "proof", "payments", "123"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "NOT_ANCHORED"

    assert main(["--json", "checkpoint"]) == 0
    cp = json.loads(capsys.readouterr().out)
    assert (cp["batch"], cp["seq"]) == (1, 2)

    assert main(["proof", "payments", "123"]) == 0
    proof = json.loads(capsys.readouterr().out)
    assert proof["inclusion"]["merkle_root"] == cp["merkle_root"]

    assert main(["--json", "verify", "payments", "123"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED"

    with psycopg.connect(db_url, autocommit=True) as c:
        c.execute("UPDATE payments SET amount = 9999999 WHERE id = 123")
    assert main(["verify", "payments", "123"]) == 1
    assert "TAMPERED" in capsys.readouterr().out

    monkeypatch.delenv("VERIDEX_SIGNING_KEY")
    monkeypatch.setenv("VERIDEX_TRUSTED_KEYS", vx.signer.public_key_hex)
    assert main(["--json", "audit"]) == 0  # the log itself is intact
    capsys.readouterr()
    assert main(["--json", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["anchored_batches"] == 1 and status["pending_events"] == 0

    monkeypatch.setenv("VERIDEX_LOG_ID", "not-this-log")
    assert main(["--json", "verify", "payments", "123"]) == 1
    assert "LOG_ID_MISMATCH" in json.loads(capsys.readouterr().out)["reasons"]
    monkeypatch.delenv("VERIDEX_LOG_ID")
    assert main(["history", "payments", "123"]) == 0
    assert "CREATE" in capsys.readouterr().out
