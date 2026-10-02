"""Attack suite. Every test simulates a concrete attacker capability and
asserts that Veridex never reports VERIFIED for tampered state.

Numbering follows spec section 54 where applicable; tests marked "beyond spec"
cover holes found in the spec review (forged events, rollback, truncation).
"""

from __future__ import annotations

import json
import threading

import psycopg
import pytest

from veridex import (
    ConfigurationError,
    FileAnchor,
    Reason,
    Signer,
    Status,
    UnavailableAnchor,
    Veridex,
)
from veridex import protocol as P
from veridex.adapters import PostgresAdapter
from veridex.canonical import CanonicalizationError, canonicalize

from .conftest import create_payment, update_amount


# ----------------------------------------------------------- baseline -------


def test_01_create_then_anchor_is_verified(vx, app):
    create_payment(vx, app)
    assert vx.checkpoint() is not None
    r = vx.verify("payments", 123)
    assert r.status == Status.VERIFIED, r.to_dict()
    assert r.version == 1 and r.anchored


def test_01b_never_verified_before_anchoring(vx, app):
    create_payment(vx, app)
    r = vx.verify("payments", 123)
    assert r.status == Status.PENDING_ANCHOR
    assert Reason.NOT_ANCHORED in r.reasons


def test_02_legitimate_update_is_verified(vx, app):
    create_payment(vx, app)
    vx.checkpoint()
    update_amount(vx, app, 123, "150.00")
    update_amount(vx, app, 123, "200.00")
    vx.checkpoint()
    r = vx.verify("payments", 123)
    assert r.status == Status.VERIFIED
    assert r.version == 3
    assert [e["op"] for e in vx.history("payments", 123)] == ["CREATE", "UPDATE", "UPDATE"]


def test_unprotected_field_change_is_not_tampering(vx, app):
    create_payment(vx, app)
    vx.checkpoint()
    with app.transaction():
        app.execute("UPDATE payments SET note = 'internal' WHERE id = 123")
    assert vx.verify("payments", 123).status == Status.VERIFIED


# ----------------------------------------------- direct data tampering -------


def test_03_direct_sql_update_is_tampered(vx, app, attacker):
    create_payment(vx, app)
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 9999999 WHERE id = 123")
    r = vx.verify("payments", 123)
    assert r.status == Status.TAMPERED
    assert Reason.STATE_MISMATCH in r.reasons
    assert r.current_record_hash != r.expected_record_hash


def test_03b_tampering_detected_even_before_anchoring(vx, app, attacker):
    create_payment(vx, app)
    with attacker() as sql:
        sql.execute("UPDATE payments SET recipient = 'mallory' WHERE id = 123")
    r = vx.verify("payments", 123)
    assert r.status == Status.TAMPERED and not r.anchored


def test_04_direct_sql_delete_is_tampered_not_deleted(vx, app, attacker):
    """Spec section 54 test 4 expected DELETED here. That would make an attack
    indistinguishable from a legitimate deletion, so Veridex reports TAMPERED."""
    create_payment(vx, app)
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("DELETE FROM payments WHERE id = 123")
    r = vx.verify("payments", 123)
    assert r.status == Status.TAMPERED
    assert Reason.RECORD_MISSING in r.reasons


def test_04b_legitimate_delete_is_deleted(vx, app):
    create_payment(vx, app)
    with app.transaction():
        app.execute("DELETE FROM payments WHERE id = 123")
        vx.record("payments", "DELETE", record_id=123, conn=app)
    assert vx.verify("payments", 123).status == Status.PENDING_ANCHOR
    vx.checkpoint()
    r = vx.verify("payments", 123)
    assert r.status == Status.DELETED
    assert r.expected_record_hash is not None  # final state preserved


def test_04c_resurrected_row_is_tampered(vx, app, attacker):
    create_payment(vx, app)
    with app.transaction():
        app.execute("DELETE FROM payments WHERE id = 123")
        vx.record("payments", "DELETE", record_id=123, conn=app)
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("INSERT INTO payments (id, amount, currency, recipient, status) "
                    "VALUES (123, 500.00, 'XAF', 'alice', 'completed')")
    r = vx.verify("payments", 123)
    assert r.status == Status.TAMPERED
    assert Reason.RECORD_RESURRECTED in r.reasons


def test_untracked_row_is_unverified(vx, attacker):
    with attacker() as sql:
        sql.execute("INSERT INTO payments (id, amount, currency, recipient, status) "
                    "VALUES (777, 1.00, 'XAF', 'x', 'completed')")
    r = vx.verify("payments", 777)
    assert r.status == Status.UNVERIFIED
    assert Reason.NO_EVIDENCE in r.reasons


# ------------------------------------------ evidence-log tampering ----------


def test_05_modified_historical_event_is_invalid_proof(vx, app, attacker):
    create_payment(vx, app)
    update_amount(vx, app, 123, "600.00")
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("UPDATE veridex.events SET record_hash = repeat('a', 64) WHERE seq = 2")
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.EVENT_HASH_MISMATCH in r.reasons


def test_05b_rehashed_event_without_key_fails_signature(vx, app, attacker):
    """Attacker edits an event AND recomputes its hash, but has no signing key."""
    create_payment(vx, app)
    vx.checkpoint()
    with attacker() as sql:
        cur = sql.cursor(row_factory=psycopg.rows.dict_row)
        e = cur.execute("SELECT * FROM veridex.events WHERE op = 'CREATE'").fetchone()
        body = P.event_body(**{k: e[k] for k in P.EVENT_FIELDS if k != "v"} | {"record_hash": "b" * 64})
        sql.execute("UPDATE veridex.events SET record_hash = %s, event_hash = %s WHERE seq = %s",
                    ("b" * 64, P.event_hash(body), e["seq"]))
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.BAD_SIGNATURE in r.reasons


def test_forged_update_event_with_attacker_key_is_invalid(vx, app, attacker):
    """Beyond spec (review hole #1): DB attacker changes the row and appends a
    perfectly chained UPDATE event, signed with a key the verifier doesn't trust."""
    create_payment(vx, app)
    vx.checkpoint()
    evil = Signer.generate()
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 9999999 WHERE id = 123")
        cur = sql.cursor(row_factory=psycopg.rows.dict_row)
        head = cur.execute("SELECT * FROM veridex.log_head").fetchone()
        last = cur.execute("SELECT * FROM veridex.events WHERE record_id = '123' ORDER BY seq DESC LIMIT 1").fetchone()
        row = cur.execute("SELECT id, amount, currency, recipient, status FROM payments WHERE id = 123").fetchone()
        from veridex.normalize import normalize_record
        rh = P.record_hash(normalize_record(row, ["amount", "currency", "id", "recipient", "status"]))
        body = P.event_body(seq=head["seq"] + 1, op="UPDATE", resource="public.payments", record_id="123",
                            version=last["version"] + 1, record_hash=rh, prev_event_hash=last["event_hash"],
                            prev_log_hash=head["head_hash"], config_hash=last["config_hash"],
                            created_at="2026-10-02T09:00:00.000000Z")
        h = P.event_hash(body)
        sql.execute(
            "INSERT INTO veridex.events (seq, op, resource, record_id, version, record_hash, prev_event_hash,"
            " prev_log_hash, config_hash, created_at, event_hash, key_id, signature)"
            " VALUES (%s,'UPDATE','public.payments','123',%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (body["seq"], body["version"], rh, last["event_hash"], head["head_hash"], last["config_hash"],
             body["created_at"], h, evil.key_id, evil.sign(h)))
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", (body["seq"], h))
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.BAD_SIGNATURE in r.reasons


def test_rollback_attack_on_anchored_history_is_invalid(vx, app, attacker):
    """Beyond spec (review hole #2): revert the row to v1 and delete the v2 event
    plus fix up log_head so the local log looks self-consistent."""
    create_payment(vx, app, amount="500.00")
    update_amount(vx, app, 123, "900.00")
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 500.00 WHERE id = 123")
        e1 = sql.execute("SELECT seq, event_hash FROM veridex.events WHERE seq = 2").fetchone()
        sql.execute("DELETE FROM veridex.events WHERE seq = 3")
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", e1)
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.CHECKPOINT_MISMATCH in r.reasons


def test_known_limitation_unanchored_tail_can_be_rolled_back(vx, app, attacker):
    """DOCUMENTED LIMITATION (docs/THREAT_MODEL.md): events after the last
    checkpoint are only as safe as the database. Rolling them back yields the
    older, anchored state as VERIFIED. Shrink the window by checkpointing often."""
    create_payment(vx, app, amount="500.00")
    vx.checkpoint()
    update_amount(vx, app, 123, "900.00")  # not yet anchored
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 500.00 WHERE id = 123")
        e1 = sql.execute("SELECT seq, event_hash FROM veridex.events WHERE seq = 2").fetchone()
        sql.execute("DELETE FROM veridex.events WHERE seq = 3")
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", e1)
    assert vx.verify("payments", 123).status == Status.VERIFIED


def test_log_truncation_after_checkpoint_is_invalid(vx, app, attacker):
    create_payment(vx, app, pid=1)
    create_payment(vx, app, pid=2)
    vx.checkpoint()
    with attacker() as sql:
        sql.execute("DELETE FROM veridex.events WHERE seq = 3")
        sql.execute("DELETE FROM payments WHERE id = 2")
        h = sql.execute("SELECT event_hash FROM veridex.events WHERE seq = 2").fetchone()[0]
        sql.execute("UPDATE veridex.log_head SET seq = 2, head_hash = %s", (h,))
    assert vx.verify("payments", 1).status == Status.INVALID_PROOF


def test_06_tampered_checkpoint_in_anchor_is_invalid(vx, app, anchor_path):
    create_payment(vx, app)
    vx.checkpoint()
    cp = json.loads(anchor_path.read_text())
    cp["head"] = "c" * 64
    anchor_path.write_text(json.dumps(cp) + "\n")
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.CHECKPOINT_INVALID in r.reasons


def test_07_anchored_head_mismatch_is_invalid(vx, app, attacker, signer, anchor_path):
    """A validly signed checkpoint whose head is not in the database."""
    create_payment(vx, app)
    head = vx.db.read_head()
    body = P.checkpoint_body(log_id=head["log_id"], seq=1, head="d" * 64, created_at="2026-10-02T00:00:00.000000Z")
    h = P.checkpoint_hash(body)
    FileAnchor(anchor_path).publish(dict(body, checkpoint_hash=h, key_id=signer.key_id, signature=signer.sign(h)))
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF
    assert Reason.CHECKPOINT_MISMATCH in r.reasons


def test_verifier_with_different_trusted_key_rejects_log(db_url, vx, app, anchor_path):
    create_payment(vx, app)
    vx.checkpoint()
    other = Veridex(database=PostgresAdapter(db_url), trusted_keys=[Signer.generate().public_key_hex],
                    anchor=FileAnchor(anchor_path))
    assert other.verify("payments", 123).status == Status.INVALID_PROOF


# ----------------------------------------------------- configuration --------


def _tamper_config(attacker, fields):
    with attacker() as sql:
        body_txt = sql.execute("SELECT body FROM veridex.configurations WHERE version = 1").fetchone()[0]
        body = json.loads(body_txt)
        body["fields"] = fields
        sql.execute("UPDATE veridex.configurations SET body = %s, config_hash = %s",
                    (canonicalize(body), P.config_hash(body)))


def test_08_config_tamper_is_configuration_error(vx, app, attacker):
    create_payment(vx, app)
    vx.checkpoint()
    _tamper_config(attacker, ["id"])  # stop protecting amount/recipient/...
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 1 WHERE id = 123")
    r = vx.verify("payments", 123)
    assert r.status == Status.CONFIGURATION_ERROR
    assert Reason.CONFIG_TAMPERED in r.reasons


def test_08b_record_refuses_to_write_under_tampered_config(vx, app, attacker):
    create_payment(vx, app)
    _tamper_config(attacker, ["id"])
    with pytest.raises(ConfigurationError):
        update_amount(vx, app, 123, "1.00")


def test_legitimate_config_change_creates_new_version(vx, app):
    create_payment(vx, app)
    vx.checkpoint()
    cfg = vx.protect("payments", ["id", "amount", "currency", "recipient", "status", "note"])
    assert cfg.version == 2
    vx.checkpoint()
    r = vx.verify("payments", 123)
    assert r.status == Status.VERIFIED
    assert Reason.CONFIG_SUPERSEDED in r.reasons  # old event, old field set
    update_amount(vx, app, 123, "501.00")
    vx.checkpoint()
    r = vx.verify("payments", 123)
    assert r.status == Status.VERIFIED and Reason.CONFIG_SUPERSEDED not in r.reasons
    assert vx.audit().ok


def test_protect_is_idempotent(vx):
    before = vx.db.read_head()["seq"]
    vx.protect("payments", ["status", "id", "amount", "recipient", "currency"])
    assert vx.db.read_head()["seq"] == before


# ------------------------------------------------- anchor availability -----


def test_09_anchor_unavailable_is_never_verified(db_url, vx, app, signer):
    create_payment(vx, app)
    offline = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex],
                      signer=signer, anchor=UnavailableAnchor())
    r = offline.verify("payments", 123)
    assert r.status == Status.ANCHOR_FAILED
    assert r.status != Status.VERIFIED


def test_09b_recording_works_while_anchor_is_down(db_url, signer, vx, app):
    offline = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex],
                      signer=signer, anchor=UnavailableAnchor())
    create_payment(offline, app)  # application keeps working
    assert vx.verify("payments", 123).status == Status.PENDING_ANCHOR
    vx.checkpoint()
    assert vx.verify("payments", 123).status == Status.VERIFIED


# ------------------------------------------------------ transactions --------


def test_10_rollback_leaves_no_event(vx, app):
    before = vx.db.read_head()
    with pytest.raises(RuntimeError):
        with app.transaction():
            app.execute("INSERT INTO payments (id, amount, currency, recipient, status) "
                        "VALUES (5, 1.00, 'XAF', 'bob', 'pending')")
            vx.record("payments", "CREATE", record={"id": 5}, conn=app)
            raise RuntimeError("application error after recording")
    assert vx.db.read_head() == before
    assert vx.history("payments", 5) == []
    assert vx.audit().problems == []


def test_10b_autocommit_connection_still_atomic(vx, db_url):
    with psycopg.connect(db_url, autocommit=True) as c:
        c.execute("INSERT INTO payments (id, amount, currency, recipient, status) VALUES (6, 1, 'XAF', 'b', 'p')")
        vx.record("payments", "CREATE", record_id=6, conn=c)
    assert vx.verify("payments", 6).status == Status.PENDING_ANCHOR


def test_concurrent_writers_keep_log_consistent(vx, db_url):
    def worker(start):
        with psycopg.connect(db_url) as c:
            for pid in range(start, start + 10):
                with c.transaction():
                    c.execute("INSERT INTO payments (id, amount, currency, recipient, status) "
                              "VALUES (%s, 1, 'XAF', 'w', 'p')", (pid,))
                    vx.record("payments", "CREATE", record_id=pid, conn=c)

    threads = [threading.Thread(target=worker, args=(i * 100,)) for i in range(1, 6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    vx.checkpoint()
    rep = vx.audit()
    assert rep.problems == [], [p.to_dict() for p in rep.problems]
    assert rep.event_count == 1 + 50
    assert vx.verify("payments", 305).status == Status.VERIFIED


# ------------------------------------------------------- operation rules ---


def test_invalid_transitions_are_rejected(vx, app):
    from veridex import InvalidOperationError, RecordNotFoundError

    with pytest.raises(RecordNotFoundError):
        vx.record("payments", "CREATE", record_id=999)
    with pytest.raises(InvalidOperationError):
        vx.record("payments", "UPDATE", record_id=999)
    create_payment(vx, app)
    with pytest.raises(InvalidOperationError):
        vx.record("payments", "CREATE", record_id=123)


def test_float_columns_are_refused(db_url, signer, anchor_path):
    with psycopg.connect(db_url, autocommit=True) as c:
        c.execute("CREATE TABLE readings (id int primary key, value double precision)")
        c.execute("INSERT INTO readings VALUES (1, 0.1)")
    v = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex],
                signer=signer, anchor=FileAnchor(anchor_path))
    v.init()
    v.protect("readings", ["value"])
    with pytest.raises(CanonicalizationError):
        v.record("readings", "CREATE", record_id=1)
