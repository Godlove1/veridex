"""Merkle batching, inclusion proofs and the checkpointer's refusal rules.

Spec section 54 tests 6 and 7 (Merkle proof modification, root mismatch) are
covered here and in test_security.py.
"""

from __future__ import annotations

import copy
import json

import psycopg
import pytest

from veridex import (
    FileAnchor,
    LogIntegrityError,
    NotAnchoredError,
    Reason,
    Signer,
    Status,
    Veridex,
)
from veridex import protocol as P
from veridex.adapters import PostgresAdapter

from .conftest import create_payment, update_amount


def _checkpoints(anchor_path):
    return [json.loads(line) for line in anchor_path.read_text().splitlines()]


def _small_batches(db_url, signer, anchor_path, **kw):
    return Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex],
                   signer=signer, anchor=FileAnchor(anchor_path), **kw)


# ------------------------------------------------------------- batching -----


def test_checkpoint_anchors_a_merkle_root_over_the_new_events(vx, app, anchor_path):
    create_payment(vx, app, pid=1)
    create_payment(vx, app, pid=2)
    cp = vx.checkpoint()
    hashes = [e["event_hash"] for e in vx.db.load_events()]
    assert (cp["batch"], cp["from_seq"], cp["seq"]) == (1, 1, 3)
    assert cp["merkle_root"] == P.merkle_root(hashes)

    update_amount(vx, app, 1, "7.00")
    cp2 = vx.checkpoint()
    assert (cp2["batch"], cp2["from_seq"], cp2["seq"]) == (2, 4, 4)
    assert vx.checkpoint() is None  # nothing new

    rep = vx.audit()
    assert rep.ok and len(rep.batches) == 2 and rep.anchored_through_seq == 4
    r = vx.verify("payments", 1)
    assert r.status == Status.VERIFIED and r.batch == 2 and r.merkle_root == cp2["merkle_root"]
    assert vx.verify("payments", 2).batch == 1
    # The database keeps a convenience copy of what was published.
    assert [b["batch"] for b in vx.db.load_batches()] == [1, 2]


def test_backlog_is_split_into_batches_of_batch_size(db_url, vx, app, signer, anchor_path):
    for pid in range(1, 8):
        create_payment(vx, app, pid=pid)  # 1 CONFIGURE + 7 CREATE = 8 events
    v = _small_batches(db_url, signer, anchor_path, batch_size=3)
    last = v.checkpoint()
    cps = _checkpoints(anchor_path)
    assert [(c["batch"], c["from_seq"], c["seq"]) for c in cps] == [(1, 1, 3), (2, 4, 6), (3, 7, 8)]
    assert last["batch"] == 3
    assert v.audit().ok
    assert [v.verify("payments", pid).batch for pid in (1, 2, 3, 6, 7)] == [1, 1, 2, 3, 3]


def test_if_due_follows_the_size_or_interval_policy(db_url, vx, app, signer, anchor_path):
    create_payment(vx, app, pid=1)
    waiting = _small_batches(db_url, signer, anchor_path, batch_size=10, batch_interval=3600)
    assert waiting.checkpoint(if_due=True) is None  # 2 events, just written
    by_size = _small_batches(db_url, signer, anchor_path, batch_size=2, batch_interval=3600)
    assert by_size.checkpoint(if_due=True)["seq"] == 2
    create_payment(vx, app, pid=2)
    by_age = _small_batches(db_url, signer, anchor_path, batch_size=10, batch_interval=0)
    assert by_age.checkpoint(if_due=True)["seq"] == 3


# --------------------------------------------------------------- proofs -----


def test_inclusion_proof_verifies_without_the_database(vx, app, signer):
    for pid in range(1, 6):
        create_payment(vx, app, pid=pid)
    vx.checkpoint()
    proof = vx.prove("payments", 3)
    proof = json.loads(json.dumps(proof))  # survives serialization

    ev, inc = proof["event"], proof["inclusion"]
    trusted = P.TrustedKeys([signer.public_key_hex])
    assert P.event_hash(ev["body"]) == ev["event_hash"]
    assert trusted.verify(ev["key_id"], ev["event_hash"], ev["signature"])
    assert inc["leaf_index"] == ev["body"]["seq"] - inc["from_seq"]
    assert inc["tree_size"] == inc["seq"] - inc["from_seq"] + 1
    assert P.verify_inclusion(ev["event_hash"], inc["leaf_index"], inc["tree_size"], inc["path"], inc["merkle_root"])
    # ... and the root is the one the anchor holds, signed.
    cp = proof["anchor"]["checkpoint"]
    assert cp["merkle_root"] == inc["merkle_root"]
    assert trusted.verify(cp["key_id"], cp["checkpoint_hash"], cp["signature"])


def test_06_modified_merkle_proof_is_rejected(vx, app):
    """Spec section 54 test 6."""
    for pid in range(1, 6):
        create_payment(vx, app, pid=pid)
    vx.checkpoint()
    good = vx.prove("payments", 3)

    def ok(p):
        i = p["inclusion"]
        return P.verify_inclusion(p["event"]["event_hash"], i["leaf_index"], i["tree_size"], i["path"], i["merkle_root"])

    assert ok(good)
    for mutate in (
        lambda p: p["inclusion"]["path"].__setitem__(0, "e" * 64),
        lambda p: p["inclusion"]["path"].pop(),
        lambda p: p["inclusion"].__setitem__("leaf_index", p["inclusion"]["leaf_index"] + 1),
        lambda p: p["inclusion"].__setitem__("merkle_root", "f" * 64),
        lambda p: p["event"].__setitem__("event_hash", "a" * 64),
    ):
        bad = copy.deepcopy(good)
        mutate(bad)
        assert not ok(bad)


def test_no_proof_for_unanchored_or_tampered_records(vx, app, attacker):
    create_payment(vx, app)
    with pytest.raises(NotAnchoredError):
        vx.prove("payments", 123)
    vx.checkpoint()
    assert vx.prove("payments", 123)["inclusion"]["batch"] == 1
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 1 WHERE id = 123")
    with pytest.raises(LogIntegrityError):
        vx.prove("payments", 123)


# ------------------------------------------------- anchored-batch attacks ---


def test_rewriting_an_event_inside_an_old_batch_is_invalid(vx, app, attacker, signer):
    """An attacker WITH the signing key re-signs a different event in place.
    Its signature and hash are valid; only the anchored Merkle root gives it away."""
    create_payment(vx, app, pid=1)
    create_payment(vx, app, pid=2)
    vx.checkpoint()
    create_payment(vx, app, pid=3)
    vx.checkpoint()
    with attacker() as sql:
        cur = sql.cursor(row_factory=psycopg.rows.dict_row)
        e = cur.execute("SELECT * FROM veridex.events WHERE seq = 3").fetchone()
        body = P.event_body(**{k: e[k] for k in P.EVENT_FIELDS if k != "v"} | {"record_hash": "b" * 64})
        h = P.event_hash(body)
        sql.execute("UPDATE veridex.events SET record_hash = %s, event_hash = %s, signature = %s WHERE seq = 3",
                    ("b" * 64, h, signer.sign(h)))
    rep = vx.audit()
    assert Reason.CHECKPOINT_MISMATCH in {p.reason for p in rep.problems}
    assert rep.batches == []  # batch 1 no longer matches; nothing after it is trusted either
    assert vx.verify("payments", 1).status == Status.INVALID_PROOF


def test_conflicting_or_skipped_batches_in_the_anchor_are_invalid(vx, app, signer, anchor_path):
    create_payment(vx, app)
    cp = vx.checkpoint()

    def signed(**changes):
        body = P.checkpoint_body(**({k: cp[k] for k in ("log_id", "batch", "from_seq", "seq", "merkle_root", "created_at")} | changes))
        h = P.checkpoint_hash(body)
        return dict(body, checkpoint_hash=h, key_id=signer.key_id, signature=signer.sign(h))

    original = anchor_path.read_text()
    FileAnchor(anchor_path).publish(signed(merkle_root="9" * 64))  # second, different batch 1
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.CHECKPOINT_INVALID in r.reasons

    anchor_path.write_text(original)
    FileAnchor(anchor_path).publish(signed(batch=3, from_seq=3, seq=3))  # batch 2 is missing
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.CHECKPOINT_INVALID in r.reasons


def test_stage_1_head_only_checkpoint_is_not_accepted(vx, app, signer, anchor_path):
    """A v1 checkpoint has no Merkle root; it must not count as an anchor."""
    create_payment(vx, app)
    head = vx.db.read_head()
    body = {"v": 1, "log_id": head["log_id"], "seq": head["seq"], "head": head["head_hash"],
            "created_at": "2026-10-02T00:00:00.000000Z"}
    h = P.checkpoint_hash(body)
    FileAnchor(anchor_path).publish(dict(body, checkpoint_hash=h, key_id=signer.key_id, signature=signer.sign(h)))
    r = vx.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.CHECKPOINT_INVALID in r.reasons


# ------------------------------------------------ checkpointer refusals -----


def test_checkpoint_refuses_to_anchor_a_forged_event(vx, app, attacker, anchor_path):
    """Anchors are write-once. Anchoring an event that fails verification
    would make the failure permanent, so the checkpointer refuses."""
    create_payment(vx, app)
    vx.checkpoint()
    evil = Signer.generate()
    with attacker() as sql:
        cur = sql.cursor(row_factory=psycopg.rows.dict_row)
        head = cur.execute("SELECT * FROM veridex.log_head").fetchone()
        last = cur.execute("SELECT * FROM veridex.events ORDER BY seq DESC LIMIT 1").fetchone()
        body = P.event_body(seq=head["seq"] + 1, op="UPDATE", resource="public.payments", record_id="123",
                            version=last["version"] + 1, record_hash="b" * 64, prev_event_hash=last["event_hash"],
                            prev_log_hash=head["head_hash"], config_hash=last["config_hash"],
                            created_at="2026-10-02T09:00:00.000000Z")
        h = P.event_hash(body)
        sql.execute(
            "INSERT INTO veridex.events (seq, op, resource, record_id, version, record_hash, prev_event_hash,"
            " prev_log_hash, config_hash, created_at, event_hash, key_id, signature)"
            " VALUES (%s,'UPDATE','public.payments','123',%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (body["seq"], body["version"], "b" * 64, last["event_hash"], head["head_hash"], last["config_hash"],
             body["created_at"], h, evil.key_id, evil.sign(h)))
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", (body["seq"], h))
    with pytest.raises(LogIntegrityError, match="BAD_SIGNATURE"):
        vx.checkpoint()
    assert len(_checkpoints(anchor_path)) == 1  # anchor untouched


def test_checkpoint_refuses_to_extend_a_rewritten_log(vx, app, attacker, anchor_path):
    create_payment(vx, app, amount="500.00")
    update_amount(vx, app, 123, "900.00")
    vx.checkpoint()
    with attacker() as sql:  # roll the anchored history back
        e = sql.execute("SELECT seq, event_hash FROM veridex.events WHERE seq = 2").fetchone()
        sql.execute("DELETE FROM veridex.events WHERE seq = 3")
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", e)
    with pytest.raises(LogIntegrityError):
        vx.checkpoint()
    create_payment(vx, app, pid=5)  # the log grows past the anchored seq again
    with pytest.raises(LogIntegrityError, match="no longer matches anchored batch 1"):
        vx.checkpoint()
    assert len(_checkpoints(anchor_path)) == 1


# -------------------------------------------------------- log replacement ---


def test_pinned_log_id_detects_a_swapped_evidence_log(db_url, vx, app, signer, anchor_path, attacker):
    """An attacker with the signing key replaces the whole evidence schema with
    a fresh, internally consistent log. A verifier that pinned the log id
    out-of-band reports it even if the anchor has nothing to say."""
    create_payment(vx, app)
    vx.checkpoint()
    real_log_id = vx.db.read_head()["log_id"]
    pinned = _small_batches(db_url, signer, anchor_path, log_id=real_log_id)
    assert pinned.verify("payments", 123).status == Status.VERIFIED

    with attacker() as sql:
        sql.execute("DROP SCHEMA veridex CASCADE")
        sql.execute("UPDATE payments SET amount = 9999999 WHERE id = 123")
    forged = _small_batches(db_url, signer, anchor_path.with_name("attacker-anchor.jsonl"))
    forged.init()
    forged.protect("payments", ["id", "amount", "currency", "recipient", "status"])
    forged.record("payments", "CREATE", record_id=123)

    r = pinned.verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.LOG_ID_MISMATCH in r.reasons
    with pytest.raises(LogIntegrityError):
        pinned.checkpoint()
