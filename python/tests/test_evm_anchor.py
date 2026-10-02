"""Blockchain anchoring against a local Anvil chain.

    anvil                      # Foundry; listens on http://127.0.0.1:8545
    pytest python/tests/test_evm_anchor.py

Skipped when web3 is not installed or no chain answers at
VERIDEX_TEST_EVM_RPC_URL. Every test deploys its own contract.
"""

from __future__ import annotations

import os

import pytest

web3 = pytest.importorskip("web3")

from veridex import AnchorError, ConfigurationError, LogIntegrityError, Reason, Signer, Status, Veridex  # noqa: E402
from veridex import protocol as P  # noqa: E402
from veridex.adapters import PostgresAdapter  # noqa: E402
from veridex.evm import ANVIL_CHAIN_ID, ARTIFACT, EvmAnchor  # noqa: E402

from .conftest import create_payment, update_amount  # noqa: E402

RPC = os.environ.get("VERIDEX_TEST_EVM_RPC_URL", "http://127.0.0.1:8545")
# Anvil's published development accounts 0 and 1. Public test keys: never fund them on a real chain.
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
PUBLISHER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
OTHER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


@pytest.fixture(scope="session")
def w3():
    w = web3.Web3(web3.Web3.HTTPProvider(RPC, request_kwargs={"timeout": 5}))
    try:
        if w.eth.chain_id != ANVIL_CHAIN_ID:
            pytest.skip(f"{RPC} is not a local Anvil chain")
    except Exception as e:
        pytest.skip(f"no EVM chain reachable at VERIDEX_TEST_EVM_RPC_URL: {e}")
    return w


@pytest.fixture
def contract(w3):
    return EvmAnchor.deploy(RPC, KEY, chain_id=ANVIL_CHAIN_ID)


@pytest.fixture
def writer(contract):
    return EvmAnchor.anvil(contract, RPC, private_key=KEY)


@pytest.fixture
def cvx(db_url, signer, writer):
    """Veridex writing to the database and anchoring on-chain."""
    v = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex], signer=signer, anchor=writer)
    v.init()
    v.protect("payments", ["id", "amount", "currency", "recipient", "status"])
    return v


def verifier(db_url, signer, contract, **kw):
    """A read-only verifier: public key and publisher address, no secrets."""
    anchor = EvmAnchor.anvil(contract, RPC, publisher=PUBLISHER, **kw)
    return Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex], anchor=anchor)


def raw(w3, contract):
    return w3.eth.contract(address=contract, abi=ARTIFACT["abi"])


# ------------------------------------------------------------ happy path ----


def test_record_anchor_on_chain_verify(db_url, cvx, app, signer, contract, w3):
    create_payment(cvx, app)
    v = verifier(db_url, signer, contract)
    assert v.verify("payments", 123).status == Status.PENDING_ANCHOR

    cp = cvx.checkpoint()
    assert cp["receipt"]["transaction_hash"].startswith("0x") and cp["receipt"]["chain_id"] == ANVIL_CHAIN_ID
    r = v.verify("payments", 123)
    assert r.status == Status.VERIFIED and r.batch == 1 and r.merkle_root == cp["merkle_root"]

    update_amount(cvx, app, 123, "650.00")
    assert v.verify("payments", 123).status == Status.PENDING_ANCHOR
    cvx.checkpoint()
    assert v.verify("payments", 123).batch == 2
    assert cvx.checkpoint() is None

    # The contract holds exactly the commitment, in order.
    key = bytes.fromhex(P.log_key(cvx.db.read_head()["log_id"]))
    batches = raw(w3, contract).functions.getBatches(PUBLISHER, key, 1, 10).call()
    assert [(b[0].hex(), b[1]) for b in batches] == [(cp["merkle_root"], 2), (v.verify("payments", 123).merkle_root, 3)]


def test_only_commitments_reach_the_chain(cvx, app, w3):
    """Spec sections 33 and 69: no application data on-chain."""
    create_payment(cvx, app)
    cp = cvx.checkpoint()
    tx = w3.eth.get_transaction(cp["receipt"]["transaction_hash"])
    data = bytes(tx["input"])
    assert len(data) == 4 + 4 * 32  # selector + logKey, batch, toSeq, merkleRoot
    assert data[-32:].hex() == cp["merkle_root"]
    for secret in (b"alice", b"XAF", b"payments", cp["log_id"].encode()):
        assert secret not in data


def test_proof_carries_the_transaction_reference(db_url, cvx, app, signer, contract):
    create_payment(cvx, app)
    cp = cvx.checkpoint()
    proof = verifier(db_url, signer, contract).prove("payments", 123)
    inc = proof["inclusion"]
    assert P.verify_inclusion(proof["event"]["event_hash"], inc["leaf_index"], inc["tree_size"], inc["path"], inc["merkle_root"])
    anchor = proof["anchor"]
    assert anchor["checkpoint"]["contract"] == contract and anchor["checkpoint"]["publisher"] == PUBLISHER
    assert anchor["receipt"]["transaction_hash"] == cp["receipt"]["transaction_hash"]


# --------------------------------------------------------------- attacks ----


def test_03_direct_sql_update_is_tampered(db_url, cvx, app, attacker, signer, contract):
    create_payment(cvx, app)
    cvx.checkpoint()
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 9999999 WHERE id = 123")
    assert verifier(db_url, signer, contract).verify("payments", 123).status == Status.TAMPERED


def test_rollback_of_anchored_history_is_invalid(db_url, cvx, app, attacker, signer, contract):
    create_payment(cvx, app, amount="500.00")
    update_amount(cvx, app, 123, "900.00")
    cvx.checkpoint()
    with attacker() as sql:
        sql.execute("UPDATE payments SET amount = 500.00 WHERE id = 123")
        e = sql.execute("SELECT seq, event_hash FROM veridex.events WHERE seq = 2").fetchone()
        sql.execute("DELETE FROM veridex.events WHERE seq = 3")
        sql.execute("UPDATE veridex.log_head SET seq = %s, head_hash = %s", e)
        sql.execute("DELETE FROM veridex.batches")  # the local copy is not what is trusted
    r = verifier(db_url, signer, contract).verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.CHECKPOINT_MISMATCH in r.reasons


def test_07_anchored_root_mismatch_is_invalid(db_url, cvx, app, signer, contract, w3):
    """Spec section 54 test 7: the chain holds a different root than the database produces."""
    create_payment(cvx, app)
    key = bytes.fromhex(P.log_key(cvx.db.read_head()["log_id"]))
    raw(w3, contract).functions.anchor(key, 1, 2, b"\x0d" * 32).transact({"from": PUBLISHER})
    r = verifier(db_url, signer, contract).verify("payments", 123)
    assert r.status == Status.INVALID_PROOF and Reason.CHECKPOINT_MISMATCH in r.reasons
    with pytest.raises(LogIntegrityError):
        cvx.checkpoint()


def test_batches_from_another_account_are_ignored(db_url, cvx, app, signer, contract, w3):
    """Anyone can write to the contract, but only under their own address."""
    create_payment(cvx, app)
    key = bytes.fromhex(P.log_key(cvx.db.read_head()["log_id"]))
    mallory = web3.Account.from_key(OTHER_KEY).address
    raw(w3, contract).functions.anchor(key, 1, 2, b"\x66" * 32).transact({"from": mallory})
    v = verifier(db_url, signer, contract)
    assert v.verify("payments", 123).status == Status.PENDING_ANCHOR
    cvx.checkpoint()
    assert v.verify("payments", 123).status == Status.VERIFIED


def test_anchored_batches_are_write_once_and_ordered(cvx, app, contract, w3):
    create_payment(cvx, app)
    cp = cvx.checkpoint()
    c, key, sender = raw(w3, contract), bytes.fromhex(P.log_key(cp["log_id"])), {"from": PUBLISHER}
    for args in (
        (key, 1, 2, b"\x01" * 32),  # overwrite batch 1
        (key, 3, 9, b"\x01" * 32),  # skip batch 2
        (key, 2, 2, b"\x01" * 32),  # seq does not advance
        (key, 2, 3, b"\x00" * 32),  # empty root
    ):
        with pytest.raises(web3.exceptions.ContractLogicError):
            c.functions.anchor(*args).call(sender)
    assert c.functions.batchCount(PUBLISHER, key).call() == 1
    # Publishing the same checkpoint again is harmless; a different one for the same batch is refused.
    assert cvx.anchor.publish(cp)["already_anchored"] is True
    with pytest.raises(AnchorError, match="different root"):
        cvx.anchor.publish(dict(cp, merkle_root="5" * 64))


# ------------------------------------------------- availability and pins ----


def test_09_chain_unreachable_is_never_verified(db_url, cvx, app, signer, contract):
    create_payment(cvx, app)
    cvx.checkpoint()
    down = EvmAnchor("http://127.0.0.1:1", contract, publisher=PUBLISHER, chain_id=ANVIL_CHAIN_ID, timeout=2)
    v = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex], anchor=down)
    r = v.verify("payments", 123)
    assert r.status == Status.ANCHOR_FAILED and Reason.ANCHOR_UNREACHABLE in r.reasons


def test_wrong_chain_or_wrong_contract_is_never_verified(db_url, cvx, app, signer, contract):
    create_payment(cvx, app)
    cvx.checkpoint()
    wrong_chain = EvmAnchor(RPC, contract, publisher=PUBLISHER, chain_id=8453)
    not_the_contract = EvmAnchor.anvil(PUBLISHER, RPC, publisher=PUBLISHER)  # an account, no code
    for anchor in (wrong_chain, not_the_contract):
        v = Veridex(database=PostgresAdapter(db_url), trusted_keys=[signer.public_key_hex], anchor=anchor)
        assert v.verify("payments", 123).status == Status.ANCHOR_FAILED


def test_unfinalized_batch_is_pending(db_url, cvx, app, signer, contract, w3):
    """A verifier reading finalized blocks does not count a batch until its block is final."""
    create_payment(cvx, app)
    cvx.checkpoint()
    v = verifier(db_url, signer, contract, block_tag="finalized")
    assert v.verify("payments", 123).status == Status.PENDING_ANCHOR
    assert cvx.checkpoint() is None  # the writer still knows the batch was published
    w3.provider.make_request("anvil_mine", [hex(200)])
    assert v.verify("payments", 123).status == Status.VERIFIED


def test_configuration_errors():
    with pytest.raises(ConfigurationError):
        EvmAnchor(RPC, PUBLISHER)  # neither publisher nor key
    with pytest.raises(ConfigurationError):
        EvmAnchor(RPC, PUBLISHER, publisher=web3.Account.from_key(OTHER_KEY).address, private_key=KEY)
    with pytest.raises(ConfigurationError):
        EvmAnchor.base(RPC, PUBLISHER, network="goerli", publisher=PUBLISHER)
    base = EvmAnchor.base("https://example.invalid", PUBLISHER, publisher=PUBLISHER)
    assert (base.chain_id, base.block_tag, base.name) == (8453, "finalized", "base")
    assert EvmAnchor.base("https://example.invalid", PUBLISHER, network="sepolia", publisher=PUBLISHER).chain_id == 84532
    assert KEY[2:] not in repr(EvmAnchor.anvil(PUBLISHER, RPC, private_key=KEY))
    read_only = EvmAnchor.anvil(PUBLISHER, RPC, publisher=PUBLISHER)
    with pytest.raises(AnchorError):
        read_only.publish({"log_id": "x", "batch": 1, "seq": 1, "merkle_root": "1" * 64})


# ------------------------------------------------------------------- CLI ----


def test_cli_deploys_anchors_and_verifies_on_chain(vx, app, db_url, monkeypatch, capsys, w3):
    """`vx` recorded the events (its own file anchor is irrelevant here); the CLI
    deploys a contract, anchors to it and verifies with a read-only setup."""
    import json

    from veridex.cli import main

    from .conftest import TEST_SEED

    create_payment(vx, app)
    for name, value in {
        "VERIDEX_DATABASE_URL": db_url, "VERIDEX_SIGNING_KEY": TEST_SEED,
        "VERIDEX_EVM_RPC_URL": RPC, "VERIDEX_EVM_CHAIN_ID": str(ANVIL_CHAIN_ID), "VERIDEX_EVM_PRIVATE_KEY": KEY,
    }.items():
        monkeypatch.setenv(name, value)

    assert main(["--json", "deploy-anchor"]) == 0
    deployed = json.loads(capsys.readouterr().out)
    assert deployed["publisher"] == PUBLISHER
    monkeypatch.setenv("VERIDEX_EVM_CONTRACT", deployed["contract"])

    assert main(["--json", "checkpoint"]) == 0
    assert json.loads(capsys.readouterr().out)["receipt"]["transaction_hash"].startswith("0x")

    # A verifier has no secrets at all: public key and publisher address only.
    monkeypatch.delenv("VERIDEX_SIGNING_KEY")
    monkeypatch.delenv("VERIDEX_EVM_PRIVATE_KEY")
    monkeypatch.setenv("VERIDEX_TRUSTED_KEYS", vx.signer.public_key_hex)
    assert main(["--json", "verify", "payments", "123"]) == 2  # publisher not pinned yet
    assert json.loads(capsys.readouterr().out)["error"] == "CONFIGURATION_ERROR"
    monkeypatch.setenv("VERIDEX_EVM_PUBLISHER", PUBLISHER)
    assert main(["--json", "verify", "payments", "123"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED"
    assert main(["--json", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["anchor"] == "evm"
