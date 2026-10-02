"""Test fixtures. Each test gets a fresh PostgreSQL database.

Set VERIDEX_TEST_DATABASE_URL to a superuser connection on a server you can
create databases on, e.g. postgresql://postgres:postgres@localhost:5432/postgres
(docker compose up -d starts one).
"""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest

from veridex import FileAnchor, Signer, Veridex
from veridex.adapters import PostgresAdapter

ADMIN_URL = os.environ.get(
    "VERIDEX_TEST_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres"
)
# Fixed test key: deterministic, never use in production.
TEST_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

PAYMENTS_DDL = """
CREATE TABLE payments (
    id         integer PRIMARY KEY,
    amount     numeric(14,2) NOT NULL,
    currency   char(3)       NOT NULL,
    recipient  text          NOT NULL,
    status     text          NOT NULL,
    note       text                      -- deliberately NOT protected
);
"""


def _admin():
    try:
        return psycopg.connect(ADMIN_URL, autocommit=True)
    except psycopg.OperationalError as e:
        pytest.skip(f"PostgreSQL not reachable at VERIDEX_TEST_DATABASE_URL: {e}")


@pytest.fixture
def db_url():
    name = "vx_test_" + uuid.uuid4().hex[:12]
    with _admin() as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    url = psycopg.conninfo.make_conninfo(ADMIN_URL, dbname=name)
    with psycopg.connect(url, autocommit=True) as c:
        c.execute(PAYMENTS_DDL)
    yield url
    with _admin() as admin:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def signer():
    return Signer.from_seed_hex(TEST_SEED)


@pytest.fixture
def anchor_path(tmp_path: Path) -> Path:
    return tmp_path / "anchor.jsonl"


@pytest.fixture
def vx(db_url, signer, anchor_path):
    v = Veridex(
        database=PostgresAdapter(db_url),
        trusted_keys=[signer.public_key_hex],
        signer=signer,
        anchor=FileAnchor(anchor_path),
    )
    v.init()
    v.protect("payments", ["id", "amount", "currency", "recipient", "status"])
    return v


@pytest.fixture
def app(db_url):
    """The application's own database connection."""
    with psycopg.connect(db_url) as c:
        yield c


@pytest.fixture
def attacker(db_url):
    """A superuser with direct SQL access that bypasses the application AND the
    append-only triggers (session_replication_role = replica disables them)."""

    @contextmanager
    def _sql():
        with psycopg.connect(db_url, autocommit=True) as c:
            c.execute("SET session_replication_role = replica")
            yield c

    return _sql


def create_payment(vx: Veridex, app, pid=123, amount="500.00"):
    with app.transaction():
        app.execute(
            "INSERT INTO payments (id, amount, currency, recipient, status) VALUES (%s, %s, 'XAF', 'alice', 'completed')",
            (pid, amount),
        )
        return vx.record("payments", "CREATE", record={"id": pid}, conn=app)


def update_amount(vx: Veridex, app, pid, amount):
    with app.transaction():
        app.execute("UPDATE payments SET amount = %s WHERE id = %s", (amount, pid))
        return vx.record("payments", "UPDATE", record={"id": pid}, conn=app)
