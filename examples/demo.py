"""The V1 demonstration from spec section 70:

    normal record  -> VERIFIED
    direct SQL     -> TAMPERED

Usage:
    docker compose up -d
    pip install -e ./python
    python examples/demo.py

Uses DATABASE_URL (default: the docker compose database). Creates a throwaway
`demo_payments` table and an ephemeral signing key.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import psycopg

from veridex import FileAnchor, Signer, Veridex
from veridex.adapters import PostgresAdapter

URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres")


def show(label: str, r) -> None:
    extra = f" ({', '.join(x.value for x in r.reasons)})" if r.reasons else ""
    print(f"  {label:<46} -> {r.status.value}{extra}")


def main() -> None:
    with psycopg.connect(URL, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS veridex_demo CASCADE")
        c.execute("DROP TABLE IF EXISTS demo_payments")
        c.execute("""CREATE TABLE demo_payments (
            id int PRIMARY KEY, amount numeric(14,2), currency char(3), recipient text, status text)""")

    signer = Signer.generate()  # in production: Signer.from_seed_hex(os.environ["VERIDEX_SIGNING_KEY"])
    anchor = FileAnchor(Path(tempfile.mkdtemp()) / "anchor.jsonl")
    vx = Veridex(
        database=PostgresAdapter(URL, integrity_schema="veridex_demo"),
        trusted_keys=[signer.public_key_hex],  # verifiers pin this; never read it from the DB
        signer=signer,
        anchor=anchor,
    )
    vx.init()
    vx.protect("demo_payments", ["id", "amount", "currency", "recipient", "status"])

    app = psycopg.connect(URL)
    with app.transaction():
        app.execute("INSERT INTO demo_payments VALUES (123, 500.00, 'XAF', 'alice', 'completed')")
        vx.record("demo_payments", "CREATE", record={"id": 123}, conn=app)

    print("\nVeridex demo — payment 123\n")
    show("1. recorded, not yet anchored", vx.verify("demo_payments", 123))
    vx.checkpoint()
    show("2. after checkpoint to external anchor", vx.verify("demo_payments", 123))

    with app.transaction():
        app.execute("UPDATE demo_payments SET amount = 750.00 WHERE id = 123")
        vx.record("demo_payments", "UPDATE", record={"id": 123}, conn=app)
    vx.checkpoint()
    show("3. legitimate update through the app", vx.verify("demo_payments", 123))

    with psycopg.connect(URL, autocommit=True) as attacker:
        attacker.execute("UPDATE demo_payments SET amount = 9999999 WHERE id = 123")
    show("4. attacker: UPDATE ... SET amount = 9999999", vx.verify("demo_payments", 123))

    with psycopg.connect(URL, autocommit=True) as attacker:
        attacker.execute("DELETE FROM demo_payments WHERE id = 123")
    show("5. attacker: DELETE FROM demo_payments", vx.verify("demo_payments", 123))
    print(f"\n  anchor file: {anchor.path}\n")
    app.close()


if __name__ == "__main__":
    main()
