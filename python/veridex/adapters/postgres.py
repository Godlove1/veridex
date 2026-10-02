"""PostgreSQL adapter.

One adapter for every PostgreSQL-compatible provider (self-hosted, Supabase,
Neon, RDS, Cloud SQL, ...). It only uses standard SQL and psycopg 3.

Transaction semantics
---------------------
Pass the application's own connection to ``Veridex.record(..., conn=conn)``
inside the application's transaction. The integrity event is then written in
the SAME transaction as the business change: if the application rolls back,
the event disappears with it; if it commits, both commit.

The log head row is locked with SELECT ... FOR UPDATE, which serializes event
writers. That gives a gap-free global sequence and an unforkable log chain at
the cost of write throughput (one event writer at a time). See docs/DECISIONS.md.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from ..results import SchemaChangedError

SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.log_head (
    id         smallint PRIMARY KEY CHECK (id = 1),
    log_id     text     NOT NULL,
    seq        bigint   NOT NULL,
    head_hash  text     NOT NULL
);

CREATE TABLE IF NOT EXISTS {schema}.events (
    seq              bigint  PRIMARY KEY,
    op               text    NOT NULL,
    resource         text    NOT NULL,
    record_id        text,
    version          integer NOT NULL,
    record_hash      text,
    prev_event_hash  text,
    prev_log_hash    text    NOT NULL,
    config_hash      text    NOT NULL,
    created_at       text    NOT NULL,
    event_hash       text    NOT NULL UNIQUE,
    key_id           text    NOT NULL,
    signature        text    NOT NULL
);
CREATE INDEX IF NOT EXISTS events_record_idx
    ON {schema}.events (resource, record_id, seq);

CREATE TABLE IF NOT EXISTS {schema}.configurations (
    resource     text    NOT NULL,
    version      integer NOT NULL,
    body         text    NOT NULL,
    config_hash  text    NOT NULL,
    PRIMARY KEY (resource, version)
);

CREATE TABLE IF NOT EXISTS {schema}.protected_resources (
    resource         text PRIMARY KEY,
    schema_name      text NOT NULL,
    table_name       text NOT NULL,
    current_version  integer NOT NULL
);

-- Convenience copy of what was published to the anchor (signed checkpoint and
-- the anchor's receipt). Never trusted: verification reads the anchor itself.
CREATE TABLE IF NOT EXISTS {schema}.batches (
    batch        bigint  PRIMARY KEY,
    from_seq     bigint  NOT NULL,
    seq          bigint  NOT NULL,
    merkle_root  text    NOT NULL,
    checkpoint   text    NOT NULL,
    receipt      text    NOT NULL,
    created_at   text    NOT NULL
);

-- Defense in depth only. A superuser can disable these triggers; the real
-- protection is signatures + external checkpoints.
CREATE OR REPLACE FUNCTION {schema}.forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'veridex: % on %.% is not allowed (append-only)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS events_append_only ON {schema}.events;
CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON {schema}.events
    FOR EACH ROW EXECUTE FUNCTION {schema}.forbid_mutation();

DROP TRIGGER IF EXISTS configurations_append_only ON {schema}.configurations;
CREATE TRIGGER configurations_append_only BEFORE UPDATE OR DELETE ON {schema}.configurations
    FOR EACH ROW EXECUTE FUNCTION {schema}.forbid_mutation();

DROP TRIGGER IF EXISTS batches_append_only ON {schema}.batches;
CREATE TRIGGER batches_append_only BEFORE UPDATE OR DELETE ON {schema}.batches
    FOR EACH ROW EXECUTE FUNCTION {schema}.forbid_mutation();
"""

EVENT_COLUMNS = (
    "seq",
    "op",
    "resource",
    "record_id",
    "version",
    "record_hash",
    "prev_event_hash",
    "prev_log_hash",
    "config_hash",
    "created_at",
    "event_hash",
    "key_id",
    "signature",
)


class PostgresAdapter:
    database_type = "postgresql"

    def __init__(self, conninfo: str, *, integrity_schema: str = "veridex"):
        self.conninfo = conninfo
        self.schema = integrity_schema
        self._s = sql.Identifier(integrity_schema)

    # ------------------------------------------------------------ plumbing --

    def connect(self) -> psycopg.Connection:
        return psycopg.connect(self.conninfo, row_factory=dict_row)

    @contextmanager
    def transaction(self, conn: Optional[psycopg.Connection] = None) -> Iterator[psycopg.Connection]:
        """Use the caller's connection/transaction if given, else open our own."""
        if conn is not None:
            # Inside the caller's transaction this is a SAVEPOINT: a Veridex
            # failure rolls back only our writes, and the caller's later
            # ROLLBACK still discards them. On an autocommit connection it is a
            # real transaction, so the head lock and the insert stay atomic.
            with conn.transaction():
                yield conn
            return
        with self.connect() as own:
            with own.transaction():
                yield own

    def _q(self, template: str) -> sql.Composed:
        return sql.SQL(template).format(schema=self._s)

    def _cur(self, conn: psycopg.Connection):
        return conn.cursor(row_factory=dict_row)

    # -------------------------------------------------------------- schema --

    def init_schema(self) -> str:
        with self.transaction() as conn:
            conn.execute(sql.SQL(SCHEMA_SQL).format(schema=self._s))
            cur = self._cur(conn)
            cur.execute(self._q("SELECT log_id FROM {schema}.log_head WHERE id = 1"))
            row = cur.fetchone()
            if row:
                return row["log_id"]
            log_id = str(uuid.uuid4())
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.log_head (id, log_id, seq, head_hash) "
                    "VALUES (1, %s, 0, %s)"
                ),
                (log_id, "0" * 64),
            )
            return log_id

    # ---------------------------------------------------------------- head --

    def lock_head(self, conn: psycopg.Connection) -> dict[str, Any]:
        cur = self._cur(conn)
        cur.execute(
            self._q("SELECT log_id, seq, head_hash FROM {schema}.log_head WHERE id = 1 FOR UPDATE")
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("veridex schema not initialized; call init() first")
        return row

    def read_head(self, conn: Optional[psycopg.Connection] = None) -> dict[str, Any]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(self._q("SELECT log_id, seq, head_hash FROM {schema}.log_head WHERE id = 1"))
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("veridex schema not initialized; call init() first")
            return row

    def set_head(self, conn: psycopg.Connection, seq: int, head_hash: str) -> None:
        conn.execute(
            self._q("UPDATE {schema}.log_head SET seq = %s, head_hash = %s WHERE id = 1"),
            (seq, head_hash),
        )

    # -------------------------------------------------------------- events --

    def insert_event(self, conn: psycopg.Connection, event: dict[str, Any]) -> None:
        cols = sql.SQL(", ").join(sql.Identifier(c) for c in EVENT_COLUMNS)
        vals = sql.SQL(", ").join(sql.Placeholder() for _ in EVENT_COLUMNS)
        conn.execute(
            sql.SQL("INSERT INTO {schema}.events ({cols}) VALUES ({vals})").format(
                schema=self._s, cols=cols, vals=vals
            ),
            [event[c] for c in EVENT_COLUMNS],
        )

    def last_record_event(
        self, conn: psycopg.Connection, resource: str, record_id: str
    ) -> Optional[dict[str, Any]]:
        cur = self._cur(conn)
        cur.execute(
            self._q(
                "SELECT * FROM {schema}.events WHERE resource = %s AND record_id = %s "
                "AND op <> 'CONFIGURE' ORDER BY seq DESC LIMIT 1"
            ),
            (resource, record_id),
        )
        return cur.fetchone()

    def last_config_event(self, conn: psycopg.Connection, resource: str) -> Optional[dict[str, Any]]:
        cur = self._cur(conn)
        cur.execute(
            self._q(
                "SELECT * FROM {schema}.events WHERE resource = %s AND op = 'CONFIGURE' "
                "ORDER BY seq DESC LIMIT 1"
            ),
            (resource,),
        )
        return cur.fetchone()

    def load_events(self, conn: Optional[psycopg.Connection] = None) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(self._q("SELECT * FROM {schema}.events ORDER BY seq"))
            return list(cur.fetchall())

    def events_range(
        self, from_seq: int, to_seq: int, conn: Optional[psycopg.Connection] = None
    ) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(
                self._q("SELECT * FROM {schema}.events WHERE seq BETWEEN %s AND %s ORDER BY seq"),
                (from_seq, to_seq),
            )
            return list(cur.fetchall())

    def record_events(
        self, resource: str, record_id: str, conn: Optional[psycopg.Connection] = None
    ) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(
                self._q(
                    "SELECT * FROM {schema}.events WHERE resource = %s AND record_id = %s ORDER BY seq"
                ),
                (resource, record_id),
            )
            return list(cur.fetchall())

    # ------------------------------------------------------------- batches --

    def insert_batch(
        self,
        *,
        batch: int,
        from_seq: int,
        seq: int,
        merkle_root: str,
        checkpoint: str,
        receipt: str,
        created_at: str,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.batches "
                    "(batch, from_seq, seq, merkle_root, checkpoint, receipt, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (batch) DO NOTHING"
                ),
                (batch, from_seq, seq, merkle_root, checkpoint, receipt, created_at),
            )

    def load_batches(self, conn: Optional[psycopg.Connection] = None) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(self._q("SELECT * FROM {schema}.batches ORDER BY batch"))
            return list(cur.fetchall())

    # ------------------------------------------------------- configuration --

    def insert_config(
        self,
        conn: psycopg.Connection,
        *,
        resource: str,
        schema_name: str,
        table_name: str,
        version: int,
        body: str,
        config_hash: str,
    ) -> None:
        conn.execute(
            self._q(
                "INSERT INTO {schema}.configurations (resource, version, body, config_hash) "
                "VALUES (%s, %s, %s, %s)"
            ),
            (resource, version, body, config_hash),
        )
        conn.execute(
            self._q(
                "INSERT INTO {schema}.protected_resources "
                "(resource, schema_name, table_name, current_version) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (resource) DO UPDATE SET current_version = EXCLUDED.current_version"
            ),
            (resource, schema_name, table_name, version),
        )

    def load_configs(self, conn: Optional[psycopg.Connection] = None) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(self._q("SELECT * FROM {schema}.configurations ORDER BY resource, version"))
            return list(cur.fetchall())

    def latest_config(
        self, conn: psycopg.Connection, resource: str
    ) -> Optional[dict[str, Any]]:
        cur = self._cur(conn)
        cur.execute(
            self._q(
                "SELECT * FROM {schema}.configurations WHERE resource = %s "
                "ORDER BY version DESC LIMIT 1"
            ),
            (resource,),
        )
        return cur.fetchone()

    def list_resources(self, conn: Optional[psycopg.Connection] = None) -> list[dict[str, Any]]:
        with self.transaction(conn) as c:
            cur = self._cur(c)
            cur.execute(self._q("SELECT * FROM {schema}.protected_resources ORDER BY resource"))
            return list(cur.fetchall())

    # --------------------------------------------------------- business data --

    def fetch_row(
        self,
        conn: psycopg.Connection,
        *,
        schema_name: str,
        table_name: str,
        primary_key: list[str],
        pk_values: list[Any],
        fields: list[str],
    ) -> Optional[dict[str, Any]]:
        """Read the protected fields of one business row. Returns None if absent."""
        where = sql.SQL(" AND ").join(
            sql.SQL("{} = %s").format(sql.Identifier(c)) for c in primary_key
        )
        cols = sql.SQL(", ").join(sql.Identifier(f) for f in fields)
        cur = self._cur(conn)
        query = sql.SQL("SELECT {cols} FROM {s}.{t} WHERE {where}").format(
            cols=cols,
            s=sql.Identifier(schema_name),
            t=sql.Identifier(table_name),
            where=where,
        )
        try:
            # Savepoint: a failed SELECT must not abort the caller's transaction.
            with conn.transaction():
                cur.execute(query, pk_values)
        except (psycopg.errors.UndefinedColumn, psycopg.errors.UndefinedTable) as e:
            raise SchemaChangedError(f"{schema_name}.{table_name}: {e.diag.message_primary}") from e
        rows = cur.fetchall()
        if len(rows) > 1:
            raise RuntimeError(
                f"primary key {primary_key} matched {len(rows)} rows in {schema_name}.{table_name}"
            )
        return rows[0] if rows else None

    def column_names(self, conn: psycopg.Connection, schema_name: str, table_name: str) -> list[str]:
        cur = self._cur(conn)
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s",
            (schema_name, table_name),
        )
        return [r["column_name"] for r in cur.fetchall()]
