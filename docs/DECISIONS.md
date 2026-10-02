# Design decisions

Security-relevant choices made while implementing the V1 spec, especially
where the implementation deliberately departs from it.

## D1. Events are signed (spec did not require it)

**Problem.** With integrity tables in the same database, an attacker who can
UPDATE business rows can also append a new, correctly chained UPDATE event. The
next anchor would then certify the forgery. Anchoring proves history was not
*rewritten*; it does not prove a new event was *authorized*.

**Decision.** Every event and checkpoint is Ed25519-signed. Verifiers accept only
keys passed in configuration (`trusted_keys`), never keys read from the DB.

## D2. One global log chain, not only per-record chains

**Problem.** Per-record hash chains + anchoring events cannot detect truncation:
delete a record's newest events, revert the row, and every remaining event is
still genuinely anchored.

**Decision.** Every event carries `prev_log_hash` (global chain) and a gap-free
`seq`. A checkpoint at `seq n` commits to all events `1..n`. Any deletion or
rewrite of an anchored event breaks the chain or mismatches the checkpoint.

**Cost.** Event writers serialize on a single `log_head` row lock. Fine for
moderate write rates; a sharded log is a later concern. Per-record verification
currently audits the whole log (O(n)); stage 4 (Merkle) fixes this.

## D3. Direct deletion is TAMPERED, not DELETED

Spec §54 test 4 expected `DELETED` after a direct SQL DELETE. That makes an
attack identical to a legitimate deletion. Veridex returns `DELETED` only when a
signed, anchored DELETE event exists; a missing row without one is
`TAMPERED / RECORD_MISSING`.

## D4. Configuration changes are events in the same log

`protect()` writes a signed `CONFIGURE` event. The `configurations` table is a
convenience copy; it is only trusted if each row's hash equals a signed
`CONFIGURE` event, in order. `record()` refuses to write under a configuration
that fails this check, so a tampered config can't poison future evidence.

## D5. `record()` re-reads the row inside the transaction

The spec's API passes `record` to `record()`. Hashing that dict would mean the
application's Python/JS types (float `500.0`) get hashed instead of the
database's (`NUMERIC 500.00`), producing false `TAMPERED` results at
verification. Veridex uses `record` only for the primary key and hashes the row
as read from the database, inside the caller's transaction.

## D6. DELETE preserves the last attested state

A DELETE event's `record_hash` equals the previous event's. It does not read
the row (which may already be gone in the transaction).

## D7. Floats are refused

Shortest round-trip float formatting differs between languages (`1e21` vs
`1e+21`, etc.). Protected columns must be NUMERIC/DECIMAL or excluded.

## D8. Transactions: same database, savepoint

`record(conn=app_conn)` runs inside the caller's transaction (as a savepoint).
Rollback discards the event with the business change; commit commits both. On
an autocommit connection Veridex opens its own transaction. Tested in `test_10*`.
Trade-off: evidence tables share the database's trust domain; signatures and the
anchor are what make that acceptable.

## D9. VERIFIED requires an anchor; TAMPERED does not

Inconsistency with recorded evidence is reported immediately (`TAMPERED`,
`anchored: false`). Consistency is only reported as `VERIFIED` once the evidence
is anchored, per spec §37–38.

## D10. Stage 1 anchor = signed checkpoint file

The spec puts blockchain at stages 5–6, but "never VERIFIED without external
evidence" needs *some* anchor from day one. `FileAnchor` implements the same
`Anchor` interface the Base/Anvil adapters will implement. It is a dev stand-in.

## D11. Python SDK is synchronous for now

The spec shows `await integrity.record(...)`. Stage 1 is sync (psycopg 3).
An async API over `psycopg.AsyncConnection` is a straightforward follow-up.

## D12. TypeScript package is protocol-only

TypeScript implements canonicalization, hashing, signatures and offline log
verification, proven byte-identical against shared vectors and against a live
Python-written log. A TypeScript PostgreSQL adapter (node-postgres) is not built
yet; its value normalization must follow protocol/SPEC.md §3 (e.g. node-pg
returns NUMERIC and BIGINT as strings already).

## Open questions (need a human decision)

- Where does the signing key live in production: in-app, a sidecar, or KMS/HSM?
- Checkpoint cadence and who runs it (cron, sidecar, hosted)?
- Should `verify()` accept an exported log + checkpoint for third-party
  verification before stage 7, or wait for the portable proof format?
- MySQL: still in V1 scope? (Recommended: defer.)
- License.
