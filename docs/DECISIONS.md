# Design decisions

Security-relevant choices made while implementing the V1 spec
(`veridex_v1.md`), especially where the implementation deliberately departs from
the original text. The spec has since been revised to match; its section 72
lists the same decisions from the spec's side.

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
`seq`. A checkpoint ending at `seq n` commits to all events `1..n`. Any deletion
or rewrite of an anchored event breaks the chain or mismatches an anchored root.

**Cost.** Event writers serialize on a single `log_head` row lock. Fine for
moderate write rates; a sharded log is a later concern. Per-record verification
audits the whole log (O(n)); see D14 for why Merkle batching does not change that.

## D3. Direct deletion is TAMPERED, not DELETED

The original spec (section 54, test 4) expected `DELETED` after a direct SQL
DELETE. That makes an attack identical to a legitimate deletion. Veridex returns
`DELETED` only when a signed, anchored DELETE event exists; a missing row
without one is `TAMPERED / RECORD_MISSING`.

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
is anchored.

## D10. FileAnchor stays as the development anchor

"Never VERIFIED without external evidence" needs *some* anchor from day one, so
stage 1 shipped `FileAnchor`. It remains for development and tests and
implements the same `Anchor` interface as the blockchain anchor. It is a real
trust boundary only on storage the database attacker cannot write.

## D11. Python SDK is synchronous for now

The spec shows `await integrity.record(...)`. The SDK is sync (psycopg 3).
An async API over `psycopg.AsyncConnection` is a straightforward follow-up.

## D12. TypeScript package is protocol-only

TypeScript implements canonicalization, hashing, signatures, Merkle trees and
offline log verification, proven byte-identical against shared vectors and
against a live Python-written log. A TypeScript PostgreSQL adapter
(node-postgres) is not built yet; its value normalization must follow
protocol/SPEC.md §3 (e.g. node-pg returns NUMERIC and BIGINT as strings already).

## D13. A checkpoint is a Merkle root over one batch (checkpoint v2)

Stage 1 checkpoints signed the log head. From stage 4 a checkpoint commits to a
**batch**: the events since the previous checkpoint, as an RFC 6962 Merkle tree
over their event hashes (`protocol/SPEC.md` §7–8). Because each event hash
covers `prev_log_hash`, a batch root still commits to the entire log before it,
so nothing D2 gave is lost.

- The tree is RFC 6962's, not Bitcoin's: leaf and node hashes are
  domain-separated and an odd node is promoted, never duplicated. A root
  therefore has exactly one list of leaves (no CVE-2012-2459-style ambiguity).
- This changed the checkpoint test vector, which the protocol's own rule calls
  a break, so checkpoints are `v: 2`. Head-only `v: 1` checkpoints are rejected.
  No log anchored by stage 1 can be verified by this version; stage 1 was
  explicitly not production-ready and its only anchor was a development file.
- Batching policy is the spec's: 5,000 events or 5 minutes, whichever first,
  both configurable. Veridex does not run a background thread: call
  `checkpoint(if_due=True)` (or `veridex checkpoint --if-due`) from a scheduler.

## D14. Inclusion proofs do not replace the full-log audit

An inclusion proof shows that one event is in the anchored log, in O(log n). It
cannot show that the event is the **latest** one for its record: that is a
statement that no later event exists, and the database is exactly the party
that might hide one. Looking up "the events of record 123" through an index
trusts unhashed columns the attacker can edit.

So `verify()` still audits the whole log, and inclusion proofs are what makes a
single event portable (stage 7). The earlier roadmap note that stage 4 "removes
the O(n) audit" was wrong on its own.

Removing it needs a commitment to per-record heads in every checkpoint (for
example a sparse Merkle tree keyed by record, with the root anchored next to
the batch root). That is a larger design: the checkpointer must then verify
every update against the previous anchored state. Deliberately not built in V1.
Until then, `verify(..., audit=report)` lets one audit serve many records.

## D15. The checkpointer refuses to anchor a log that fails its checks

An anchor is write-once. If a forged or broken event were anchored, every later
verification would be `INVALID_PROOF` forever, with no way to repair the log.
Before publishing, `checkpoint()` therefore re-checks the last anchored batch
against the database and checks every waiting event's hash, signature and chain
link. On failure it raises `LogIntegrityError` and publishes nothing. It does
not run the per-record transition rules; the full audit does.

## D16. What the contract stores, and who may write

`VeridexAnchor` stores, per batch: Merkle root, last `seq`, block timestamp. It
is keyed by publisher address and by `logKey = H("log", log_id)`.

- **Per-publisher namespace, no owner.** Anyone may use a deployed contract, but
  only under their own address. There is no admin, pause or upgrade path to
  compromise.
- **Write-once and sequential.** The contract accepts only batch `count + 1`
  with a higher `seq`. Even a stolen publisher key cannot rewrite history; it
  can only append, which shows up as a root the database does not produce.
- **`seq` is on-chain** so the chain alone says which events a root covers. A
  verifier needs nothing from the database but the events themselves.
- **Verifier pins chain id, contract address and publisher address**, the same
  way it pins trusted keys. The SDK also checks that the deployed runtime
  bytecode is exactly the one built from `contracts/src` (compiled without
  metadata so the hash is reproducible).
- The spec's sketch (`batchId`, `merkleRoot`, `timestamp`) is what is stored,
  plus `toSeq`. The spec's adapter interface (`anchorRoot` / `getAnchor` /
  `verifyAnchor`) maps to `publish()` / `checkpoints()`; comparing roots is the
  core's job, so no anchor implementation can get it wrong.

## D17. On-chain batches carry no Ed25519 signature

A file does not say who wrote it, so a `FileAnchor` entry must be a checkpoint
signed by a trusted key. A blockchain authenticates the sender, so an on-chain
batch is authenticated by the pinned publisher address instead
(`Anchor.requires_signature`). Events inside the batch are still signed.

## D18. Finality is the verifier's choice

`EvmAnchor(block_tag=...)` selects the block verification reads at. The Base
preset uses `finalized`: a batch counts only once its block is final on
Ethereum, and until then the record is `PENDING_ANCHOR`. Anvil uses `latest`.
The writer always reads `latest` to decide the next batch number.

## D19. Optional log id pin

Every anchor is looked up by log id. If an attacker replaces the whole evidence
schema with a fresh log (new id), a blockchain anchor simply has no batches for
it, which would read as `PENDING_ANCHOR`. A verifier that passes `log_id=` (from
`veridex init`, stored outside the database) gets `INVALID_PROOF /
LOG_ID_MISMATCH` instead.

## D20. `batches` table is a convenience copy; no `proofs` table

`veridex.batches` keeps each published checkpoint and the anchor's receipt
(transaction hash). It is never trusted: verification reads the anchor. Proofs
are derived on demand from the events, so the spec's `integrity.proofs` table
would only be a cache that could go stale; it is not created.

## Open questions (need a human decision)

- Where does the signing key live in production: in-app, a sidecar, or KMS/HSM?
- Who runs the checkpointer, and with which chain account? It holds the
  blockchain key, so it should not be the application process.
- One shared `VeridexAnchor` deployment on Base that everyone uses, or one per
  customer? The contract supports both; a canonical address is a product decision.
- Build the per-record head commitment (D14), or accept the full audit for V1?
- MySQL: still in V1 scope? (Recommended: defer.)
- License (the contract's SPDX line is `UNLICENSED` until this is decided).
