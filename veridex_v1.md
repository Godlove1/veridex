# Veridex
## V1 Product & Technical Specification

**Status:** V1 Specification, revision 2 (2026-10-02)  
**Revision 2:** the product is named Veridex, and the text now matches the security decisions made while building stages 1–6. Section 72 lists every change and why; `docs/DECISIONS.md` has the full reasoning and `docs/SPEC_AUDIT.md` the build status.  
**Purpose:** Implementation specification for AI coding agents and developers  
**Primary Goal:** Build a framework-independent, tamper-evident integrity layer for existing relational databases using cryptographic hashing, digital signatures, hash chains, Merkle trees, and public blockchain anchoring.

---

# 1. Product Definition

Veridex is a developer-focused infrastructure layer that allows applications to add **tamper-evident integrity verification** to existing relational databases without modifying their business tables.

The system records cryptographic evidence of protected database state, builds a verifiable history of changes, periodically aggregates integrity events into Merkle trees, and anchors Merkle roots to a public blockchain.

The system must allow developers to answer:

> "Can I cryptographically verify that this database record has not been altered outside the legitimate application flow?"

The system does **not** prevent database modification.

It detects modifications that are inconsistent with the previously recorded cryptographic history.

---

# 2. Core Problem

Applications commonly trust their databases as the source of truth.

However, a database administrator, compromised application server, malicious insider, compromised credentials, or direct SQL access may modify or delete records without going through the application's normal business logic.

Traditional audit logs can also be modified if they exist inside the same compromised database.

For example:

```text
payments
---------
id
amount
currency
recipient
status
```

An attacker could execute:

```sql
UPDATE payments
SET amount = 5000000
WHERE id = 123;
```

The application may never know.

Veridex provides an independent cryptographic evidence layer.

---

# 3. Security Model

The system follows this model:

```text
Application
     │
     ▼
Relational Database
     │
     ▼
Veridex Engine
     │
     ├── Signed cryptographic event history
     │
     ├── Hash chains
     │
     └── Merkle batches
              │
              ▼
       Public Blockchain
```

The database remains the primary application data store.

The blockchain stores only cryptographic commitments.

No sensitive application data should be stored on-chain.

---

# 4. Important Security Principle

A hash stored in the same database as the data it protects is insufficient.

For example:

```text
payments.amount = 500
payments.hash = ABC123
```

If an attacker can modify both fields:

```text
payments.amount = 900000
payments.hash = NEW_HASH
```

the hash provides no meaningful independent evidence.

Therefore, Veridex separates:

1. Business/application data
2. Integrity metadata
3. External cryptographic anchoring

Integrity metadata must live in dedicated integrity tables/schema rather than requiring developers to modify their existing business tables.

The blockchain provides an additional trust boundary.

Separation of tables is not enough on its own. An attacker who can write the business tables can usually write the integrity tables too, and could append a new, correctly chained integrity event for a forged change. Every integrity event is therefore **digitally signed**, and verifiers accept only public keys they were given outside the database. The signing key, the database and the blockchain anchor are three separate trust boundaries.

---

# 5. V1 Goals

V1 must provide:

- PostgreSQL support
- MySQL support
- PostgreSQL-compatible managed database support
- Framework independence
- TypeScript/Node.js SDK
- Python SDK
- Explicit protected fields
- CREATE integrity events
- UPDATE integrity events
- DELETE/tombstone events
- Signed integrity events (Ed25519)
- Per-record hash chains
- A global, gap-free log chain across all records
- Protection configuration versioning
- Configuration integrity verification
- Merkle tree batching
- Blockchain anchoring
- Base blockchain adapter
- Local EVM development using Anvil
- Portable cryptographic proofs
- Independent verification
- Tamper-detection tests
- CLI
- Clear developer documentation
- AI-agent-friendly integration
- Architecture prepared for a future MCP interface

---

# 6. Non-Goals for V1

Do not build:

- A replacement database
- A blockchain database
- A new ORM
- A proprietary SQL language
- A complete SIEM
- A complete compliance platform
- A generic event-streaming platform
- A blockchain wallet product
- Raw data storage on-chain
- A complicated consensus system
- Bespoke integrations for every managed database provider
- Framework-specific core logic
- An MCP implementation inside the core integrity engine

V1 should remain focused.

---

# 7. Competitive Position

The underlying cryptographic primitives are not unique.

Hash chains, Merkle trees, cryptographic timestamping, append-only logs, and blockchain anchoring already exist in various products and systems.

Relevant adjacent/competing approaches include:

- immutable databases
- cryptographically verifiable databases
- append-only audit logs
- blockchain timestamping systems
- cryptographic integrity platforms
- database integrity products

Veridex should therefore **not** position itself simply as:

> "Blockchain for databases."

The product positioning should instead emphasize:

> **A drop-in cryptographic integrity layer for existing relational databases.**

The important characteristics are:

- Existing database remains in place
- Existing business tables remain untouched
- PostgreSQL/MySQL compatibility
- Managed PostgreSQL compatibility
- Framework independence
- Multiple language SDKs
- Public blockchain anchoring
- Portable proofs
- Independent verification
- Developer-friendly integration
- AI-agent-friendly integration

Do not attempt to build "another immutable database."

---

# 8. Architecture Principles

The architecture must be:

### Protocol-first

The cryptographic protocol must not depend on a particular programming language or framework.

### Database-independent

The core integrity protocol must not depend on PostgreSQL-specific behavior.

### Framework-independent

FastAPI, Django, Flask, Express, NestJS, Next.js, Laravel, etc. must be integrations rather than core dependencies.

### Blockchain-independent

Base is the initial production blockchain, but the core must support other blockchain implementations through adapters.

### Provider-independent

Supabase and Neon are PostgreSQL providers, not separate database technologies.

Do not create separate Supabase and Neon database adapters.

### Verifiable

A third party should eventually be able to verify a proof without trusting the original application server.

### Minimal on-chain data

Only cryptographic commitments should be stored on-chain.

---

# 9. High-Level Architecture

```text
                    Application
                         │
          ┌──────────────┴──────────────┐
          │                             │
    TypeScript SDK                 Python SDK
          │                             │
          └──────────────┬──────────────┘
                         │
                  Veridex Core
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
 Database Layer     Protocol Layer   Blockchain Layer
        │                │                │
        │                │                │
 PostgreSQL           Hashing          Base
 MySQL                Canonicalization Anvil
                      Hash Chains      Other chains
                      Merkle Trees
                      Proofs
```

---

# 10. Protocol Layer

The protocol layer is the most important part of the system.

It must define:

- Canonical serialization
- Hash algorithm
- Record hash format
- Event hash format
- Signature scheme and key identification
- Hash chain format
- Protection configuration format
- Merkle tree format
- Merkle proof format
- Blockchain anchor format
- Portable proof format
- Protocol versioning

The protocol must be deterministic.

The same input must produce the same cryptographic output regardless of programming language.

---

# 11. Hash Algorithm

V1 uses:

```text
SHA-256
```

The hash algorithm must be explicitly included in protocol metadata.

Example:

```json
{
  "protocolVersion": "1.0",
  "hashAlgorithm": "SHA-256"
}
```

Do not allow individual implementations to silently choose different algorithms.

Signatures use **Ed25519** over the 32 raw bytes of a hash. Every hash is domain-separated by type (record, configuration, event, checkpoint, Merkle leaf, Merkle node) so that a hash of one kind can never be presented as another.

The normative definition of every format in this section is `protocol/SPEC.md`.

---

# 12. Canonicalization

Canonicalization is mandatory.

The system must produce exactly the same canonical representation for the same protected data regardless of whether the SDK is implemented in Python, TypeScript, or another language.

The canonicalization specification must define:

- field ordering
- string encoding
- number representation
- boolean representation
- null representation
- date/time representation
- Unicode normalization
- escaping
- nested object handling
- array handling
- missing fields
- decimal handling

Do not rely blindly on language-specific JSON serialization.

Floating-point column values are **refused**, not canonicalized: their shortest text form differs between languages. Protected numeric columns must be NUMERIC/DECIMAL (hashed as fixed-point strings) or integers.

Canonicalization of values is only half of the problem. Database drivers return the same column as different native types in different languages, so the protocol also defines **value normalization**: one rule per column type for turning a driver value into a canonical value.

For example, Python and JavaScript must not produce different hashes simply because their JSON serializers order or format values differently.

---

# 13. Cross-Language Test Vectors

The repository must contain shared protocol test vectors.

Example:

```json
{
  "input": {
    "id": 123,
    "amount": "5000.00",
    "currency": "XAF",
    "status": "completed"
  },
  "canonical": "...",
  "sha256": "..."
}
```

The TypeScript and Python implementations must produce exactly the same output.

These test vectors are mandatory before considering the protocol implementation complete.

---

# 14. Protected Resources

Developers explicitly define which database resources are protected.

Python:

```python
vx.protect(
    "payments",
    fields=[
        "id",
        "amount",
        "currency",
        "recipient",
        "status"
    ]
)
```

TypeScript (target API; the TypeScript SDK is not built yet):

```ts
veridex.protect("payments", {
  fields: [
    "id",
    "amount",
    "currency",
    "recipient",
    "status"
  ]
});
```

The original business table does not need an integrity column.

---

# 15. Protection Configuration

Protection configuration must itself be integrity-protected.

This is critical.

An attacker must not be able to silently change:

```text
Protected fields:
amount
currency
recipient
status
```

to:

```text
Protected fields:
id
```

and then modify the excluded fields without detection.

Configuration must therefore be:

- versioned
- hashed
- recorded as integrity metadata
- included in the verification process

Changing protection configuration creates a new configuration version.

Historical events must remain associated with the configuration version under which they were created.

A configuration change is itself a signed event (`CONFIGURE`) in the same log as record events. A configuration row in the database is only valid if a signed `CONFIGURE` event carries its hash. Recording must refuse to write under a configuration that fails this check.

---

# 16. Integrity Schema

Integrity metadata must be stored separately from application/business tables.

PostgreSQL schema (the schema name is configurable; `veridex` is the default):

```text
veridex.log_head
veridex.events
veridex.configurations
veridex.protected_resources
veridex.batches
```

The exact physical schema may evolve during implementation, but the separation principle is mandatory.

Business tables should remain unchanged.

`batches` and `protected_resources` are convenience copies. Verification never trusts them: batches are read from the anchor, and protected fields from the signed configuration.

There is no `proofs` table. Proofs are derived on demand from the events; a stored copy could only go stale.

---

# 17. Protected Resources Table

Conceptually:

```text
protected_resources
-------------------
id
database_type
schema_name
table_name
primary_key_definition
configuration_version
created_at
status
```

It identifies which application resources are protected.

---

# 18. Configuration Table

Conceptually:

```text
configuration
-------------
id
resource_id
version
protected_fields
canonicalization_version
hash_algorithm
configuration_hash
previous_configuration_hash
created_at
```

Configuration changes create a chain.

Example:

```text
Configuration V1
      │
      ▼
Configuration V2
      │
      ▼
Configuration V3
```

---

# 19. Integrity Events

Each protected state change creates an integrity event. Each protection configuration change does too.

Supported operations:

```text
CONFIGURE
CREATE
UPDATE
DELETE
```

Conceptually:

```text
events
------
seq
operation
resource
record_id
version
record_hash
previous_event_hash
previous_log_hash
configuration_hash
created_at
event_hash
key_id
signature
```

`seq` is a gap-free sequence number over the whole log. `previous_event_hash` links the event to the previous event of the same record. `previous_log_hash` links it to the previous event of the whole log.

The implementation may add additional fields where required.

---

# 20. Record Hash

A record hash represents the canonicalized protected state of a record.

Conceptually:

```text
recordHash =
SHA256(
  canonicalize(
    protected fields
  )
)
```

Only protected fields are included.

Unprotected fields do not affect the record hash.

---

# 21. Hash Chain

Each record maintains an integrity history.

Example:

```text
Version 1
   │
   ▼
H1
   │
   ▼
Version 2
   │
   ▼
H2
   │
   ▼
Version 3
   │
   ▼
H3
```

The new event must reference the previous integrity state.

Conceptually:

```text
eventHash =
SHA256(
  canonicalize(
    recordHash,
    previousRecordHash,
    operation,
    recordId,
    version,
    configurationVersion,
    metadata
  )
)
```

The exact protocol serialization must be specified centrally.

Two additions are mandatory.

**Signatures.** Every event hash is signed. A correctly chained event with a missing, invalid or untrusted signature makes the log invalid. Without this, anyone with database access could extend a record's chain.

**A global chain.** Per-record chains cannot reveal that a record's newest events were deleted: what remains is still a valid, anchored chain. Every event therefore also references the previous event of the whole log, and sequence numbers have no gaps. Anchoring the log up to event N then commits to every event before it, for every record.

---

# 22. Legitimate Updates

An UPDATE is not automatically tampering.

For example:

```text
$100
   ↓
$150
   ↓
$200
```

These are legitimate state transitions if they are properly recorded.

The system should preserve the history:

```text
Version 1 → Version 2 → Version 3
```

Verification checks whether the current state is consistent with the recorded history.

---

# 23. DELETE Events

DELETE must be a first-class integrity event.

When a protected record is deleted:

```text
DELETE event
```

must preserve enough cryptographic information to prove that the record existed and what its final protected state was.

The physical business record can disappear.

The integrity history remains.

Verification should therefore be able to return:

```text
DELETED
```

rather than simply:

```text
NOT FOUND
```

`DELETED` is returned only when a signed, anchored DELETE event exists. A record that has disappeared **without** a DELETE event was removed outside the application and is `TAMPERED`. A record that is present although its last event is a DELETE is also `TAMPERED`.

The DELETE event carries the record hash of the previous event, which preserves the final protected state.

---

# 24. Transaction Semantics

Integrity events must correspond to committed database state.

A rolled-back application transaction must not leave behind a permanent integrity event claiming that the operation occurred.

The implementation must define transaction behavior for each database adapter.

Required principle:

```text
Database transaction commits
        ↓
Integrity state commits
```

A failed or rolled-back transaction must not produce a falsely committed integrity event.

Transaction handling must be tested explicitly.

The PostgreSQL adapter does this by writing the integrity event on the application's own connection, inside the application's transaction. This requires the integrity schema to live in the same database as the business tables. The signatures and the external anchor, not the location of the tables, are what protect the evidence.

---

# 25. Event Capture

V1 supports explicit SDK recording, inside the application's transaction.

Python:

```python
with conn.transaction():
    conn.execute("UPDATE payments SET amount = %s WHERE id = %s", (150, 123))
    vx.record(
        table="payments",
        operation="UPDATE",
        record={"id": 123},
        conn=conn
    )
```

TypeScript (target API):

```ts
await veridex.record({
  table: "payments",
  operation: "UPDATE",
  record: { id: 123 },
  connection
});
```

The `record` argument identifies the row. The protected fields are **read back from the database** inside the same transaction and those values are hashed. Hashing the application's in-memory object would hash the application's types (a float `500.0`) instead of the database's (`NUMERIC 500.00`) and produce false tampering reports.

The Python SDK is currently synchronous. An asynchronous API is a planned addition.

Automatic database change capture may be explored later.

V1 should not become a complicated database CDC platform unless implementation requirements make it necessary.

---

# 26. Direct Database Modification

A core security test is:

1. Create record normally.
2. Record integrity event.
3. Verify successfully.
4. Modify the business record directly using SQL.
5. Run verification again.
6. Verification must detect the mismatch.

Example:

```sql
UPDATE payments
SET amount = 9999999
WHERE id = 123;
```

Expected result:

```text
TAMPERED
```

This is one of the most important V1 demonstrations.

---

# 27. Integrity Event Store Security

Integrity metadata is security-sensitive.

The architecture should support database permissions that make integrity metadata harder to modify than ordinary application data.

Where practical:

- application users should not receive unnecessary write access
- integrity tables should have restricted permissions
- integrity service credentials should be separated
- production blockchain credentials must not be exposed to ordinary application processes unnecessarily

However, the system must not claim that database-level permissions alone provide cryptographic security.

The signatures on events and the external blockchain anchor are the trust model. Verifiers must obtain trusted public keys, the anchor contract address and the publisher account address from configuration, never from the protected database.

---

# 28. Merkle Batching

Do not write every integrity event directly to the blockchain.

That would be expensive and unnecessary.

Instead:

```text
Event 1
Event 2
Event 3
Event 4
...
Event N
    │
    ▼
Merkle Tree
    │
    ▼
Merkle Root
    │
    ▼
Blockchain
```

Default batching policy:

```text
5 minutes
OR
5,000 events
```

whichever occurs first.

These defaults may be configurable.

A batch is the contiguous run of events since the previous batch. Batches are numbered from 1 without gaps.

The SDK does not run a background scheduler. The application's scheduler (cron, a worker) asks the SDK to anchor whatever is due.

Before anchoring, the batching process must check the events it is about to anchor (hash, signature, chain) and the previous anchored batch against the database, and must refuse to anchor if a check fails. An anchor cannot be undone, so anchoring a broken log would make the failure permanent.

---

# 29. Merkle Tree

Each event becomes a leaf.

The implementation must define:

- leaf encoding
- internal node hashing
- ordering
- odd-node behavior
- duplicate handling
- proof encoding

The algorithm must be deterministic across implementations.

V1 uses the Merkle tree of RFC 6962:

- **leaf encoding**: the event hash, hashed with a leaf prefix
- **internal node hashing**: left and right child, hashed with a node prefix
- **ordering**: by event sequence number, never sorted
- **odd-node behavior**: an odd node is promoted; nothing is duplicated or padded
- **duplicate handling**: cannot occur, because every event hash covers its sequence number
- **proof encoding**: leaf index, tree size and sibling hashes from the leaf up

Duplicating the last node, as some blockchains do, must not be used: it lets two different lists of leaves share one root.

---

# 30. Merkle Proof

An individual event must be verifiable against the Merkle root.

A proof should contain the necessary sibling hashes and ordering information.

Conceptually:

```text
Event
  │
  ├── sibling
  │
  ├── sibling
  │
  └── sibling
        │
        ▼
    Merkle Root
```

A Merkle proof shows that one event belongs to the anchored log. It does **not** show that the event is the latest one for its record. That requires knowing that no later event was removed, which takes the whole log (or a separate anchored commitment to each record's latest event, which V1 does not have). Record verification therefore audits the full log; Merkle proofs are what make a single event portable.

---

# 31. Blockchain

V1 production blockchain target:

**Base**

Base is used as the initial production anchor because it is EVM-compatible and provides relatively inexpensive transaction costs and strong Ethereum ecosystem compatibility.

However:

> Base is an implementation choice, not a protocol dependency.

---

# 32. Blockchain Adapter

The core system defines one anchor interface:

```python
class Anchor(Protocol):
    name: str
    requires_signature: bool

    def publish(self, checkpoint: dict) -> dict: ...

    def checkpoints(self, log_id: str, *, pending: bool = False) -> list[dict]: ...
```

`publish` anchors the commitment of one batch and returns a receipt. `checkpoints` returns every batch the anchor holds for a log.

Comparing the anchored roots with the database is done by the core, once, for every kind of anchor. An adapter only stores and returns commitments.

The exact interface can evolve during implementation.

The integrity engine must not directly depend on Base-specific code.

---

# 33. Smart Contract

V1 should use a minimal Solidity contract.

The contract stores, per batch:

```text
merkleRoot
toSeq        (the last event sequence number the batch covers)
timestamp
```

keyed by:

```text
publisher    (the account that anchored it)
logKey       (a hash of the log id)
batch number
```

Required properties:

- **Write-once.** A stored batch can never be changed or removed.
- **Sequential.** Only the next batch number, with a higher sequence number, is accepted.
- **Namespaced by publisher.** Anyone may use the contract, but only under their own account. Verifiers read one pinned publisher.
- **No owner, no upgrade mechanism.**

No raw business data.

No customer information.

No payment details.

No personal information.

No application payloads.

---

# 34. Local Blockchain Development

Local development should use:

**Anvil / Foundry**

The local environment should provide:

```text
PostgreSQL
MySQL
Veridex SDK
Anvil
VeridexAnchor.sol
```

Ganache may be supported as an alternative local EVM environment if useful, but it should not be required by the architecture.

The compiled contract ships inside the SDK. Developers who only use the SDK need neither Solidity nor Foundry.

---

# 35. Blockchain Environments

V1 should support:

```text
Local
  ↓
Anvil

Test
  ↓
Base test environment

Production
  ↓
Base mainnet
```

Blockchain credentials must be supplied through environment variables or secure secret management.

Never hard-code private keys.

A verifier must be configured with the chain id, the contract address and the publisher address, and must fail if the endpoint serves a different chain or the address holds different code.

On Base, verification reads **finalized** blocks. A batch whose block is not final yet is not anchored yet.

---

# 36. Verification Workflow

Verification should perform the following process:

```text
1. Load the integrity log
2. Verify every event: hash, signature by a trusted key, global chain, per-record chain, operation rules
3. Verify that configuration rows match the signed CONFIGURE events
4. Retrieve the anchored batches
5. Recompute each batch's Merkle root from the log and compare it with the anchored root
6. Find the latest event of the record
7. Retrieve the protection configuration that event was made under
8. Retrieve the current record and select the protected fields
9. Canonicalize and calculate the current record hash
10. Compare it with the event's record hash
11. Check that the event lies in an anchored batch
12. Return structured verification result
```

Steps 1–5 are the same for every record and can be shared when many records are verified together.

---

# 37. Verification States

V1 should support at least:

```text
VERIFIED
TAMPERED
DELETED
PENDING_ANCHOR
INVALID_PROOF
UNVERIFIED
ANCHOR_FAILED
CONFIGURATION_ERROR
```

The system must never report:

```text
VERIFIED
```

when the relevant integrity evidence has not been independently anchored.

`TAMPERED` does not wait for an anchor: a contradiction between the current state and the recorded evidence is reported immediately.

Every result also carries machine-readable reason codes (for example `STATE_MISMATCH`, `RECORD_MISSING`, `BAD_SIGNATURE`, `CHECKPOINT_MISMATCH`).

---

# 38. Blockchain Failure

If the blockchain is unavailable:

```text
PENDING_ANCHOR
```

may be returned.

The system must never convert:

```text
local hash exists
```

into:

```text
VERIFIED
```

without the required external evidence.

This distinction is fundamental.

---

# 39. Portable Proof Format

V1 should define a portable proof format.

The inclusion proof produced today:

```json
{
  "protocol": {
    "version": 1,
    "hash_algorithm": "SHA-256",
    "canonicalization": "vcf-1",
    "merkle": "vmt-1"
  },

  "log_id": "...",

  "event": {
    "body": {
      "seq": 42,
      "op": "UPDATE",
      "resource": "public.payments",
      "record_id": "123",
      "version": 3,
      "record_hash": "...",
      "prev_event_hash": "...",
      "prev_log_hash": "...",
      "config_hash": "...",
      "created_at": "..."
    },
    "event_hash": "...",
    "key_id": "...",
    "signature": "..."
  },

  "inclusion": {
    "batch": 7,
    "from_seq": 40,
    "seq": 44,
    "leaf_index": 2,
    "tree_size": 5,
    "path": ["..."],
    "merkle_root": "..."
  },

  "anchor": {
    "name": "base",
    "checkpoint": {
      "chain_id": 8453,
      "contract": "0x...",
      "publisher": "0x...",
      "batch": 7,
      "seq": 44,
      "merkle_root": "..."
    },
    "receipt": { "transaction_hash": "0x..." }
  }
}
```

The exact schema may evolve. Packaging this as the final portable bundle, with a verifier that needs only the bundle, the trusted public keys and a blockchain endpoint, is stage 7.

The proof must contain enough information for independent verification.

---

# 40. Independent Verification

Long-term, a third party should be able to receive a proof and verify it without access to:

- the original database
- the original application
- the original server
- the application's credentials

For example:

```text
Company
   │
   ▼
Integrity Proof
   │
   ▼
Auditor
   │
   ▼
Independent Verification
```

This is an important long-term product capability.

---

# 41. Language SDKs

V1 should initially provide:

```text
TypeScript / Node.js
Python
```

The SDKs must implement the same protocol.

They must produce identical cryptographic outputs for identical inputs.

---

# 42. Framework Independence

The SDK must not require:

- Next.js
- Express
- NestJS
- FastAPI
- Django
- Flask
- SQLAlchemy
- Prisma
- Drizzle

These frameworks may be used by the application around the SDK.

Example:

```text
FastAPI
   │
   ├── SQLAlchemy
   │
   └── Veridex Python SDK
```

or:

```text
Next.js
   │
   ├── Prisma
   │
   └── Veridex TypeScript SDK
```

The application architecture should not need to be rewritten.

---

# 43. PostgreSQL Compatibility

V1 targets standard PostgreSQL and PostgreSQL-compatible managed environments.

Initial compatibility targets:

- Self-hosted PostgreSQL
- Supabase PostgreSQL
- Neon PostgreSQL
- AWS RDS PostgreSQL
- Google Cloud SQL for PostgreSQL
- Azure Database for PostgreSQL
- Railway PostgreSQL
- Render PostgreSQL
- DigitalOcean Managed PostgreSQL

The system must use **one PostgreSQL adapter**.

Do not create:

```text
SupabaseAdapter
NeonAdapter
RDSAdapter
RailwayAdapter
```

unless a provider-specific limitation genuinely requires one.

The architecture should instead be:

```text
Veridex SDK
      │
      ▼
PostgreSQL Adapter
      │
      ▼
PostgreSQL Driver / Connection
      │
      ├── Supabase
      ├── Neon
      ├── RDS
      ├── Cloud SQL
      ├── Railway
      └── Self-hosted PostgreSQL
```

The adapter should primarily rely on standard PostgreSQL semantics and connection mechanisms.

Compatibility testing should explicitly include at least:

```text
Supabase
Neon
```

because these are common managed PostgreSQL environments for modern applications.

Any provider-specific limitations must be documented.

---

# 44. MySQL Compatibility

V1 also targets standard MySQL.

The architecture should use:

```text
MySQL Adapter
```

rather than framework-specific database integrations.

Managed MySQL providers can be supported through the standard MySQL interface where compatible.

The same provider-independence principle used for PostgreSQL should apply to MySQL.

---

# 45. Example TypeScript API

Target API. The TypeScript package currently implements the protocol only (canonicalization, hashing, signatures, Merkle proofs, offline log verification).

```ts
const veridex = new Veridex({
  database: postgresAdapter,
  blockchain: baseAdapter,
  signer,
  trustedKeys
});

veridex.protect("payments", {
  fields: [
    "id",
    "amount",
    "currency",
    "recipient",
    "status"
  ]
});

await veridex.record({
  table: "payments",
  operation: "CREATE",
  record: payment,
  connection
});

const result = await veridex.verify({
  table: "payments",
  recordId: 123
});
```

---

# 46. Example Python API

```python
vx = Veridex(
    database=PostgresAdapter(database_url),
    anchor=EvmAnchor.base(rpc_url, contract_address, private_key=publisher_key),
    signer=Signer.from_seed_hex(signing_key),
    trusted_keys=[public_key]
)

vx.protect(
    "payments",
    fields=[
        "id",
        "amount",
        "currency",
        "recipient",
        "status"
    ]
)

vx.record(
    table="payments",
    operation="CREATE",
    record=payment,
    conn=conn
)

vx.checkpoint()

result = vx.verify(
    table="payments",
    record_id=123
)
```

A verifier is constructed without `signer` and with `EvmAnchor.base(rpc_url, contract_address, publisher=publisher_address)`. It holds no secrets.

---

# 47. FastAPI Example

FastAPI must work without being a dependency of the core SDK.

Example:

```python
from fastapi import FastAPI
from veridex import Veridex

app = FastAPI()

vx = Veridex(
    database=database,
    anchor=anchor,
    signer=signer,
    trusted_keys=trusted_keys
)
```

The application may continue using:

```text
FastAPI
SQLAlchemy
asyncpg
repositories
services
routers
```

without changing its fundamental architecture.

---

# 48. Supabase Example

A typical application may look like:

```text
Next.js / FastAPI
       │
       ▼
Supabase PostgreSQL
       │
       ▼
Veridex PostgreSQL Adapter
       │
       ▼
Veridex Protocol
       │
       ▼
Base
```

The developer should not need a special blockchain architecture simply because the database is hosted by Supabase.

---

# 49. Neon Example

A typical application may look like:

```text
Next.js / Node.js
       │
       ▼
Neon PostgreSQL
       │
       ▼
Veridex PostgreSQL Adapter
       │
       ▼
Veridex Protocol
       │
       ▼
Base
```

Again, Neon is simply PostgreSQL from the adapter's perspective.

---

# 50. AI-Assisted Development

Modern developers increasingly build applications using AI coding agents such as Claude, ChatGPT, Cursor, and similar tools.

Veridex should therefore have an exceptionally clear developer experience.

The SDK should provide:

- simple installation
- copy-paste configuration
- framework-neutral examples
- FastAPI examples
- Next.js examples
- Supabase examples
- Neon examples
- machine-readable errors
- protocol documentation
- test fixtures
- security tests
- explicit attack examples
- predictable API names

An AI coding agent should be able to understand the integration without requiring a human to reverse-engineer undocumented security semantics.

However, AI integration is a **developer-experience/distribution advantage**, not a replacement for the underlying cryptographic security model.

---

# 51. Future MCP Interface

MCP is **not part of the core V1 integrity protocol**.

The architecture must nevertheless be designed so a future MCP server can expose Veridex capabilities to AI agents.

The intended architecture is:

```text
AI Agent
   │
   ▼
Veridex MCP
   │
   ▼
Public Veridex SDK/API
   │
   ▼
Veridex Core
   │
   ├── Database adapters
   ├── Protocol
   └── Blockchain adapters
```

The MCP must not implement a second integrity engine.

It should call the same underlying public APIs used by normal applications and CLI tooling.

Potential future MCP tools include:

```text
protect_resource
list_protected_resources
record_integrity_event
verify_record
verify_batch
get_integrity_history
generate_proof
verify_proof
get_anchor_status
```

Example future interaction:

```text
Developer:

"Protect the payments table and monitor
amount, currency, recipient and status."

AI Agent
   │
   ▼
Veridex MCP
   │
   ▼
Veridex SDK
```

Another example:

```text
Developer:

"Verify payment 8492."

AI Agent
   │
   ▼
Veridex MCP
   │
   ▼
verify_record()
   │
   ▼
VERIFIED
```

The MCP should be an interface to the integrity system, not the integrity system itself.

---

# 52. Repository Structure

The repository structure:

```text
veridex/
│
├── protocol/
│   ├── SPEC.md              normative protocol definition
│   └── test-vectors/        shared by every implementation
│
├── python/
│   ├── veridex/
│   │   ├── canonical.py     canonicalization
│   │   ├── normalize.py     database value normalization
│   │   ├── protocol.py      hashing, events, signatures, Merkle
│   │   ├── core.py          protect, record, checkpoint, audit, verify, prove
│   │   ├── anchor.py        anchor interface, file anchor
│   │   ├── evm.py           blockchain anchor (Anvil, Base)
│   │   ├── adapters/        postgres (mysql later)
│   │   ├── contracts/       compiled anchor contract
│   │   └── cli.py
│   └── tests/
│
├── typescript/              protocol package (SDK later)
│
├── contracts/               VeridexAnchor.sol, Foundry project
│
├── examples/
│
├── sql/
│
└── docs/
```

The exact structure may change during implementation, but responsibilities must remain separated: the protocol modules do no I/O, the core knows no database or blockchain, and adapters hold everything specific to one.

---

# 53. CLI

V1 should provide a basic CLI.

Commands:

```bash
veridex keygen
veridex init
veridex protect
veridex verify
veridex history
veridex proof
veridex checkpoint
veridex deploy-anchor
veridex audit
veridex status
```

`checkpoint` batches the waiting events and anchors the Merkle root; it replaces the separate `batch` and `anchor` commands of the first draft.

Example:

```bash
veridex verify payments 123
```

Possible output:

```text
Status: VERIFIED
Resource: public.payments
Record Id: 123
Version: 3
Event Hash: ...
Anchored: True
Batch: 7
Merkle Root: ...
```

Every command supports machine-readable JSON output, and `verify` and `audit` report failure through the exit code.

---

# 54. Required Security Test Suite

The implementation must include automated security tests.

### Test 1: Create

```text
Create record
→ integrity event
→ verify
→ VERIFIED
```

### Test 2: Legitimate update

```text
Create
→ Update
→ new integrity version
→ verify
→ VERIFIED
```

### Test 3: Direct SQL modification

```text
Create
→ integrity event
→ direct SQL modification
→ verify
→ TAMPERED
```

### Test 4: Direct deletion

```text
Create
→ integrity event
→ direct SQL DELETE
→ verify
→ TAMPERED
```

A deletion recorded through the SDK, then anchored, verifies as:

```text
DELETED
```

### Test 5: Historical event modification

Modify an old integrity event.

Expected:

```text
INVALID_PROOF
```

or equivalent integrity failure.

### Test 6: Merkle proof modification

Modify a Merkle proof.

Expected:

```text
INVALID_PROOF
```

### Test 7: Blockchain root mismatch

Use a different root from the anchored root.

Expected:

```text
INVALID_PROOF
```

### Test 8: Protection configuration modification

Modify protected fields or configuration without creating a valid new configuration version.

Expected:

```text
CONFIGURATION_ERROR
```

or equivalent verification failure.

### Test 9: Blockchain unavailable

Attempt verification without an available anchor.

Expected:

```text
PENDING_ANCHOR
```

or another explicitly non-verified state.

The system must never return:

```text
VERIFIED
```

when external anchoring has not occurred.

### Test 10: Transaction rollback

Start a transaction, create or update a protected record, then roll back.

Expected:

```text
No committed integrity event
```

for the rolled-back state.

### Test 11: Forged event

Change a record directly, then append a correctly chained integrity event for the change, signed with a key the verifier does not trust.

Expected:

```text
INVALID_PROOF
```

### Test 12: Rollback of anchored history

Revert a record to an earlier state and delete its later, anchored integrity events so the remaining log is self-consistent.

Expected:

```text
INVALID_PROOF
```

### Test 13: Anchoring a broken log

Ask the batching process to anchor a log that contains a forged event or no longer matches the previous anchored batch.

Expected:

```text
Refused; nothing is anchored
```

### Test 14: Foreign blockchain account

Anchor a root for the same log from an account other than the pinned publisher.

Expected:

```text
Ignored
```

---

# 55. Attack Model

V1 must explicitly test:

### Attacker can modify business data

Expected:

```text
Detected
```

### Attacker can delete business data

Expected:

```text
Detected
```

### Attacker can modify historical integrity metadata

Expected:

```text
Detected
```

### Attacker can modify Merkle proof data

Expected:

```text
Detected
```

### Attacker can append forged integrity events

Expected:

```text
Detected
```

unless the attacker also holds a trusted signing key.

### Attacker cannot modify blockchain history

The external anchor remains the independent reference.

---

# 56. Important Security Limitation

Veridex cannot provide absolute security if the attacker controls every trust boundary.

For example, if an attacker simultaneously controls:

```text
Application
+
Database
+
Integrity service
+
Integrity event store
+
Signing key
+
Blockchain credentials
```

the guarantees are significantly weakened.

The system's security depends on keeping the external blockchain anchor outside the compromised trust domain.

Further limits that must be documented:

- Events recorded after the last anchored batch are protected only by the database and the signatures until they are anchored.
- Whoever holds a trusted signing key can record events that verify.
- A verifier believes its blockchain endpoint; the endpoint must not be under the attacker's control.
- A change recorded through the legitimate application flow is attested, whether or not it was right.

This limitation must be clearly documented.

Do not market the system as:

> "Impossible to hack."

The correct claim is:

> **Unauthorized changes can be detected when they conflict with independently anchored integrity evidence.**

---

# 57. Performance

V1 should avoid unnecessary blockchain operations.

The normal flow should be:

```text
Database operation
        ↓
Cryptographic event
        ↓
Local integrity storage
        ↓
Batch
        ↓
Merkle tree
        ↓
Blockchain anchor
```

Database operations must not require an individual blockchain transaction.

The system should support asynchronous batching.

Known costs of the V1 design: event writers are serialized (one global log), and verifying a record audits the whole log.

---

# 58. Failure Handling

Blockchain failure must not destroy the application's normal database functionality.

If:

```text
Database = available
Blockchain = unavailable
```

the application may continue operating according to configured policy while integrity events remain pending.

The system must clearly distinguish:

```text
Recorded
```

from:

```text
Anchored
```

and:

```text
Verified
```

These are not interchangeable.

---

# 59. Configuration

Environment variables should be used for deployment configuration.

```env
VERIDEX_DATABASE_URL=
VERIDEX_SIGNING_KEY=
VERIDEX_TRUSTED_KEYS=
VERIDEX_LOG_ID=
VERIDEX_BATCH_INTERVAL=
VERIDEX_BATCH_SIZE=
VERIDEX_EVM_RPC_URL=
VERIDEX_EVM_CHAIN_ID=
VERIDEX_EVM_CONTRACT=
VERIDEX_EVM_PUBLISHER=
VERIDEX_EVM_PRIVATE_KEY=
VERIDEX_EVM_BLOCK_TAG=
```

`VERIDEX_SIGNING_KEY` is needed only by the process that records events. `VERIDEX_EVM_PRIVATE_KEY` is needed only by the process that anchors batches. Verifiers need neither.

There is no separate integrity database URL: integrity events are written in the application's own transaction (section 24).

Never hard-code credentials.

---

# 60. Developer Experience

The simplest possible integration should look approximately like:

```text
Install SDK
      ↓
Configure database
      ↓
Configure blockchain
      ↓
Select protected resource
      ↓
Record events
      ↓
Verify
```

The developer should not need to understand Solidity to use the basic SDK.

Blockchain complexity should remain behind the adapter.

---

# 61. Example Product Flow

A developer has:

```text
Supabase PostgreSQL
```

with:

```text
payments
customers
orders
```

They install Veridex.

They configure:

```text
payments:
    id
    amount
    currency
    recipient
    status
```

They continue using Supabase normally.

Veridex maintains:

```text
veridex.log_head
veridex.events
veridex.configurations
veridex.protected_resources
veridex.batches
```

Every protected state transition creates cryptographic evidence.

Every few minutes:

```text
Events
   ↓
Merkle root
   ↓
Base
```

Later:

```text
Verify payment 123
```

Veridex reconstructs the evidence and returns:

```text
VERIFIED
```

If somebody directly changes the payment:

```sql
UPDATE payments
SET amount = 999999999
WHERE id = 123;
```

verification returns:

```text
TAMPERED
```

---

# 62. Open Source / Hosted Strategy

The underlying SDK and protocol can be open source.

Potential future hosted offering:

```text
Veridex Cloud
```

The hosted service could provide:

- managed blockchain anchoring
- monitoring
- dashboards
- proof storage
- alerting
- audit interfaces
- team management
- API access
- compliance reporting
- long-term proof retention

The open-source core provides trust and adoption.

The hosted product provides convenience and operational infrastructure.

Do not let monetization requirements distort the cryptographic protocol.

---

# 63. V1 Success Criteria

V1 is successful when a developer can:

1. Install the SDK.
2. Connect an existing PostgreSQL database.
3. Use Supabase or Neon without a provider-specific adapter.
4. Select protected fields.
5. Record CREATE, UPDATE, and DELETE events.
6. Generate deterministic hashes.
7. Maintain a record hash chain.
8. Batch events into Merkle trees.
9. Anchor the root to a local Anvil blockchain.
10. Anchor the root to Base.
11. Verify records.
12. Detect direct SQL modification.
13. Detect deletion.
14. Detect historical integrity manipulation.
15. Verify a portable proof.
16. Run the same protocol from Python and TypeScript.
17. Use the SDK without adopting a specific web framework.

---

# 64. Implementation Stages

## Stage 1: Protocol

Implement:

- canonicalization
- SHA-256
- record hashing
- event hashing
- signatures
- hash chains (per record and global)
- configuration versioning
- protocol test vectors

No blockchain yet. A development anchor (a file of signed checkpoints) stands in, so that `VERIFIED` is never returned without external evidence.

---

## Stage 2: PostgreSQL

Implement:

- PostgreSQL adapter
- integrity schema
- protected resources
- events
- configuration
- verification

Test against:

- self-hosted PostgreSQL
- Supabase
- Neon

---

## Stage 3: MySQL

Implement:

- MySQL adapter
- equivalent integrity functionality
- transaction semantics
- verification

---

## Stage 4: Merkle Trees

Implement:

- batching
- deterministic Merkle tree
- Merkle proofs
- proof verification

---

## Stage 5: Local Blockchain

Implement:

- Solidity contract
- Anvil environment
- blockchain adapter
- local anchoring
- local verification

---

## Stage 6: Base

Implement:

- Base adapter configuration
- deployment
- anchoring
- blockchain verification

---

## Stage 7: Portable Proofs

Implement:

- proof generation
- proof serialization
- independent verification

---

## Stage 8: CLI

Implement:

```bash
veridex init
veridex protect
veridex verify
veridex history
veridex proof
veridex checkpoint
veridex status
```

---

## Stage 9: SDKs

Finalize:

```text
TypeScript
Python
```

Ensure cross-language protocol compatibility.

---

## Stage 10: Security Suite

Run the complete attack suite.

Do not consider V1 complete until direct database tampering can reliably be detected.

---

# 65. Future Work

Potential post-V1 capabilities:

- automatic database change capture
- PostgreSQL triggers
- CDC integrations
- additional databases
- additional blockchains
- hosted Veridex Cloud
- dashboards
- alerting
- compliance reports
- organization/team support
- long-term proof archival
- third-party verification service
- browser-based proof verifier
- mobile verification
- SDKs for additional languages
- AI coding-agent integrations
- Veridex MCP
- AI-native database integrity management

These should not unnecessarily complicate V1.

---

# 66. Future MCP Architecture

When MCP is implemented, it should expose the existing integrity capabilities rather than creating new business logic.

Architecture:

```text
Claude / ChatGPT / Cursor / Other AI
                    │
                    ▼
              Veridex MCP
                    │
                    ▼
            Veridex SDK/API
                    │
                    ▼
             Veridex Core
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Databases           Blockchain
```

Potential commands:

```text
protect_resource
unprotect_resource
list_resources
get_configuration
get_history
verify_record
verify_batch
generate_proof
verify_proof
get_anchor_status
get_integrity_status
```

The MCP should respect the same permission model as the SDK.

An AI agent must not automatically gain privileged database or blockchain access simply because it is connected through MCP.

---

# 67. Important Product Principle

The system must separate:

```text
Application truth
```

from:

```text
Integrity evidence
```

The application database answers:

> What does the application currently say?

Veridex answers:

> Can the current state be cryptographically reconciled with independently anchored historical evidence?

Those are different questions.

---

# 68. Important Terminology

Use:

- tamper-evident
- integrity verification
- cryptographic evidence
- integrity event
- hash chain
- Merkle root
- blockchain anchor
- independent verification
- portable proof
- protected resource

Avoid unsupported claims such as:

- tamper-proof
- impossible to hack
- blockchain-secured database
- immutable application database
- guaranteed security

The system provides evidence and detection, not magical invulnerability.

---

# 69. AI Coding-Agent Instructions

When implementing this specification:

### Do not silently invent security semantics.

If a security-critical behavior is ambiguous, isolate the decision and document it.

### Do not store application data on-chain.

Only cryptographic commitments should be anchored.

### Do not claim unanchored data is verified.

Local cryptographic consistency and external blockchain anchoring are distinct states.

### Do not ignore transaction rollback.

Integrity events must correspond to committed state.

### Do not allow configuration changes to silently invalidate historical assumptions.

Configuration must be versioned and integrity-protected.

### Do not create provider-specific PostgreSQL adapters unnecessarily.

Supabase and Neon should use the PostgreSQL adapter.

### Do not make FastAPI or Next.js core dependencies.

Frameworks belong in examples/integrations.

### Do not build MCP into the cryptographic core.

MCP will be an interface layer.

### Do not accept unsigned or untrusted evidence.

Events are signed. Trusted public keys, the contract address and the publisher address come from configuration, never from the protected database.

### Do not report a direct deletion as DELETED.

Only a signed, anchored DELETE event makes a missing record `DELETED`.

### Do not anchor a log that fails its checks.

Anchors are permanent.

### Do not over-engineer V1.

Prefer a small, testable, auditable system over a huge architecture with features nobody can verify.

---

# 70. First Implementation Goal

The first implementation milestone is **not blockchain**.

Build this first:

```text
PostgreSQL
    ↓
Veridex SDK
    ↓
Canonicalization
    ↓
SHA-256
    ↓
Signed Integrity Events
    ↓
Hash Chain
    ↓
Verification
```

Then demonstrate:

```text
Normal record
     ↓
VERIFIED
```

followed by:

```text
Direct SQL modification
     ↓
TAMPERED
```

Only after this works reliably should Merkle batching and blockchain anchoring be introduced.

This establishes that the fundamental integrity mechanism works before adding distributed anchoring complexity.

---

# 71. Final V1 Principle

The product should feel simple to the developer:

```text
"I have a database.
I want cryptographic evidence that important records
have not been silently altered."
```

The developer should not need to become:

```text
Database engineer
+
cryptographer
+
Solidity developer
+
blockchain engineer
+
DevOps engineer
```

to accomplish this.

The complexity belongs inside the infrastructure.

The developer experience should remain:

```text
Protect.
Record.
Verify.
```

while the system underneath provides:

```text
Canonicalization
+
Cryptographic hashing
+
Hash chains
+
Merkle aggregation
+
Blockchain anchoring
+
Independent verification
```

That is the core of Veridex V1.

---

# 72. Revision Notes

Revision 2 changed this specification where building it showed the first draft to be unsafe, ambiguous or different from what was built. Each entry names the sections it changed. `docs/DECISIONS.md` gives the reasoning under the same numbers.

| Decision | Change | Sections |
|---|---|---|
| Name | The product is Veridex: package, schema, CLI and environment variables. | all |
| D1 | Integrity events are Ed25519-signed; verifiers pin public keys outside the database. The first draft let anyone with database access extend a chain. | 4, 5, 10, 11, 19, 21, 27, 54, 55, 56, 69 |
| D2 | One global, gap-free log chain in addition to per-record chains. Per-record chains cannot reveal deleted newest events. | 5, 19, 21, 57 |
| D3 | A direct SQL DELETE is `TAMPERED`, not `DELETED`. The first draft made an attack look like a legitimate deletion. | 23, 54 |
| D4 | Configuration changes are signed `CONFIGURE` events in the same log. | 15, 19 |
| D5 | `record()` hashes the row as read back from the database, not the object passed in. | 25 |
| D6 | A DELETE event carries the previous record hash. | 23 |
| D7 | Floating-point values are refused. | 12 |
| D8 | Events are written in the application's transaction; the integrity schema lives in the same database. | 16, 24, 59 |
| D9 | `TAMPERED` is reported without waiting for an anchor; `VERIFIED` never is. | 37 |
| D10 | Stage 1 uses a file of signed checkpoints as a development anchor, so VERIFIED always has external evidence. | 64 |
| D11 | The Python SDK is synchronous for now. | 25, 46 |
| D12 | The TypeScript package implements the protocol only, so far. | 14, 25, 45 |
| D13 | A checkpoint is the RFC 6962 Merkle root of one batch; no background scheduler. | 28, 29 |
| D14 | Merkle proofs do not replace the full-log audit for record verification. | 30, 36, 57 |
| D15 | The batching process refuses to anchor a log that fails its checks. | 28, 54, 69 |
| D16 | The contract is write-once, sequential, per-publisher and ownerless, and also stores the last sequence number. The anchor interface is `publish` / `checkpoints`. | 32, 33, 35 |
| D17 | Batches on a blockchain are authenticated by the pinned publisher account; batches in a file anchor by a signature. | 27, 32, 33 |
| D18 | On Base, verification reads finalized blocks. | 35 |
| D19 | Verifiers may pin the log id. | 59 |
| D20 | No `proofs` table; `batches` is a convenience copy. | 16, 61 |

Not changed, still open: MySQL (section 44) remains a V1 goal although deferring it is recommended; the portable proof bundle (sections 39–40) and the full TypeScript SDK (sections 41, 45) are specified but not built.
