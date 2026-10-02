# Veridex

Tamper-evident integrity evidence for the PostgreSQL database you already have.

Veridex records signed, hash-chained evidence of every protected change, anchors
the log head outside the database, and tells you when a row no longer matches
that evidence. Your business tables are untouched; evidence lives in its own
`veridex` schema.

```
  1. recorded, not yet anchored                  -> PENDING_ANCHOR (NOT_ANCHORED)
  2. after checkpoint to external anchor         -> VERIFIED
  3. legitimate update through the app           -> VERIFIED
  4. attacker: UPDATE ... SET amount = 9999999   -> TAMPERED (STATE_MISMATCH)
  5. attacker: DELETE FROM demo_payments         -> TAMPERED (RECORD_MISSING)
```
*(real output of `examples/demo.py`)*

> **Status: Stage 1 of the V1 spec** (protocol + PostgreSQL + verification) plus
> signed events and checkpoints. Not production-ready. No blockchain, Merkle
> batching, MySQL, or portable proof bundle yet. Read
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before trusting it with anything.

## Quick start

```bash
docker compose up -d
pip install -e "./python[dev]"
python examples/demo.py
```

## Use it

```python
import os, psycopg
from veridex import Veridex, Signer, FileAnchor
from veridex.adapters import PostgresAdapter

vx = Veridex(
    database=PostgresAdapter(os.environ["DATABASE_URL"]),   # Supabase, Neon, RDS… all plain PostgreSQL
    signer=Signer.from_seed_hex(os.environ["VERIDEX_SIGNING_KEY"]),
    trusted_keys=os.environ["VERIDEX_TRUSTED_KEYS"].split(","),  # pinned out-of-band, never read from the DB
    anchor=FileAnchor("/mnt/worm/veridex-anchor.jsonl"),         # must be outside the DB attacker's reach
)
vx.init()
vx.protect("payments", ["id", "amount", "currency", "recipient", "status"])

with conn.transaction():                       # your existing transaction
    conn.execute("UPDATE payments SET amount = %s WHERE id = %s", (150, 123))
    vx.record("payments", "UPDATE", record={"id": 123}, conn=conn)   # rolls back with it

vx.checkpoint()                                # run on a schedule: this is your exposure window
result = vx.verify("payments", 123)
result.status          # Status.VERIFIED | TAMPERED | DELETED | PENDING_ANCHOR | INVALID_PROOF | ...
result.to_dict()       # machine-readable, includes reason codes
```

Framework-free: works the same under FastAPI, Django, Flask or a script.

## CLI

```bash
veridex keygen                                  # prints signing key + public key
export VERIDEX_DATABASE_URL=… VERIDEX_SIGNING_KEY=… VERIDEX_ANCHOR_FILE=…
veridex init
veridex protect payments id,amount,currency,recipient,status
veridex checkpoint
veridex verify payments 123                     # exit code 0 = VERIFIED/DELETED, 1 = anything else
veridex history payments 123
veridex audit --json                            # verify the whole evidence log
veridex status
```

## How it works

- **Canonical form (VCF-1)** and **value normalization** make the same row hash
  identically in Python and TypeScript. Floats are refused.
- **Events** (`CONFIGURE`, `CREATE`, `UPDATE`, `DELETE`) are domain-separated
  SHA-256 hashes, **Ed25519-signed**, chained per record *and* globally.
- **Checkpoints** sign the global log head and go to an **anchor** outside the DB.
- **Verification** recomputes the whole log, checks signatures against pinned
  keys and checkpoints, then compares the live row to the latest event.
  `VERIFIED` is never returned for unanchored evidence.

Full protocol: [protocol/SPEC.md](protocol/SPEC.md).
Why it departs from the original spec: [docs/DECISIONS.md](docs/DECISIONS.md).

## Repository

```
protocol/      SPEC.md + shared cross-language test vectors
python/        reference SDK: core, PostgreSQL adapter, CLI, tests (39)
typescript/    protocol package: canonicalization, hashing, signatures, offline log verification
examples/      demo.py
docs/          THREAT_MODEL.md, DECISIONS.md
sql/roles.sql  recommended privilege separation
```

## Tests

```bash
docker compose up -d
VERIDEX_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest python/tests
cd typescript && npm install && npm test && npm run typecheck
```

The Python suite runs every attack in the threat model against a real
PostgreSQL as a superuser with triggers disabled, plus a live check that the
TypeScript code verifies a log written by Python.

## Roadmap (spec stages)

- [x] 1 Protocol, hashing, chains, config versioning, test vectors
- [x] 2 PostgreSQL adapter (self-hosted tested; Supabase/Neon not yet tested)
- [ ] 3 MySQL — recommended to defer
- [ ] 4 Merkle batching + inclusion proofs (removes O(n) audit)
- [ ] 5 Solidity anchor contract + Anvil
- [ ] 6 Base
- [ ] 7 Portable proof bundle + independent verifier
- [x] 8 CLI (basic)
- [ ] 9 TypeScript PostgreSQL adapter; async Python API
- [x] 10 Security suite (for what exists)

## License

Not yet chosen.
