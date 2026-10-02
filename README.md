# Veridex

Tamper-evident integrity evidence for the PostgreSQL database you already have.

Veridex records signed, hash-chained evidence of every protected change, batches
it into Merkle trees, anchors each root outside the database (a smart contract
on Base, or a file in development), and tells you when a row no longer matches
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

> **Status: stages 1, 2, 4, 5 and 6 of the V1 spec** (protocol, PostgreSQL,
> Merkle batching, the anchor contract on a local chain, the Base adapter).
> Not production-ready. Nothing has been deployed to or tested against Base
> itself, and Supabase/Neon are untested. No MySQL, no portable proof bundle.
> Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before trusting it with
> anything; [docs/SPEC_AUDIT.md](docs/SPEC_AUDIT.md) lists what is and is not
> built, section by section.

## Quick start

```bash
docker compose up -d
pip install -e "./python[dev,evm]"
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
result.to_dict()       # machine-readable, includes reason codes, batch and Merkle root
vx.prove("payments", 123)   # Merkle inclusion proof of the record's latest event
```

Framework-free: works the same under FastAPI, Django, Flask or a script.

## Anchor on a blockchain

`pip install "veridex[evm]"`. The anchor is one small contract,
[VeridexAnchor.sol](contracts/src/VeridexAnchor.sol); its compiled bytecode
ships with the SDK, so you do not need Solidity or Foundry to use it. Only a
Merkle root and two numbers per batch go on-chain, never your data.

```python
from veridex.evm import EvmAnchor

# Local development: start `anvil`, then
address = EvmAnchor.deploy("http://127.0.0.1:8545", os.environ["VERIDEX_EVM_PRIVATE_KEY"])
anchor = EvmAnchor.anvil(address, private_key=os.environ["VERIDEX_EVM_PRIVATE_KEY"])

# Base (network="sepolia" for the test network). The process that checkpoints:
anchor = EvmAnchor.base(rpc_url, address, private_key=os.environ["VERIDEX_EVM_PRIVATE_KEY"])
# A verifier holds no secrets. It pins the contract and the publishing account:
anchor = EvmAnchor.base(rpc_url, address, publisher="0xYourPublisherAddress")
```

Pass it as `anchor=`; nothing else changes. On Base a batch counts once its
block is finalized; until then records are `PENDING_ANCHOR`. Deploying and
anchoring send transactions that cost gas, paid by the publishing account.

## CLI

```bash
veridex keygen                                  # prints signing key + public key
export VERIDEX_DATABASE_URL=… VERIDEX_SIGNING_KEY=… VERIDEX_ANCHOR_FILE=…
veridex init                                    # prints the log id; set VERIDEX_LOG_ID to pin it
veridex protect payments id,amount,currency,recipient,status
veridex checkpoint                              # batch the waiting events, anchor the Merkle root
veridex checkpoint --if-due                     # for cron: only at 5,000 events or 5 minutes
veridex verify payments 123                     # exit code 0 = VERIFIED/DELETED, 1 = anything else
veridex proof payments 123                      # Merkle inclusion proof, JSON
veridex history payments 123
veridex audit --json                            # verify the whole evidence log
veridex status
```

For a blockchain anchor, replace `VERIDEX_ANCHOR_FILE` with:

```bash
export VERIDEX_EVM_RPC_URL=… VERIDEX_EVM_CHAIN_ID=8453     # 31337 Anvil, 84532 Base Sepolia
export VERIDEX_EVM_PRIVATE_KEY=…                           # checkpoint and deploy-anchor only
veridex deploy-anchor                                      # once; prints contract and publisher
export VERIDEX_EVM_CONTRACT=0x… VERIDEX_EVM_PUBLISHER=0x…  # verifiers need only these two
```

All variables are listed at the top of [cli.py](python/veridex/cli.py).

## How it works

- **Canonical form (VCF-1)** and **value normalization** make the same row hash
  identically in Python and TypeScript. Floats are refused.
- **Events** (`CONFIGURE`, `CREATE`, `UPDATE`, `DELETE`) are domain-separated
  SHA-256 hashes, **Ed25519-signed**, chained per record *and* globally.
- **Checkpoints** turn the events since the last one into a **Merkle tree**
  (RFC 6962) and publish its signed root to an **anchor** outside the DB. The
  anchor is write-once.
- **Verification** recomputes the whole log, checks signatures against pinned
  keys and every anchored root against the events, then compares the live row
  to the latest event. `VERIFIED` is never returned for unanchored evidence.
- **Inclusion proofs** show that a single event is under an anchored root
  without the rest of the log.

Full protocol: [protocol/SPEC.md](protocol/SPEC.md).
Why it departs from the original spec: [docs/DECISIONS.md](docs/DECISIONS.md).

## Repository

```
protocol/      SPEC.md + shared cross-language test vectors
python/        reference SDK: core, PostgreSQL adapter, anchors, CLI, tests
typescript/    protocol package: canonicalization, hashing, signatures, Merkle, offline log verification
contracts/     VeridexAnchor.sol (Foundry project) + build script for the SDK artifact
examples/      demo.py
docs/          THREAT_MODEL.md, DECISIONS.md, SPEC_AUDIT.md
sql/roles.sql  recommended privilege separation
veridex_v1.md  product and technical specification
```

## Tests

```bash
docker compose up -d
anvil &                      # optional; the blockchain tests are skipped without it
export VERIDEX_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
pytest python/tests
cd typescript && npm install && npm test && npm run typecheck
```

The Python suite runs every attack in the threat model against a real
PostgreSQL as a superuser with triggers disabled, the anchor contract on a real
local chain, and a live check that the TypeScript code verifies a log written
by Python.

After changing the contract: `forge build --root contracts && python contracts/build.py`.

## Roadmap (spec stages)

- [x] 1 Protocol, hashing, chains, config versioning, test vectors
- [x] 2 PostgreSQL adapter (self-hosted tested; Supabase/Neon not yet tested)
- [ ] 3 MySQL — recommended to defer
- [x] 4 Merkle batching + inclusion proofs (the full-log audit stays, see DECISIONS D14)
- [x] 5 Solidity anchor contract + Anvil
- [ ] 6 Base — adapter and CLI done; not yet deployed or run against Base Sepolia or mainnet
- [ ] 7 Portable proof bundle + independent verifier
- [x] 8 CLI (basic)
- [ ] 9 TypeScript PostgreSQL adapter; async Python API
- [x] 10 Security suite (for what exists)

## License

Not yet chosen.
