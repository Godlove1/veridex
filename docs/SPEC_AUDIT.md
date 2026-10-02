# Spec audit

The code compared with [veridex_v1.md](../veridex_v1.md), section by section.
Audited on 2026-10-02 against the working tree that adds stages 4–6.

**Legend.** Done: built and covered by a test that ran. Partial: some of it is
built. Not built. Departs: built differently on purpose (see
[DECISIONS.md](DECISIONS.md)). n/a: product or positioning text with nothing to
implement.

**What "tested" means here.** Python against PostgreSQL 18 and a local Anvil
chain, and the TypeScript package, on one Windows machine. The CI workflow was
edited but has not run. Nothing was run against Supabase, Neon, Base Sepolia or
Base mainnet.

## The gaps that matter

| # | Gap | Spec | Why it matters |
|---|---|---|---|
| 1 | Never run against Base (Sepolia or mainnet) | §31, §35, §63.10 | A V1 success criterion. Needs a funded account, so it is yours to run. The adapter is only proven on Anvil. |
| 2 | Supabase and Neon untested | §43, §63.3 | A V1 success criterion. Likely risk: their transaction-mode poolers and psycopg's automatic prepared statements. |
| 3 | No portable proof bundle or independent verifier | §39, §40, §63.15 | Stage 7. Inclusion proofs exist, but nothing packages one with the anchor reference and verifies it without the database. |
| 4 | TypeScript has no database adapter and no `protect / record / verify` | §41, §45, §63.16 | TypeScript can check hashes, signatures, Merkle proofs and an exported log, but cannot be used as an SDK. |
| 5 | No MySQL | §44, stage 3 | Listed as a V1 goal. Recommended to defer; needs your decision. |
| 6 | Verifying a record still reads the whole log | §36, §57 | Sound, but O(total events) per audit. Fixing it needs a per-record head commitment (D14). |
| 7 | Python API is synchronous | §25, §46 | The spec's examples use `await`. |
| 8 | No framework or provider examples | §47–§50 | FastAPI, Next.js, Supabase and Neon examples are listed deliverables. |
| 9 | Integrity tables live in the same database as the data | §4, §59 | `INTEGRITY_DATABASE_URL` (a separate evidence database) is not supported; it conflicts with same-transaction recording (D8). |
| 10 | No license | §62 | Blocks open-sourcing; the contract carries `UNLICENSED`. |

Smaller ones: no `transaction_reference` on events (§19); `protected_resources`
lacks `database_type`, `status` and `created_at` (§17); no database adapter
interface is written down, only the PostgreSQL adapter's shape (§8); no scan
for rows that were never recorded; no key revocation (a key in `trusted_keys`
is trusted for the whole log); the publisher sends one transaction at a time
with the node's default fees and does not replace a stuck one; packages are not
published to PyPI or npm; the `anvil` service in `docker-compose.yml` is untested.

## Section by section

| § | Topic | Status | Notes |
|---|---|---|---|
| 1 | Product definition | Done | Business tables untouched; detects, does not prevent. |
| 2 | Core problem | n/a | |
| 3 | Security model | Done | Database → integrity engine → hash chains + Merkle batches → chain. |
| 4 | Separate integrity metadata | Partial | Own schema (`veridex`), same database (gap 9). The anchor is the external boundary. |
| 5 | V1 goals | Partial | Missing: MySQL, tested managed PostgreSQL, full TypeScript SDK, portable proofs, a run on Base. Everything else is built. |
| 6 | Non-goals | Done | None of them was built. |
| 7 | Positioning | n/a | README uses the recommended framing. |
| 8 | Architecture principles | Partial | Protocol-first, framework-, chain- and provider-independent: yes. Database-independent: the core only calls an adapter, but one adapter exists and its interface is implicit. |
| 9 | High-level architecture | Partial | As drawn, minus MySQL and the TypeScript SDK layer. |
| 10 | Protocol layer | Partial | All defined in `protocol/SPEC.md` except the portable proof format. |
| 11 | SHA-256, stated in metadata | Done | In every configuration body and proof. |
| 12 | Canonicalization | Done | VCF-1 plus value normalization. Floats are refused (D7). A missing protected column is `TAMPERED / SCHEMA_CHANGED`. |
| 13 | Cross-language vectors | Done | Canonical form, records, config, log, checkpoint, Merkle. Python and TypeScript both pass. |
| 14 | Protected resources | Done | `vx.protect("payments", [...])`. |
| 15 | Configuration is protected | Done | Signed `CONFIGURE` events (D4); `test_08*`. |
| 16 | Integrity schema | Departs | `log_head`, `events`, `configurations`, `protected_resources`, `batches`. No `proofs` table (D20). |
| 17 | Protected resources table | Partial | A convenience list; the signed configuration is authoritative. Fewer columns than sketched. |
| 18 | Configuration table | Done | Stores the canonical body and its hash; the sketched columns are inside the body. |
| 19 | Events | Departs | Adds `seq`, `prev_log_hash`, `key_id`, `signature` (D1, D2). No `transaction_reference`. |
| 20 | Record hash | Done | |
| 21 | Hash chain | Departs | Per-record chain plus a global chain (D2). No free-form `metadata` in the event hash. |
| 22 | Legitimate updates | Done | `test_02`. |
| 23 | DELETE events | Done | Keeps the last attested state (D6); `test_04b`. |
| 24 | Transaction semantics | Done | Same transaction, savepoint (D8); `test_10*`. PostgreSQL only. |
| 25 | Event capture | Departs | Explicit `record()`, synchronous, and the row is re-read from the database (D5). |
| 26 | Direct modification | Done | `test_03`, on both anchors. |
| 27 | Event store security | Partial | Append-only triggers and `sql/roles.sql`. Separation of credentials is documented, not enforced. The CLI loads the chain key only for `checkpoint`. |
| 28 | Merkle batching | Done | 5,000 events or 5 minutes, configurable. No built-in scheduler: run `checkpoint --if-due` from cron (D13). |
| 29 | Merkle tree | Done | RFC 6962 with domain separation; all five listed points specified (`protocol/SPEC.md` §8). |
| 30 | Merkle proof | Done | `inclusion_proof()`, `prove()`, `verify_inclusion` in both languages. |
| 31 | Base | Partial | `EvmAnchor.base()`; never run against Base (gap 1). |
| 32 | Blockchain adapter interface | Departs | `publish()` / `checkpoints()`; root comparison lives in the core (D16). |
| 33 | Smart contract | Done | Root, last seq, timestamp, per publisher; write-once; no data on-chain (`test_only_commitments_reach_the_chain`). |
| 34 | Local blockchain development | Partial | Anvil works. No MySQL. The compose service for Anvil is untested. |
| 35 | Environments | Partial | Local tested. Base Sepolia and mainnet are configuration only. Keys come from the environment. |
| 36 | Verification workflow | Departs | All twelve steps happen, inside a full-log audit instead of a per-record lookup (D14). |
| 37 | Verification states | Done | All eight. |
| 38 | Blockchain failure | Done | `ANCHOR_FAILED` / `PENDING_ANCHOR`, never `VERIFIED`; `test_09*`. |
| 39 | Portable proof format | Not built | `prove()` returns an inclusion proof; the bundle format is stage 7. |
| 40 | Independent verification | Partial | TypeScript verifies an exported log and Merkle proofs offline. No bundle verifier. |
| 41 | Language SDKs | Partial | Python: yes. TypeScript: protocol only (gap 4). |
| 42 | Framework independence | Done | Dependencies: `cryptography`, `psycopg`; `web3` only for the chain anchor. |
| 43 | PostgreSQL compatibility | Partial | One adapter, standard SQL. Only self-hosted PostgreSQL tested (gap 2). |
| 44 | MySQL | Not built | Gap 5. |
| 45 | TypeScript API | Not built | Gap 4. |
| 46 | Python API | Departs | `Veridex(database=, trusted_keys=, signer=, anchor=)`; synchronous. |
| 47 | FastAPI example | Not built | |
| 48 | Supabase example | Not built | |
| 49 | Neon example | Not built | |
| 50 | AI-assisted development | Partial | Machine-readable results and error codes, protocol document, attack tests. No integration examples. |
| 51 | Future MCP interface | n/a | Not built, as specified. Everything is reachable through the public API. |
| 52 | Repository structure | Departs | Flatter: `protocol/`, `python/`, `typescript/`, `contracts/`, `examples/`, `docs/`, `sql/`. |
| 53 | CLI | Done | `init protect verify history proof checkpoint status audit keygen deploy-anchor`. `batch` and `anchor` are one command, `checkpoint`. |
| 54 | Security test suite | Done | Tests 1–3 and 5–10 as specified; test 4 departs (direct delete is `TAMPERED`, D3). |
| 55 | Attack model | Done | Each line has a test; see THREAT_MODEL.md. |
| 56 | Security limitation | Done | Documented in THREAT_MODEL.md, including what the spec did not list (RPC trust, publisher key). |
| 57 | Performance | Partial | No per-operation chain transaction. One event writer at a time (D2). Audit is O(n) (gap 6). |
| 58 | Failure handling | Done | Recording continues while the anchor is down (`test_09b`). Recorded, anchored and verified are separate states. |
| 59 | Configuration | Departs | `VERIDEX_*` names. No separate integrity database URL (gap 9). |
| 60 | Developer experience | Done | No Solidity needed: the compiled contract ships with the SDK. |
| 61 | Example product flow | Partial | Works on self-hosted PostgreSQL with Anvil. Supabase and Base untested. |
| 62 | Open source / hosted | n/a | License undecided (gap 10). |
| 63 | Success criteria | Partial | Met: 1, 2, 4–9, 11–14, 17. Not met: 3 (untested), 10 (Base), 15 (portable proof), 16 (TypeScript runs the protocol but is not an SDK). |
| 64 | Implementation stages | Partial | See below. |
| 65 | Future work | n/a | |
| 66 | Future MCP architecture | n/a | |
| 67 | Application truth vs evidence | Done | |
| 68 | Terminology | Done | No unsupported claims in the README or docs. |
| 69 | Coding-agent instructions | Done | Every security-relevant ambiguity is recorded in DECISIONS.md. |
| 70 | First implementation goal | Done | `examples/demo.py`. |
| 71 | Protect. Record. Verify. | Done | |

## Stages (§64)

| Stage | Status | Evidence |
|---|---|---|
| 1 Protocol | Done | `test_protocol.py`, shared vectors |
| 2 PostgreSQL | Partial | `test_security.py`; Supabase and Neon untested |
| 3 MySQL | Not built | |
| 4 Merkle trees | Done | `test_batching.py`, Merkle vectors in both languages |
| 5 Local blockchain | Done | `test_evm_anchor.py` on Anvil |
| 6 Base | Partial | Preset and CLI exist; no deployment, no run against Base |
| 7 Portable proofs | Not built | |
| 8 CLI | Done | `test_cli.py` |
| 9 SDKs | Partial | Python sync; TypeScript protocol only |
| 10 Security suite | Done for what exists | 69 Python tests, 10 TypeScript tests |

## Found during this audit and fixed

- Dropping a protected column or table made `verify()` raise a database driver
  error. It now returns `TAMPERED / SCHEMA_CHANGED`.
- The TypeScript cross-check test failed on Windows (file path used as a module
  specifier).
- The checkpointer would anchor events without checking them. With a write-once
  anchor that could make a forged event's failure permanent; it now refuses (D15).
- Replacing the whole evidence log read as "not anchored yet" on a blockchain
  anchor. Verifiers can now pin the log id (D19).
- The roadmap claimed Merkle batching would remove the full-log audit. It does
  not (D14); the README and protocol document are corrected.
