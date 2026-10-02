# Threat model

Veridex detects changes to protected rows that are inconsistent with signed,
externally anchored evidence. It does not prevent changes. It is only as strong
as the separation between three things:

1. **the database** (business rows + the `veridex` evidence tables),
2. **the signing key** (held by whatever process calls `record()`),
3. **the anchor** (where batch Merkle roots are published), and for a blockchain
   anchor the **publisher account key** that pays for and sends the roots.

A verifier needs none of the secrets. It pins, outside the database: the trusted
public keys, and for a blockchain anchor the chain id, contract address and
publisher address. Optionally the log id.

## What is detected

| Attacker can… | Result | Test |
|---|---|---|
| UPDATE a protected row directly | `TAMPERED / STATE_MISMATCH` | `test_03_*` |
| DELETE a protected row directly | `TAMPERED / RECORD_MISSING` | `test_04_*` |
| drop a protected column or the whole table | `TAMPERED / SCHEMA_CHANGED` | `test_dropped_column_or_table_*` |
| re-insert a legitimately deleted row | `TAMPERED / RECORD_RESURRECTED` | `test_04c_*` |
| edit an evidence event | `INVALID_PROOF / EVENT_HASH_MISMATCH` | `test_05_*` |
| edit an event and recompute its hash | `INVALID_PROOF / BAD_SIGNATURE` | `test_05b_*` |
| append a forged, perfectly chained event | `INVALID_PROOF / BAD_SIGNATURE` | `test_forged_update_*` |
| roll a record back and delete anchored events | `INVALID_PROOF / CHECKPOINT_MISMATCH` | `test_rollback_attack_*`, `test_rollback_of_anchored_history_*` |
| truncate the log after a checkpoint | `INVALID_PROOF` | `test_log_truncation_*` |
| re-sign a different event in place **with the signing key** | `INVALID_PROOF / CHECKPOINT_MISMATCH` | `test_rewriting_an_event_inside_an_old_batch_*` |
| alter a Merkle inclusion proof | proof does not verify | `test_06_modified_merkle_proof_*` |
| edit a checkpoint in a file anchor | `INVALID_PROOF / CHECKPOINT_INVALID` | `test_06_tampered_checkpoint_*` |
| add a conflicting or out-of-order batch to a file anchor | `INVALID_PROOF / CHECKPOINT_INVALID` | `test_conflicting_or_skipped_batches_*` |
| anchor a root the database does not produce | `INVALID_PROOF / CHECKPOINT_MISMATCH` | `test_07_*` |
| write batches to the contract from another account | ignored | `test_batches_from_another_account_*` |
| overwrite, reorder or skip a batch on-chain | transaction reverts | `test_anchored_batches_are_write_once_*` |
| get a forged event anchored by the checkpointer | checkpointer refuses, anchor untouched | `test_checkpoint_refuses_*` |
| swap the whole evidence log for a fresh one | `INVALID_PROOF / LOG_ID_MISMATCH` (if the verifier pins the log id) | `test_pinned_log_id_*` |
| shrink the protected field list | `CONFIGURATION_ERROR`, and `record()` refuses to write | `test_08_*` |
| make the anchor unreachable, or point the verifier at another chain or contract | `ANCHOR_FAILED`, never `VERIFIED` | `test_09_*`, `test_wrong_chain_*` |

Attackers here are database superusers who also disable the append-only triggers.

## What is NOT detected (read this)

**1. The unanchored tail.** Events written after the last checkpoint are protected
only by the database. An attacker with DB access can delete them and revert the
row, and the older anchored state verifies as `VERIFIED`
(`test_known_limitation_unanchored_tail_can_be_rolled_back`). Exposure window =
checkpoint interval, plus finality time on a blockchain anchor. Checkpoint
frequently.

**2. A stolen signing key.** Whoever holds the key can write events that verify.
If the key lives in the same application process that holds DB credentials, an
application-server compromise defeats Veridex for all future events. Past
anchored events remain protected: even with the key, changing one breaks an
anchored Merkle root. Mitigation: run `record()` in a separate service; rotate
keys (trusted keys are a list).

**3. A stolen publisher account key.** It cannot change or remove anchored
batches (the contract has no such function). It can append a batch with a wrong
root, which makes verification report `INVALID_PROOF` from then on, and it can
spend the account's funds. With the signing key **and** database access as well,
the attacker controls every trust boundary; see 9.

**4. Lies told through the front door.** If the application itself is
compromised and records a malicious change via `record()`, Veridex faithfully
attests it. Veridex proves "this is what the integrity writer saw", not "this
change was right".

**5. Rows that were never recorded.** A row inserted directly via SQL has no
evidence: `UNVERIFIED`. Veridex does not yet scan tables for untracked rows.

**6. Verification on demand only.** Tampering is found when someone runs
`verify()` or `audit()`. There is no continuous monitor yet.

**7. A file anchor on the same machine.** `FileAnchor` is a real trust boundary
only if the file is somewhere the DB attacker cannot write (another host,
object-lock/WORM storage). Next to the database it is a development
convenience, not a security control.

**8. A lying RPC endpoint.** The verifier believes what its JSON-RPC endpoint
says about the chain. An attacker who controls that endpoint can serve roots
that were never anchored. Use an endpoint the database attacker does not
control: your own node, or a provider reached over TLS, ideally more than one.

**9. Everything at once.** An attacker holding the database, the signing key
and the publisher key can build and anchor a consistent false history going
forward. History anchored before the compromise still cannot be rewritten.

**10. Trusted keys and pins must come from outside the database.** If the
verifier reads public keys, the publisher address or the log id from the
protected database, an attacker swaps them. Veridex never reads them from the
database; pass them in configuration. A verifier that does not pin the log id
sees a swapped evidence log as "not anchored yet", not as tampering.

## On-chain privacy

The chain receives, per batch: a hash of the log id, the batch number, the last
sequence number and a Merkle root. No table names, record ids, field values or
event contents (`test_only_commitments_reach_the_chain`). Sequence numbers do
reveal how many protected changes happened between two batches.

## Correct claim

> Unauthorized changes to protected fields are detected when they conflict with
> signed evidence covered by an independently anchored Merkle root.

Not: tamper-proof, unhackable, immutable.
