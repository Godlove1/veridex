# Threat model

Veridex detects changes to protected rows that are inconsistent with signed,
externally anchored evidence. It does not prevent changes. It is only as strong
as the separation between three things:

1. **the database** (business rows + the `veridex` evidence tables),
2. **the signing key** (held by whatever process calls `record()`),
3. **the anchor** (where checkpoints are published).

## What is detected

| Attacker can… | Result | Test |
|---|---|---|
| UPDATE a protected row directly | `TAMPERED / STATE_MISMATCH` | `test_03_*` |
| DELETE a protected row directly | `TAMPERED / RECORD_MISSING` | `test_04_*` |
| re-insert a legitimately deleted row | `TAMPERED / RECORD_RESURRECTED` | `test_04c_*` |
| edit an evidence event | `INVALID_PROOF / EVENT_HASH_MISMATCH` | `test_05_*` |
| edit an event and recompute its hash | `INVALID_PROOF / BAD_SIGNATURE` | `test_05b_*` |
| append a forged, perfectly chained event | `INVALID_PROOF / BAD_SIGNATURE` | `test_forged_update_*` |
| roll a record back and delete anchored events | `INVALID_PROOF / CHECKPOINT_MISMATCH` | `test_rollback_attack_*` |
| truncate the log after a checkpoint | `INVALID_PROOF` | `test_log_truncation_*` |
| edit a checkpoint in the anchor | `INVALID_PROOF / CHECKPOINT_INVALID` | `test_06_*` |
| shrink the protected field list | `CONFIGURATION_ERROR`, and `record()` refuses to write | `test_08_*` |
| make the anchor unreachable | `ANCHOR_FAILED`, never `VERIFIED` | `test_09_*` |

Attackers here are superusers who also disable the append-only triggers.

## What is NOT detected (read this)

**1. The unanchored tail.** Events written after the last checkpoint are protected
only by the database. An attacker with DB access can delete them and revert the
row, and the older anchored state verifies as `VERIFIED`
(`test_known_limitation_unanchored_tail_can_be_rolled_back`). Exposure window =
checkpoint interval. Checkpoint frequently.

**2. A stolen signing key.** Whoever holds the key can write events that verify.
If the key lives in the same application process that holds DB credentials, an
application-server compromise defeats Veridex for all future events. Past
anchored events remain protected. Mitigation: run `record()` in a separate
service; rotate keys (trusted keys are a list).

**3. Lies told through the front door.** If the application itself is
compromised and records a malicious change via `record()`, Veridex faithfully
attests it. Veridex proves "this is what the integrity writer saw", not "this
change was right".

**4. Rows that were never recorded.** A row inserted directly via SQL has no
evidence: `UNVERIFIED`. Veridex does not yet scan tables for untracked rows.

**5. Verification on demand only.** Tampering is found when someone runs
`verify()` or `audit()`. There is no continuous monitor yet.

**6. The anchor in stage 1 is a file.** `FileAnchor` is a real trust boundary only
if the file is somewhere the DB attacker cannot write (another host,
object-lock/WORM storage). On the same machine as the database it is a
development convenience, not a security control.

**7. Trusted keys must come from outside the database.** If the verifier reads
public keys from the protected database, an attacker swaps them. Veridex never
reads keys from the database; pass them in configuration.

## Correct claim

> Unauthorized changes to protected fields are detected when they conflict with
> signed evidence covered by an independently anchored checkpoint.

Not: tamper-proof, unhackable, immutable.
