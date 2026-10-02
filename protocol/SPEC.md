# Veridex Protocol v1

Status: implemented by `python/veridex` (reference) and `typescript/src` (protocol only).
Any change that alters an existing test vector is a protocol break and requires a
new `v` on the object it changes. So far: checkpoints are `v: 2` (section 7).

Key words MUST / MUST NOT are normative.

---

## 1. Overview

Veridex keeps a **single, global, signed, hash-chained event log** per database.
Every protected state change (and every protection-configuration change) is one
event. Periodically the events recorded since the last checkpoint form a
**batch**; the **Merkle root** of the batch is signed and published to an
**anchor** outside the database (a checkpoint). Verification recomputes
everything from the log, checks it against trusted public keys and the anchored
roots, then compares the current business row against the latest event for that
record.

```
event_1 ─► event_2 ─► event_3 ─► event_4 ─► event_5 ─► …   (prev_log_hash chain, global)
   │          │          │          │          │
   └─ per-record chain via prev_event_hash + version
└──────── batch 1 ───────┘└────── batch 2 ─────┘
        Merkle root 1            Merkle root 2
             │                        │
   checkpoint{batch:1, seq:3}   checkpoint{batch:2, seq:5}   ──►  anchor
```

Three independent properties, three mechanisms:

| Property | Mechanism |
|---|---|
| An event was not altered | event hash + Ed25519 signature |
| An event was written by the integrity writer, not a DB attacker | signature by a key the verifier pins out-of-band |
| The log was not truncated or rewritten up to seq N | global hash chain + externally anchored Merkle roots covering 1..N |
| One event belongs to the anchored log, shown without the rest of the log | Merkle inclusion proof against an anchored root |

## 2. Canonical form (VCF-1)

Input is a tree of: string, integer, boolean, null, array, object (string keys).

- **null / true / false** → `null`, `true`, `false`.
- **Integers** → shortest decimal form, no sign for zero, no leading zeros.
  MUST satisfy `|n| ≤ 2^53 − 1`; otherwise rejected (encode as a string).
- **Non-integer numbers** (floats, NaN, ±Infinity) → MUST be rejected.
- **Strings** → NFC-normalized, then written as `"` + escaped content + `"`:
  - `"` → `\"`, `\` → `\\`, U+0008 `\b`, U+0009 `\t`, U+000A `\n`, U+000C `\f`, U+000D `\r`
  - other U+0000–U+001F → `\u00xx` (lowercase hex)
  - every other code point (including U+007F, `/`, non-ASCII) → raw UTF-8
  - strings with unpaired surrogates MUST be rejected.
- **Arrays** → `[` + elements joined by `,` + `]`, order preserved.
- **Objects** → keys NFC-normalized; sorted by **UTF-8 byte order**; duplicate keys
  after normalization MUST be rejected; `{"k":v,...}` with no whitespace.
- Nesting deeper than 64 levels MUST be rejected.
- Output bytes are the UTF-8 encoding of the resulting string.

Known risk: NFC tables differ across Unicode versions. Characters assigned after
the oldest supported runtime's Unicode version may normalize differently.

## 3. Value normalization (database → VCF-1)

Applied to every protected column value before canonicalization. This is where
cross-language drift actually happens (drivers return different native types).

| Column value | Normalized |
|---|---|
| NULL | `null` |
| boolean | boolean |
| integer, `|n| ≤ 2^53−1` | integer |
| integer outside safe range (e.g. large BIGINT) | decimal string |
| NUMERIC / DECIMAL | fixed-point string, scale preserved (`5000.00`); NaN/Inf rejected |
| REAL / DOUBLE | **rejected** (not deterministic across languages) |
| TIMESTAMPTZ | UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (always 6 fraction digits) |
| TIMESTAMP (no tz) | `YYYY-MM-DDTHH:MM:SS.ffffff` (no `Z`) |
| DATE | `YYYY-MM-DD` |
| TIME | `HH:MM:SS.ffffff`; TIME WITH TIME ZONE rejected |
| UUID | lowercase hyphenated string |
| BYTEA / BLOB | `0x` + lowercase hex |
| arrays | arrays of normalized values |
| JSON / JSONB | object/array of normalized values (floats inside rejected) |
| text / char | string as returned by the driver (CHAR padding included) |

**Record id**: single-column key → the normalized value as a string;
composite key → the VCF-1 canonical array of normalized values.

## 4. Hashing

SHA-256 with domain separation. For tag `t` and value `v`:

```
H(t, v) = lowercase_hex( SHA256( "veridex/v1/" || t || 0x00 || VCF-1(v) ) )
```

Tags: `record`, `config`, `event`, `checkpoint`, `log`. A hash of one type can
never be presented as a hash of another type. Merkle leaves and nodes use their
own prefixes over raw bytes (section 8).

- `record_hash = H("record", {field: normalized_value, …})` over the protected fields only.

## 5. Configuration

```json
{ "v": 1, "resource": "public.payments", "schema": "public", "table": "payments",
  "primary_key": ["id"], "fields": ["amount","currency","id","recipient","status"],
  "version": 1, "prev_config_hash": null,
  "canonicalization": "vcf-1", "hash_algorithm": "SHA-256" }
```

`fields` is sorted and de-duplicated. `config_hash = H("config", body)`.
A configuration is only valid if a signed `CONFIGURE` event in the log carries
its `config_hash`. Configuration versions form a chain via `prev_config_hash`
and via the `CONFIGURE` events' `prev_event_hash`.

## 6. Events

```json
{ "v": 1, "seq": 42, "op": "UPDATE", "resource": "public.payments",
  "record_id": "123", "version": 3,
  "record_hash": "…", "prev_event_hash": "…", "prev_log_hash": "…",
  "config_hash": "…", "created_at": "2026-10-02T08:34:00.000000Z" }
```

- `event_hash = H("event", body)`; `signature = Ed25519(sk, bytes(event_hash))`
  (the 32 raw hash bytes are signed). Stored with `key_id`.
- `key_id = first 16 hex chars of SHA256(raw 32-byte public key)`.
- `seq` starts at 1 and MUST be gap-free.
- `prev_log_hash` = `event_hash` of `seq − 1`; for `seq = 1`, 64 zeros.
- `op ∈ {CONFIGURE, CREATE, UPDATE, DELETE}`.

Rules a verifier MUST enforce:

| op | record_id / record_hash | prev_event_hash | version | allowed after |
|---|---|---|---|---|
| CONFIGURE | null / null | previous CONFIGURE of same resource, else null | prev + 1, else 1 | anything |
| CREATE | set / hash of row | previous event of same record, else null | prev + 1, else 1 | nothing, or DELETE |
| UPDATE | set / hash of row | previous event of same record | prev + 1 | CREATE or UPDATE |
| DELETE | set / **equal to previous record_hash** | previous event of same record | prev + 1 | CREATE or UPDATE |

Record events MUST carry the `config_hash` of the latest `CONFIGURE` event for
their resource at that point in the log.

## 7. Batches and checkpoints

A **batch** is a contiguous run of events. Batch 1 starts at `seq = 1`; batch
`n + 1` starts at the event after the last one of batch `n`. A batch is never
empty. Implementations limit the batch size (default 5,000 events) and anchor a
batch when that many events are waiting or the oldest waiting event is older
than the batch interval (default 5 minutes), whichever comes first.

A **checkpoint** commits to one batch:

```json
{ "v": 2, "log_id": "uuid", "batch": 2, "from_seq": 4, "seq": 5,
  "merkle_root": "<VMT-1 root of event hashes 4..5>", "created_at": "…" }
```

`checkpoint_hash = H("checkpoint", body)`, signed like events.

The commitment an anchor must preserve is `(log_id, batch, seq, merkle_root)`.
`from_seq` is implied by the previous batch and `created_at` is informative.
Because every event hash covers `prev_log_hash`, the root of batch `n` commits
to every event `1..seq`, not only to the events inside the batch.

Rules a verifier MUST enforce on what the anchor returns for a log:

- batches are numbered `1, 2, 3, …` with no gap, and `seq` strictly increases;
- if `from_seq` is present it equals the previous batch's `seq + 1`;
- two different commitments for the same batch number are an error;
- the Merkle root recomputed from the database's events `from_seq..seq` equals
  the anchored root. If not, the log was rewritten or truncated.

An event is **anchored** if it lies in a batch that passes all of these, and
every earlier batch passes too.

`v: 1` checkpoints (stage 1: `{log_id, seq, head}`) carry no Merkle root and
MUST NOT be accepted.

## 8. Merkle tree (VMT-1)

The tree of RFC 6962 / RFC 9162 with Veridex prefixes. Leaves are the event
hashes of one batch, in `seq` order, as raw 32-byte values.

```
leaf(h)    = SHA256( "veridex/v1/merkle-leaf" || 0x00 || h )
node(l, r) = SHA256( "veridex/v1/merkle-node" || 0x00 || l || r )

MTH([h])        = leaf(h)
MTH(D[0:n])     = node( MTH(D[0:k]), MTH(D[k:n]) )     k = largest power of two < n
```

- **Ordering**: by `seq`. Leaves are not sorted or de-duplicated.
- **Odd nodes**: a subtree that is not a power of two is split at `k`; nothing
  is duplicated or padded. `[a, b, c]` and `[a, b, c, c]` have different roots.
- **Duplicates**: cannot occur, since every event hash covers its `seq`.
- **Empty tree**: not defined; a batch has at least one event.
- Leaf and node prefixes differ, so an interior node can never pass as a leaf.

**Inclusion proof.** For the leaf at index `m` of `n` leaves:

```
PATH(m, D[0:1]) = []
PATH(m, D[0:n]) = PATH(m, D[0:k]) + [ MTH(D[k:n]) ]        if m < k
                  PATH(m − k, D[k:n]) + [ MTH(D[0:k]) ]    otherwise
```

Encoded as `{ "leaf_index": m, "tree_size": n, "path": [hex, …] }`, siblings
ordered from the leaf up. Verification is the algorithm of RFC 9162 section
2.1.3.2 with the functions above.

A root does not encode its leaf count. A verifier MUST take the position from
the anchored checkpoint and the event, not from the prover:
`tree_size = seq − from_seq + 1` and `leaf_index = event.seq − from_seq`.

## 9. Anchors

An anchor stores the commitment `(log_id, batch, seq, merkle_root)` per batch,
outside the database, and must not allow a stored batch to change.

**File** (development). Each line is a full signed checkpoint. The file does
not authenticate its writer, so a verifier MUST check each checkpoint's hash
and signature against its trusted keys.

**EVM contract** (`contracts/src/VeridexAnchor.sol`).

```
anchor(bytes32 logKey, uint64 batch, uint64 toSeq, bytes32 merkleRoot)
batchCount(address publisher, bytes32 logKey) → uint256
getBatches(address publisher, bytes32 logKey, uint256 fromBatch, uint256 maxCount)
        → (bytes32 merkleRoot, uint64 toSeq, uint64 timestamp)[]
```

- `logKey = H("log", log_id)` as 32 bytes. The log id itself is not published.
- Batches are stored per `msg.sender`. The contract only accepts batch
  `count + 1` with a larger `toSeq` and a non-zero root, and has no function
  that changes or removes a batch, no owner and no upgrade mechanism.
- A verifier pins **chain id, contract address and publisher address**
  out-of-band and reads only that publisher's batches. The chain authenticates
  the publisher, so no Ed25519 signature is stored on-chain.
- A verifier SHOULD check that the code at the contract address is the
  published VeridexAnchor runtime bytecode, and SHOULD read at a block that is
  final for its purposes (`finalized` on Base).
- Nothing but these four values is ever sent to the chain.

## 10. Verification result

A record is `VERIFIED` only if **all** hold:

1. the whole log passes §6 (hashes, signatures by trusted keys, chains, rules);
2. everything the anchor holds for the log passes §7 (and §9 for its medium);
3. the configuration rows match the signed `CONFIGURE` events;
4. the latest event for the record is not a DELETE, the row exists, and its
   `record_hash` (under the event's configuration) equals the event's;
5. that event is anchored (§7).

Precedence: `INVALID_PROOF` (1, 2) → `CONFIGURATION_ERROR` (3) → `UNVERIFIED`
(no events) → `TAMPERED` (4 fails) → `DELETED` / `VERIFIED` if anchored, else
`PENDING_ANCHOR` (anchor reachable) or `ANCHOR_FAILED` (anchor unreachable).

A verifier that pins a `log_id` MUST report `INVALID_PROOF` if the database
holds a different log.

An inclusion proof (§8) shows that one event is part of the anchored log. It
does not show that the event is the latest one for its record; that needs
conditions 1 and 2 over the whole log.

## 11. Not yet specified (later stages)

Portable proof bundle and its independent verifier (stage 7). A commitment to
per-record heads, which would let a verifier establish "latest event for this
record" without reading the whole log (docs/DECISIONS.md D14).
