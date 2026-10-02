# Veridex Protocol v1

Status: implemented by `python/veridex` (reference) and `typescript/src` (protocol only).
Any change that alters an existing test vector is a protocol break and requires `v: 2`.

Key words MUST / MUST NOT are normative.

---

## 1. Overview

Veridex keeps a **single, global, signed, hash-chained event log** per database.
Every protected state change (and every protection-configuration change) is one
event. The head of the log is periodically **signed and published to an anchor**
outside the database (a checkpoint). Verification recomputes everything from the
log, checks it against trusted public keys and anchored checkpoints, then compares
the current business row against the latest event for that record.

```
event_1 ─► event_2 ─► event_3 ─► … ─► event_n          (prev_log_hash chain, global)
   │          │          │
   └─ per-record chain via prev_event_hash + version
                                         │
                         checkpoint{seq:n, head:hash(event_n)}  ──►  anchor
                                         signed (Ed25519)
```

Three independent properties, three mechanisms:

| Property | Mechanism |
|---|---|
| An event was not altered | event hash + Ed25519 signature |
| An event was written by the integrity writer, not a DB attacker | signature by a key the verifier pins out-of-band |
| The log was not truncated or rewritten up to seq N | global hash chain + externally anchored checkpoint at N |

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

Tags: `record`, `config`, `event`, `checkpoint`. A hash of one type can never be
presented as a hash of another type.

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

## 7. Checkpoints

```json
{ "v": 1, "log_id": "uuid", "seq": 42, "head": "<event_hash of seq 42>",
  "created_at": "…" }
```

`checkpoint_hash = H("checkpoint", body)`, signed like events. Published to an
anchor. A valid checkpoint for `seq = n` commits to every event `1..n` through
the log chain. Any anchored checkpoint whose `head` is not the database's event
at that `seq` means the log was rewritten or truncated.

## 8. Verification result

A record is `VERIFIED` only if **all** hold:

1. the whole log passes §6 (hashes, signatures by trusted keys, chains, rules);
2. every anchored checkpoint is validly signed and matches the log;
3. the configuration rows match the signed `CONFIGURE` events;
4. the latest event for the record is not a DELETE, the row exists, and its
   `record_hash` (under the event's configuration) equals the event's;
5. that event's `seq ≤` the highest valid anchored checkpoint.

Precedence: `INVALID_PROOF` (1, 2) → `CONFIGURATION_ERROR` (3) → `UNVERIFIED`
(no events) → `TAMPERED` (4 fails) → `DELETED` / `VERIFIED` if anchored, else
`PENDING_ANCHOR` (anchor reachable) or `ANCHOR_FAILED` (anchor unreachable).

## 9. Not yet specified (later stages)

Merkle batching and inclusion proofs (stage 4), blockchain anchor format
(stages 5–6), portable proof bundle (stage 7). Stage 4 will replace the O(n)
full-log audit with Merkle inclusion + a commitment to per-record heads.
