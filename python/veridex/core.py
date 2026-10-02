"""Veridex core: protect, record, checkpoint, audit, verify."""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Sequence, Union

from . import protocol as P
from .anchor import Anchor, AnchorError
from .canonical import CanonicalizationError, canonicalize
from .normalize import normalize_record, normalize_record_id
from .results import (
    ConfigurationError,
    InvalidOperationError,
    LogIntegrityError,
    NotAnchoredError,
    Problem,
    Reason,
    RecordNotFoundError,
    SchemaChangedError,
    Status,
    VerificationResult,
)

PkInput = Union[Any, Sequence[Any]]

# Problems that mean the evidence log itself cannot be trusted.
LOG_REASONS = {
    Reason.SEQ_GAP,
    Reason.EVENT_HASH_MISMATCH,
    Reason.BAD_SIGNATURE,
    Reason.LOG_CHAIN_BROKEN,
    Reason.RECORD_CHAIN_BROKEN,
    Reason.INVALID_TRANSITION,
    Reason.HEAD_MISMATCH,
    Reason.CHECKPOINT_MISMATCH,
    Reason.CHECKPOINT_INVALID,
    Reason.LOG_ID_MISMATCH,
    Reason.CONFIG_REFERENCE_INVALID,
}

DEFAULT_BATCH_SIZE = 5000  # events per Merkle batch
DEFAULT_BATCH_INTERVAL = 300  # seconds an event may wait before a batch is due


def utc_now() -> str:
    t = _dt.datetime.now(_dt.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}Z"


def split_table(table: str, default_schema: str = "public") -> tuple[str, str]:
    if "." in table:
        s, t = table.split(".", 1)
        return s, t
    return default_schema, table


@dataclass
class ResourceConfig:
    resource: str
    schema: str
    table: str
    primary_key: list[str]
    fields: list[str]
    version: int
    config_hash: str

    @classmethod
    def from_body(cls, body: dict[str, Any], config_hash: str) -> "ResourceConfig":
        return cls(
            resource=body["resource"],
            schema=body["schema"],
            table=body["table"],
            primary_key=list(body["primary_key"]),
            fields=list(body["fields"]),
            version=body["version"],
            config_hash=config_hash,
        )


@dataclass
class AuditReport:
    """Result of auditing the whole evidence log against the trusted keys and anchor."""

    log_id: str
    event_count: int
    problems: list[Problem] = field(default_factory=list)
    anchored_through_seq: int = 0
    anchor_error: Optional[str] = None
    configs_by_hash: dict[str, ResourceConfig] = field(default_factory=dict)
    latest_config: dict[str, ResourceConfig] = field(default_factory=dict)
    record_events: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    events_by_seq: dict[int, dict[str, Any]] = field(default_factory=dict)
    # Anchored batches that match the database, oldest first. Each entry is
    # what the anchor returned plus ``from_seq``.
    batches: list[dict[str, Any]] = field(default_factory=list)

    def batch_for(self, seq: int) -> Optional[dict[str, Any]]:
        """The anchored batch whose Merkle tree contains event ``seq``."""
        for b in self.batches:
            if b["from_seq"] <= seq <= b["seq"]:
                return b
        return None

    @property
    def log_problems(self) -> list[Problem]:
        return [p for p in self.problems if p.reason in LOG_REASONS]

    def config_problems(self, resource: Optional[str] = None) -> list[Problem]:
        return [
            p
            for p in self.problems
            if p.reason == Reason.CONFIG_TAMPERED and (resource is None or p.resource == resource)
        ]

    @property
    def ok(self) -> bool:
        return not self.problems and self.anchor_error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "event_count": self.event_count,
            "anchored_batches": len(self.batches),
            "anchored_through_seq": self.anchored_through_seq,
            "anchor_error": self.anchor_error,
            "problems": [p.to_dict() for p in self.problems],
            "ok": self.ok,
        }


@dataclass
class RecordedEvent:
    seq: int
    op: str
    resource: str
    record_id: Optional[str]
    version: int
    event_hash: str
    record_hash: Optional[str]


def _event_body_from_row(e: dict[str, Any]) -> dict[str, Any]:
    return P.event_body(
        seq=e["seq"],
        op=e["op"],
        resource=e["resource"],
        record_id=e["record_id"],
        version=e["version"],
        record_hash=e["record_hash"],
        prev_event_hash=e["prev_event_hash"],
        prev_log_hash=e["prev_log_hash"],
        config_hash=e["config_hash"],
        created_at=e["created_at"],
    )


class Veridex:
    """Tamper-evident integrity layer for an existing relational database.

    Parameters
    ----------
    database:     a database adapter (PostgresAdapter).
    trusted_keys: public keys (hex) whose signatures the verifier accepts.
                  Load them from configuration, NEVER from the protected database.
    signer:       Ed25519 signer used to write events and checkpoints. Only the
                  process that records events needs it; verifiers do not.
    anchor:       where checkpoints are published (FileAnchor, EvmAnchor).
    log_id:       optional pin of the log this verifier expects, obtained from
                  init() and kept outside the database. Detects the whole
                  evidence log being swapped for a fresh one.
    batch_size:   maximum number of events per anchored Merkle batch.
    batch_interval: seconds an unanchored event may wait before
                  ``checkpoint(if_due=True)`` anchors it.
    """

    def __init__(
        self,
        *,
        database: Any,
        trusted_keys: Iterable[str],
        signer: Optional[P.Signer] = None,
        anchor: Optional[Anchor] = None,
        log_id: Optional[str] = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_interval: float = DEFAULT_BATCH_INTERVAL,
    ):
        if batch_size < 1:
            raise ConfigurationError("batch_size must be at least 1")
        self.db = database
        self.trusted = P.TrustedKeys(trusted_keys)
        self.signer = signer
        self.anchor = anchor
        self.log_id = log_id
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        if signer is not None and signer.key_id not in self.trusted:
            raise ConfigurationError("the signer's public key is not in trusted_keys")
        self._declared: dict[str, tuple[list[str], list[str]]] = {}

    # -------------------------------------------------------------- setup --

    def init(self) -> str:
        """Create the integrity schema if needed. Returns the log id."""
        return self.db.init_schema()

    def _require_signer(self) -> P.Signer:
        if self.signer is None:
            raise ConfigurationError("this operation writes evidence and needs a signer")
        return self.signer

    def _append(
        self,
        conn: Any,
        head: dict[str, Any],
        *,
        op: str,
        resource: str,
        record_id: Optional[str],
        version: int,
        record_hash: Optional[str],
        prev_event_hash: Optional[str],
        config_hash: str,
    ) -> RecordedEvent:
        signer = self._require_signer()
        seq = head["seq"] + 1
        body = P.event_body(
            seq=seq,
            op=op,
            resource=resource,
            record_id=record_id,
            version=version,
            record_hash=record_hash,
            prev_event_hash=prev_event_hash,
            prev_log_hash=head["head_hash"],
            config_hash=config_hash,
            created_at=utc_now(),
        )
        h = P.event_hash(body)
        row = dict(body)
        del row["v"]
        row.update(event_hash=h, key_id=signer.key_id, signature=signer.sign(h))
        self.db.insert_event(conn, row)
        self.db.set_head(conn, seq, h)
        head["seq"], head["head_hash"] = seq, h
        return RecordedEvent(seq, op, resource, record_id, version, h, record_hash)

    def _load_verified_config(self, conn: Any, resource: str) -> ResourceConfig:
        """Latest config for a resource, checked against its signed CONFIGURE event."""
        row = self.db.latest_config(conn, resource)
        if row is None:
            raise ConfigurationError(f"{resource} is not protected; call protect() first")
        body = json.loads(row["body"])
        h = P.config_hash(body)
        last = self.db.last_config_event(conn, resource)
        if h != row["config_hash"] or last is None or last["config_hash"] != h:
            raise ConfigurationError(
                f"stored configuration for {resource} does not match its signed CONFIGURE event; "
                "refusing to record under a possibly tampered configuration"
            )
        return ResourceConfig.from_body(body, h)

    # ------------------------------------------------------------ protect --

    def protect(
        self,
        table: str,
        fields: Sequence[str],
        *,
        primary_key: Union[str, Sequence[str]] = "id",
        schema: str = "public",
    ) -> ResourceConfig:
        """Declare which fields of a table are protected.

        Idempotent: if the stored configuration already matches, nothing is
        written. A different field set creates a new, signed configuration
        version; earlier events stay bound to the version they were made under.
        """
        s, t = split_table(table, schema)
        resource = f"{s}.{t}"
        pk = [primary_key] if isinstance(primary_key, str) else list(primary_key)
        flds = sorted(set(fields))
        if not flds:
            raise ConfigurationError("at least one protected field is required")
        self._declared[resource] = (pk, flds)

        with self.db.transaction() as conn:
            existing = set(self.db.column_names(conn, s, t))
            if not existing:
                raise ConfigurationError(f"table {resource} not found")
            unknown = [c for c in pk + flds if c not in existing]
            if unknown:
                raise ConfigurationError(f"columns not found in {resource}: {unknown}")

            head = self.db.lock_head(conn)
            current = self.db.latest_config(conn, resource)
            prev_hash: Optional[str] = None
            version = 1
            if current is not None:
                cfg = self._load_verified_config(conn, resource)
                if cfg.fields == flds and cfg.primary_key == pk:
                    return cfg
                prev_hash, version = cfg.config_hash, cfg.version + 1

            body = P.config_body(
                resource=resource,
                schema=s,
                table=t,
                primary_key=pk,
                fields=flds,
                version=version,
                prev_config_hash=prev_hash,
            )
            h = P.config_hash(body)
            last_cfg_event = self.db.last_config_event(conn, resource)
            self._append(
                conn,
                head,
                op=P.OP_CONFIGURE,
                resource=resource,
                record_id=None,
                version=version,
                record_hash=None,
                prev_event_hash=last_cfg_event["event_hash"] if last_cfg_event else None,
                config_hash=h,
            )
            self.db.insert_config(
                conn,
                resource=resource,
                schema_name=s,
                table_name=t,
                version=version,
                body=canonicalize(body),
                config_hash=h,
            )
            return ResourceConfig.from_body(body, h)

    # ------------------------------------------------------------- record --

    @staticmethod
    def _pk_values(cfg: ResourceConfig, record: Optional[dict], record_id: Optional[PkInput]) -> list[Any]:
        if record is not None:
            missing = [c for c in cfg.primary_key if c not in record]
            if missing:
                raise InvalidOperationError(f"record is missing primary key columns {missing}")
            return [record[c] for c in cfg.primary_key]
        if record_id is None:
            raise InvalidOperationError("pass either record= or record_id=")
        if len(cfg.primary_key) == 1:
            return [record_id]
        vals = list(record_id)
        if len(vals) != len(cfg.primary_key):
            raise InvalidOperationError(
                f"composite key {cfg.primary_key} needs {len(cfg.primary_key)} values"
            )
        return vals

    def record(
        self,
        table: str,
        operation: str,
        *,
        record: Optional[dict[str, Any]] = None,
        record_id: Optional[PkInput] = None,
        conn: Any = None,
        schema: str = "public",
    ) -> RecordedEvent:
        """Record a CREATE, UPDATE or DELETE of a protected row.

        Call it inside the same transaction as the business change and pass
        that connection as ``conn``. The protected fields are re-read from the
        database inside that transaction (not taken from ``record``) so the
        hash reflects exactly what was written, in the database's own types.

        ``record`` is only used to find the primary key.
        """
        op = operation.upper()
        if op not in P.OPS_RECORD:
            raise InvalidOperationError(f"operation must be one of {P.OPS_RECORD}")
        s, t = split_table(table, schema)
        resource = f"{s}.{t}"

        with self.db.transaction(conn) as c:
            head = self.db.lock_head(c)
            cfg = self._load_verified_config(c, resource)
            declared = self._declared.get(resource)
            if declared is not None and declared != (cfg.primary_key, cfg.fields):
                raise ConfigurationError(
                    f"protect() declared {declared[1]} for {resource} but the stored "
                    f"configuration protects {cfg.fields}"
                )
            pk_vals = self._pk_values(cfg, record, record_id)
            rid = normalize_record_id(pk_vals)
            last = self.db.last_record_event(c, resource, rid)

            if op == "CREATE":
                if last is not None and last["op"] != "DELETE":
                    raise InvalidOperationError(f"{resource}/{rid} already has live evidence; use UPDATE")
            elif last is None or last["op"] == "DELETE":
                raise InvalidOperationError(f"{resource}/{rid} has no live evidence; {op} not allowed")

            if op == "DELETE":
                # The DELETE event preserves the last attested state.
                rhash = last["record_hash"]
            else:
                row = self.db.fetch_row(
                    c,
                    schema_name=cfg.schema,
                    table_name=cfg.table,
                    primary_key=cfg.primary_key,
                    pk_values=pk_vals,
                    fields=cfg.fields,
                )
                if row is None:
                    raise RecordNotFoundError(
                        f"{resource}/{rid} not found; write the row before recording {op}"
                    )
                rhash = P.record_hash(normalize_record(row, cfg.fields))

            return self._append(
                c,
                head,
                op=op,
                resource=resource,
                record_id=rid,
                version=(last["version"] + 1) if last else 1,
                record_hash=rhash,
                prev_event_hash=last["event_hash"] if last else None,
                config_hash=cfg.config_hash,
            )

    # --------------------------------------------------------- checkpoint --

    def _event_problems(self, e: dict[str, Any], expected_seq: int, prev_log: str) -> list[Problem]:
        """The checks one event needs no other state for: position, hash,
        signature and its link to the previous event."""
        seq, out = e["seq"], []
        if seq != expected_seq:
            out.append(Problem(Reason.SEQ_GAP, f"expected seq {expected_seq}, found {seq}", seq))
        try:
            recomputed = P.event_hash(_event_body_from_row(e))
        except CanonicalizationError as ex:
            recomputed = None
            out.append(Problem(Reason.EVENT_HASH_MISMATCH, f"event not canonicalizable: {ex}", seq))
        if recomputed != e["event_hash"]:
            out.append(Problem(Reason.EVENT_HASH_MISMATCH, "stored event does not match its hash", seq))
        if not self.trusted.verify(e["key_id"], e["event_hash"], e["signature"]):
            out.append(Problem(Reason.BAD_SIGNATURE, f"signature invalid or key {e['key_id']} not trusted", seq))
        if e["prev_log_hash"] != prev_log:
            out.append(Problem(Reason.LOG_CHAIN_BROKEN, "prev_log_hash does not link to previous event", seq))
        return out

    def _read_anchor(self, log_id: str, *, pending: bool = False) -> tuple[list[dict[str, Any]], list[Problem]]:
        """Read the anchor. Returns the gap-free chain of batches 1..k published
        for this log (each with ``from_seq``) and the problems found. Whether a
        batch matches the database is the caller's check. Raises AnchorError."""
        assert self.anchor is not None
        signed = getattr(self.anchor, "requires_signature", True)
        problems: list[Problem] = []
        own: dict[int, dict[str, Any]] = {}
        for cp in self.anchor.checkpoints(log_id, pending=pending):
            try:
                batch, seq, root = cp["batch"], cp["seq"], cp["merkle_root"]
                if not all(type(n) is int and n >= 1 for n in (batch, seq)):
                    raise ValueError("batch and seq must be positive integers")
                P._hash32(root)
                if signed:
                    if cp["v"] != P.CHECKPOINT_VERSION:
                        raise ValueError(f"unsupported checkpoint version {cp['v']}")
                    h = P.checkpoint_hash(P.checkpoint_body(
                        log_id=cp["log_id"], batch=batch, from_seq=cp["from_seq"], seq=seq,
                        merkle_root=root, created_at=cp["created_at"]))
                    if h != cp.get("checkpoint_hash") or not self.trusted.verify(
                        cp.get("key_id", ""), h, cp.get("signature", "")
                    ):
                        problems.append(Problem(Reason.CHECKPOINT_INVALID,
                                                "checkpoint hash or signature invalid", seq))
                        continue
                cp_log = cp["log_id"]
            except (KeyError, TypeError, ValueError, CanonicalizationError) as ex:
                problems.append(Problem(Reason.CHECKPOINT_INVALID, f"malformed checkpoint: {ex!r}"))
                continue
            if cp_log != log_id:
                problems.append(Problem(
                    Reason.CHECKPOINT_MISMATCH,
                    f"anchor holds a checkpoint for log {cp_log}, database is log {log_id}", seq))
                continue
            seen = own.setdefault(batch, cp)
            if (seen["seq"], seen["merkle_root"]) != (seq, root):
                problems.append(Problem(Reason.CHECKPOINT_INVALID,
                                        f"anchor holds conflicting checkpoints for batch {batch}", seq))

        chain: list[dict[str, Any]] = []
        prev_seq = 0
        for n in sorted(own):
            cp = own[n]
            if n != len(chain) + 1:
                problems.append(Problem(Reason.CHECKPOINT_INVALID,
                                        f"anchored batch numbering has a gap before batch {n}", cp["seq"]))
                break
            if cp["seq"] <= prev_seq or cp.get("from_seq", prev_seq + 1) != prev_seq + 1:
                problems.append(Problem(Reason.CHECKPOINT_INVALID,
                                        f"anchored batch {n} does not continue batch {n - 1}", cp["seq"]))
                break
            chain.append(dict(cp, from_seq=prev_seq + 1))
            prev_seq = cp["seq"]
        return chain, problems

    def _due(self, pending: list[dict[str, Any]]) -> bool:
        """Batching policy: a batch is due once ``batch_size`` events are
        waiting or the oldest waiting event is ``batch_interval`` seconds old."""
        if len(pending) >= self.batch_size:
            return True
        try:
            oldest = _dt.datetime.strptime(pending[0]["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return True
        age = _dt.datetime.now(_dt.timezone.utc) - oldest.replace(tzinfo=_dt.timezone.utc)
        return age.total_seconds() >= self.batch_interval

    def checkpoint(self, *, if_due: bool = False) -> Optional[dict[str, Any]]:
        """Anchor every event recorded since the last checkpoint.

        The waiting events are split into batches of at most ``batch_size``.
        Each batch becomes a Merkle tree whose root is signed and published to
        the anchor. Returns the last checkpoint published, or None if there was
        nothing to anchor (or, with ``if_due=True``, the batching policy says
        to wait).

        Before publishing, the last anchored batch is re-checked against the
        database and the waiting events are checked for valid hashes, trusted
        signatures and an unbroken chain. An anchor is write-once, so a batch
        that would fail verification is refused, not anchored: this raises
        LogIntegrityError and leaves the anchor untouched.
        """
        signer = self._require_signer()
        if self.anchor is None:
            raise ConfigurationError("no anchor configured")
        head = self.db.read_head()
        if self.log_id is not None and head["log_id"] != self.log_id:
            raise LogIntegrityError(
                f"database holds log {head['log_id']}, expected {self.log_id}; refusing to anchor")
        if head["seq"] == 0:
            return None
        chain, problems = self._read_anchor(head["log_id"], pending=True)
        invalid = [p for p in problems if p.reason == Reason.CHECKPOINT_INVALID]
        if invalid:
            raise LogIntegrityError(f"the anchor holds invalid checkpoints: {invalid[0].message}")

        last_seq, prev_hash = 0, P.GENESIS_HASH
        if chain:
            last = chain[-1]
            last_seq = last["seq"]
            if head["seq"] < last_seq:
                raise LogIntegrityError(
                    f"database log ends at seq {head['seq']} but seq {last_seq} is anchored")
            hashes = [e["event_hash"] for e in self.db.events_range(last["from_seq"], last_seq)]
            try:
                matches = (len(hashes) == last_seq - last["from_seq"] + 1
                           and P.merkle_root(hashes) == last["merkle_root"])
            except ValueError:
                matches = False
            if not matches:
                raise LogIntegrityError(
                    f"the database no longer matches anchored batch {last['batch']}; "
                    "refusing to anchor on top of it")
            prev_hash = hashes[-1]
        if head["seq"] == last_seq:
            return None

        pending = self.db.events_range(last_seq + 1, head["seq"])
        if len(pending) != head["seq"] - last_seq:
            raise LogIntegrityError("events are missing between the anchor and the log head")
        if if_due and not self._due(pending):
            return None
        for i, e in enumerate(pending, start=last_seq + 1):
            bad = self._event_problems(e, i, prev_hash)
            if bad:
                raise LogIntegrityError(
                    f"refusing to anchor event {e['seq']}: {bad[0].reason.value}: {bad[0].message}")
            prev_hash = e["event_hash"]

        published: Optional[dict[str, Any]] = None
        for i in range(0, len(pending), self.batch_size):
            chunk = pending[i:i + self.batch_size]
            body = P.checkpoint_body(
                log_id=head["log_id"],
                batch=len(chain) + 1 + i // self.batch_size,
                from_seq=chunk[0]["seq"],
                seq=chunk[-1]["seq"],
                merkle_root=P.merkle_root([e["event_hash"] for e in chunk]),
                created_at=utc_now(),
            )
            h = P.checkpoint_hash(body)
            cp = dict(body, checkpoint_hash=h, key_id=signer.key_id, signature=signer.sign(h))
            receipt = self.anchor.publish(cp)
            self.db.insert_batch(
                batch=body["batch"], from_seq=body["from_seq"], seq=body["seq"],
                merkle_root=body["merkle_root"], checkpoint=canonicalize(cp),
                receipt=json.dumps(receipt, sort_keys=True), created_at=body["created_at"],
            )
            published = dict(cp, receipt=receipt)
        return published

    # -------------------------------------------------------------- audit --

    def audit(self) -> AuditReport:
        """Verify the entire evidence log: hashes, signatures, chains,
        transitions, configuration table, and external checkpoints.

        Cost is O(total events): knowing that an event is the LATEST one for
        its record means knowing nothing later was removed, which takes the
        whole log (see docs/DECISIONS.md D14).
        """
        head = self.db.read_head()
        events = self.db.load_events()
        rep = AuditReport(log_id=head["log_id"], event_count=len(events))
        add = rep.problems.append
        if self.log_id is not None and head["log_id"] != self.log_id:
            add(Problem(Reason.LOG_ID_MISMATCH,
                        f"database holds log {head['log_id']}, expected {self.log_id}"))

        prev_log = P.GENESIS_HASH
        by_seq = rep.events_by_seq
        last_rec: dict[tuple[str, str], dict[str, Any]] = {}
        last_cfg: dict[str, dict[str, Any]] = {}
        cfg_events: dict[str, list[dict[str, Any]]] = {}

        for i, e in enumerate(events, start=1):
            seq = e["seq"]
            by_seq[seq] = e
            rep.problems.extend(self._event_problems(e, i, prev_log))
            prev_log = e["event_hash"]

            res = e["resource"]
            if e["op"] == P.OP_CONFIGURE:
                lc = last_cfg.get(res)
                exp_prev = lc["event_hash"] if lc else None
                exp_ver = (lc["version"] + 1) if lc else 1
                if e["prev_event_hash"] != exp_prev or e["version"] != exp_ver:
                    add(Problem(Reason.RECORD_CHAIN_BROKEN, "configuration chain broken", seq, res))
                if e["record_id"] is not None or e["record_hash"] is not None:
                    add(Problem(Reason.INVALID_TRANSITION, "CONFIGURE event carries record data", seq, res))
                last_cfg[res] = e
                cfg_events.setdefault(res, []).append(e)
                continue

            if e["op"] not in P.OPS_RECORD:
                add(Problem(Reason.INVALID_TRANSITION, f"unknown op {e['op']}", seq, res))
                continue
            lc = last_cfg.get(res)
            if lc is None or lc["config_hash"] != e["config_hash"]:
                add(Problem(Reason.CONFIG_REFERENCE_INVALID,
                            "event not made under the then-current configuration", seq, res))
            key = (res, e["record_id"])
            lr = last_rec.get(key)
            exp_prev = lr["event_hash"] if lr else None
            exp_ver = (lr["version"] + 1) if lr else 1
            if e["prev_event_hash"] != exp_prev or e["version"] != exp_ver:
                add(Problem(Reason.RECORD_CHAIN_BROKEN, f"record chain broken for {res}/{e['record_id']}", seq, res))
            live = lr is not None and lr["op"] != "DELETE"
            if (e["op"] == "CREATE" and live) or (e["op"] != "CREATE" and not live):
                add(Problem(Reason.INVALID_TRANSITION, f"{e['op']} not valid after {lr['op'] if lr else 'nothing'}", seq, res))
            if e["op"] == "DELETE" and lr is not None and e["record_hash"] != lr["record_hash"]:
                add(Problem(Reason.INVALID_TRANSITION, "DELETE does not preserve last attested state", seq, res))
            last_rec[key] = e
            rep.record_events.setdefault(key, []).append(e)

        if head["seq"] != len(events) or head["head_hash"] != prev_log:
            add(Problem(Reason.HEAD_MISMATCH, "log_head does not match the last event"))

        # Configuration table must match the signed CONFIGURE events exactly.
        rows_by_res: dict[str, list[dict[str, Any]]] = {}
        for r in self.db.load_configs():
            rows_by_res.setdefault(r["resource"], []).append(r)
        for res in set(rows_by_res) | set(cfg_events):
            rows = rows_by_res.get(res, [])
            signed = [e["config_hash"] for e in cfg_events.get(res, [])]
            stored: list[str] = []
            for r in rows:
                try:
                    body = json.loads(r["body"])
                    h = P.config_hash(body)
                except (ValueError, CanonicalizationError, KeyError):
                    add(Problem(Reason.CONFIG_TAMPERED, f"configuration v{r['version']} unreadable", resource=res))
                    continue
                if h != r["config_hash"] or body.get("version") != r["version"] or body.get("resource") != res:
                    add(Problem(Reason.CONFIG_TAMPERED,
                                f"configuration v{r['version']} body does not match its hash", resource=res))
                    continue
                stored.append(h)
                cfg = ResourceConfig.from_body(body, h)
                rep.configs_by_hash[h] = cfg
            if stored != signed:
                add(Problem(Reason.CONFIG_TAMPERED,
                            "configuration rows do not match the signed CONFIGURE events", resource=res))
            elif signed and signed[-1] in rep.configs_by_hash:
                rep.latest_config[res] = rep.configs_by_hash[signed[-1]]

        # Anchored batches: each Merkle root must match the events in the database.
        if self.anchor is None:
            rep.anchor_error = "no anchor configured"
            return rep
        try:
            chain, anchor_problems = self._read_anchor(head["log_id"])
        except AnchorError as ex:
            rep.anchor_error = str(ex)
            return rep
        rep.problems.extend(anchor_problems)
        for cp in chain:
            try:
                matches = cp["seq"] <= len(events) and P.merkle_root(
                    [by_seq[n]["event_hash"] for n in range(cp["from_seq"], cp["seq"] + 1)]
                ) == cp["merkle_root"]
            except (KeyError, ValueError):
                matches = False
            if not matches:
                add(Problem(Reason.CHECKPOINT_MISMATCH,
                            f"anchored Merkle root of batch {cp['batch']} does not match the database: "
                            "log was rewritten or truncated", cp["seq"]))
                break
            rep.batches.append(cp)
            rep.anchored_through_seq = cp["seq"]
        return rep

    # ------------------------------------------------------------- verify --

    def verify(
        self,
        table: str,
        record_id: PkInput,
        *,
        schema: str = "public",
        audit: Optional[AuditReport] = None,
    ) -> VerificationResult:
        """Verify one record. Never returns VERIFIED unless the evidence is
        consistent AND covered by a valid external checkpoint."""
        s, t = split_table(table, schema)
        resource = f"{s}.{t}"
        rep = audit or self.audit()

        def result(status: Status, *reasons: Reason, **kw: Any) -> VerificationResult:
            return VerificationResult(
                status=status,
                resource=resource,
                record_id=kw.pop("rid", str(record_id)),
                reasons=list(reasons),
                anchored_through_seq=rep.anchored_through_seq,
                **kw,
            )

        if rep.log_problems:
            return result(Status.INVALID_PROOF, *{p.reason for p in rep.log_problems},
                          problems=rep.log_problems)
        if rep.config_problems(resource):
            return result(Status.CONFIGURATION_ERROR, Reason.CONFIG_TAMPERED,
                          problems=rep.config_problems(resource))
        latest = rep.latest_config.get(resource)
        if latest is None:
            return result(Status.CONFIGURATION_ERROR, Reason.NOT_PROTECTED)

        pk_vals = self._pk_values(latest, None, record_id)
        rid = normalize_record_id(pk_vals)
        events = rep.record_events.get((resource, rid), [])
        if not events:
            return result(Status.UNVERIFIED, Reason.NO_EVIDENCE, rid=rid)

        last = events[-1]
        cfg = rep.configs_by_hash.get(last["config_hash"])
        if cfg is None:
            return result(Status.CONFIGURATION_ERROR, Reason.CONFIG_REFERENCE_INVALID, rid=rid)
        batch = rep.batch_for(last["seq"])
        anchored = batch is not None
        warn = [Reason.CONFIG_SUPERSEDED] if cfg.config_hash != latest.config_hash else []
        common = dict(
            rid=rid,
            version=last["version"],
            event_seq=last["seq"],
            event_hash=last["event_hash"],
            expected_record_hash=last["record_hash"],
            anchored=anchored,
            batch=batch["batch"] if batch else None,
            merkle_root=batch["merkle_root"] if batch else None,
        )

        try:
            with self.db.transaction() as conn:
                row = self.db.fetch_row(
                    conn,
                    schema_name=cfg.schema,
                    table_name=cfg.table,
                    primary_key=cfg.primary_key,
                    pk_values=pk_vals,
                    fields=cfg.fields,
                )
        except SchemaChangedError:
            # The evidence describes columns that can no longer be read.
            return result(Status.TAMPERED, Reason.SCHEMA_CHANGED, *warn, **common)

        def unanchored() -> VerificationResult:
            st = Status.ANCHOR_FAILED if rep.anchor_error else Status.PENDING_ANCHOR
            reason = Reason.ANCHOR_UNREACHABLE if rep.anchor_error else Reason.NOT_ANCHORED
            return result(st, reason, *warn, **common)

        if last["op"] == "DELETE":
            if row is not None:
                return result(Status.TAMPERED, Reason.RECORD_RESURRECTED, *warn, **common)
            return result(Status.DELETED, *warn, **common) if anchored else unanchored()

        if row is None:
            return result(Status.TAMPERED, Reason.RECORD_MISSING, *warn, **common)
        try:
            current = P.record_hash(normalize_record(row, cfg.fields))
        except (CanonicalizationError, KeyError):
            return result(Status.TAMPERED, Reason.UNREADABLE_VALUE, *warn, **common)
        common["current_record_hash"] = current
        if current != last["record_hash"]:
            return result(Status.TAMPERED, Reason.STATE_MISMATCH, *warn, **common)
        return result(Status.VERIFIED, *warn, **common) if anchored else unanchored()

    # ------------------------------------------------------------- proofs --

    def inclusion_proof(self, seq: int, *, audit: Optional[AuditReport] = None) -> dict[str, Any]:
        """Merkle proof that event ``seq`` is part of an anchored batch.

        The proof holds the signed event, its Merkle path and the anchored
        root. Check it with ``protocol.verify_inclusion`` and the event
        signature; neither needs the database.
        """
        rep = audit or self.audit()
        if rep.log_problems:
            raise LogIntegrityError("the evidence log fails audit; no proof can be issued")
        batch = rep.batch_for(seq)
        if batch is None:
            if rep.anchor_error:
                raise AnchorError(rep.anchor_error)
            raise NotAnchoredError(f"event {seq} is not covered by an anchored batch")
        e = rep.events_by_seq[seq]
        hashes = [rep.events_by_seq[n]["event_hash"] for n in range(batch["from_seq"], batch["seq"] + 1)]
        index = seq - batch["from_seq"]
        receipt = None
        for row in self.db.load_batches():  # convenience copy, e.g. the transaction hash
            if row["batch"] == batch["batch"] and row["merkle_root"] == batch["merkle_root"]:
                receipt = json.loads(row["receipt"])
        return {
            "protocol": {
                "version": P.PROTOCOL_VERSION,
                "hash_algorithm": P.HASH_ALGORITHM,
                "canonicalization": P.CANONICALIZATION,
                "merkle": P.MERKLE,
            },
            "log_id": rep.log_id,
            "event": {
                "body": _event_body_from_row(e),
                "event_hash": e["event_hash"],
                "key_id": e["key_id"],
                "signature": e["signature"],
            },
            "inclusion": {
                "batch": batch["batch"],
                "from_seq": batch["from_seq"],
                "seq": batch["seq"],
                "leaf_index": index,
                "tree_size": len(hashes),
                "path": P.merkle_path(hashes, index),
                "merkle_root": batch["merkle_root"],
            },
            "anchor": {
                "name": getattr(self.anchor, "name", None),
                "checkpoint": batch,
                "receipt": receipt,
            },
        }

    def prove(self, table: str, record_id: PkInput, *, schema: str = "public") -> dict[str, Any]:
        """Inclusion proof for the latest event of a record. Only issued when
        the record currently verifies (VERIFIED or DELETED)."""
        rep = self.audit()
        r = self.verify(table, record_id, schema=schema, audit=rep)
        if not r.ok:
            if r.status in (Status.PENDING_ANCHOR, Status.ANCHOR_FAILED):
                raise NotAnchoredError(f"{r.resource}/{r.record_id} is {r.status.value}")
            raise LogIntegrityError(
                f"{r.resource}/{r.record_id} is {r.status.value}; no proof can be issued")
        assert r.event_seq is not None
        return self.inclusion_proof(r.event_seq, audit=rep)

    # ------------------------------------------------------------ history --

    def history(self, table: str, record_id: PkInput, *, schema: str = "public") -> list[dict[str, Any]]:
        s, t = split_table(table, schema)
        resource = f"{s}.{t}"
        with self.db.transaction() as conn:
            cfg = self._load_verified_config(conn, resource)
        rid = normalize_record_id(self._pk_values(cfg, None, record_id))
        return self.db.record_events(resource, rid)
