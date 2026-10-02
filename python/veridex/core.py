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
    Problem,
    Reason,
    RecordNotFoundError,
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
    Reason.CONFIG_REFERENCE_INVALID,
}


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
    anchor:       where checkpoints are published (FileAnchor in stage 1).
    """

    def __init__(
        self,
        *,
        database: Any,
        trusted_keys: Iterable[str],
        signer: Optional[P.Signer] = None,
        anchor: Optional[Anchor] = None,
    ):
        self.db = database
        self.trusted = P.TrustedKeys(trusted_keys)
        self.signer = signer
        self.anchor = anchor
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

    def checkpoint(self) -> Optional[dict[str, Any]]:
        """Sign the current log head and publish it to the anchor.

        Returns None if there is nothing new to anchor. In stage 4+ this is
        where Merkle batching will live; the checkpoint already commits to every
        event up to ``seq`` through the log hash chain.
        """
        signer = self._require_signer()
        if self.anchor is None:
            raise ConfigurationError("no anchor configured")
        head = self.db.read_head()
        if head["seq"] == 0:
            return None
        try:
            prior = [c for c in self.anchor.checkpoints(head["log_id"]) if c.get("log_id") == head["log_id"]]
        except AnchorError:
            prior = []
        if prior and max(c["seq"] for c in prior) >= head["seq"]:
            return None
        body = P.checkpoint_body(
            log_id=head["log_id"], seq=head["seq"], head=head["head_hash"], created_at=utc_now()
        )
        h = P.checkpoint_hash(body)
        cp = dict(body, checkpoint_hash=h, key_id=signer.key_id, signature=signer.sign(h))
        cp["receipt"] = self.anchor.publish(cp)
        return cp

    # -------------------------------------------------------------- audit --

    def audit(self) -> AuditReport:
        """Verify the entire evidence log: hashes, signatures, chains,
        transitions, configuration table, and external checkpoints.

        Cost is O(total events). Merkle batching (stage 4) will make
        per-record verification cheaper; correctness comes first.
        """
        head = self.db.read_head()
        events = self.db.load_events()
        rep = AuditReport(log_id=head["log_id"], event_count=len(events))
        add = rep.problems.append

        prev_log = P.GENESIS_HASH
        by_seq: dict[int, dict[str, Any]] = {}
        last_rec: dict[tuple[str, str], dict[str, Any]] = {}
        last_cfg: dict[str, dict[str, Any]] = {}
        cfg_events: dict[str, list[dict[str, Any]]] = {}

        for i, e in enumerate(events, start=1):
            seq = e["seq"]
            by_seq[seq] = e
            if seq != i:
                add(Problem(Reason.SEQ_GAP, f"expected seq {i}, found {seq}", seq))
            try:
                recomputed = P.event_hash(_event_body_from_row(e))
            except CanonicalizationError as ex:
                recomputed = None
                add(Problem(Reason.EVENT_HASH_MISMATCH, f"event not canonicalizable: {ex}", seq))
            if recomputed != e["event_hash"]:
                add(Problem(Reason.EVENT_HASH_MISMATCH, "stored event does not match its hash", seq))
            if not self.trusted.verify(e["key_id"], e["event_hash"], e["signature"]):
                add(Problem(Reason.BAD_SIGNATURE, f"signature invalid or key {e['key_id']} not trusted", seq))
            if e["prev_log_hash"] != prev_log:
                add(Problem(Reason.LOG_CHAIN_BROKEN, "prev_log_hash does not link to previous event", seq))
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

        # External checkpoints.
        if self.anchor is None:
            rep.anchor_error = "no anchor configured"
        else:
            try:
                cps = self.anchor.checkpoints(head["log_id"])
            except AnchorError as ex:
                cps = []
                rep.anchor_error = str(ex)
            for cp in cps:
                try:
                    body = P.checkpoint_body(
                        log_id=cp["log_id"], seq=cp["seq"], head=cp["head"], created_at=cp["created_at"]
                    )
                    h = P.checkpoint_hash(body)
                except (KeyError, TypeError, CanonicalizationError):
                    add(Problem(Reason.CHECKPOINT_INVALID, "malformed checkpoint"))
                    continue
                if h != cp.get("checkpoint_hash") or not self.trusted.verify(
                    cp.get("key_id", ""), h, cp.get("signature", "")
                ):
                    add(Problem(Reason.CHECKPOINT_INVALID, "checkpoint hash or signature invalid", cp.get("seq")))
                    continue
                if cp["log_id"] != head["log_id"]:
                    add(Problem(Reason.CHECKPOINT_MISMATCH,
                                f"anchor holds a checkpoint for log {cp['log_id']}, database is log {head['log_id']}",
                                cp["seq"]))
                    continue
                anchored_event = by_seq.get(cp["seq"])
                if anchored_event is None or anchored_event["event_hash"] != cp["head"]:
                    add(Problem(Reason.CHECKPOINT_MISMATCH,
                                "anchored log head not found in the database: log was rewritten or truncated",
                                cp["seq"]))
                    continue
                rep.anchored_through_seq = max(rep.anchored_through_seq, cp["seq"])
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
        anchored = last["seq"] <= rep.anchored_through_seq
        warn = [Reason.CONFIG_SUPERSEDED] if cfg.config_hash != latest.config_hash else []
        common = dict(
            rid=rid,
            version=last["version"],
            event_seq=last["seq"],
            event_hash=last["event_hash"],
            expected_record_hash=last["record_hash"],
            anchored=anchored,
        )

        with self.db.transaction() as conn:
            row = self.db.fetch_row(
                conn,
                schema_name=cfg.schema,
                table_name=cfg.table,
                primary_key=cfg.primary_key,
                pk_values=pk_vals,
                fields=cfg.fields,
            )

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

    # ------------------------------------------------------------ history --

    def history(self, table: str, record_id: PkInput, *, schema: str = "public") -> list[dict[str, Any]]:
        s, t = split_table(table, schema)
        resource = f"{s}.{t}"
        with self.db.transaction() as conn:
            cfg = self._load_verified_config(conn, resource)
        rid = normalize_record_id(self._pk_values(cfg, None, record_id))
        return self.db.record_events(resource, rid)
