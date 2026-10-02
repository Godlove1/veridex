"""Verification statuses and machine-readable result objects."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    VERIFIED = "VERIFIED"  # current state matches the latest event AND that event is anchored
    TAMPERED = "TAMPERED"  # current state contradicts the recorded evidence
    DELETED = "DELETED"  # a legitimate, anchored DELETE event exists and the row is gone
    PENDING_ANCHOR = "PENDING_ANCHOR"  # evidence is consistent but not yet externally anchored
    INVALID_PROOF = "INVALID_PROOF"  # the evidence log itself is broken (rewritten, forged, truncated)
    UNVERIFIED = "UNVERIFIED"  # no evidence exists for this record
    ANCHOR_FAILED = "ANCHOR_FAILED"  # the anchor could not be read
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"  # protection config is tampered or unusable


class Reason(str, Enum):
    # record-level
    STATE_MISMATCH = "STATE_MISMATCH"
    RECORD_MISSING = "RECORD_MISSING"  # row gone but no DELETE event
    RECORD_RESURRECTED = "RECORD_RESURRECTED"  # DELETE event exists but row is present
    NO_EVIDENCE = "NO_EVIDENCE"
    NOT_ANCHORED = "NOT_ANCHORED"
    CONFIG_SUPERSEDED = "CONFIG_SUPERSEDED"  # warning: protected fields changed since last event
    UNREADABLE_VALUE = "UNREADABLE_VALUE"
    SCHEMA_CHANGED = "SCHEMA_CHANGED"  # protected table or column no longer exists
    # log-level
    SEQ_GAP = "SEQ_GAP"
    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    LOG_CHAIN_BROKEN = "LOG_CHAIN_BROKEN"
    RECORD_CHAIN_BROKEN = "RECORD_CHAIN_BROKEN"
    INVALID_TRANSITION = "INVALID_TRANSITION"
    HEAD_MISMATCH = "HEAD_MISMATCH"
    CHECKPOINT_MISMATCH = "CHECKPOINT_MISMATCH"
    CHECKPOINT_INVALID = "CHECKPOINT_INVALID"
    LOG_ID_MISMATCH = "LOG_ID_MISMATCH"  # database holds a different log than the pinned one
    # config-level
    CONFIG_TAMPERED = "CONFIG_TAMPERED"
    CONFIG_REFERENCE_INVALID = "CONFIG_REFERENCE_INVALID"
    NOT_PROTECTED = "NOT_PROTECTED"
    # anchor
    ANCHOR_UNREACHABLE = "ANCHOR_UNREACHABLE"


@dataclass
class Problem:
    reason: Reason
    message: str
    seq: Optional[int] = None
    resource: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reason"] = self.reason.value
        return d


@dataclass
class VerificationResult:
    status: Status
    resource: str
    record_id: str
    reasons: list[Reason] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    version: Optional[int] = None
    event_seq: Optional[int] = None
    event_hash: Optional[str] = None
    expected_record_hash: Optional[str] = None
    current_record_hash: Optional[str] = None
    anchored: bool = False
    anchored_through_seq: int = 0
    batch: Optional[int] = None  # anchored batch that contains the event
    merkle_root: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status in (Status.VERIFIED, Status.DELETED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "resource": self.resource,
            "record_id": self.record_id,
            "reasons": [r.value for r in self.reasons],
            "problems": [p.to_dict() for p in self.problems],
            "version": self.version,
            "event_seq": self.event_seq,
            "event_hash": self.event_hash,
            "expected_record_hash": self.expected_record_hash,
            "current_record_hash": self.current_record_hash,
            "anchored": self.anchored,
            "anchored_through_seq": self.anchored_through_seq,
            "batch": self.batch,
            "merkle_root": self.merkle_root,
        }


class VeridexError(Exception):
    """Base error. ``code`` is machine-readable."""

    code = "VERIDEX_ERROR"


class ConfigurationError(VeridexError):
    code = "CONFIGURATION_ERROR"


class InvalidOperationError(VeridexError):
    code = "INVALID_OPERATION"


class RecordNotFoundError(VeridexError):
    code = "RECORD_NOT_FOUND"


class SchemaChangedError(VeridexError):
    """A protected table or column no longer exists in the database."""

    code = "SCHEMA_CHANGED"


class LogIntegrityError(VeridexError):
    """The evidence log or the anchor failed a check; nothing was written."""

    code = "LOG_INTEGRITY"


class NotAnchoredError(VeridexError):
    """A proof was requested for evidence that is not anchored (yet)."""

    code = "NOT_ANCHORED"
