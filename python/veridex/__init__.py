"""Veridex: tamper-evident integrity evidence for existing relational databases."""

from .anchor import Anchor, AnchorError, FileAnchor, UnavailableAnchor
from .core import AuditReport, RecordedEvent, ResourceConfig, Veridex
from .protocol import Signer, TrustedKeys
from .results import (
    ConfigurationError,
    InvalidOperationError,
    LogIntegrityError,
    NotAnchoredError,
    Reason,
    RecordNotFoundError,
    SchemaChangedError,
    Status,
    VerificationResult,
    VeridexError,
)

__version__ = "0.1.0"

__all__ = [
    "Veridex",
    "Signer",
    "TrustedKeys",
    "FileAnchor",
    "UnavailableAnchor",
    "Anchor",
    "AnchorError",
    "AuditReport",
    "RecordedEvent",
    "ResourceConfig",
    "Status",
    "Reason",
    "VerificationResult",
    "VeridexError",
    "ConfigurationError",
    "InvalidOperationError",
    "LogIntegrityError",
    "NotAnchoredError",
    "RecordNotFoundError",
    "SchemaChangedError",
]
