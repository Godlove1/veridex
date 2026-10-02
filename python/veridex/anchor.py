"""Anchors: where signed checkpoints are published outside the protected database.

A checkpoint commits to the entire event log up to a sequence number. Its value
as evidence depends entirely on the anchor being OUTSIDE the attacker's reach.

A checkpoint commits to one batch: (log_id, batch number, last seq, Merkle root).

FileAnchor is a development stand-in. It is a trust boundary only if the file
lives somewhere the database attacker cannot write (another host,
WORM/object-lock storage). EvmAnchor (veridex.evm) anchors the same commitment
in a smart contract on Anvil, Base or any other EVM chain.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol


class AnchorError(RuntimeError):
    """The anchor could not be read or written."""


class Anchor(Protocol):
    name: str
    # True: the medium does not authenticate the publisher, so every entry
    # returned by checkpoints() must be a full checkpoint signed by a trusted
    # key. False: the medium itself authenticates the publisher (a blockchain
    # account pinned by the verifier) and entries carry only the commitment.
    requires_signature: bool

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        """Publish a signed checkpoint. Returns a receipt."""
        ...

    def checkpoints(self, log_id: str, *, pending: bool = False) -> list[dict[str, Any]]:
        """Return the published checkpoints, oldest first. Each entry has at
        least ``log_id``, ``batch``, ``seq`` and ``merkle_root``.

        Implementations must not hide entries of a medium that is shared
        between logs; the verifier decides. ``pending=True`` also returns
        entries that are published but not yet final. It is used only to decide
        what to anchor next, never for verification.
        """
        ...


class FileAnchor:
    """Append-only JSON-lines file. DEVELOPMENT ONLY - see module docstring."""

    name = "file"
    requires_signature = True

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(checkpoint, sort_keys=True, separators=(",", ":"))
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            raise AnchorError(f"could not write anchor file {self.path}: {e}") from e
        return {"anchor": self.name, "location": str(self.path)}

    def checkpoints(self, log_id: str, *, pending: bool = False) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            with open(self.path, encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except (OSError, json.JSONDecodeError) as e:
            raise AnchorError(f"could not read anchor file {self.path}: {e}") from e


class UnavailableAnchor:
    """Simulates an anchor that cannot be reached (used in tests)."""

    name = "unavailable"
    requires_signature = True

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        raise AnchorError("anchor unavailable")

    def checkpoints(self, log_id: str, *, pending: bool = False) -> list[dict[str, Any]]:
        raise AnchorError("anchor unavailable")
