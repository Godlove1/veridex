"""EVM anchor: Merkle roots of evidence batches in the VeridexAnchor contract.

Works with any EVM chain. ``EvmAnchor.anvil`` and ``EvmAnchor.base`` are
presets; nothing else in Veridex knows which chain is used.

Needs the optional dependency:  pip install "veridex[evm]"

What goes on-chain per batch: the log key (a hash of the log id), the batch
number, the last sequence number and the Merkle root. Never application data.

Trust
-----
The contract keeps batches per publisher account. A verifier pins three things
out-of-band, like trusted keys: the chain, the contract address and the
publisher address. The chain then authenticates who anchored a root and makes
it impossible to change afterwards, so entries need no Ed25519 signature.

The private key pays for transactions and decides what gets anchored. Keep it
out of ordinary application processes; verifiers never need it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from . import protocol as P
from .anchor import AnchorError
from .results import ConfigurationError

try:
    from eth_account import Account
    from web3 import Web3
except ImportError as e:  # pragma: no cover
    raise ImportError('the EVM anchor needs web3: pip install "veridex[evm]"') from e

ARTIFACT = json.loads(
    (Path(__file__).parent / "contracts" / "VeridexAnchor.json").read_text(encoding="utf-8")
)

ANVIL_CHAIN_ID = 31337
BASE_CHAIN_IDS = {"mainnet": 8453, "sepolia": 84532}
_PAGE = 500  # batches per getBatches call


class EvmAnchor:
    """Anchor backed by a deployed VeridexAnchor contract.

    rpc_url:          JSON-RPC endpoint.
    contract_address: the deployed VeridexAnchor.
    publisher:        account whose batches are trusted. Required for
                      verifiers; derived from ``private_key`` for writers.
    private_key:      hex key of the publishing account (writers only).
    chain_id:         expected chain id. Reads and writes fail if the endpoint
                      serves a different chain.
    block_tag:        block at which verification reads the contract:
                      "latest", "safe" or "finalized". A batch that is not in
                      that block yet is simply not anchored yet.
    verify_code:      check that the code at ``contract_address`` is exactly
                      the VeridexAnchor bytecode shipped with this package.
    """

    requires_signature = False

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        *,
        publisher: Optional[str] = None,
        private_key: Optional[str] = None,
        chain_id: Optional[int] = None,
        block_tag: str = "latest",
        verify_code: bool = True,
        timeout: float = 30.0,
        name: str = "evm",
    ):
        self.name = name
        self.block_tag = block_tag
        self.chain_id = chain_id
        self.verify_code = verify_code
        self.timeout = timeout
        self._account = Account.from_key(private_key) if private_key else None
        try:
            self.contract_address = Web3.to_checksum_address(contract_address)
            if publisher is None:
                if self._account is None:
                    raise ConfigurationError("EvmAnchor needs publisher= (verifier) or private_key= (writer)")
                self.publisher = self._account.address
            else:
                self.publisher = Web3.to_checksum_address(publisher)
        except ValueError as e:
            raise ConfigurationError(f"invalid address: {e}") from e
        if self._account is not None and self._account.address != self.publisher:
            raise ConfigurationError("private_key does not belong to the publisher address")
        self._w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
        self._contract = self._w3.eth.contract(address=self.contract_address, abi=ARTIFACT["abi"])
        self._checked = False

    def __repr__(self) -> str:  # never show the key
        return (f"EvmAnchor(name={self.name!r}, chain_id={self.chain_id}, "
                f"contract={self.contract_address}, publisher={self.publisher})")

    # ------------------------------------------------------------- presets --

    @classmethod
    def anvil(cls, contract_address: str, rpc_url: str = "http://127.0.0.1:8545", **kw: Any) -> "EvmAnchor":
        """Local development chain (Foundry's Anvil)."""
        kw.setdefault("chain_id", ANVIL_CHAIN_ID)
        kw.setdefault("name", "anvil")
        return cls(rpc_url, contract_address, **kw)

    @classmethod
    def base(cls, rpc_url: str, contract_address: str, *, network: str = "mainnet", **kw: Any) -> "EvmAnchor":
        """Base mainnet or Base Sepolia. Verification reads finalized blocks."""
        if network not in BASE_CHAIN_IDS:
            raise ConfigurationError(f"network must be one of {sorted(BASE_CHAIN_IDS)}")
        kw.setdefault("chain_id", BASE_CHAIN_IDS[network])
        kw.setdefault("block_tag", "finalized")
        kw.setdefault("name", "base" if network == "mainnet" else f"base-{network}")
        return cls(rpc_url, contract_address, **kw)

    @classmethod
    def deploy(
        cls, rpc_url: str, private_key: str, *, chain_id: Optional[int] = None, timeout: float = 120.0
    ) -> str:
        """Deploy a VeridexAnchor contract and return its address. One contract
        can serve any number of publishers and logs."""
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
            actual = w3.eth.chain_id
            if chain_id is not None and actual != chain_id:
                raise AnchorError(f"endpoint serves chain {actual}, expected {chain_id}")
            account = Account.from_key(private_key)
            tx = w3.eth.contract(abi=ARTIFACT["abi"], bytecode=ARTIFACT["bytecode"]).constructor().build_transaction({
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                "chainId": actual,
            })
            signed = account.sign_transaction(tx)
            receipt = w3.eth.wait_for_transaction_receipt(
                w3.eth.send_raw_transaction(signed.raw_transaction), timeout=timeout)
        except AnchorError:
            raise
        except Exception as e:
            raise AnchorError(f"could not deploy VeridexAnchor: {e}") from e
        if receipt["status"] != 1 or not receipt["contractAddress"]:
            raise AnchorError("VeridexAnchor deployment transaction failed")
        return receipt["contractAddress"]

    # ------------------------------------------------------------ plumbing --

    def _check(self) -> int:
        """Confirm the endpoint is the pinned chain and the address holds the
        VeridexAnchor code. Returns the chain id."""
        actual = self._w3.eth.chain_id
        if self.chain_id is not None and actual != self.chain_id:
            raise AnchorError(f"endpoint serves chain {actual}, expected {self.chain_id}")
        if self.verify_code and not self._checked:
            code = bytes(self._w3.eth.get_code(self.contract_address))
            if "0x" + Web3.keccak(code).hex().removeprefix("0x") != ARTIFACT["runtime_code_hash"]:
                raise AnchorError(f"the code at {self.contract_address} is not VeridexAnchor")
        self._checked = True
        return actual

    def _info(self, chain_id: int) -> dict[str, Any]:
        return {"anchor": self.name, "chain_id": chain_id, "contract": self.contract_address,
                "publisher": self.publisher}

    def _read(self, log_id: str, tag: str) -> tuple[int, list[tuple[bytes, int, int]]]:
        chain_id = self._check()
        block = self._w3.eth.get_block(tag)["number"]  # one consistent view for every call
        if not self._w3.eth.get_code(self.contract_address, block_identifier=block):
            return chain_id, []  # the contract itself is newer than this block
        key = bytes.fromhex(P.log_key(log_id))
        count = self._contract.functions.batchCount(self.publisher, key).call(block_identifier=block)
        batches: list[tuple[bytes, int, int]] = []
        while len(batches) < count:
            page = self._contract.functions.getBatches(
                self.publisher, key, len(batches) + 1, _PAGE).call(block_identifier=block)
            if not page:
                raise AnchorError("contract returned fewer batches than it reported")
            batches.extend((bytes(b[0]), int(b[1]), int(b[2])) for b in page)
        return chain_id, batches

    # -------------------------------------------------------------- Anchor --

    def checkpoints(self, log_id: str, *, pending: bool = False) -> list[dict[str, Any]]:
        try:
            chain_id, batches = self._read(log_id, "latest" if pending else self.block_tag)
        except AnchorError:
            raise
        except Exception as e:
            raise AnchorError(f"could not read anchor {self.name}: {e}") from e
        info = self._info(chain_id)
        return [
            dict(info, log_id=log_id, batch=n, seq=to_seq, merkle_root=root.hex(), anchored_at=ts)
            for n, (root, to_seq, ts) in enumerate(batches, start=1)
        ]

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        if self._account is None:
            raise AnchorError("this EvmAnchor has no private key; it can only verify")
        batch, seq, root = checkpoint["batch"], checkpoint["seq"], checkpoint["merkle_root"]
        try:
            chain_id, existing = self._read(checkpoint["log_id"], "latest")
            if batch <= len(existing):
                # A previous attempt already landed. The contract is write-once,
                # so the only acceptable outcome is that it holds the same batch.
                if (existing[batch - 1][0].hex(), existing[batch - 1][1]) != (root, seq):
                    raise AnchorError(f"batch {batch} is already anchored with a different root")
                return dict(self._info(chain_id), already_anchored=True)
            tx = self._contract.functions.anchor(
                bytes.fromhex(P.log_key(checkpoint["log_id"])), batch, seq, bytes.fromhex(root)
            ).build_transaction({
                "from": self.publisher,
                "nonce": self._w3.eth.get_transaction_count(self.publisher, "pending"),
                "chainId": chain_id,
            })
            signed = self._account.sign_transaction(tx)
            receipt = self._w3.eth.wait_for_transaction_receipt(
                self._w3.eth.send_raw_transaction(signed.raw_transaction), timeout=self.timeout)
        except AnchorError:
            raise
        except Exception as e:
            raise AnchorError(f"could not anchor batch {batch} on {self.name}: {e}") from e
        if receipt["status"] != 1:
            raise AnchorError(f"anchor transaction for batch {batch} reverted")
        return dict(
            self._info(chain_id),
            transaction_hash="0x" + bytes(receipt["transactionHash"]).hex(),
            block_number=receipt["blockNumber"],
        )
