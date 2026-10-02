"""Compile VeridexAnchor.sol and write the artifact the Python SDK ships.

    forge build --root contracts && python contracts/build.py

Commit the result. CI rebuilds it and fails if it differs, so the bytecode in
python/veridex/contracts/ always corresponds to contracts/src/.
"""

from __future__ import annotations

import json
from pathlib import Path

from eth_utils import keccak

ROOT = Path(__file__).resolve().parent
FORGE_OUT = ROOT / "out" / "VeridexAnchor.sol" / "VeridexAnchor.json"
ARTIFACT = ROOT.parent / "python" / "veridex" / "contracts" / "VeridexAnchor.json"


def main() -> None:
    built = json.loads(FORGE_OUT.read_text(encoding="utf-8"))
    runtime = built["deployedBytecode"]["object"]
    artifact = {
        "contract": "VeridexAnchor",
        "source": "contracts/src/VeridexAnchor.sol",
        "compiler": {"solc": "0.8.30", "evm_version": "paris", "optimizer_runs": 200, "metadata": "none"},
        "abi": built["abi"],
        "bytecode": built["bytecode"]["object"],
        "runtime_bytecode": runtime,
        "runtime_code_hash": "0x" + keccak(hexstr=runtime).hex(),
    }
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {ARTIFACT} (runtime code hash {artifact['runtime_code_hash']})")


if __name__ == "__main__":
    main()
