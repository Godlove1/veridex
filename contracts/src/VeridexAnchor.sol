// SPDX-License-Identifier: UNLICENSED
// The repository has not chosen a license yet; update this line when it does.
pragma solidity 0.8.30;

/// @title VeridexAnchor
/// @notice Write-once registry of Merkle roots of Veridex evidence batches.
///
/// It stores cryptographic commitments only: a 32-byte Merkle root and the
/// sequence number the batch ends at. No application data ever reaches it.
///
/// Batches are namespaced by the account that anchors them. A verifier pins
/// (chain, contract, publisher) out-of-band and reads only that publisher's
/// batches, so anybody else writing to the same contract cannot affect it.
///
/// There is no owner, no upgrade path and no way to change or delete a batch.
/// A publisher can only append the next batch of a log.
contract VeridexAnchor {
    struct Batch {
        bytes32 merkleRoot;
        uint64 toSeq; // last event sequence number covered by this batch
        uint64 timestamp; // block timestamp at which the batch was anchored
    }

    uint256 public constant PROTOCOL_VERSION = 1;

    // publisher => log key => batches; batch number n is stored at index n - 1
    mapping(address => mapping(bytes32 => Batch[])) private _batches;

    event Anchored(
        address indexed publisher, bytes32 indexed logKey, uint64 indexed batch, uint64 toSeq, bytes32 merkleRoot
    );

    error WrongBatchNumber(uint256 expected);
    error SeqNotIncreasing(uint64 lastSeq);
    error EmptyRoot();

    /// @notice Anchor batch number `batch` of log `logKey` for the caller.
    /// @dev Batches are numbered 1, 2, 3, ... with strictly increasing `toSeq`.
    function anchor(bytes32 logKey, uint64 batch, uint64 toSeq, bytes32 merkleRoot) external {
        Batch[] storage list = _batches[msg.sender][logKey];
        uint256 count = list.length;
        if (batch != count + 1) revert WrongBatchNumber(count + 1);
        uint64 lastSeq = count == 0 ? 0 : list[count - 1].toSeq;
        if (toSeq <= lastSeq) revert SeqNotIncreasing(lastSeq);
        if (merkleRoot == bytes32(0)) revert EmptyRoot();
        list.push(Batch(merkleRoot, toSeq, uint64(block.timestamp)));
        emit Anchored(msg.sender, logKey, batch, toSeq, merkleRoot);
    }

    /// @notice Number of batches `publisher` has anchored for `logKey`.
    function batchCount(address publisher, bytes32 logKey) external view returns (uint256) {
        return _batches[publisher][logKey].length;
    }

    /// @notice Up to `maxCount` batches starting at batch number `fromBatch` (1-based).
    function getBatches(address publisher, bytes32 logKey, uint256 fromBatch, uint256 maxCount)
        external
        view
        returns (Batch[] memory page)
    {
        Batch[] storage list = _batches[publisher][logKey];
        uint256 count = list.length;
        if (fromBatch == 0 || fromBatch > count) return new Batch[](0);
        uint256 size = count - fromBatch + 1;
        if (size > maxCount) size = maxCount;
        page = new Batch[](size);
        for (uint256 i = 0; i < size; i++) {
            page[i] = list[fromBatch - 1 + i];
        }
    }
}
