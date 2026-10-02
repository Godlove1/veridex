import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  CanonicalizationError,
  Signer,
  TrustedKeys,
  canonicalize,
  checkpointHash,
  configHash,
  eventHash,
  logKey,
  merklePath,
  merkleRoot,
  recordHash,
  verifyInclusion,
  verifyLog,
  type SignedEvent,
} from "../src/index.ts";

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../protocol/test-vectors/vectors.json", import.meta.url)), "utf8"),
);

test("canonical form matches Python byte-for-byte", () => {
  for (const c of vectors.canonical) {
    assert.equal(canonicalize(c.input), c.canonical, c.name);
    assert.equal(recordHash(c.input), c.record_hash, c.name);
  }
});

test("invalid inputs are rejected", () => {
  for (const c of vectors.invalid) {
    assert.throws(() => canonicalize(c.input), CanonicalizationError, c.name);
  }
  assert.throws(() => canonicalize({ x: "\uD800" }), CanonicalizationError, "lone surrogate");
  assert.throws(() => canonicalize({ x: 10n }), CanonicalizationError, "bigint");
  assert.throws(() => canonicalize({ x: new Date() }), CanonicalizationError, "Date");
});

test("record hashes match", () => {
  for (const r of vectors.records) assert.equal(recordHash(r.input), r.record_hash);
});

test("config hash matches", () => {
  assert.equal(canonicalize(vectors.config.body), vectors.config.canonical);
  assert.equal(configHash(vectors.config.body), vectors.config.config_hash);
});

test("event hashes and Ed25519 signatures match", () => {
  const signer = new Signer(vectors.key.seed);
  assert.equal(signer.publicKeyHex, vectors.key.public_key);
  assert.equal(signer.keyId, vectors.key.key_id);
  for (const e of vectors.log) {
    assert.equal(canonicalize(e.body), e.canonical);
    assert.equal(eventHash(e.body), e.event_hash);
    assert.equal(signer.sign(e.event_hash), e.signature, "Ed25519 is deterministic");
  }
});

test("checkpoint hash and signature match", () => {
  const cp = vectors.checkpoint;
  assert.equal(checkpointHash(cp.body), cp.checkpoint_hash);
  const trusted = new TrustedKeys([vectors.key.public_key]);
  assert.ok(trusted.verify(cp.key_id, cp.checkpoint_hash, cp.signature));
  const hashes = vectors.log.map((e: SignedEvent) => e.event_hash);
  assert.equal(cp.body.merkle_root, merkleRoot(hashes), "checkpoint commits to the batch's Merkle root");
  assert.equal(logKey(vectors.log_key.log_id), vectors.log_key.log_key);
});

test("Merkle roots and inclusion paths match", () => {
  for (const t of vectors.merkle) {
    const n = t.leaves.length;
    assert.equal(merkleRoot(t.leaves), t.root, `root of ${n} leaves`);
    t.leaves.forEach((leaf: string, i: number) => {
      assert.deepEqual(merklePath(t.leaves, i), t.paths[i], `path ${i} of ${n}`);
      assert.ok(verifyInclusion(leaf, i, n, t.paths[i], t.root), `inclusion ${i} of ${n}`);
    });
  }
});

test("inclusion proofs reject anything but the exact leaf, position and root", () => {
  const t = vectors.merkle.find((m: { leaves: string[] }) => m.leaves.length === 7);
  const [leaf, path, root, n] = [t.leaves[2], t.paths[2], t.root, 7];
  assert.ok(verifyInclusion(leaf, 2, n, path, root));
  assert.ok(!verifyInclusion(t.leaves[3], 2, n, path, root), "different leaf");
  assert.ok(!verifyInclusion(leaf, 3, n, path, root), "different position");
  assert.ok(!verifyInclusion(leaf, 2, 4, path, root), "tree size with a different path shape");
  assert.ok(!verifyInclusion(leaf, 2, n, path.slice(1), root), "truncated path");
  assert.ok(!verifyInclusion(leaf, 2, n, [...path, path[0]], root), "extended path");
  assert.ok(!verifyInclusion(leaf, 2, n, path, "0".repeat(64)), "different root");
  assert.ok(!verifyInclusion(leaf, 7, n, path, root), "index out of range");
  assert.ok(!verifyInclusion(leaf, 2, n, ["zz"], root), "malformed path");
  // An interior node must not be accepted as a leaf (leaf/node domain separation).
  assert.ok(!verifyInclusion(path[0], 1, 2, [], root));
  assert.throws(() => merkleRoot([]));
});

test("offline log verification accepts the valid log", () => {
  const trusted = new TrustedKeys([vectors.key.public_key]);
  assert.deepEqual(verifyLog(vectors.log as SignedEvent[], trusted), []);
});

test("offline log verification detects tampering", () => {
  const trusted = new TrustedKeys([vectors.key.public_key]);
  const clone = (): SignedEvent[] => structuredClone(vectors.log);

  const edited = clone();
  edited[1].body.record_hash = "a".repeat(64);
  assert.ok(verifyLog(edited, trusted).some((p) => p.reason === "EVENT_HASH_MISMATCH"));

  const rehashed = clone();
  rehashed[1].body.record_hash = "a".repeat(64);
  rehashed[1].event_hash = eventHash(rehashed[1].body);
  assert.ok(verifyLog(rehashed, trusted).some((p) => p.reason === "BAD_SIGNATURE"));

  const truncated = clone();
  truncated.splice(2, 1);
  const reasons = verifyLog(truncated, trusted).map((p) => p.reason);
  assert.ok(reasons.includes("SEQ_GAP") && reasons.includes("LOG_CHAIN_BROKEN"));

  const untrusted = new TrustedKeys([new Signer("11".repeat(32)).publicKeyHex]);
  assert.ok(verifyLog(clone(), untrusted).every((p) => p.reason === "BAD_SIGNATURE"));
});
