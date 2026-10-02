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
  recordHash,
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
  assert.equal(cp.body.head, vectors.log.at(-1).event_hash, "checkpoint commits to the log head");
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
