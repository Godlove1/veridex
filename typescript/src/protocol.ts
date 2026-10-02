/**
 * Veridex protocol v1: hashing, bodies, signatures, offline log verification.
 * Must match python/veridex/protocol.py. Uses only node:crypto.
 */

import { createHash, createPublicKey, createPrivateKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalBytes } from "./canonical.ts";

export const PROTOCOL_VERSION = 1;
export const HASH_ALGORITHM = "SHA-256";
export const CANONICALIZATION = "vcf-1";
export const MERKLE = "vmt-1";
export const CHECKPOINT_VERSION = 2; // v1 (stage 1) committed to the log head only
export const GENESIS_HASH = "0".repeat(64);

export type Op = "CONFIGURE" | "CREATE" | "UPDATE" | "DELETE";

export interface EventBody {
  v: 1;
  seq: number;
  op: Op;
  resource: string;
  record_id: string | null;
  version: number;
  record_hash: string | null;
  prev_event_hash: string | null;
  prev_log_hash: string;
  config_hash: string;
  created_at: string;
}

export interface SignedEvent {
  body: EventBody;
  event_hash: string;
  key_id: string;
  signature: string;
}

/** A checkpoint commits to batch number `batch`: events `from_seq..seq`. */
export interface CheckpointBody {
  v: 2;
  log_id: string;
  batch: number;
  from_seq: number;
  seq: number;
  merkle_root: string;
  created_at: string;
}

/** H(tag, v) = SHA256("veridex/v1/" || tag || 0x00 || VCF-1(v)) */
export function taggedHash(tag: string, value: unknown): string {
  const h = createHash("sha256");
  h.update("veridex/v1/" + tag, "ascii");
  h.update(new Uint8Array([0]));
  h.update(canonicalBytes(value));
  return h.digest("hex");
}

export const recordHash = (protectedFields: Record<string, unknown>) => taggedHash("record", protectedFields);
export const configHash = (body: Record<string, unknown>) => taggedHash("config", body);
export const eventHash = (body: EventBody) => taggedHash("event", body);
export const checkpointHash = (body: CheckpointBody) => taggedHash("checkpoint", body);
/** 32-byte key under which a log's batches are anchored on a blockchain. */
export const logKey = (logId: string) => taggedHash("log", logId);

// ---------------------------------------------------------------- merkle --
//
// VMT-1: the RFC 6962 / RFC 9162 Merkle tree over the event hashes of one
// batch, in seq order. Leaves and interior nodes are domain-separated, and an
// odd node is promoted (never duplicated), so a root commits to exactly one
// ordered list of leaves.

function hash32(hashHex: string): Buffer {
  if (typeof hashHex !== "string" || !/^[0-9a-f]{64}$/.test(hashHex)) {
    throw new Error("expected a 64-character lowercase hex hash");
  }
  return Buffer.from(hashHex, "hex");
}

const LEAF_PREFIX = Buffer.from("veridex/v1/merkle-leaf\0", "ascii");
const NODE_PREFIX = Buffer.from("veridex/v1/merkle-node\0", "ascii");

const merkleLeaf = (eventHashHex: string): Buffer =>
  createHash("sha256").update(LEAF_PREFIX).update(hash32(eventHashHex)).digest();
const merkleNode = (left: Buffer, right: Buffer): Buffer =>
  createHash("sha256").update(NODE_PREFIX).update(left).update(right).digest();

/** Largest power of two strictly less than n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function subtree(leaves: Buffer[]): Buffer {
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return merkleNode(subtree(leaves.slice(0, k)), subtree(leaves.slice(k)));
}

/** Merkle root of a non-empty, ordered list of event hashes. */
export function merkleRoot(eventHashes: string[]): string {
  if (eventHashes.length === 0) throw new Error("a batch must contain at least one event");
  return subtree(eventHashes.map(merkleLeaf)).toString("hex");
}

/** Inclusion path (sibling hashes, leaf to root) for the leaf at `index`. */
export function merklePath(eventHashes: string[], index: number): string[] {
  if (!Number.isInteger(index) || index < 0 || index >= eventHashes.length) {
    throw new Error("leaf index out of range");
  }
  let leaves = eventHashes.map(merkleLeaf);
  const path: Buffer[] = [];
  while (leaves.length > 1) {
    const k = split(leaves.length);
    if (index < k) {
      path.push(subtree(leaves.slice(k)));
      leaves = leaves.slice(0, k);
    } else {
      path.push(subtree(leaves.slice(0, k)));
      leaves = leaves.slice(k);
      index -= k;
    }
  }
  return path.reverse().map((p) => p.toString("hex"));
}

/**
 * True iff `eventHashHex` is leaf `leafIndex` of the `treeSize`-leaf tree with
 * root `root` (RFC 9162 section 2.1.3.2). Never throws.
 */
export function verifyInclusion(
  eventHashHex: string,
  leafIndex: number,
  treeSize: number,
  path: string[],
  root: string,
): boolean {
  try {
    if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize)) return false;
    if (leafIndex < 0 || leafIndex >= treeSize) return false;
    // BigInt: JavaScript's bitwise operators truncate numbers to 32 bits.
    let fn = BigInt(leafIndex);
    let sn = BigInt(treeSize) - 1n;
    let r = merkleLeaf(eventHashHex);
    for (const p of path) {
      const sibling = hash32(p);
      if (sn === 0n) return false;
      if (fn & 1n || fn === sn) {
        r = merkleNode(sibling, r);
        while (!(fn & 1n) && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      } else {
        r = merkleNode(r, sibling);
      }
      fn >>= 1n;
      sn >>= 1n;
    }
    return sn === 0n && r.equals(hash32(root));
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ keys --

// DER prefixes for raw 32-byte Ed25519 keys (RFC 8410).
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function keyId(publicKeyHex: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 16);
}

function publicKeyFromHex(hex: string): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
}

export class Signer {
  readonly publicKeyHex: string;
  readonly keyId: string;
  #key: KeyObject;

  constructor(seedHex: string) {
    const seed = Buffer.from(seedHex, "hex");
    if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes (64 hex chars)");
    this.#key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
    const spki = createPublicKey(this.#key).export({ format: "der", type: "spki" });
    this.publicKeyHex = spki.subarray(SPKI_PREFIX.length).toString("hex");
    this.keyId = keyId(this.publicKeyHex);
  }

  sign(hashHex: string): string {
    return sign(null, Buffer.from(hashHex, "hex"), this.#key).toString("hex");
  }
}

/** Keys the verifier trusts. Load them from configuration, never from the protected database. */
export class TrustedKeys {
  #keys = new Map<string, KeyObject>();

  constructor(publicKeysHex: Iterable<string>) {
    for (const raw of publicKeysHex) {
      const pk = raw.trim().toLowerCase();
      if (pk) this.#keys.set(keyId(pk), publicKeyFromHex(pk));
    }
    if (this.#keys.size === 0) throw new Error("at least one trusted public key is required");
  }

  verify(kid: string, hashHex: string, signatureHex: string): boolean {
    const key = this.#keys.get(kid);
    if (!key) return false;
    try {
      return verify(null, Buffer.from(hashHex, "hex"), key, Buffer.from(signatureHex, "hex"));
    } catch {
      return false;
    }
  }
}

// ----------------------------------------------------- offline verification --

export interface LogProblem {
  reason: string;
  seq?: number;
  message: string;
}

/**
 * Verify an exported event log without database access: hashes, signatures,
 * global chain, per-record chains and transitions. Mirrors the log-level part
 * of Veridex.audit() in Python. Does not check business rows or anchors.
 */
export function verifyLog(events: SignedEvent[], trusted: TrustedKeys): LogProblem[] {
  const problems: LogProblem[] = [];
  let prevLog = GENESIS_HASH;
  const lastRec = new Map<string, EventBody & { event_hash: string }>();
  const lastCfg = new Map<string, EventBody & { event_hash: string }>();

  events.forEach((e, i) => {
    const b = e.body;
    const seq = b.seq;
    if (seq !== i + 1) problems.push({ reason: "SEQ_GAP", seq, message: `expected seq ${i + 1}` });
    let recomputed: string | null = null;
    try {
      recomputed = eventHash(b);
    } catch (err) {
      problems.push({ reason: "EVENT_HASH_MISMATCH", seq, message: String(err) });
    }
    if (recomputed !== e.event_hash) {
      problems.push({ reason: "EVENT_HASH_MISMATCH", seq, message: "event does not match its hash" });
    }
    if (!trusted.verify(e.key_id, e.event_hash, e.signature)) {
      problems.push({ reason: "BAD_SIGNATURE", seq, message: `signature invalid or key ${e.key_id} not trusted` });
    }
    if (b.prev_log_hash !== prevLog) {
      problems.push({ reason: "LOG_CHAIN_BROKEN", seq, message: "prev_log_hash does not link" });
    }
    prevLog = e.event_hash;
    const cur = { ...b, event_hash: e.event_hash };

    if (b.op === "CONFIGURE") {
      const lc = lastCfg.get(b.resource);
      if (b.prev_event_hash !== (lc?.event_hash ?? null) || b.version !== (lc ? lc.version + 1 : 1)) {
        problems.push({ reason: "RECORD_CHAIN_BROKEN", seq, message: "configuration chain broken" });
      }
      lastCfg.set(b.resource, cur);
      return;
    }
    if (!["CREATE", "UPDATE", "DELETE"].includes(b.op)) {
      problems.push({ reason: "INVALID_TRANSITION", seq, message: `unknown op ${b.op}` });
      return;
    }
    if (lastCfg.get(b.resource)?.config_hash !== b.config_hash) {
      problems.push({ reason: "CONFIG_REFERENCE_INVALID", seq, message: "not made under the current configuration" });
    }
    const key = JSON.stringify([b.resource, b.record_id]);
    const lr = lastRec.get(key);
    if (b.prev_event_hash !== (lr?.event_hash ?? null) || b.version !== (lr ? lr.version + 1 : 1)) {
      problems.push({ reason: "RECORD_CHAIN_BROKEN", seq, message: `record chain broken for ${b.record_id}` });
    }
    const live = lr !== undefined && lr.op !== "DELETE";
    if ((b.op === "CREATE" && live) || (b.op !== "CREATE" && !live)) {
      problems.push({ reason: "INVALID_TRANSITION", seq, message: `${b.op} not valid here` });
    }
    if (b.op === "DELETE" && lr && b.record_hash !== lr.record_hash) {
      problems.push({ reason: "INVALID_TRANSITION", seq, message: "DELETE does not preserve last state" });
    }
    lastRec.set(key, cur);
  });
  return problems;
}
