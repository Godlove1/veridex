/**
 * Veridex protocol v1: hashing, bodies, signatures, offline log verification.
 * Must match python/veridex/protocol.py. Uses only node:crypto.
 */

import { createHash, createPublicKey, createPrivateKey, sign, verify, type KeyObject } from "node:crypto";
import { canonicalBytes } from "./canonical.ts";

export const PROTOCOL_VERSION = 1;
export const HASH_ALGORITHM = "SHA-256";
export const CANONICALIZATION = "vcf-1";
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

export interface CheckpointBody {
  v: 1;
  log_id: string;
  seq: number;
  head: string;
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
