/**
 * Veridex Canonical Form, version 1 (VCF-1). Must match python/veridex/canonical.py
 * byte-for-byte. See protocol/SPEC.md section 2.
 */

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER; // 2^53 - 1

export class CanonicalizationError extends Error {
  readonly code = "CANONICALIZATION_ERROR";
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

const encoder = new TextEncoder();

function nfc(s: string): string {
  if (!s.isWellFormed()) {
    throw new CanonicalizationError("string contains a lone surrogate");
  }
  return s.normalize("NFC");
}

function encodeString(raw: string): string {
  const s = nfc(raw);
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    const short = SHORT_ESCAPES[cp];
    if (short !== undefined) out += short;
    else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function encode(value: unknown, depth: number): string {
  if (depth > 64) throw new CanonicalizationError("nesting deeper than 64 levels");
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new CanonicalizationError("floats are not allowed in VCF-1; use a decimal string");
    }
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalizationError(`integer ${value} outside safe range; encode it as a string`);
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value === "bigint") {
    throw new CanonicalizationError("bigint is not allowed; encode it as a decimal string");
  }
  if (typeof value === "string") return encodeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => encode(v, depth + 1)).join(",") + "]";
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalizationError(
        `type ${proto?.constructor?.name ?? "unknown"} is not canonicalizable; normalize it first`,
      );
    }
    const seen = new Set<string>();
    const entries: { key: string; bytes: Uint8Array; value: unknown }[] = [];
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const nk = nfc(k);
      if (seen.has(nk)) {
        throw new CanonicalizationError(`duplicate key after NFC normalization: ${JSON.stringify(nk)}`);
      }
      seen.add(nk);
      entries.push({ key: nk, bytes: encoder.encode(nk), value: v });
    }
    entries.sort((a, b) => compareBytes(a.bytes, b.bytes));
    return "{" + entries.map((e) => encodeString(e.key) + ":" + encode(e.value, depth + 1)).join(",") + "}";
  }
  throw new CanonicalizationError(`type ${typeof value} is not canonicalizable`);
}

/** Return the VCF-1 canonical string for `value`. */
export function canonicalize(value: unknown): string {
  return encode(value, 0);
}

/** UTF-8 bytes of the VCF-1 canonical string. */
export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value));
}
