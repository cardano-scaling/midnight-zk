/**
 * Scalar-field (Fr of BLS12-381, called `Fq` in midnight-curves) arithmetic
 * over native BigInt.
 *
 * Encoding convention (matches `proofs/src/dev/json_dump.rs`): scalars are
 * canonical 32-byte little-endian, lowercase hex, no 0x prefix.
 */

/** The BLS12-381 scalar field modulus r. */
export const R =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

/** Multiplicative generator of Fr (midnight-curves: GENERATOR = 7). */
export const GENERATOR = 7n;

/** Fr is 2-adic with 2^32 | r - 1. */
export const S = 32n;

export type Fr = bigint;

export function mod(a: bigint): Fr {
  const m = a % R;
  return m < 0n ? m + R : m;
}

export const add = (a: Fr, b: Fr): Fr => mod(a + b);
export const sub = (a: Fr, b: Fr): Fr => mod(a - b);
export const mul = (a: Fr, b: Fr): Fr => mod(a * b);
export const neg = (a: Fr): Fr => mod(-a);

export function pow(base: Fr, exp: bigint): Fr {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mul(result, b);
    b = mul(b, b);
    e >>= 1n;
  }
  return result;
}

/** Modular inverse via Fermat (r is prime). Throws on zero. */
export function inv(a: Fr): Fr {
  if (mod(a) === 0n) throw new Error("division by zero in Fr");
  return pow(a, R - 2n);
}

/**
 * Batch inversion: returns the element-wise inverses using a single `inv`.
 * Zero entries are not allowed.
 */
export function batchInvert(values: Fr[]): Fr[] {
  const prefix: Fr[] = new Array(values.length);
  let acc = 1n;
  for (let i = 0; i < values.length; i++) {
    prefix[i] = acc;
    acc = mul(acc, values[i]);
  }
  let accInv = inv(acc);
  const out: Fr[] = new Array(values.length);
  for (let i = values.length - 1; i >= 0; i--) {
    out[i] = mul(accInv, prefix[i]);
    accInv = mul(accInv, values[i]);
  }
  return out;
}

/**
 * The 2^k-th primitive root of unity used by the evaluation domain:
 * omega_k = g^((r-1) / 2^k).
 */
export function omega(k: number): Fr {
  return pow(GENERATOR, (R - 1n) >> BigInt(k));
}

/** ROOT_OF_UNITY = g^((r-1)/2^S), the maximal 2-adic root. */
export const ROOT_OF_UNITY = omega(Number(S));

/**
 * DELTA = g^(2^S): generator of the multiplicative subgroup of order
 * (r-1)/2^S, used to shift permutation-argument columns.
 */
export const DELTA = pow(GENERATOR, 1n << S);

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/** Parses a 32-byte little-endian hex scalar. Throws if non-canonical. */
export function fromLEHex(hex: string): Fr {
  if (hex.length !== 64) throw new Error(`scalar hex must be 64 chars, got ${hex.length}`);
  const v = leBytesToBigint(hexToBytes(hex));
  if (v >= R) throw new Error(`non-canonical scalar: ${hex}`);
  return v;
}

/** Serialises to 32-byte little-endian lowercase hex. */
export function toLEHex(v: Fr): string {
  return bytesToHex(bigintToLEBytes(mod(v), 32));
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at ${2 * i}`);
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function leBytesToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

export function bigintToLEBytes(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let x = v;
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("value does not fit in the requested length");
  return out;
}
