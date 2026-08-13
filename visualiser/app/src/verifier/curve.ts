/**
 * BLS12-381 group operations via @noble/curves.
 *
 * midnight-curves (blstrs-derived) uses the ZCash compressed encoding for
 * points, which is exactly what noble's `fromHex`/`fromBytes` expect:
 * G1 = 48 bytes, G2 = 96 bytes, identity = 0xc0 00...00.
 */

import { bls12_381 } from "@noble/curves/bls12-381.js";
import { pippenger } from "@noble/curves/abstract/curve.js";
import { Fr, mod, bytesToHex } from "./field";

export type G1 = InstanceType<typeof bls12_381.G1.Point>;
export type G2 = InstanceType<typeof bls12_381.G2.Point>;

export const G1Point = bls12_381.G1.Point;
export const G2Point = bls12_381.G2.Point;

/** Decompresses a 48-byte compressed G1 point from hex (throws if invalid). */
export function g1FromHex(hex: string): G1 {
  if (hex.length !== 96) throw new Error(`G1 hex must be 96 chars, got ${hex.length}`);
  return G1Point.fromHex(hex);
}

/** Decompresses a 96-byte compressed G2 point from hex. */
export function g2FromHex(hex: string): G2 {
  if (hex.length !== 192) throw new Error(`G2 hex must be 192 chars, got ${hex.length}`);
  return G2Point.fromHex(hex);
}

export function g1ToHex(p: G1): string {
  return bytesToHex(p.toBytes(true));
}

/** Multi-scalar multiplication sum(scalars_i * points_i). */
export function msm(points: G1[], scalars: Fr[]): G1 {
  if (points.length !== scalars.length) throw new Error("msm length mismatch");
  // noble's pippenger MSM requires non-zero scalars to be < r and rejects
  // zeros; filter them (0 * P = identity).
  const ps: G1[] = [];
  const ss: bigint[] = [];
  for (let i = 0; i < points.length; i++) {
    const s = mod(scalars[i]);
    if (s === 0n) continue;
    ps.push(points[i]);
    ss.push(s);
  }
  if (ps.length === 0) return G1Point.ZERO;
  return pippenger(G1Point, ps, ss);
}

/**
 * The final SHPLONK check
 *   e(W, [s]_2) = e(F - v*[1]_1 + u*W, [1]_2)
 * rearranged as a product of pairings equal to 1:
 *   e(-W, [s]_2) * e(F - v*[1]_1 + u*W, [1]_2) == 1.
 */
export function pairingCheck(pairs: { g1: G1; g2: G2 }[]): boolean {
  const nonInfinity = pairs.filter((p) => !p.g1.is0());
  const gt = bls12_381.pairingBatch(
    nonInfinity.map((p) => ({ g1: p.g1, g2: p.g2 })),
    true,
  );
  return bls12_381.fields.Fp12.eql(gt, bls12_381.fields.Fp12.ONE);
}
