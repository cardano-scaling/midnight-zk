/**
 * Univariate polynomial root-finding over Fr (the BLS12-381 scalar field).
 *
 * Used by the constraint solver: a gate constraint restricted to one unknown
 * cell is a univariate polynomial of degree ≤ the constraint-system degree,
 * so its Fr-roots (the cell values repairing the constraint) are computable:
 *
 *   1. interpolate f(v) from deg+1 samples of the residual,
 *   2. g = gcd(f, X^r − X)  — the product of (X − root) over distinct
 *      Fr-roots, computed via X^r mod f (square-and-multiply, ~255 steps
 *      on degree-<16 polynomials: cheap),
 *   3. split g into linear factors (Cantor–Zassenhaus equal-degree
 *      splitting with random shifts).
 *
 * Polynomials are coefficient arrays, lowest degree first.
 */

import { Fr, R, add, sub, mul, neg, inv, mod, pow, batchInvert } from "../verifier/field";

/** Roots of a monic quadratic X^2 + bX + c via the Tonelli–Shanks sqrt. */
function quadraticRoots(b: Fr, c: Fr): Fr[] {
  const disc = mod(mul(b, b) - mul(4n, c));
  const s = sqrtFr(disc);
  if (s === null) return [];
  const inv2 = inv(2n);
  const r1 = mul(sub(s, b), inv2);
  const r2 = mul(sub(neg(s), b), inv2);
  return r1 === r2 ? [r1] : [r1, r2].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
}

/** Square root in Fr (Tonelli–Shanks); null if a is a non-residue. */
export function sqrtFr(a: Fr): Fr | null {
  if (a === 0n) return 0n;
  if (pow(a, (R - 1n) >> 1n) !== 1n) return null; // non-residue
  // Fr − 1 = 2^S · Q with S = 32.
  const S = 32n;
  const Q = (R - 1n) >> S;
  let z = 2n;
  while (pow(z, (R - 1n) >> 1n) === 1n) z += 1n; // a non-residue
  let m = S;
  let c = pow(z, Q);
  let t = pow(a, Q);
  let r = pow(a, (Q + 1n) >> 1n);
  while (t !== 1n) {
    let i = 0n;
    let t2 = t;
    while (t2 !== 1n) {
      t2 = mul(t2, t2);
      i += 1n;
    }
    const b = pow(c, 1n << (m - i - 1n));
    m = i;
    c = mul(b, b);
    t = mul(t, c);
    r = mul(r, b);
  }
  return r;
}

export type Poly = Fr[];

export function trim(p: Poly): Poly {
  let d = p.length - 1;
  while (d >= 0 && p[d] === 0n) d--;
  return p.slice(0, d + 1);
}

export const degree = (p: Poly): number => trim(p).length - 1;

/** Lagrange interpolation through (xs[i], ys[i]); xs must be distinct. */
export function interpolate(xs: Fr[], ys: Fr[]): Poly {
  const m = xs.length;
  let acc: Poly = new Array(m).fill(0n);
  // Denominators prod_{j!=i}(x_i - x_j), batch-inverted.
  const dens = xs.map((xi, i) => {
    let d = 1n;
    xs.forEach((xj, j) => {
      if (j !== i) d = mul(d, sub(xi, xj));
    });
    return d;
  });
  const invDens = batchInvert(dens);
  for (let i = 0; i < m; i++) {
    // numerator prod_{j!=i}(X - x_j), built incrementally.
    let num: Poly = [1n];
    xs.forEach((xj, j) => {
      if (j === i) return;
      const next: Poly = new Array(num.length + 1).fill(0n);
      for (let k = 0; k < num.length; k++) {
        next[k] = add(next[k], mul(num[k], neg(xj)));
        next[k + 1] = add(next[k + 1], num[k]);
      }
      num = next;
    });
    const scale = mul(ys[i], invDens[i]);
    for (let k = 0; k < num.length; k++) acc[k] = add(acc[k], mul(num[k], scale));
  }
  return trim(acc);
}

function polyMod(a: Poly, f: Poly): Poly {
  const fd = f.length - 1;
  const fLeadInv = inv(f[fd]);
  const r = [...a];
  for (let d = r.length - 1; d >= fd; d--) {
    const c = mul(r[d], fLeadInv);
    if (c === 0n) continue;
    for (let k = 0; k <= fd; k++) {
      r[d - fd + k] = sub(r[d - fd + k], mul(c, f[k]));
    }
  }
  return trim(r.slice(0, fd));
}

function polyMulMod(a: Poly, b: Poly, f: Poly): Poly {
  const out: Poly = new Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++) {
    if (a[i] === 0n) continue;
    for (let j = 0; j < b.length; j++) {
      out[i + j] = add(out[i + j], mul(a[i], b[j]));
    }
  }
  return polyMod(out, f);
}

/** base^e mod f, e a (large) non-negative integer. */
function polyPowMod(base: Poly, e: bigint, f: Poly): Poly {
  let result: Poly = [1n];
  let b = polyMod(base, f);
  let k = e;
  while (k > 0n) {
    if (k & 1n) result = polyMulMod(result, b, f);
    b = polyMulMod(b, b, f);
    k >>= 1n;
  }
  return result;
}

function polySub(a: Poly, b: Poly): Poly {
  const out: Poly = new Array(Math.max(a.length, b.length)).fill(0n);
  for (let i = 0; i < out.length; i++) out[i] = sub(a[i] ?? 0n, b[i] ?? 0n);
  return trim(out);
}

function monic(p: Poly): Poly {
  const t = trim(p);
  if (t.length === 0) return t;
  const s = inv(t[t.length - 1]);
  return t.map((c) => mul(c, s));
}

function polyGcd(a: Poly, b: Poly): Poly {
  let x = trim(a);
  let y = trim(b);
  while (y.length > 0) {
    const r = polyMod(x, y);
    x = y;
    y = r;
  }
  return monic(x);
}

/** Deterministic-enough PRNG for factorisation shifts (no security needed). */
let rngState = 0x9e3779b97f4a7c15n;
function nextShift(): Fr {
  rngState = mod(rngState * 6364136223846793005n + 1442695040888963407n);
  return rngState;
}

/**
 * All distinct roots of p in Fr. Returns [] for nonzero constants;
 * throws for the zero polynomial (every value is a root).
 */
export function rootsOf(p: Poly): Fr[] {
  const f = monic(p);
  if (f.length === 0) throw new Error("zero polynomial: every value is a root");
  if (f.length === 1) return []; // nonzero constant
  // Low-degree short-circuits avoid the expensive X^r mod f step, which
  // dominates the forward solver (most gate constraints are linear).
  if (f.length === 2) return [mul(neg(f[0]), inv(f[1]))]; // monic: X + f0
  if (f.length === 3) return quadraticRoots(f[1], f[0]); // monic: X^2 + f1 X + f0
  // g = product of (X - root) over the distinct roots: gcd(f, X^r - X).
  const xr = polyPowMod([0n, 1n], R, f);
  let g = polyGcd(polySub(xr, [0n, 1n]), f);
  const out: Fr[] = [];
  const stack: Poly[] = [g];
  while (stack.length > 0) {
    g = stack.pop()!;
    if (g.length <= 1) continue;
    if (g.length === 2) {
      out.push(mul(neg(g[0]), inv(g[1])));
      continue;
    }
    // Equal-degree splitting: gcd(g, (X+a)^((r-1)/2) - 1) is a proper factor
    // with probability ~1/2 per random shift a.
    for (;;) {
      const a = nextShift();
      const h = polyPowMod([a, 1n], (R - 1n) >> 1n, g);
      const d = polyGcd(polySub(h, [1n]), g);
      if (d.length > 1 && d.length < g.length) {
        stack.push(d);
        // g / d via repeated division: compute quotient.
        stack.push(polyDiv(g, d));
        break;
      }
    }
  }
  return out.sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
}

function polyDiv(a: Poly, b: Poly): Poly {
  const bd = b.length - 1;
  const bLeadInv = inv(b[bd]);
  const r = [...a];
  const q: Poly = new Array(a.length - bd).fill(0n);
  for (let d = r.length - 1; d >= bd; d--) {
    const c = mul(r[d], bLeadInv);
    q[d - bd] = c;
    if (c === 0n) continue;
    for (let k = 0; k <= bd; k++) r[d - bd + k] = sub(r[d - bd + k], mul(c, b[k]));
  }
  return trim(q);
}

/**
 * Roots of the univariate function v ↦ residual(v), sampled and interpolated
 * up to `maxDegree`. Returns null if the function is identically zero on the
 * sample set (constraint independent of the cell / always satisfied).
 */
export function rootsOfFunction(residual: (v: Fr) => Fr, maxDegree: number): Fr[] | null {
  const xs: Fr[] = [];
  const ys: Fr[] = [];
  for (let i = 0; i <= maxDegree; i++) {
    xs.push(BigInt(i));
    ys.push(residual(BigInt(i)));
  }
  if (ys.every((y) => y === 0n)) return null;
  return rootsOf(interpolate(xs, ys));
}
