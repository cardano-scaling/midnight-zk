/**
 * The recursive expression AST of vk.json (see `proofs/src/dev/json_dump.rs`)
 * and its evaluator.
 *
 * One evaluator, two bindings:
 *  - the verifier binds query indices to the proof's evaluation vectors
 *    (`QueryBinding`), evaluating gates at the challenge point x;
 *  - the table view binds (column, rotation) to cell values at a concrete
 *    row (`RowBinding`), evaluating gates over the trace.
 */

import { Fr, add, mul, neg, mod, fromLEHex } from "./field";

export interface QueryRef {
  query: number;
  column: number;
  rotation: number;
}

export type Expr =
  | { const: string }
  | { fixed: QueryRef }
  | { advice: QueryRef }
  | { instance: QueryRef }
  | { neg: Expr }
  | { sum: [Expr, Expr] }
  | { prod: [Expr, Expr] }
  | { scaled: [string, Expr] };

/** Resolves leaves by query index (the verifier's evaluation vectors). */
export interface QueryBinding {
  kind: "query";
  fixed: Fr[];
  advice: Fr[];
  instance: Fr[];
}

/** Resolves leaves by (column, rotation) relative to a row (the table). */
export interface RowBinding {
  kind: "row";
  /** cell(kind, columnIndex, row) -> value; row already includes rotation. */
  cell: (kind: "fixed" | "advice" | "instance", column: number, row: number) => Fr;
  row: number;
  /** Domain size, for rotation wrap-around. */
  n: number;
}

export type Binding = QueryBinding | RowBinding;

function leaf(binding: Binding, kind: "fixed" | "advice" | "instance", q: QueryRef): Fr {
  if (binding.kind === "query") {
    return binding[kind][q.query];
  }
  const row = (((binding.row + q.rotation) % binding.n) + binding.n) % binding.n;
  return binding.cell(kind, q.column, row);
}

export function evaluate(e: Expr, binding: Binding): Fr {
  if ("const" in e) return fromLEHex(e.const);
  if ("fixed" in e) return leaf(binding, "fixed", e.fixed);
  if ("advice" in e) return leaf(binding, "advice", e.advice);
  if ("instance" in e) return leaf(binding, "instance", e.instance);
  if ("neg" in e) return neg(evaluate(e.neg, binding));
  if ("sum" in e) return add(evaluate(e.sum[0], binding), evaluate(e.sum[1], binding));
  if ("prod" in e) return mul(evaluate(e.prod[0], binding), evaluate(e.prod[1], binding));
  if ("scaled" in e) return mul(fromLEHex(e.scaled[0]), evaluate(e.scaled[1], binding));
  throw new Error(`unknown expression node: ${JSON.stringify(e)}`);
}

/**
 * Finds the fixed column of the unique simple (multiplicative) selector in a
 * constraint, or null. Mirrors `specialize.py::find_simple_selector`: simple
 * selectors only ever multiply the rest of the constraint, so the first
 * simple-selector fixed leaf (depth-first) is the factored-out kappa.
 */
export function findSimpleSelector(e: Expr, simple: Set<number>): number | null {
  if ("fixed" in e) return simple.has(e.fixed.column) ? e.fixed.column : null;
  if ("neg" in e) return findSimpleSelector(e.neg, simple);
  if ("scaled" in e) return findSimpleSelector(e.scaled[1], simple);
  if ("sum" in e) {
    return (
      findSimpleSelector(e.sum[0], simple) ?? findSimpleSelector(e.sum[1], simple)
    );
  }
  if ("prod" in e) {
    return (
      findSimpleSelector(e.prod[0], simple) ?? findSimpleSelector(e.prod[1], simple)
    );
  }
  return null;
}

/**
 * Horner fold with values[0] as the HIGHEST power:
 * ((values[0]*c + values[1])*c + ...) + values[last].
 * This is the order used by the Rust theta/tau compressions.
 */
export function horner(values: Fr[], c: Fr): Fr {
  let acc = 0n;
  for (const v of values) {
    acc = mod(mul(acc, c) + v);
  }
  return acc;
}

/** All column-query leaves of an expression. */
export function queryLeaves(
  e: Expr,
  out: { kind: "fixed" | "advice" | "instance"; column: number; rotation: number }[] = [],
): { kind: "fixed" | "advice" | "instance"; column: number; rotation: number }[] {
  if ("fixed" in e) out.push({ kind: "fixed", ...e.fixed });
  else if ("advice" in e) out.push({ kind: "advice", ...e.advice });
  else if ("instance" in e) out.push({ kind: "instance", ...e.instance });
  else if ("neg" in e) queryLeaves(e.neg, out);
  else if ("scaled" in e) queryLeaves(e.scaled[1], out);
  else if ("sum" in e) {
    queryLeaves(e.sum[0], out);
    queryLeaves(e.sum[1], out);
  } else if ("prod" in e) {
    queryLeaves(e.prod[0], out);
    queryLeaves(e.prod[1], out);
  }
  return out;
}

/** All distinct rotations appearing in an expression. */
export function rotationsOf(e: Expr, out: Set<number> = new Set()): Set<number> {
  if ("fixed" in e) out.add(e.fixed.rotation);
  else if ("advice" in e) out.add(e.advice.rotation);
  else if ("instance" in e) out.add(e.instance.rotation);
  else if ("neg" in e) rotationsOf(e.neg, out);
  else if ("scaled" in e) rotationsOf(e.scaled[1], out);
  else if ("sum" in e) {
    rotationsOf(e.sum[0], out);
    rotationsOf(e.sum[1], out);
  } else if ("prod" in e) {
    rotationsOf(e.prod[0], out);
    rotationsOf(e.prod[1], out);
  }
  return out;
}
