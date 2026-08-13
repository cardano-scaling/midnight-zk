/**
 * Constraint-coverage analysis: through which enforcement mechanism (if any)
 * is each assigned advice cell touched?
 *
 * A cell is only constrained via four channels:
 *  - a gate constraint that queries it, active at the base row (its simple
 *    selector is on, or it has no simple selector and holds on every row);
 *  - a trash-argument constraint, enforced where the additive selector is 1;
 *  - a lookup input, where the lookup selector is on;
 *  - a permutation copy (equality with another cell).
 *
 * Assigned advice cells on usable rows with NO channel are degrees of freedom
 * the prover can set arbitrarily — either intentional scratch or an
 * under-constraint bug. Copy-only cells are pinned to *equality* with another
 * cell, not to a computed value — a weaker guarantee worth surfacing.
 *
 * This is a structural heuristic, not a proof of constrainedness: a covering
 * gate can still be vacuous for the cell (e.g. its fixed coefficient is zero
 * at that row), and correlated multi-cell freedom is invisible. See
 * `perturb.ts` for the semantic single-cell test.
 */

import type { LoadedExample } from "../data/loader";
import { findSimpleSelector, queryLeaves } from "../verifier/expr";

export const COV_GATE = 1;
export const COV_TRASH = 2;
export const COV_LOOKUP = 4;
export const COV_COPY = 8;

export interface Coverage {
  /** Per advice column, per row: bitmask of COV_* flags. */
  flags: Uint8Array[];
  /** Assigned advice cells on usable rows with no coverage at all. */
  uncovered: { column: number; row: number }[];
  /** Assigned advice cells on usable rows covered ONLY by a copy. */
  copyOnly: { column: number; row: number }[];
}

export function computeCoverage(ex: LoadedExample): Coverage {
  const cs = ex.vk.vk.cs;
  const n = ex.n;
  const usable = ex.layout.domain.usable_rows;
  const numFixedBase = ex.layout.columns.num_fixed_base;
  const simple = new Set(cs.simple_selector_columns);
  const flags = ex.layout.columns.advice.map(() => new Uint8Array(n));

  const mark = (column: number, baseRow: number, rotation: number, flag: number) => {
    const row = (((baseRow + rotation) % n) + n) % n;
    if (row < usable) flags[column][row] |= flag;
  };

  /** Rows where a (converted) selector fixed-column is nonzero. */
  const selectorRows = (fixedCol: number): Iterable<number> => {
    const sel = ex.layout.columns.selectors.find((s) => s.fixed_column === fixedCol);
    if (sel) {
      return (function* () {
        for (const [a, b] of sel.enabled_ranges) {
          for (let r = a; r < Math.min(b, usable); r++) yield r;
        }
      })();
    }
    // Not a converted selector (plain fixed column used as a flag): scan it.
    return (function* () {
      for (let r = 0; r < usable; r++) {
        if (ex.cell("fixed", fixedCol, r) !== 0n) yield r;
      }
    })();
  };

  const allUsableRows = function* () {
    for (let r = 0; r < usable; r++) yield r;
  };

  // Gates: active where the constraint's simple selector is on; a constraint
  // without one must hold on every usable row.
  for (const gate of cs.gates) {
    for (const cst of gate.constraints) {
      const kappa = findSimpleSelector(cst, simple);
      const advice = queryLeaves(cst).filter((l) => l.kind === "advice");
      if (advice.length === 0) continue;
      const rows = kappa === null ? allUsableRows() : selectorRows(kappa);
      for (const r of rows) {
        for (const leaf of advice) mark(leaf.column, r, leaf.rotation, COV_GATE);
      }
    }
  }

  // Trash: constraints enforced where the additive selector is nonzero.
  for (const trash of cs.trash) {
    const selCols = queryLeaves(trash.selector)
      .filter((l) => l.kind === "fixed")
      .map((l) => l.column);
    const advice = trash.constraints.flatMap((c) =>
      queryLeaves(c).filter((l) => l.kind === "advice"),
    );
    if (advice.length === 0) continue;
    for (const selCol of selCols) {
      for (const r of selectorRows(selCol)) {
        for (const leaf of advice) mark(leaf.column, r, leaf.rotation, COV_TRASH);
      }
    }
  }

  // Lookups: inputs constrained where the lookup selector is on.
  for (const lookup of cs.lookups) {
    const selCols = queryLeaves(lookup.selector)
      .filter((l) => l.kind === "fixed")
      .map((l) => l.column);
    const advice = lookup.input_expression_chunks
      .flat(2)
      .flatMap((e) => queryLeaves(e).filter((l) => l.kind === "advice"));
    if (advice.length === 0) continue;
    for (const selCol of selCols) {
      for (const r of selectorRows(selCol)) {
        for (const leaf of advice) mark(leaf.column, r, leaf.rotation, COV_LOOKUP);
      }
    }
  }

  // Permutation copies (both endpoints).
  const permCols = ex.layout.permutation.columns;
  for (const c of ex.copies) {
    for (const [pc, pr] of [
      [c.col, c.row],
      [c.mappedCol, c.mappedRow],
    ] as const) {
      const ref = permCols[pc];
      if (ref.kind === "advice" && pr < usable) flags[ref.index][pr] |= COV_COPY;
    }
  }

  const uncovered: Coverage["uncovered"] = [];
  const copyOnly: Coverage["copyOnly"] = [];
  ex.layout.columns.advice.forEach((_, column) => {
    for (let row = 0; row < usable; row++) {
      if (!ex.cellAssigned("advice", column, row)) continue;
      const f = flags[column][row];
      if (f === 0) uncovered.push({ column, row });
      else if (f === COV_COPY) copyOnly.push({ column, row });
    }
  });

  // `numFixedBase` intentionally unused for now; selectors resolve via layout.
  void numFixedBase;
  return { flags, uncovered, copyOnly };
}
