/**
 * Determinism map — the robust answer to "would the witness reconstruct
 * byte-for-byte?".
 *
 * A true global refill "from inputs" is ill-posed: a circuit doesn't label
 * which advice cells are the prover's free inputs, and you cannot recover them
 * from the output (that would invert the hash). So instead we ask, per cell,
 * the local question that IS well-defined and decisive:
 *
 *   Holding every other cell at its honest value, is THIS cell's value
 *   uniquely forced by the constraints?
 *
 * We perturb the single cell and check whether any constraint touching it
 * breaks. If some check breaks, the cell is DETERMINED — a from-inputs
 * reconstruction would reproduce its exact bytes. If nothing breaks, it is a
 * FREE degree of freedom: under-constraint (or unassigned scratch).
 *
 * "Determined given all others honest" cannot see correlated multi-cell
 * freedom (two cells free together but each pinned given the other); that
 * needs formal tools. But every cell green, together with the per-cell
 * freedom sweep, is strong evidence the witness is rigid.
 */

import type { LoadedExample } from "../data/loader";
import { perturbAdviceCell } from "./perturb";
import { ovKey } from "./workshop";

export type CellDeterminism = "determined" | "free";

export interface DeterminismMap {
  /** advice cell key -> determined | free (only assigned usable cells). */
  status: Map<string, CellDeterminism>;
  determined: number;
  free: number;
  freeCells: { column: number; row: number }[];
}

export function determinismMap(ex: LoadedExample): DeterminismMap {
  const usable = ex.layout.domain.usable_rows;
  const status = new Map<string, CellDeterminism>();
  const freeCells: { column: number; row: number }[] = [];
  let determined = 0;
  let free = 0;

  ex.layout.columns.advice.forEach((col) => {
    for (let r = 0; r < usable; r++) {
      if (!ex.cellAssigned("advice", col.index, r)) continue;
      const honest = ex.cell("advice", col.index, r);
      const res = perturbAdviceCell(ex, col.index, r, honest + 0x9999n, { followCopies: false });
      const det = res.violations > 0;
      status.set(ovKey(col.index, r), det ? "determined" : "free");
      if (det) determined++;
      else {
        free++;
        freeCells.push({ column: col.index, row: r });
      }
    }
  });

  return { status, determined, free, freeCells };
}

/** Overlay colours consumed by the grid: determined -> green, free -> red. */
export function determinismOverlay(
  map: DeterminismMap,
): Map<string, "match" | "differ"> {
  const out = new Map<string, "match" | "differ">();
  for (const [k, v] of map.status) out.set(k, v === "determined" ? "match" : "differ");
  return out;
}
