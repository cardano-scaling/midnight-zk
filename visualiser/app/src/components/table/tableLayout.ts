/** Shared geometry for the canvas grid: column order and x-offsets. */

import type { LoadedExample } from "../../data/loader";
import type { ColumnKind } from "../../data/types";

export const ROW_H = 22;
export const HEADER_H = 48;
export const GUTTER_W = 56;
export const REGION_BAND_W = 14;
export const CELL_W = 92;
export const SELECTOR_W = 34;

export interface ColumnSpec {
  kind: ColumnKind;
  /** Index within the unified kind indexing (fixed includes selectors). */
  index: number;
  x: number;
  width: number;
  label: string;
  group: "instance" | "advice" | "fixed" | "selector";
}

export interface GridGeometry {
  columns: ColumnSpec[];
  totalWidth: number;
  totalHeight: number;
}

export function computeGeometry(ex: LoadedExample): GridGeometry {
  const cols: ColumnSpec[] = [];
  let x = GUTTER_W + REGION_BAND_W;
  const { columns } = ex.layout;

  columns.instance.forEach((c) => {
    cols.push({ kind: "instance", index: c.index, x, width: CELL_W, label: `i${c.index}`, group: "instance" });
    x += CELL_W;
  });
  columns.advice.forEach((c) => {
    cols.push({
      kind: "advice",
      index: c.index,
      x,
      width: CELL_W,
      label: c.name ?? `a${c.index}`,
      group: "advice",
    });
    x += CELL_W;
  });
  columns.fixed.forEach((c) => {
    cols.push({
      kind: "fixed",
      index: c.index,
      x,
      width: CELL_W,
      label: c.name ?? `f${c.index}`,
      group: "fixed",
    });
    x += CELL_W;
  });
  columns.selectors.forEach((s) => {
    cols.push({
      kind: "fixed",
      index: s.fixed_column,
      x,
      width: SELECTOR_W,
      label: `q${s.selector_index}`,
      group: "selector",
    });
    x += SELECTOR_W;
  });

  return {
    columns: cols,
    totalWidth: x + 8,
    totalHeight: HEADER_H + ex.n * ROW_H,
  };
}

export const GROUP_COLORS: Record<ColumnSpec["group"], { bg: string; text: string; header: string }> = {
  instance: { bg: "#0c4a6e22", text: "#7dd3fc", header: "#0ea5e9" },
  advice: { bg: "#14532d22", text: "#86efac", header: "#22c55e" },
  fixed: { bg: "#713f1222", text: "#fcd34d", header: "#f59e0b" },
  selector: { bg: "#83184322", text: "#f9a8d4", header: "#ec4899" },
};

/** Distinguishable region band colours (cycled). */
export const REGION_COLORS = [
  "#38bdf8",
  "#a78bfa",
  "#fb923c",
  "#4ade80",
  "#f472b6",
  "#facc15",
  "#2dd4bf",
  "#f87171",
];
