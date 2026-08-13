import { create } from "zustand";
import type { ColumnKind } from "./data/types";

/** A cell address in the unified table (fixed indices include selectors). */
export interface CellAddr {
  kind: ColumnKind;
  column: number;
  row: number;
}

interface VisualiserState {
  /** Selected row in the table (drives the row inspector + domain view). */
  selectedRow: number | null;
  /** Cell highlighted from hovering an expression leaf. */
  hoverCells: CellAddr[];
  /**
   * Kept perturbations of the workshop: advice cells ("col/row") overriding
   * the honest witness. All views read cells through these.
   */
  overrides: Map<string, bigint>;
  /** Public-input overrides ("col/row") — moving these constructs a proof for
   * a NEW statement. */
  instanceOverrides: Map<string, bigint>;
  /**
   * Soundness mode: treat public inputs as pinned constants. Then closing the
   * workshop by perturbing a PRIVATE input while the public inputs stay fixed
   * would be a collision / under-constraint — so this is the mode that tests
   * soundness. When off, public inputs may be moved to build a new statement.
   */
  soundnessMode: boolean;
  setSoundnessMode: (on: boolean) => void;
  /** Reconstruction diff overlay: advice cell key -> match/differ/etc. When
   * set, the grid tints cells by how the from-inputs reconstruction compares
   * to the honest witness. */
  reconstructDiff: Map<string, "source" | "match" | "differ" | "unreached"> | null;
  setReconstructDiff: (
    d: Map<string, "source" | "match" | "differ" | "unreached"> | null,
  ) => void;
  setSelectedRow: (row: number | null) => void;
  setHoverCells: (cells: CellAddr[]) => void;
  setOverride: (column: number, row: number, value: bigint) => void;
  removeOverride: (key: string) => void;
  setInstanceOverride: (column: number, row: number, value: bigint) => void;
  applyOverrides: (advice: Map<string, bigint>, instance: Map<string, bigint>) => void;
  clearOverrides: () => void;
}

export const useStore = create<VisualiserState>((set) => ({
  selectedRow: null,
  hoverCells: [],
  overrides: new Map(),
  instanceOverrides: new Map(),
  soundnessMode: true,
  setSoundnessMode: (soundnessMode) => set({ soundnessMode }),
  reconstructDiff: null,
  setReconstructDiff: (reconstructDiff) => set({ reconstructDiff }),
  setSelectedRow: (selectedRow) => set({ selectedRow }),
  setHoverCells: (hoverCells) => set({ hoverCells }),
  setOverride: (column, row, value) =>
    set((s) => {
      const overrides = new Map(s.overrides);
      overrides.set(`${column}/${row}`, value);
      return { overrides };
    }),
  removeOverride: (key) =>
    set((s) => {
      const overrides = new Map(s.overrides);
      overrides.delete(key);
      return { overrides };
    }),
  setInstanceOverride: (column, row, value) =>
    set((s) => {
      const instanceOverrides = new Map(s.instanceOverrides);
      instanceOverrides.set(`${column}/${row}`, value);
      return { instanceOverrides };
    }),
  applyOverrides: (advice, instance) =>
    set({ overrides: new Map(advice), instanceOverrides: new Map(instance) }),
  clearOverrides: () =>
    set({ overrides: new Map(), instanceOverrides: new Map(), reconstructDiff: null }),
}));

/** Shared value formatting: small numbers decimal, big ones truncated hex. */
export function fmtValue(v: bigint): string {
  if (v < 0x10000n) return v.toString();
  const hex = v.toString(16);
  return `0x${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

export function fmtValueFull(v: bigint): string {
  return v < 0x10000n ? v.toString() : `0x${v.toString(16)}`;
}
