/** Types for layout.json / trace.json / manifest.json (see the generator:
 * zk_stdlib/examples/export_visualiser.rs). */

export interface ManifestExample {
  id: string;
  k: number;
  n: number;
  transcript_hash: string;
  files: Record<string, { size: number }>;
  binary_bytes: number;
}

export interface Manifest {
  version: number;
  examples: ManifestExample[];
}

export type ColumnKind = "advice" | "fixed" | "instance";

export interface ColumnRef {
  kind: ColumnKind;
  index: number;
}

export interface Layout {
  version: number;
  meta: { name: string; transcript_hash: string };
  domain: {
    k: number;
    n: number;
    extended_k: number;
    omega: string;
    omega_inv: string;
    blinding_factors: number;
    usable_rows: number;
  };
  columns: {
    num_advice: number;
    num_fixed_total: number;
    num_fixed_base: number;
    num_selectors: number;
    num_instance: number;
    advice: { index: number; name: string | null; file: string }[];
    fixed: { index: number; name: string | null; file: string }[];
    selectors: {
      selector_index: number;
      fixed_column: number;
      simple: boolean;
      enabled_ranges: [number, number][];
    }[];
    instance: { index: number; committed: boolean; values: string[] }[];
  };
  regions: {
    index: number;
    name: string;
    rows: [number, number] | null;
    columns: ColumnRef[];
    enabled_selectors: { selector: number; rows: [number, number][] }[];
    annotations: { kind: ColumnKind; index: number; label: string }[];
  }[];
  permutation: {
    columns: ColumnRef[];
    copies_file: string;
    num_copies: number;
  };
}

export interface TracePolyRef {
  id: string;
  file: string | null;
}

export interface Trace {
  version: number;
  meta: { name: string; transcript_hash: string };
  challenges: { theta: string; beta: string; gamma: string; trash: string; y: string };
  steps: { id: string; polys: TracePolyRef[] }[];
}
