/** Artifact loading and the in-memory model of a loaded example. */

import { parseVkBundle, VkBundle } from "../verifier/vk";
import { fromLEHex, Fr } from "../verifier/field";
import type { RowBinding } from "../verifier/expr";
import { ColumnData, CopyRecord, parseCopies } from "./columns";
import type { Layout, Manifest, Trace } from "./types";

const BASE = import.meta.env.BASE_URL + "artifacts";

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return (await res.json()) as T;
}

async function fetchBin(path: string): Promise<ArrayBuffer> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return await res.arrayBuffer();
}

export async function loadManifest(): Promise<Manifest> {
  return fetchJson<Manifest>(`${BASE}/manifest.json`);
}

/** Bit-set view of a selector column, from its (sorted) RLE ranges. */
export class SelectorData {
  private readonly ranges: [number, number][];
  constructor(ranges: [number, number][]) {
    this.ranges = ranges;
  }
  isEnabled(row: number): boolean {
    // Binary search for the last range starting at or before `row`.
    let lo = 0;
    let hi = this.ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [s, e] = this.ranges[mid];
      if (row < s) hi = mid - 1;
      else if (row >= e) lo = mid + 1;
      else return true;
    }
    return false;
  }
  enabledRows(): number[] {
    return this.ranges.flatMap(([s, e]) =>
      Array.from({ length: e - s }, (_, i) => s + i),
    );
  }
}

export class LoadedExample {
  constructor(
    readonly id: string,
    readonly vk: VkBundle,
    readonly layout: Layout,
    readonly trace: Trace,
    readonly advice: ColumnData[],
    readonly fixedBase: ColumnData[],
    readonly selectors: SelectorData[],
    readonly instances: Fr[][],
    readonly copies: CopyRecord[],
    readonly tracePolys: Map<string, ColumnData>,
  ) {}

  get n(): number {
    return this.layout.domain.n;
  }

  /** Cell accessor across the unified fixed indexing (base + selectors). */
  cell(kind: "fixed" | "advice" | "instance", column: number, row: number): Fr {
    if (kind === "advice") return this.advice[column].get(row).value;
    if (kind === "instance") return this.instances[column]?.[row] ?? 0n;
    const base = this.layout.columns.num_fixed_base;
    if (column < base) return this.fixedBase[column].get(row).value;
    return this.selectors[column - base].isEnabled(row) ? 1n : 0n;
  }

  /** Is the cell explicitly assigned (vs unassigned-default-0)? */
  cellAssigned(kind: "fixed" | "advice" | "instance", column: number, row: number): boolean {
    if (kind === "advice") return this.advice[column].isAssigned(row);
    if (kind === "instance") return row < (this.instances[column]?.length ?? 0);
    const base = this.layout.columns.num_fixed_base;
    if (column < base) return this.fixedBase[column].isAssigned(row);
    return true; // selector columns are fully defined
  }

  rowBinding(row: number): RowBinding {
    return {
      kind: "row",
      cell: (kind, column, r) => this.cell(kind, column, r),
      row,
      n: this.n,
    };
  }

  /** Regions covering a given row. */
  regionsAt(row: number) {
    return this.layout.regions.filter(
      (r) => r.rows !== null && row >= r.rows[0] && row <= r.rows[1],
    );
  }
}

const cache = new Map<string, Promise<LoadedExample>>();

export function loadExample(id: string): Promise<LoadedExample> {
  if (!cache.has(id)) cache.set(id, loadExampleUncached(id));
  return cache.get(id)!;
}

async function loadExampleUncached(id: string): Promise<LoadedExample> {
  const dir = `${BASE}/${id}`;
  const [vkJson, layout, trace] = await Promise.all([
    fetchJson<unknown>(`${dir}/vk.json`),
    fetchJson<Layout>(`${dir}/layout.json`),
    fetchJson<Trace>(`${dir}/trace.json`),
  ]);
  const vk = parseVkBundle(vkJson);

  const [advice, fixedBase, copiesBuf] = await Promise.all([
    Promise.all(layout.columns.advice.map((c) => fetchBin(`${dir}/${c.file}`))),
    Promise.all(layout.columns.fixed.map((c) => fetchBin(`${dir}/${c.file}`))),
    fetchBin(`${dir}/${layout.permutation.copies_file}`),
  ]);
  const tracePolys = new Map<string, ColumnData>();
  await Promise.all(
    trace.steps.flatMap((step) =>
      step.polys
        .filter((p) => p.file !== null)
        .map(async (p) => {
          tracePolys.set(p.id, new ColumnData(await fetchBin(`${dir}/${p.file}`)));
        }),
    ),
  );

  return new LoadedExample(
    id,
    vk,
    layout,
    trace,
    advice.map((b) => new ColumnData(b)),
    fixedBase.map((b) => new ColumnData(b)),
    layout.columns.selectors.map((s) => new SelectorData(s.enabled_ranges)),
    layout.columns.instance.map((c) => c.values.map(fromLEHex)),
    parseCopies(copiesBuf),
    tracePolys,
  );
}
