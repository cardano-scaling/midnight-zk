/**
 * Determinism map: for every assigned advice cell, is its value uniquely
 * forced by the rest of the witness? If every cell is determined, a
 * from-inputs reconstruction would reproduce the witness byte-for-byte — the
 * property behind "same witness, same bytes". A `free` cell would be an
 * under-constraint (or unassigned scratch, which we skip).
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { determinismMap, determinismOverlay } from "../analysis/reconstruct";
import { parseVkBundle } from "../verifier/vk";
import { fromLEHex } from "../verifier/field";
import { ColumnData, parseCopies } from "../data/columns";
import { LoadedExample, SelectorData } from "../data/loader";
import type { Layout, Trace } from "../data/types";

const DIR = join(__dirname, "../../public/artifacts/poseidon");

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}
function loadFromDisk(dir: string): LoadedExample {
  const vk = parseVkBundle(JSON.parse(readFileSync(join(dir, "vk.json"), "utf8")));
  const layout = JSON.parse(readFileSync(join(dir, "layout.json"), "utf8")) as Layout;
  const trace = JSON.parse(readFileSync(join(dir, "trace.json"), "utf8")) as Trace;
  const bin = (file: string) => toArrayBuffer(readFileSync(join(dir, file)));
  return new LoadedExample(
    "poseidon",
    vk,
    layout,
    trace,
    layout.columns.advice.map((c) => new ColumnData(bin(c.file))),
    layout.columns.fixed.map((c) => new ColumnData(bin(c.file))),
    layout.columns.selectors.map((s) => new SelectorData(s.enabled_ranges)),
    layout.columns.instance.map((c) => c.values.map(fromLEHex)),
    parseCopies(bin(layout.permutation.copies_file)),
    new Map(),
  );
}

describe.skipIf(!existsSync(join(DIR, "vk.json")))("determinism map (poseidon)", () => {
  const ex = loadFromDisk(DIR);

  it("every assigned advice cell is rigidly determined (no free cells)", () => {
    const map = determinismMap(ex);
    expect(map.determined).toBeGreaterThan(0);
    // The whole witness is forced by the constraints given the rest: a
    // from-inputs reconstruction would be byte-for-byte identical.
    expect(map.free).toBe(0);
    expect(map.freeCells).toEqual([]);
  });

  it("overlay maps determined -> match (green), free -> differ (red)", () => {
    const map = determinismMap(ex);
    const overlay = determinismOverlay(map);
    expect(overlay.size).toBe(map.status.size);
    for (const [k, v] of map.status) {
      expect(overlay.get(k)).toBe(v === "determined" ? "match" : "differ");
    }
  });
});
