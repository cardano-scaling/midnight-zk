/**
 * Coverage + freedom-test analyses against the generated poseidon artifacts:
 *  - the audited poseidon circuit must have no uncovered cells;
 *  - perturbing a constrained cell must break at least one check;
 *  - "perturbing" to the original value must break none (and not claim freedom).
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseVkBundle } from "../verifier/vk";
import { fromLEHex } from "../verifier/field";
import { ColumnData, parseCopies } from "../data/columns";
import { LoadedExample, SelectorData } from "../data/loader";
import type { Layout, Trace } from "../data/types";
import { computeCoverage } from "../analysis/coverage";
import { perturbAdviceCell } from "../analysis/perturb";

const DIR = join(__dirname, "../../public/artifacts/poseidon");

function toArrayBuffer(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/** Node-side artifact loader (the browser one uses fetch). */
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

describe.skipIf(!existsSync(join(DIR, "vk.json")))("under-constraint analyses (poseidon)", () => {
  const ex = loadFromDisk(DIR);

  it("coverage: every assigned advice cell on a usable row is constrained", () => {
    const coverage = computeCoverage(ex);
    expect(coverage.uncovered).toEqual([]);
  });

  it("perturbing a round-state cell breaks at least one check", () => {
    // a3[2] is full-round state (covered only by the full_round gate).
    const result = perturbAdviceCell(ex, 3, 2, ex.cell("advice", 3, 2) + 1n);
    expect(result.unchanged).toBe(false);
    expect(result.checks.length).toBeGreaterThan(0);
    expect(result.violations).toBeGreaterThan(0);
    expect(result.free).toBe(false);
  });

  it("witness input a0[0]: single-cell mode breaks ONLY its copy (deduped)", () => {
    // a0[0] holds a witness input; no gate reads it in place — it is pinned
    // purely by equality with its copy in the round state.
    const result = perturbAdviceCell(ex, 0, 0, 0x1234n);
    expect(result.violations).toBeGreaterThan(0);
    expect(result.checks.filter((c) => !c.ok).every((c) => c.kind === "copy")).toBe(true);
    // The 2-cycle used to be reported twice; partners are deduped now.
    const copyChecks = result.checks.filter((c) => c.kind === "copy");
    expect(new Set(copyChecks.map((c) => c.label)).size).toBe(copyChecks.length);
  });

  it("witness input a0[0]: follow-copies mode shows the class IS computation-pinned", () => {
    const result = perturbAdviceCell(ex, 0, 0, 0x1234n, { followCopies: true });
    expect(result.followedCopies).toBe(true);
    expect(result.classMembers.length).toBeGreaterThan(1);
    // With the whole class moved, equality holds; what breaks now must be a
    // real computation (the first poseidon round consuming the input).
    expect(result.violations).toBeGreaterThan(0);
    expect(result.checks.some((c) => !c.ok && c.kind !== "copy")).toBe(true);
    expect(result.free).toBe(false);
  });

  it("perturbing a copy-linked cell reports the broken copy", () => {
    // Find a copy endpoint on an advice column.
    const permCols = ex.layout.permutation.columns;
    const copy = ex.copies.find(
      (c) => permCols[c.col].kind === "advice" && c.row < ex.layout.domain.usable_rows,
    )!;
    const column = permCols[copy.col].index;
    const result = perturbAdviceCell(ex, column, copy.row, 0xdeadbeefn);
    expect(result.checks.some((c) => c.kind === "copy" && !c.ok)).toBe(true);
  });

  it("an unassigned, unread cell is free — but reported as unassigned slack", () => {
    // a3[0] is never written (the poseidon rounds start later); the gates
    // querying a3 have their selectors off at the relevant base rows, so
    // every check holds vacuously. Genuine freedom, benign kind.
    expect(ex.cellAssigned("advice", 3, 0)).toBe(false);
    const result = perturbAdviceCell(ex, 3, 0, 0x72acn);
    expect(result.free).toBe(true);
    expect(result.assigned).toBe(false);
    expect(result.checks.every((c) => c.ok)).toBe(true);
    expect(result.checks.some((c) => c.detail.includes("vacuously"))).toBe(true);
  });

  it("the original value perturbs nothing and does not claim freedom", () => {
    const result = perturbAdviceCell(ex, 3, 2, ex.cell("advice", 3, 2));
    expect(result.unchanged).toBe(true);
    expect(result.violations).toBe(0);
    expect(result.free).toBe(false);
  });

  it("every assigned advice cell is constrained against a random perturbation", () => {
    // The strong end-to-end statement for a sound circuit: no single-cell
    // freedom anywhere on the usable rows.
    const usable = ex.layout.domain.usable_rows;
    const free: string[] = [];
    ex.layout.columns.advice.forEach((c) => {
      for (let row = 0; row < usable; row++) {
        if (!ex.cellAssigned("advice", c.index, row)) continue;
        const result = perturbAdviceCell(
          ex,
          c.index,
          row,
          ex.cell("advice", c.index, row) + 0x1234567n,
        );
        if (result.free) free.push(`a${c.index}[${row}]`);
      }
    });
    expect(free).toEqual([]);
  });
});
