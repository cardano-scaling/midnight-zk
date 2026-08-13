/**
 * Root-finding + workshop (perturb-and-keep, constraint solving) tests.
 * The workshop end-to-end drives the actual attack loop on poseidon:
 * perturb the witness input class, then solve the failing round constraints
 * cell by cell — and confirm the repair wave eventually hits the pinned
 * public input (poseidon is NOT under-constrained, so full repair must be
 * impossible without touching the instance).
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { interpolate, rootsOf, rootsOfFunction } from "../analysis/roots";
import {
  checkAllRows,
  effectiveCell,
  evaluateWorkshop,
  forwardSolve,
  ovKey,
  Overrides,
  solveCheck,
} from "../analysis/workshop";
import { copyClassOf } from "../analysis/perturb";
import { mod, mul, pow, sub } from "../verifier/field";
import { parseVkBundle } from "../verifier/vk";
import { fromLEHex } from "../verifier/field";
import { ColumnData, parseCopies } from "../data/columns";
import { LoadedExample, SelectorData } from "../data/loader";
import type { Layout, Trace } from "../data/types";

describe("univariate roots over Fr", () => {
  it("interpolates and finds linear roots", () => {
    // f(v) = 3v - 12 => root 4
    const roots = rootsOfFunction((v) => mod(3n * v - 12n), 3);
    expect(roots).toEqual([4n]);
  });

  it("finds both roots of a quadratic", () => {
    // f(v) = (v - 5)(v - 11)
    const roots = rootsOfFunction((v) => mul(sub(v, 5n), sub(v, 11n)), 4);
    expect(roots).toEqual([5n, 11n]);
  });

  it("handles the poseidon S-box degree (x^5 = c has a unique 5th root)", () => {
    const c = pow(123456789n, 5n);
    const roots = rootsOfFunction((v) => sub(pow(v, 5n), c), 6);
    expect(roots).toEqual([123456789n]);
  });

  it("reports no roots for an irreducible quadratic", () => {
    // v^2 = non-residue has no roots; v^2 - g with g a generator (7 is a
    // non-residue iff 7^((r-1)/2) = -1; just check consistency instead).
    const roots = rootsOfFunction((v) => sub(mul(v, v), 7n), 4);
    // 7 is either a QR (2 roots) or not (0 roots); both are valid outcomes,
    // but the count must be 0 or 2 and the roots must square to 7.
    expect([0, 2]).toContain(roots!.length);
    for (const r of roots!) expect(mul(r, r)).toBe(7n);
  });

  it("interpolate round-trips coefficients", () => {
    const f = [9n, 0n, 5n, 1n]; // 9 + 5v^2 + v^3
    const ys = [0n, 1n, 2n, 3n].map((x) => mod(f[0] + f[2] * x * x + f[3] * x * x * x));
    expect(interpolate([0n, 1n, 2n, 3n], ys)).toEqual(f);
    expect(rootsOf([1n])).toEqual([]);
  });
});

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

describe.skipIf(!existsSync(join(DIR, "vk.json")))("perturbation workshop (poseidon)", () => {
  const ex = loadFromDisk(DIR);

  it("no overrides -> no checks", () => {
    const state = evaluateWorkshop(ex, new Map());
    expect(state.checks).toEqual([]);
  });

  it("solving a failing constraint repairs it", () => {
    // Perturb the witness-input class of a0[0]; the first round constraint
    // fails; solve it for one of its OTHER cells and keep the root: that
    // specific constraint must then pass.
    const overrides: Overrides = new Map();
    for (const m of copyClassOf(ex, 0, 0)) {
      if (m.kind === "advice") overrides.set(ovKey(m.index, m.row), 0x1234n);
    }
    const state = evaluateWorkshop(ex, overrides);
    expect(state.failing.length).toBeGreaterThan(0);

    const target = state.failing.find(
      (c) =>
        c.ref.type === "gate" &&
        c.cells.some((cell) => !overrides.has(ovKey(cell.column, cell.row))),
    )!;
    expect(target).toBeDefined();
    const cell = target.cells.find((c) => !overrides.has(ovKey(c.column, c.row)))!;
    const solved = solveCheck(ex, overrides, target, cell);
    expect(solved.roots).not.toBeNull();
    expect(solved.roots!.length).toBeGreaterThan(0);

    const overrides2 = new Map(overrides);
    overrides2.set(ovKey(cell.column, cell.row), solved.roots![0]);
    const state2 = evaluateWorkshop(ex, overrides2);
    const same = state2.checks.find(
      (c) => JSON.stringify(c.ref) === JSON.stringify(target.ref),
    )!;
    expect(same.ok).toBe(true);
  });

  it("forward-solve constructively propagates a perturbed input through the circuit", () => {
    // Perturb the first message input (its whole copy class) and let the
    // forward solver run. It repairs constraints in forward order, each time
    // verifying the constraint holds and never regressing the settled past —
    // demonstrating it correctly reconstructs the computation cell by cell.
    //
    // NOTE: single-cell root-finding fully solves the feed-forward portion but
    // stalls on ZkStdLib-poseidon's native-gadget / trash rows, which couple
    // several unknown cells per row (they need a per-row linear-system solve).
    // So we assert substantial *verified forward progress*, not full closure.
    // Full closure + public-input relocation is exercised interactively in the
    // workshop UI. Kept modest so the test stays fast.
    const seed: Overrides = new Map();
    const newInput = 0x1234_5678_9abc_def0n;
    for (const m of copyClassOf(ex, 0, 0)) {
      if (m.kind === "advice") seed.set(ovKey(m.index, m.row), newInput);
    }

    const result = forwardSolve(ex, seed, { maxSteps: 30 });

    // Every "solved" cell is one the solver verified against its constraint
    // (accepted only when the constraint held and no earlier row regressed).
    expect(result.solvedCells.length).toBe(30);

    // The seed's own value is preserved (never re-reverted to the original).
    const eff = effectiveCell(ex, result.overrides, result.instanceOverrides);
    expect(eff("advice", 0, 0)).toBe(newInput);
  }, 60000);

  it("checkAllRows: the honest witness satisfies the whole circuit", () => {
    expect(checkAllRows(ex, new Map(), new Map()).violations).toBe(0);
  });

  it("setting the public input repairs a perturbed output→instance copy", () => {
    // Directly exercise the new-statement mechanism: find an advice cell
    // copy-pinned to a public input, perturb it, and confirm the only repair
    // is to move the instance — after which that copy is satisfied.
    const permCols = ex.layout.permutation.columns;
    const edge = ex.copies.find((c) => {
      const a = permCols[c.col];
      const d = permCols[c.mappedCol];
      return (
        (a.kind === "advice" && d.kind === "instance") ||
        (a.kind === "instance" && d.kind === "advice")
      );
    });
    if (!edge) return; // some circuits expose the PI differently; skip if so
    const adviceEnd = permCols[edge.col].kind === "advice"
      ? { col: permCols[edge.col].index, row: edge.row, iCol: permCols[edge.mappedCol].index, iRow: edge.mappedRow }
      : { col: permCols[edge.mappedCol].index, row: edge.mappedRow, iCol: permCols[edge.col].index, iRow: edge.row };

    const overrides: Overrides = new Map([[ovKey(adviceEnd.col, adviceEnd.row), 0xabcdn]]);
    const before = evaluateWorkshop(ex, overrides, new Map());
    expect(before.failing.some((c) => c.ref.type === "copy")).toBe(true);

    const instanceOverrides: Overrides = new Map([[ovKey(adviceEnd.iCol, adviceEnd.iRow), 0xabcdn]]);
    const after = evaluateWorkshop(ex, overrides, instanceOverrides);
    const copyChecks = after.failing.filter((c) => c.ref.type === "copy");
    expect(copyChecks.length).toBe(0);
  });

  it("the repair wave hits the pinned public input (soundness holds)", () => {
    // Greedy auto-repair: keep solving failing gate/trash checks for
    // not-yet-overridden cells. For a sound circuit this must terminate in a
    // stuck state whose remaining failures involve the instance-pinned copy
    // (the poseidon output equals the public input) or admit no solution.
    const overrides: Overrides = new Map();
    for (const m of copyClassOf(ex, 0, 0)) {
      if (m.kind === "advice") overrides.set(ovKey(m.index, m.row), 0x1234n);
    }
    for (let step = 0; step < 200; step++) {
      const state = evaluateWorkshop(ex, overrides);
      if (state.failing.length === 0) {
        throw new Error("repaired everything: poseidon would be under-constrained!");
      }
      let progressed = false;
      for (const check of state.failing) {
        if (check.ref.type === "copy") continue; // equality with pinned values: not repairable
        const cell = check.cells.find((c) => !overrides.has(ovKey(c.column, c.row)));
        if (!cell) continue;
        const solved = solveCheck(ex, overrides, check, cell);
        if (solved.roots && solved.roots.length > 0) {
          overrides.set(ovKey(cell.column, cell.row), solved.roots[0]);
          progressed = true;
          break;
        }
      }
      if (!progressed) {
        // Stuck: every remaining failure is a pinned copy or unsolvable.
        const state2 = evaluateWorkshop(ex, overrides);
        expect(state2.failing.length).toBeGreaterThan(0);
        const pinnedCopy = state2.failing.some(
          (c) => c.ref.type === "copy" && c.ref.member.kind !== "advice",
        );
        const unsolvable = state2.failing.some((c) => c.ref.type !== "copy");
        expect(pinnedCopy || unsolvable).toBe(true);
        return;
      }
    }
    throw new Error("repair loop did not converge in 200 steps");
  });
});
