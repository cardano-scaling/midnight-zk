/**
 * The perturbation workshop: a persistent set of advice-cell overrides
 * ("perturb and keep"), the list of constraints they currently violate, and
 * solvers that repair a chosen failing constraint by computing the value of
 * one of its cells.
 *
 * This is interactive perturb-and-repair: if you drive the failing-check list
 * to empty without touching a pinned cell (public input / fixed constant),
 * you have CONSTRUCTED a second witness for the same instance — a proof of
 * multi-cell under-constraint. Conversely, getting stuck on a constraint
 * with no admissible root shows you which computation pins your changes.
 */

import type { LoadedExample } from "../data/loader";
import { evaluate, findSimpleSelector, queryLeaves, RowBinding } from "../verifier/expr";
import { Fr, inv, mod, toLEHex } from "../verifier/field";
import { ClassMember, copyClassOf, memberKey, memberLabel } from "./perturb";
import { rootsOfFunction } from "./roots";

export type Overrides = Map<string, Fr>;
export const ovKey = (column: number, row: number) => `${column}/${row}`;

/**
 * Effective cell accessor: advice overrides shadow the honest witness, and
 * (optionally) instance overrides shadow the public inputs — the latter let
 * the workshop construct proofs for a *new statement*.
 */
export function effectiveCell(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides?: Overrides,
) {
  return (kind: "fixed" | "advice" | "instance", column: number, row: number): Fr => {
    if (kind === "advice") {
      const v = overrides.get(ovKey(column, row));
      if (v !== undefined) return v;
    } else if (kind === "instance" && instanceOverrides) {
      const v = instanceOverrides.get(ovKey(column, row));
      if (v !== undefined) return v;
    }
    if (kind === "instance") return ex.instances[column]?.[row] ?? 0n;
    return ex.cell(kind, column, row);
  };
}

export function effectiveBinding(
  ex: LoadedExample,
  overrides: Overrides,
  row: number,
  instanceOverrides?: Overrides,
): RowBinding {
  return { kind: "row", row, n: ex.n, cell: effectiveCell(ex, overrides, instanceOverrides) };
}

export type CheckRef =
  | { type: "gate"; gate: number; constraint: number; baseRow: number }
  | { type: "trash"; trash: number; constraint: number; baseRow: number }
  | { type: "lookup"; lookup: number; chunk: number; input: number; baseRow: number }
  | { type: "copy"; member: ClassMember; overriddenKey: string };

export interface WorkshopCheck {
  ref: CheckRef;
  label: string;
  ok: boolean;
  detail: string;
  /** Advice cells this check reads (candidates to solve for), resolved rows. */
  cells: { column: number; row: number }[];
}

export interface WorkshopState {
  checks: WorkshopCheck[];
  failing: WorkshopCheck[];
  /** Overrides whose copy class contains a pinned (instance/fixed) member. */
  pinnedNotes: string[];
}

/** Every check affected by the current override set, evaluated effectively. */
export function evaluateWorkshop(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides?: Overrides,
): WorkshopState {
  const cs = ex.vk.vk.cs;
  const n = ex.n;
  const usable = ex.layout.domain.usable_rows;
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  const binding = (row: number) => effectiveBinding(ex, overrides, row, instanceOverrides);
  const checks: WorkshopCheck[] = [];
  if (overrides.size === 0 && (!instanceOverrides || instanceOverrides.size === 0)) {
    return { checks, failing: [], pinnedNotes: [] };
  }

  // Base rows to re-check come from advice targets, plus any gate that queries
  // an overridden instance cell.
  const targets = [...overrides.keys()].map((k) => {
    const [c, r] = k.split("/").map(Number);
    return { column: c, row: r };
  });
  const instTargets = [...(instanceOverrides?.keys() ?? [])].map((k) => {
    const [c, r] = k.split("/").map(Number);
    return { column: c, row: r };
  });

  // Base rows to re-check: any row from which an advice/instance leaf reaches
  // an overridden cell of the matching kind.
  const baseRows = (
    leaves: { kind: string; column: number; rotation: number }[],
  ): number[] => {
    const rows = new Set<number>();
    for (const leaf of leaves) {
      const ts = leaf.kind === "instance" ? instTargets : leaf.kind === "advice" ? targets : [];
      for (const t of ts) {
        if (leaf.column !== t.column) continue;
        const base = (((t.row - leaf.rotation) % n) + n) % n;
        if (base < usable) rows.add(base);
      }
    }
    return [...rows].sort((a, b) => a - b);
  };

  const resolvedCells = (
    leaves: { column: number; rotation: number }[],
    baseRow: number,
  ): { column: number; row: number }[] => {
    const out = new Map<string, { column: number; row: number }>();
    for (const leaf of leaves) {
      const row = (((baseRow + leaf.rotation) % n) + n) % n;
      out.set(`${leaf.column}/${row}`, { column: leaf.column, row });
    }
    return [...out.values()];
  };

  const simple = new Set(cs.simple_selector_columns);
  cs.gates.forEach((gate, gi) => {
    gate.constraints.forEach((cst, ci) => {
      const all = queryLeaves(cst);
      const advice = all.filter((l) => l.kind === "advice");
      const kappa = findSimpleSelector(cst, simple);
      for (const base of baseRows(all)) {
        const vacuous = kappa !== null && ex.cell("fixed", kappa, base) === 0n;
        const residual = evaluate(cst, binding(base));
        checks.push({
          ref: { type: "gate", gate: gi, constraint: ci, baseRow: base },
          label: `gate "${gate.name}" #${ci} @ row ${base}`,
          ok: residual === 0n,
          detail: vacuous
            ? "selector off — holds vacuously"
            : residual === 0n
              ? "residual 0"
              : `residual ${short(residual)}`,
          cells: resolvedCells(advice, base),
        });
      }
    });
  });

  cs.trash.forEach((trash, ti) => {
    trash.constraints.forEach((cst, ci) => {
      const all = queryLeaves(cst);
      const advice = all.filter((l) => l.kind === "advice");
      for (const base of baseRows(all)) {
        if (evaluate(trash.selector, binding(base)) === 0n) continue;
        const residual = evaluate(cst, binding(base));
        checks.push({
          ref: { type: "trash", trash: ti, constraint: ci, baseRow: base },
          label: `trash ${ti} term #${ci} @ row ${base}`,
          ok: residual === 0n,
          detail: residual === 0n ? "residual 0" : `residual ${short(residual)}`,
          cells: resolvedCells(advice, base),
        });
      }
    });
  });

  cs.lookups.forEach((lookup, li) => {
    const table = tableKeysOf(ex, li);
    lookup.input_expression_chunks.forEach((chunk, ci) => {
      chunk.forEach((pl, pi) => {
        const all = pl.flatMap((e) => queryLeaves(e));
        const advice = all.filter((l) => l.kind === "advice");
        for (const base of baseRows(all)) {
          if (evaluate(lookup.selector, binding(base)) === 0n) continue;
          const tuple = pl.map((e) => evaluate(e, binding(base)));
          const hit = table.has(tuple.map(toLEHex).join("|"));
          checks.push({
            ref: { type: "lookup", lookup: li, chunk: ci, input: pi, baseRow: base },
            label: `lookup ${li} input ${pi} @ row ${base}`,
            ok: hit,
            detail: `(${tuple.map(short).join(", ")}) ${hit ? "in table" : "NOT in table"}`,
            cells: resolvedCells(advice, base),
          });
        }
      });
    });
  });

  // Copies: for each overridden cell, equality across its class, evaluated
  // effectively (a fully-overridden class holds by construction). Deduped.
  const pinnedNotes: string[] = [];
  const seenEdges = new Set<string>();
  for (const t of targets) {
    for (const m of copyClassOf(ex, t.column, t.row)) {
      if (m.kind === "advice" && m.index === t.column && m.row === t.row) continue;
      const edge = [ovKey(t.column, t.row), memberKey(m)].sort().join("::");
      if (seenEdges.has(edge)) continue;
      seenEdges.add(edge);
      const mine = eff("advice", t.column, t.row);
      const theirs = eff(m.kind, m.index, m.row);
      const role =
        m.kind === "instance" ? "public input" : m.kind === "fixed" ? "fixed constant" : "cell";
      if (m.kind !== "advice") {
        pinnedNotes.push(`a${t.column}[${t.row}] is copy-pinned to ${role} ${memberLabel(m)}`);
      }
      checks.push({
        ref: { type: "copy", member: m, overriddenKey: ovKey(t.column, t.row) },
        label: `copy a${t.column}[${t.row}] ↔ ${memberLabel(m)} (${role})`,
        ok: mine === theirs,
        detail: mine === theirs ? "equal" : `${short(mine)} ≠ ${short(theirs)}`,
        cells: m.kind === "advice" ? [{ column: m.index, row: m.row }] : [],
      });
    }
  }

  return { checks, failing: checks.filter((c) => !c.ok), pinnedNotes };
}

export interface SolveResult {
  /** Values of the chosen cell that repair this check; null = the check does
   * not depend on the cell. */
  roots: Fr[] | null;
  note?: string;
}

/** Repair a failing check by solving for one of its advice cells. */
export function solveCheck(
  ex: LoadedExample,
  overrides: Overrides,
  check: WorkshopCheck,
  cell: { column: number; row: number },
  instanceOverrides?: Overrides,
): SolveResult {
  const cs = ex.vk.vk.cs;
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  const bindingWith = (row: number, v: Fr): RowBinding => ({
    kind: "row",
    row,
    n: ex.n,
    cell: (kind, c, rr) =>
      kind === "advice" && c === cell.column && rr === cell.row ? v : eff(kind, c, rr),
  });
  const maxDegree = Math.min(cs.degree + 1, 16);

  const ref = check.ref;
  if (ref.type === "gate" || ref.type === "trash") {
    const cst =
      ref.type === "gate"
        ? cs.gates[ref.gate].constraints[ref.constraint]
        : cs.trash[ref.trash].constraints[ref.constraint];
    try {
      const roots = rootsOfFunction((v) => evaluate(cst, bindingWith(ref.baseRow, v)), maxDegree);
      if (roots === null) {
        return { roots: null, note: "the constraint does not depend on this cell here" };
      }
      if (roots.length === 0) {
        return { roots: [], note: "no value of this cell satisfies the constraint (given the other current values) — it pins your other changes" };
      }
      return { roots };
    } catch (e) {
      return { roots: null, note: String(e) };
    }
  }

  if (ref.type === "lookup") {
    // For each table row, solve each tuple coordinate for the cell (they are
    // affine in a single cell in practice); keep values making the whole
    // tuple match. Capped enumeration.
    const lookup = cs.lookups[ref.lookup];
    const pl = lookup.input_expression_chunks[ref.chunk][ref.input];
    const usable = Math.min(ex.layout.domain.usable_rows, 1 << 16);
    const roots = new Set<Fr>();
    const evalTuple = (v: Fr) => pl.map((e) => evaluate(e, bindingWith(ref.baseRow, v)));
    // Affinity samples per coordinate: t(v) = A v + B.
    const t0 = evalTuple(0n);
    const t1 = evalTuple(1n);
    const t2 = evalTuple(2n);
    for (let i = 0; i < pl.length; i++) {
      const A = mod(t1[i] - t0[i]);
      if (mod(t2[i] - t0[i]) !== mod(2n * A)) {
        return { roots: null, note: "lookup input is non-linear in this cell — not solvable here" };
      }
    }
    for (let r = 0; r < usable; r++) {
      const target = lookup.table_expressions.map((e) => evaluate(e, effectiveBinding(ex, overrides, r)));
      // Solve the first coordinate that depends on the cell, then verify all.
      let v: Fr | null = null;
      for (let i = 0; i < pl.length; i++) {
        const A = mod(t1[i] - t0[i]);
        if (A === 0n) {
          if (t0[i] !== target[i]) {
            v = null;
            break;
          }
          continue;
        }
        const cand = mod((target[i] - t0[i]) * inv(A));
        if (v === null) v = cand;
        else if (v !== cand) {
          v = null;
          break;
        }
      }
      if (v !== null) {
        const got = evalTuple(v);
        if (got.every((g, i) => g === target[i])) roots.add(v);
      }
    }
    return { roots: [...roots].slice(0, 16) };
  }

  // Copy: the only repairing value is the partner's.
  const m = ref.member;
  const theirs = eff(m.kind, m.index, m.row);
  return { roots: [theirs], note: `equal to ${memberLabel(m)}` };
}

// ---------------------------------------------------------------------------
// Full-circuit satisfaction and the forward auto-solver
// ---------------------------------------------------------------------------

export interface FullCheckResult {
  violations: number;
  /** A few representative failing checks, for reporting. */
  sample: string[];
}

/**
 * Checks the ENTIRE circuit on the usable rows under the given overrides —
 * every gate at every row (active per its selector), every trash term, every
 * lookup input, every permutation copy. This is a TypeScript
 * `MockProver::verify` over the perturbed witness: violations === 0 means the
 * (possibly new) assignment is a genuine satisfying witness for the
 * (possibly new) instance.
 */
export function checkAllRows(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides?: Overrides,
): FullCheckResult {
  const cs = ex.vk.vk.cs;
  const usable = ex.layout.domain.usable_rows;
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  const binding = (row: number) => effectiveBinding(ex, overrides, row, instanceOverrides);
  let violations = 0;
  const sample: string[] = [];
  const fail = (label: string) => {
    violations++;
    if (sample.length < 8) sample.push(label);
  };

  for (let row = 0; row < usable; row++) {
    const b = binding(row);
    cs.gates.forEach((gate) => {
      gate.constraints.forEach((cst, ci) => {
        if (evaluate(cst, b) !== 0n) fail(`gate "${gate.name}" #${ci} @ ${row}`);
      });
    });
    cs.trash.forEach((trash, ti) => {
      if (evaluate(trash.selector, b) === 0n) return;
      trash.constraints.forEach((cst, ci) => {
        if (evaluate(cst, b) !== 0n) fail(`trash ${ti} #${ci} @ ${row}`);
      });
    });
    cs.lookups.forEach((lookup, li) => {
      if (evaluate(lookup.selector, b) === 0n) return;
      const table = tableKeysOf(ex, li);
      lookup.input_expression_chunks.forEach((chunk) => {
        chunk.forEach((pl) => {
          const key = pl.map((e) => toLEHex(evaluate(e, b))).join("|");
          if (!table.has(key)) fail(`lookup ${li} @ ${row}`);
        });
      });
    });
  }

  const permCols = ex.layout.permutation.columns;
  for (const c of ex.copies) {
    const a = permCols[c.col];
    const d = permCols[c.mappedCol];
    if (c.row >= usable || c.mappedRow >= usable) continue;
    if (eff(a.kind, a.index, c.row) !== eff(d.kind, d.index, c.mappedRow)) {
      fail(`copy ${memberLabel({ kind: a.kind, index: a.index, row: c.row })} ↔ ${memberLabel({ kind: d.kind, index: d.index, row: c.mappedRow })}`);
    }
  }

  return { violations, sample };
}

/** Violations among constraints at base row ≤ maxRow (and copies whose both
 * endpoints sit at rows ≤ maxRow). The "settled past" the forward solver must
 * never regress. */
function checkPrefix(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides: Overrides,
  maxRow: number,
): number {
  const cs = ex.vk.vk.cs;
  const usable = Math.min(ex.layout.domain.usable_rows, maxRow + 1);
  const binding = (row: number) => effectiveBinding(ex, overrides, row, instanceOverrides);
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  let v = 0;
  for (let row = 0; row < usable; row++) {
    const b = binding(row);
    cs.gates.forEach((gate) =>
      gate.constraints.forEach((cst) => {
        if (evaluate(cst, b) !== 0n) v++;
      }),
    );
    cs.trash.forEach((trash) => {
      if (evaluate(trash.selector, b) === 0n) return;
      trash.constraints.forEach((cst) => {
        if (evaluate(cst, b) !== 0n) v++;
      });
    });
    cs.lookups.forEach((lookup, li) => {
      if (evaluate(lookup.selector, b) === 0n) return;
      const table = tableKeysOf(ex, li);
      lookup.input_expression_chunks.forEach((chunk) =>
        chunk.forEach((pl) => {
          if (!table.has(pl.map((e) => toLEHex(evaluate(e, b))).join("|"))) v++;
        }),
      );
    });
  }
  const permCols = ex.layout.permutation.columns;
  for (const c of ex.copies) {
    if (Math.max(c.row, c.mappedRow) > maxRow) continue;
    if (c.row >= ex.layout.domain.usable_rows || c.mappedRow >= ex.layout.domain.usable_rows) continue;
    const a = permCols[c.col];
    const d = permCols[c.mappedCol];
    if (eff(a.kind, a.index, c.row) !== eff(d.kind, d.index, c.mappedRow)) v++;
  }
  return v;
}

export interface ForwardSolveResult {
  ok: boolean;
  overrides: Overrides;
  instanceOverrides: Overrides;
  steps: number;
  /** Advice cells whose value the solver changed (excluding the seed). */
  solvedCells: string[];
  /** Instance cells (public inputs) the solver had to move. */
  changedInstances: string[];
  stuckReason?: string;
}

/**
 * Incremental forward auto-solver. Starting from a seed of advice overrides
 * (typically a perturbed witness input and its copy class), each `step()`
 * repairs ONE frontier constraint: it takes the lowest-base-row failing
 * gate/trash/lookup, solves it for its output cell, and propagates the value
 * across that cell's copy class. A move is accepted if the constraint then
 * holds and the settled PAST (rows ≤ this base row) does not regress —
 * downstream constraints may break; the frontier reaches them next. Copies
 * pinning a cell to a public input are repaired by moving that public input
 * (a new statement) when `allowInstanceMoves`; copies to a fixed constant are
 * a hard wall.
 *
 * Exposed as a stepper so the UI can animate progress and stay responsive.
 */
export class ForwardSolver {
  readonly overrides: Overrides;
  readonly instanceOverrides: Overrides;
  readonly solved = new Set<string>();
  readonly changedInstances = new Set<string>();
  done = false;
  stuckReason?: string;
  private full: FullCheckResult;
  private readonly allowInstanceMoves: boolean;

  constructor(
    private readonly ex: LoadedExample,
    private readonly seed: Overrides,
    opts: { allowInstanceMoves?: boolean; extraOverrides?: Overrides } = {},
  ) {
    this.allowInstanceMoves = opts.allowInstanceMoves ?? true;
    // `seed` cells are frozen (never moved); `extraOverrides` are additional
    // initial values the solver MAY change — used by witness reconstruction to
    // blank the derived cells to 0 while keeping the source inputs frozen.
    this.overrides = new Map([...(opts.extraOverrides ?? []), ...seed]);
    this.instanceOverrides = new Map();
    this.full = checkAllRows(ex, this.overrides, this.instanceOverrides);
    if (this.full.violations === 0) this.done = true;
  }

  get violations(): number {
    return this.full.violations;
  }

  get ok(): boolean {
    return this.full.violations === 0;
  }

  /** A signal (copy class) shares one value; write it across the class. */
  private applyClassValue(column: number, row: number, value: Fr): () => void {
    const prevAdvice: [string, Fr | undefined][] = [];
    const prevInstance: [string, Fr | undefined][] = [];
    for (const m of copyClassOf(this.ex, column, row)) {
      if (m.kind === "advice") {
        const key = ovKey(m.index, m.row);
        prevAdvice.push([key, this.overrides.get(key)]);
        this.overrides.set(key, value);
      } else if (m.kind === "instance" && this.allowInstanceMoves) {
        const key = ovKey(m.index, m.row);
        prevInstance.push([key, this.instanceOverrides.get(key)]);
        this.instanceOverrides.set(key, value);
      }
    }
    return () => {
      for (const [k, v] of prevAdvice)
        v === undefined ? this.overrides.delete(k) : this.overrides.set(k, v);
      for (const [k, v] of prevInstance)
        v === undefined ? this.instanceOverrides.delete(k) : this.instanceOverrides.set(k, v);
    };
  }

  /** One repair. Returns true if it made progress; sets `done`/`stuckReason` on stall. */
  step(): boolean {
    if (this.done) return false;
    if (this.full.violations === 0) {
      this.done = true;
      return false;
    }
    const { ex, overrides, instanceOverrides, seed } = this;
    const ws = evaluateWorkshop(ex, overrides, instanceOverrides);
    const computational = ws.failing
      .filter((c) => c.ref.type !== "copy")
      .sort((a, b) => baseRowOf(a) - baseRowOf(b));

    for (const check of computational) {
      const targetRow = baseRowOf(check);
      const before = checkPrefix(ex, overrides, instanceOverrides, targetRow);
      const cells = [...check.cells].sort((a, b) => b.row - a.row || b.column - a.column);
      for (const cell of cells) {
        if (seed.has(ovKey(cell.column, cell.row))) continue; // never move the seed
        const sol = solveCheck(ex, overrides, check, cell, instanceOverrides);
        if (!sol.roots || sol.roots.length === 0) continue;
        for (const root of sol.roots) {
          if (root === eff(ex, overrides, instanceOverrides, cell)) continue;
          const revert = this.applyClassValue(cell.column, cell.row, root);
          const after = checkPrefix(ex, overrides, instanceOverrides, targetRow);
          if (after <= before && checkOk(ex, overrides, instanceOverrides, check)) {
            this.solved.add(ovKey(cell.column, cell.row));
            for (const m of copyClassOf(ex, cell.column, cell.row)) {
              if (m.kind === "instance") this.changedInstances.add(ovKey(m.index, m.row));
            }
            this.full = checkAllRows(ex, overrides, instanceOverrides);
            return true;
          }
          revert();
        }
      }
    }

    // No repair available — stuck. Report the wall.
    this.done = true;
    const wall = ws.failing.find((c) => c.ref.type === "copy" && c.ref.member.kind === "fixed");
    const pinnedPI = ws.failing.find(
      (c) => c.ref.type === "copy" && c.ref.member.kind === "instance",
    );
    this.stuckReason = wall
      ? "a signal is pinned to a fixed constant — cannot be repaired"
      : !this.allowInstanceMoves && pinnedPI
        ? "a computed cell must equal a pinned public input — repairing it would be a collision (or the circuit is under-constrained)"
        : `${this.full.violations} violations remain, none single-cell-repairable (likely a joint native-gadget/trash row needing a linear-system solve): ${this.full.sample.join("; ")}`;
    return false;
  }
}

/** Run the forward solver to completion (or a step budget). */
export function forwardSolve(
  ex: LoadedExample,
  seed: Overrides,
  opts: { maxSteps?: number; allowInstanceMoves?: boolean } = {},
): ForwardSolveResult {
  const maxSteps = opts.maxSteps ?? 5000;
  const solver = new ForwardSolver(ex, seed, opts);
  let steps = 0;
  while (!solver.done && steps < maxSteps) {
    if (solver.step()) steps++;
    else break;
  }
  return {
    ok: solver.ok,
    overrides: solver.overrides,
    instanceOverrides: solver.instanceOverrides,
    steps,
    solvedCells: [...solver.solved],
    changedInstances: [...solver.changedInstances],
    stuckReason: solver.ok
      ? undefined
      : (solver.stuckReason ?? (steps >= maxSteps ? "did not converge within the step budget" : undefined)),
  };
}

function baseRowOf(c: WorkshopCheck): number {
  return c.ref.type === "copy" ? c.ref.member.row : c.ref.baseRow;
}

/** Whether a single check currently holds under the overrides. */
function checkOk(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides: Overrides,
  check: WorkshopCheck,
): boolean {
  const cs = ex.vk.vk.cs;
  const ref = check.ref;
  const b = (row: number) => effectiveBinding(ex, overrides, row, instanceOverrides);
  if (ref.type === "gate") {
    return evaluate(cs.gates[ref.gate].constraints[ref.constraint], b(ref.baseRow)) === 0n;
  }
  if (ref.type === "trash") {
    return evaluate(cs.trash[ref.trash].constraints[ref.constraint], b(ref.baseRow)) === 0n;
  }
  if (ref.type === "lookup") {
    const lookup = cs.lookups[ref.lookup];
    const pl = lookup.input_expression_chunks[ref.chunk][ref.input];
    const key = pl.map((e) => toLEHex(evaluate(e, b(ref.baseRow)))).join("|");
    return tableKeysOf(ex, ref.lookup).has(key);
  }
  const m = ref.member;
  const [oc, or] = ref.overriddenKey.split("/").map(Number);
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  return eff("advice", oc, or) === eff(m.kind, m.index, m.row);
}

function eff(
  ex: LoadedExample,
  overrides: Overrides,
  instanceOverrides: Overrides,
  cell: { column: number; row: number },
): Fr {
  return effectiveCell(ex, overrides, instanceOverrides)("advice", cell.column, cell.row);
}

const tableCache = new WeakMap<LoadedExample, Map<number, Set<string>>>();
function tableKeysOf(ex: LoadedExample, lookupIndex: number): Set<string> {
  let byLookup = tableCache.get(ex);
  if (!byLookup) tableCache.set(ex, (byLookup = new Map()));
  let keys = byLookup.get(lookupIndex);
  if (!keys) {
    keys = new Set();
    const lookup = ex.vk.vk.cs.lookups[lookupIndex];
    for (let r = 0; r < ex.layout.domain.usable_rows; r++) {
      const binding = ex.rowBinding(r);
      keys.add(lookup.table_expressions.map((e) => toLEHex(evaluate(e, binding))).join("|"));
    }
    byLookup.set(lookupIndex, keys);
  }
  return keys;
}

function short(v: Fr): string {
  if (v < 0x10000n) return v.toString();
  const hex = v.toString(16);
  return `0x${hex.slice(0, 6)}…${hex.slice(-4)}`;
}
