/**
 * Freedom test: override an advice cell — optionally together with its whole
 * copy-equivalence class — with a chosen value, and re-evaluate every
 * enforcement mechanism that touches the overridden cells:
 *
 *  - every gate constraint querying them, at each affected base row
 *    (full expression incl. its selectors: must still evaluate to 0);
 *  - every trash constraint querying them, on rows where the additive trash
 *    selector is 1 (each τ-batched term must individually be 0);
 *  - every lookup whose input references them, on rows where the lookup
 *    selector is on (the perturbed input tuple must still be in the table);
 *  - every permutation copy leaving the overridden set (equality with a
 *    partner that keeps its honest value — including instance cells, i.e.
 *    public inputs, and fixed cells, i.e. constants).
 *
 * In single-cell mode, a copy-linked cell trivially fails its copy check —
 * which only proves it is pinned to EQUALITY, not to a computed value. In
 * follow-copies mode the entire class moves together, copy checks inside the
 * class hold by construction, and what remains is whatever actually computes
 * or reads the value. If NOTHING breaks, the perturbed assignment is another
 * satisfying witness for the same instance: the class is a proven free
 * degree of freedom. Correlated freedom across *different* classes
 * (perturb-and-repair through gates) remains out of scope.
 */

import type { LoadedExample } from "../data/loader";
import type { ColumnKind } from "../data/types";
import { evaluate, findSimpleSelector, queryLeaves, RowBinding } from "../verifier/expr";
import { Fr, mod, toLEHex } from "../verifier/field";

export interface PerturbCheck {
  kind: "gate" | "trash" | "lookup" | "copy";
  label: string;
  /** Base row the check was evaluated at (or partner row for copies). */
  row: number;
  ok: boolean;
  detail: string;
}

export interface ClassMember {
  kind: ColumnKind;
  index: number;
  row: number;
}

export interface PerturbResult {
  column: number;
  row: number;
  originalValue: Fr;
  /** Was the cell ever written by the circuit? Unassigned cells default to 0
   * and, when additionally unread, are expected slack — their freedom is not
   * an under-constraint bug. */
  assigned: boolean;
  value: Fr;
  unchanged: boolean;
  /** Whether the whole copy class was perturbed together. */
  followedCopies: boolean;
  /** The copy-equivalence class of the cell (always computed). */
  classMembers: ClassMember[];
  checks: PerturbCheck[];
  violations: number;
  /** No check noticed the change: a free degree of freedom. */
  free: boolean;
}

export const memberKey = (m: ClassMember) => `${m.kind}/${m.index}/${m.row}`;

export function memberLabel(m: ClassMember): string {
  return `${m.kind[0]}${m.index}[${m.row}]`;
}

/**
 * The copy-equivalence class of a cell: BFS over the permutation mapping.
 * Includes the cell itself; members can live in advice, instance (public
 * input) or fixed (constant) columns.
 */
export function copyClassOf(ex: LoadedExample, column: number, row: number): ClassMember[] {
  const permCols = ex.layout.permutation.columns;
  const start: ClassMember = { kind: "advice", index: column, row };
  const seen = new Map<string, ClassMember>([[memberKey(start), start]]);
  const queue = [start];
  while (queue.length > 0) {
    const cur = queue.pop()!;
    // Find `cur` as a permutation-column endpoint.
    const pcIdx = permCols.findIndex((c) => c.kind === cur.kind && c.index === cur.index);
    if (pcIdx < 0) continue;
    for (const c of ex.copies) {
      const ends: [number, number][] = [
        [c.col, c.row],
        [c.mappedCol, c.mappedRow],
      ];
      for (let i = 0; i < 2; i++) {
        if (ends[i][0] === pcIdx && ends[i][1] === cur.row) {
          const [oc, or] = ends[1 - i];
          const ref = permCols[oc];
          const member: ClassMember = { kind: ref.kind, index: ref.index, row: or };
          const key = memberKey(member);
          if (!seen.has(key)) {
            seen.set(key, member);
            queue.push(member);
          }
        }
      }
    }
  }
  return [...seen.values()];
}

export interface PerturbOptions {
  /** Perturb the entire copy class together instead of the single cell. */
  followCopies?: boolean;
  /**
   * Baseline cell accessor (e.g. with the workshop's kept overrides applied);
   * defaults to the honest witness.
   */
  base?: (kind: "fixed" | "advice" | "instance", column: number, row: number) => Fr;
}

export function perturbAdviceCell(
  ex: LoadedExample,
  column: number,
  row: number,
  rawValue: Fr,
  options: PerturbOptions = {},
): PerturbResult {
  const cs = ex.vk.vk.cs;
  const n = ex.n;
  const usable = ex.layout.domain.usable_rows;
  const value = mod(rawValue);
  const base = options.base ?? ((kind, c, r) => ex.cell(kind, c, r));
  const originalValue = base("advice", column, row);
  const followCopies = options.followCopies ?? false;
  const checks: PerturbCheck[] = [];

  const classMembers = copyClassOf(ex, column, row);

  // The advice cells whose value we override. Non-advice class members
  // (public inputs, fixed constants) are not prover-controlled and keep
  // their honest values — in follow mode they become equality violations.
  const targets = new Map<string, ClassMember>();
  const addTarget = (m: ClassMember) => targets.set(`${m.index}/${m.row}`, m);
  if (followCopies) {
    for (const m of classMembers) if (m.kind === "advice") addTarget(m);
  } else {
    addTarget({ kind: "advice", index: column, row });
  }

  const isTarget = (c: number, r: number) => targets.has(`${c}/${r}`);
  const overridden = (r: number): RowBinding => ({
    kind: "row",
    row: r,
    n,
    cell: (kind, c, rr) => (kind === "advice" && isTarget(c, rr) ? value : base(kind, c, rr)),
  });

  /** Usable base rows from which a leaf on some target column sees a target row. */
  const baseRows = (leaves: { column: number; rotation: number }[]): number[] => {
    const rows = new Set<number>();
    for (const leaf of leaves) {
      for (const t of targets.values()) {
        if (leaf.column !== t.index) continue;
        const base = (((t.row - leaf.rotation) % n) + n) % n;
        if (base < usable) rows.add(base);
      }
    }
    return [...rows].sort((a, b) => a - b);
  };

  // Gates: the full constraint expression (selectors included) must vanish.
  // Constraints whose simple selector is off at the base row hold vacuously —
  // flagged as such, so a "passes" verdict explains itself.
  const simple = new Set(cs.simple_selector_columns);
  cs.gates.forEach((gate) => {
    gate.constraints.forEach((cst, ci) => {
      const advice = queryLeaves(cst).filter((l) => l.kind === "advice");
      const kappa = findSimpleSelector(cst, simple);
      for (const base of baseRows(advice)) {
        const vacuous = kappa !== null && ex.cell("fixed", kappa, base) === 0n;
        const residual = evaluate(cst, overridden(base));
        checks.push({
          kind: "gate",
          label: `gate "${gate.name}" #${ci}`,
          row: base,
          ok: residual === 0n,
          detail: vacuous
            ? "selector off — holds vacuously"
            : residual === 0n
              ? "residual 0"
              : `residual ${short(residual)}`,
        });
      }
    });
  });

  // Trash: each constraint term must vanish where the trash selector is 1.
  cs.trash.forEach((trash, ti) => {
    trash.constraints.forEach((cst, ci) => {
      const advice = queryLeaves(cst).filter((l) => l.kind === "advice");
      for (const base of baseRows(advice)) {
        const sel = evaluate(trash.selector, overridden(base));
        if (sel === 0n) continue; // absorbed by the trash polynomial here
        const residual = evaluate(cst, overridden(base));
        checks.push({
          kind: "trash",
          label: `trash ${ti} term #${ci}`,
          row: base,
          ok: residual === 0n,
          detail: residual === 0n ? "residual 0" : `residual ${short(residual)}`,
        });
      }
    });
  });

  // Lookups: the perturbed input tuple must still be a table row.
  cs.lookups.forEach((lookup, li) => {
    let tableKeys: Set<string> | null = null;
    const tableIndex = () => {
      if (!tableKeys) {
        tableKeys = new Set();
        for (let r = 0; r < usable; r++) {
          const binding = ex.rowBinding(r);
          tableKeys.add(
            lookup.table_expressions.map((e) => toLEHex(evaluate(e, binding))).join("|"),
          );
        }
      }
      return tableKeys;
    };
    lookup.input_expression_chunks.forEach((chunk, ci) => {
      chunk.forEach((pl, pi) => {
        const advice = pl.flatMap((e) => queryLeaves(e).filter((l) => l.kind === "advice"));
        for (const base of baseRows(advice)) {
          const sel = evaluate(lookup.selector, overridden(base));
          if (sel === 0n) continue;
          const tuple = pl.map((e) => evaluate(e, overridden(base)));
          const hit = tableIndex().has(tuple.map(toLEHex).join("|"));
          checks.push({
            kind: "lookup",
            label: `lookup ${li} chunk ${ci} input ${pi}`,
            row: base,
            ok: hit,
            detail: `(${tuple.map(short).join(", ")}) ${hit ? "in table" : "NOT in table"}`,
          });
        }
      });
    });
  });

  // Copies: equality with partners that keep their honest value. Deduped per
  // partner (a 2-cycle yields two mapping records for the same edge). In
  // follow mode only edges LEAVING the overridden set remain — i.e. class
  // members in instance (public input) or fixed (constant) columns.
  const seenPartners = new Set<string>();
  for (const m of classMembers) {
    const key = memberKey(m);
    if (seenPartners.has(key)) continue;
    seenPartners.add(key);
    if (m.kind === "advice" && isTarget(m.index, m.row)) continue; // inside the overridden set
    const partnerValue =
      m.kind === "instance"
        ? (ex.instances[m.index]?.[m.row] ?? 0n)
        : base(m.kind as "advice" | "fixed", m.index, m.row);
    const ok = partnerValue === value;
    const role =
      m.kind === "instance"
        ? "public input"
        : m.kind === "fixed"
          ? "fixed constant"
          : "cell";
    checks.push({
      kind: "copy",
      label: `copy ↔ ${memberLabel(m)} (${role})`,
      row: m.row,
      ok,
      detail: ok ? "still equal" : `partner holds ${short(partnerValue)}`,
    });
  }

  const violations = checks.filter((c) => !c.ok).length;
  return {
    column,
    row,
    originalValue,
    assigned: ex.cellAssigned("advice", column, row),
    value,
    unchanged: value === originalValue,
    followedCopies: followCopies,
    classMembers,
    checks,
    violations,
    free: violations === 0 && value !== originalValue,
  };
}

function short(v: Fr): string {
  if (v < 0x10000n) return v.toString();
  const hex = v.toString(16);
  return `0x${hex.slice(0, 6)}…${hex.slice(-4)}`;
}
