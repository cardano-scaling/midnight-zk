/**
 * For the selected row: which regions cover it, which gates are active
 * (simple selector ≠ 0), each active constraint rendered with substituted
 * cell values and its residual, the lookups (input tuple → matching table
 * row), and copy-constraint links.
 */

import { useEffect, useMemo, useState } from "react";
import { useExample } from "../Shell";
import { useStore, fmtValue, fmtValueFull } from "../../store";
import ExprView, { LeafValueSource } from "../expr/ExprView";
import { evaluate, findSimpleSelector, Expr, QueryRef } from "../../verifier/expr";
import { R, mod, toLEHex } from "../../verifier/field";
import { memberLabel, perturbAdviceCell, PerturbResult } from "../../analysis/perturb";
import { effectiveBinding, effectiveCell } from "../../analysis/workshop";
import { LoadedExample } from "../../data/loader";
import { REGION_COLORS } from "./tableLayout";

/**
 * Freedom test: override one advice cell of this row with a chosen (or
 * random) value and re-run every constraint touching it. If nothing breaks,
 * the cell is a free degree of freedom — i.e. under-constrained.
 */
function FreedomTest({ ex, row }: { ex: LoadedExample; row: number }) {
  const [column, setColumn] = useState(0);
  const [valueText, setValueText] = useState("");
  const [followCopies, setFollowCopies] = useState(false);
  const [result, setResult] = useState<PerturbResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);
  const setOverride = useStore((s) => s.setOverride);
  const eff = effectiveCell(ex, overrides, instanceOverrides);

  // Reset when the row changes.
  useEffect(() => {
    setResult(null);
    setError(null);
    setValueText("");
  }, [row]);

  const original = eff("advice", column, row);

  const parseValue = (): bigint | null => {
    const t = valueText.trim();
    if (t === "") return null;
    try {
      const v = t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t);
      return mod(v);
    } catch {
      setError(`cannot parse "${t}" as a decimal or 0x-hex integer`);
      return null;
    }
  };

  const randomFr = (): bigint => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v % R;
  };

  const run = (value: bigint, follow = followCopies) => {
    setError(null);
    setResult(perturbAdviceCell(ex, column, row, value, { followCopies: follow, base: eff }));
  };

  /** Keep the perturbation: it becomes a workshop override (grid + all
   * inspector values switch to the perturbed world). */
  const keep = (r: PerturbResult) => {
    if (r.followedCopies) {
      for (const m of r.classMembers) {
        if (m.kind === "advice") setOverride(m.index, m.row, r.value);
      }
    } else {
      setOverride(r.column, r.row, r.value);
    }
    setResult(null);
  };

  // Only copies broke: the cell is pinned to equality, not to a computation —
  // suggest escalating to the class-wide test.
  const onlyCopiesBroke =
    result !== null &&
    !result.followedCopies &&
    result.violations > 0 &&
    result.checks.every((c) => c.ok || c.kind === "copy");

  return (
    <div>
      <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
        Freedom test (perturb a cell)
      </div>
      <div className="rounded border border-slate-700 bg-slate-900/70 p-2 text-xs">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <select
            className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-green-300"
            value={column}
            onChange={(e) => {
              setColumn(parseInt(e.target.value, 10));
              setResult(null);
            }}
          >
            {ex.layout.columns.advice.map((c) => (
              <option key={c.index} value={c.index}>
                a{c.index}[{row}]{" "}
                {overrides.has(`${c.index}/${row}`)
                  ? `= ${fmtValue(eff("advice", c.index, row))} (perturbed)`
                  : ex.cellAssigned("advice", c.index, row)
                    ? `= ${fmtValue(ex.cell("advice", c.index, row))}`
                    : "· unassigned (0)"}
              </option>
            ))}
          </select>
          <input
            value={valueText}
            onChange={(e) => setValueText(e.target.value)}
            placeholder="new value (dec or 0x…)"
            title={`current value: ${fmtValueFull(original)}`}
            className="w-44 rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-slate-200 outline-none focus:border-sky-600"
          />
          <button
            className="rounded bg-sky-800 px-2 py-0.5 text-sky-100 hover:bg-sky-700 disabled:opacity-40"
            disabled={valueText.trim() === ""}
            onClick={() => {
              const v = parseValue();
              if (v !== null) run(v);
            }}
          >
            perturb to value
          </button>
          <button
            className="rounded bg-fuchsia-900 px-2 py-0.5 text-fuchsia-100 hover:bg-fuchsia-800"
            onClick={() => {
              const v = randomFr();
              setValueText("0x" + v.toString(16));
              run(v);
            }}
          >
            perturb randomly
          </button>
          <label
            className="flex cursor-pointer items-center gap-1 text-slate-300"
            title="Perturb the whole copy-equivalence class together: equality checks inside the class then hold by construction, and what remains is whatever actually computes or reads the value."
          >
            <input
              type="checkbox"
              checked={followCopies}
              onChange={(e) => setFollowCopies(e.target.checked)}
            />
            follow copies
          </label>
        </div>
        {error && <div className="text-red-400">{error}</div>}
        {result && (
          <div className="space-y-1">
            {result.followedCopies && result.classMembers.length > 1 && (
              <div className="text-slate-400">
                perturbed the whole class:{" "}
                <span className="font-mono text-sky-300">
                  {result.classMembers
                    .filter((m) => m.kind === "advice")
                    .map(memberLabel)
                    .join(" ↔ ")}
                </span>
                {result.classMembers.some((m) => m.kind !== "advice") && (
                  <span>
                    {" "}
                    (pinned members kept honest:{" "}
                    {result.classMembers
                      .filter((m) => m.kind !== "advice")
                      .map(memberLabel)
                      .join(", ")}
                    )
                  </span>
                )}
              </div>
            )}
            {result.unchanged ? (
              <div className="rounded bg-slate-800 px-2 py-1 text-slate-400">
                That is the cell's current value — nothing was perturbed. Pick a different value.
              </div>
            ) : result.free && result.assigned ? (
              <div className="rounded border border-red-700 bg-red-950/70 px-2 py-1 font-semibold text-red-300">
                ⚠ FREE {result.followedCopies ? "CLASS" : "CELL"}: a{result.column}[{result.row}]
                {result.followedCopies && result.classMembers.length > 1
                  ? " (with its whole copy class)"
                  : ""}{" "}
                was changed to {fmtValue(result.value)} and {result.checks.length} check
                {result.checks.length === 1 ? "" : "s"} all still pass — this is another valid
                witness for the same instance. The circuit WROTE here but nothing pins the value:
                under-constrained.
              </div>
            ) : result.free ? (
              <div className="rounded border border-amber-800 bg-amber-950/50 px-2 py-1 text-amber-300">
                Free, but <span className="font-semibold">unassigned</span>: nothing in the
                circuit ever wrote a{result.column}[{result.row}], and every check referencing it
                is inactive here (selectors off). Any committed value yields a valid proof, but no
                active constraint reads the cell — this is expected slack space, like the blinding
                rows, not an under-constraint bug.
              </div>
            ) : (
              <div className="rounded border border-green-800 bg-green-950/60 px-2 py-1 text-green-300">
                ✓ constrained against this perturbation: {result.violations} of{" "}
                {result.checks.length} checks break
                {result.followedCopies ? " (copy class perturbed together)" : ""}.
              </div>
            )}
            {onlyCopiesBroke && (
              <div className="rounded border border-sky-800 bg-sky-950/50 px-2 py-1 text-sky-300">
                Only copy checks broke — this cell is pinned to <em>equality</em> with its class,
                not directly to a computation.{" "}
                <button
                  className="rounded bg-sky-800 px-1.5 py-0.5 text-sky-100 hover:bg-sky-700"
                  onClick={() => {
                    setFollowCopies(true);
                    run(result.value, true);
                  }}
                >
                  perturb the whole class
                </button>{" "}
                to see what (if anything) pins the class itself.
              </div>
            )}
            {!result.unchanged && (
              <button
                className="rounded bg-fuchsia-800 px-2 py-0.5 text-fuchsia-100 hover:bg-fuchsia-700"
                title="Apply this perturbation persistently: the grid and all inspector values switch to the perturbed witness, and the workshop panel tracks every constraint it breaks — so you can perturb further cells on top, or solve the failures."
                onClick={() => keep(result)}
              >
                keep — add to workshop
              </button>
            )}
            <div className="max-h-48 space-y-0.5 overflow-y-auto">
              {[...result.checks]
                .sort((a, b) => Number(a.ok) - Number(b.ok))
                .map((c, i) => (
                  <div key={i} className="flex gap-2">
                    <span className={c.ok ? "text-green-500" : "text-red-400"}>
                      {c.ok ? "✓" : "✗"}
                    </span>
                    <span className="text-slate-400">
                      {c.label} @ row {c.row}
                    </span>
                    <span className="ml-auto font-mono text-slate-500">{c.detail}</span>
                  </div>
                ))}
              {result.checks.length === 0 && (
                <div className="text-red-400">
                  No gate, trash, lookup or copy references this cell at all.
                </div>
              )}
            </div>
            <div className="pt-1 text-[10px] leading-4 text-slate-500">
              Per-cell test: catches forgot-selector / forgot-copy / vacuous-coefficient bugs.
              It cannot see correlated multi-cell freedom (perturb-and-repair attacks).
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function RowInspector() {
  const ex = useExample();
  const row = useStore((s) => s.selectedRow);
  const setSelectedRow = useStore((s) => s.setSelectedRow);
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);

  const cs = ex.vk.vk.cs;
  const simple = useMemo(() => new Set(cs.simple_selector_columns), [cs]);
  const numFixedBase = ex.layout.columns.num_fixed_base;

  // Constraint metadata: (gate, constraint, kappa) — static per example.
  const gateInfo = useMemo(
    () =>
      cs.gates.map((g) => ({
        name: g.name,
        constraints: g.constraints.map((c) => ({
          expr: c,
          kappa: findSimpleSelector(c, simple),
        })),
      })),
    [cs, simple],
  );

  // Lookup table index: tuple key -> table row (usable rows only).
  const tableIndex = useMemo(() => {
    const maps = cs.lookups.map(() => new Map<string, number>());
    const usable = ex.layout.domain.usable_rows;
    cs.lookups.forEach((lk, l) => {
      for (let r = 0; r < usable; r++) {
        const binding = ex.rowBinding(r);
        const key = lk.table_expressions.map((e) => toLEHex(evaluate(e, binding))).join("|");
        if (!maps[l].has(key)) maps[l].set(key, r);
      }
    });
    return maps;
  }, [cs, ex]);

  // Copy-constraint index: "permColIdx/row" -> records.
  const copyIndex = useMemo(() => {
    const map = new Map<string, { toCol: number; toRow: number }[]>();
    for (const c of ex.copies) {
      const key = `${c.col}/${c.row}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push({ toCol: c.mappedCol, toRow: c.mappedRow });
    }
    return map;
  }, [ex]);

  if (row === null) {
    return (
      <div className="p-4 text-sm text-slate-500">
        Click a row in the table to inspect its gates, lookups and copies.
      </div>
    );
  }

  // All values below are "effective": kept workshop perturbations shadow the
  // honest witness, so residuals go red where your perturbations break things.
  const binding = effectiveBinding(ex, overrides, row, instanceOverrides);
  const eff = effectiveCell(ex, overrides, instanceOverrides);
  const usable = row < ex.layout.domain.usable_rows;
  const values: LeafValueSource = {
    value: (kind: "fixed" | "advice" | "instance", q: QueryRef) => {
      const r = (((row + q.rotation) % ex.n) + ex.n) % ex.n;
      return eff(kind, q.column, r);
    },
  };

  const regions = ex.regionsAt(row);

  const activeGates = gateInfo
    .map((g) => ({
      ...g,
      constraints: g.constraints.map((c) => ({
        ...c,
        active: c.kappa === null || eff("fixed", c.kappa, row) !== 0n,
        residual: usable ? evaluate(c.expr, binding) : null,
      })),
    }))
    .filter((g) => g.constraints.some((c) => c.active));

  return (
    <div className="space-y-4 p-4 text-sm">
      <div>
        <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
          Row {row} {usable ? "" : "· blinding row"}
        </div>
        {regions.length === 0 && <div className="text-slate-500">No region covers this row.</div>}
        {regions.map((r) => (
          <div key={r.index} className="flex items-center gap-2">
            <span
              className="inline-block h-3 w-3 rounded-sm"
              style={{ background: REGION_COLORS[r.index % REGION_COLORS.length] }}
            />
            <span className="text-slate-300">{r.name}</span>
            <span className="text-xs text-slate-500">
              rows {r.rows![0]}–{r.rows![1]}
            </span>
          </div>
        ))}
      </div>

      <div>
        <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
          Active gates ({activeGates.length}/{gateInfo.length})
        </div>
        {!usable && (
          <div className="text-xs text-slate-500">
            Blinding row: gate constraints are not enforced here (selectors are 0, the active-row
            factor vanishes).
          </div>
        )}
        <div className="space-y-3">
          {activeGates.map((g, gi) => (
            <div key={gi} className="rounded border border-slate-700 bg-slate-900/70 p-2">
              <div className="mb-1 font-mono text-xs text-slate-300">{g.name}</div>
              {g.constraints.map(
                (c, ci) =>
                  c.active && (
                    <div key={ci} className="mb-2 border-l-2 border-slate-700 pl-2">
                      <ExprView
                        expr={c.expr as Expr}
                        values={values}
                        row={row}
                        n={ex.n}
                        simpleSelectors={simple}
                        numFixedBase={numFixedBase}
                      />
                      {c.residual !== null && (
                        <div
                          className={`mt-1 text-xs ${
                            c.residual === 0n ? "text-green-400" : "text-red-400"
                          }`}
                        >
                          = {fmtValue(c.residual)} {c.residual === 0n ? "✓" : "✗ (should be 0)"}
                        </div>
                      )}
                    </div>
                  ),
              )}
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">Lookups</div>
        <div className="space-y-2">
          {cs.lookups.map((lk, l) => {
            const sel = usable ? evaluate(lk.selector, binding) : 0n;
            return (
              <div key={l} className="rounded border border-slate-700 bg-slate-900/70 p-2">
                <div className="mb-1 flex items-center gap-2 font-mono text-xs text-slate-300">
                  {lk.name}
                  <span
                    className={`rounded px-1 ${sel !== 0n ? "bg-pink-900 text-pink-200" : "bg-slate-800 text-slate-500"}`}
                  >
                    selector = {sel.toString()}
                  </span>
                </div>
                {sel !== 0n &&
                  lk.input_expression_chunks.map((chunk, ci) =>
                    chunk.map((pl, pi) => {
                      const tuple = pl.map((e) => evaluate(e, binding));
                      const key = tuple.map(toLEHex).join("|");
                      const tableRow = tableIndex[l].get(key);
                      return (
                        <div key={`${ci}/${pi}`} className="mb-1 text-xs">
                          <span className="text-slate-400">
                            chunk {ci}, input {pi}:{" "}
                          </span>
                          <span className="font-mono text-green-300">
                            ({tuple.map(fmtValue).join(", ")})
                          </span>
                          {tableRow !== undefined ? (
                            <button
                              className="ml-2 rounded bg-amber-900/60 px-1 text-amber-200 hover:bg-amber-800"
                              onClick={() => setSelectedRow(tableRow)}
                            >
                              → table row {tableRow}
                            </button>
                          ) : (
                            <span className="ml-2 text-red-400">not in table ✗</span>
                          )}
                        </div>
                      );
                    }),
                  )}
              </div>
            );
          })}
          {cs.lookups.length === 0 && <div className="text-slate-500">none</div>}
        </div>
      </div>

      {usable && <FreedomTest ex={ex} row={row} />}

      <div>
        <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
          Copy constraints (permutation)
        </div>
        <div className="space-y-1">
          {ex.layout.permutation.columns.map((colRef, pi) => {
            const copies = copyIndex.get(`${pi}/${row}`);
            if (!copies) return null;
            return copies.map((c, i) => {
              const target = ex.layout.permutation.columns[c.toCol];
              return (
                <div key={`${pi}/${i}`} className="text-xs">
                  <span className="font-mono text-slate-300">
                    {colRef.kind[0]}
                    {colRef.index}[{row}]
                  </span>
                  <span className="text-slate-500"> ↔ </span>
                  <button
                    className="rounded bg-slate-800 px-1 font-mono text-sky-300 hover:bg-slate-700"
                    onClick={() => setSelectedRow(c.toRow)}
                  >
                    {target.kind[0]}
                    {target.index}[{c.toRow}]
                  </button>
                </div>
              );
            });
          })}
        </div>
      </div>
    </div>
  );
}
