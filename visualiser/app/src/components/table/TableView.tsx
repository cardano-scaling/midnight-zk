import { useMemo, useRef, useState } from "react";
import { useExample } from "../Shell";
import { useStore } from "../../store";
import { computeCoverage } from "../../analysis/coverage";
import { determinismMap, determinismOverlay, DeterminismMap } from "../../analysis/reconstruct";
import GridCanvas from "./GridCanvas";
import PerturbWorkshop from "./PerturbWorkshop";
import RowInspector from "./RowInspector";
import { computeGeometry, HEADER_H, ROW_H } from "./tableLayout";

export default function TableView() {
  const ex = useExample();
  const geometry = useMemo(() => computeGeometry(ex), [ex]);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const setSelectedRow = useStore((s) => s.setSelectedRow);
  const setReconstructDiff = useStore((s) => s.setReconstructDiff);
  const [rowInput, setRowInput] = useState("");
  const [coverageOn, setCoverageOn] = useState(false);
  const coverage = useMemo(() => (coverageOn ? computeCoverage(ex) : null), [coverageOn, ex]);
  const [determinism, setDeterminism] = useState<DeterminismMap | null>(null);
  // Per-cell determinism is O(cells); gate it to small circuits.
  const detAvailable = ex.n <= 8192;

  const runDeterminism = () => {
    const map = determinismMap(ex);
    setDeterminism(map);
    setReconstructDiff(determinismOverlay(map));
  };
  const clearDeterminism = () => {
    setDeterminism(null);
    setReconstructDiff(null);
  };

  const jumpTo = (row: number) => {
    const clamped = Math.max(0, Math.min(ex.n - 1, row));
    setSelectedRow(clamped);
    scrollRef.current?.scrollTo({
      top: Math.max(0, clamped * ROW_H - (scrollRef.current.clientHeight - HEADER_H) / 2),
      behavior: "smooth",
    });
  };

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-3 border-b border-slate-800 bg-slate-900/60 px-3 py-1.5 text-sm">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const v = parseInt(rowInput, 10);
              if (!Number.isNaN(v)) jumpTo(v);
            }}
          >
            <input
              value={rowInput}
              onChange={(e) => setRowInput(e.target.value)}
              placeholder="jump to row…"
              className="w-28 rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs text-slate-200 outline-none focus:border-sky-600"
            />
          </form>
          <select
            className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs text-slate-300"
            defaultValue=""
            onChange={(e) => {
              const r = ex.layout.regions[parseInt(e.target.value, 10)];
              if (r?.rows) jumpTo(r.rows[0]);
            }}
          >
            <option value="" disabled>
              jump to region…
            </option>
            {ex.layout.regions.map(
              (r) =>
                r.rows && (
                  <option key={r.index} value={r.index}>
                    {r.name} ({r.rows[0]}–{r.rows[1]})
                  </option>
                ),
            )}
          </select>
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={coverageOn}
              onChange={(e) => setCoverageOn(e.target.checked)}
            />
            coverage
          </label>
          {coverage && (
            <span className="text-xs">
              {coverage.uncovered.length > 0 ? (
                <button
                  className="rounded bg-red-900/70 px-1.5 py-0.5 text-red-200 hover:bg-red-800"
                  title="jump to first uncovered cell"
                  onClick={() => jumpTo(coverage.uncovered[0].row)}
                >
                  ⚠ {coverage.uncovered.length} uncovered cell
                  {coverage.uncovered.length === 1 ? "" : "s"}
                </button>
              ) : (
                <span className="rounded bg-green-950 px-1.5 py-0.5 text-green-400">
                  ✓ all assigned cells covered
                </span>
              )}
              {coverage.copyOnly.length > 0 && (
                <button
                  className="ml-1 rounded bg-amber-950 px-1.5 py-0.5 text-amber-300 hover:bg-amber-900"
                  title="pinned only to EQUALITY with another cell, not to a computed value — jump to first"
                  onClick={() => jumpTo(coverage.copyOnly[0].row)}
                >
                  {coverage.copyOnly.length} copy-only
                </button>
              )}
            </span>
          )}
          {detAvailable && (
            <span className="flex items-center gap-1.5 text-xs">
              {determinism ? (
                <button
                  className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300 hover:bg-slate-700"
                  onClick={clearDeterminism}
                >
                  clear determinism map
                </button>
              ) : (
                <button
                  className="rounded bg-emerald-800 px-1.5 py-0.5 text-emerald-100 hover:bg-emerald-700"
                  title="For every assigned advice cell: is its value uniquely forced by the rest of the witness? Green = determined (would reconstruct byte-for-byte); red = free (under-constrained)."
                  onClick={runDeterminism}
                >
                  determinism map
                </button>
              )}
              {determinism && (
                <span className="text-slate-400">
                  <span className="text-green-400">{determinism.determined} determined</span>
                  {determinism.free > 0 ? (
                    <>
                      {" "}
                      ·{" "}
                      <button
                        className="text-red-400 underline hover:text-red-300"
                        title="jump to first free cell"
                        onClick={() =>
                          determinism.freeCells[0] && jumpTo(determinism.freeCells[0].row)
                        }
                      >
                        {determinism.free} FREE ⚠
                      </button>
                    </>
                  ) : (
                    <span className="text-green-400"> — every cell rigidly forced ✓</span>
                  )}
                </span>
              )}
            </span>
          )}
          <span className="ml-auto text-xs text-slate-500">
            usable rows 0–{ex.layout.domain.usable_rows - 1}, blinding{" "}
            {ex.layout.domain.usable_rows}–{ex.n - 1} (red line) · click a row to inspect
          </span>
        </div>
        <div className="min-h-0 flex-1">
          <GridCanvas ex={ex} geometry={geometry} scrollRef={scrollRef} coverage={coverage} />
        </div>
      </div>
      <aside className="w-[30rem] shrink-0 overflow-y-auto border-l border-slate-800 bg-slate-900/40">
        <PerturbWorkshop />
        <RowInspector />
      </aside>
    </div>
  );
}
