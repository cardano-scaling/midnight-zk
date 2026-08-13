/**
 * The evaluation domain H = <ω> as a circle of the n-th roots of unity:
 * row i lives at ω^i. Blinding rows are the final t rows; rotations step
 * around the circle. Below, any column or prover polynomial can be plotted
 * over the domain.
 */

import { useMemo, useState } from "react";
import { useExample } from "../Shell";
import { useStore } from "../../store";
import PolyPlot, { Series } from "./PolyPlot";

export default function DomainView() {
  const ex = useExample();
  const selectedRow = useStore((s) => s.selectedRow);
  const setSelectedRow = useStore((s) => s.setSelectedRow);
  const n = ex.n;
  const usable = ex.layout.domain.usable_rows;

  const seriesOptions = useMemo(() => {
    const opts: { id: string; label: string; series: Series }[] = [];
    ex.layout.columns.advice.forEach((c) => {
      opts.push({
        id: `advice_${c.index}`,
        label: `advice ${c.index}${c.name ? ` (${c.name})` : ""}`,
        series: { label: `advice ${c.index}`, n, get: (r) => ex.cell("advice", c.index, r) },
      });
    });
    ex.layout.columns.fixed.forEach((c) => {
      opts.push({
        id: `fixed_${c.index}`,
        label: `fixed ${c.index}${c.name ? ` (${c.name})` : ""}`,
        series: { label: `fixed ${c.index}`, n, get: (r) => ex.cell("fixed", c.index, r) },
      });
    });
    for (const [id, col] of ex.tracePolys) {
      opts.push({
        id: `trace_${id}`,
        label: `prover: ${id}`,
        series: { label: id, n, get: (r) => col.get(r).value },
      });
    }
    return opts;
  }, [ex, n]);
  const [seriesId, setSeriesId] = useState<string | null>(null);
  const selected = seriesOptions.find((o) => o.id === seriesId) ?? seriesOptions[0];

  const size = 480;
  const cx = size / 2;
  const cy = size / 2;
  const radius = size / 2 - 40;
  const showDots = n <= 512;
  const angle = (i: number) => -((2 * Math.PI * i) / n) + Math.PI / 2; // row 0 at top, ω counter-clockwise

  return (
    <div className="flex h-full gap-6 overflow-y-auto p-6">
      <div>
        <svg width={size} height={size}>
          <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#334155" />
          {showDots &&
            Array.from({ length: n }, (_, i) => {
              const a = angle(i);
              const x = cx + radius * Math.cos(a);
              const y = cy - radius * Math.sin(a);
              const blinding = i >= usable;
              const isSel = i === selectedRow;
              return (
                <g key={i} onClick={() => setSelectedRow(i)} className="cursor-pointer">
                  <circle
                    cx={x}
                    cy={y}
                    r={isSel ? 8 : blinding ? 4 : 5}
                    fill={isSel ? "#7dd3fc" : blinding ? "#7f1d1d" : i === 0 ? "#4ade80" : "#475569"}
                    stroke={isSel ? "#e0f2fe" : "none"}
                  />
                  {(n <= 128 && (i % Math.max(1, Math.floor(n / 32)) === 0 || isSel)) && (
                    <text
                      x={cx + (radius + 16) * Math.cos(a)}
                      y={cy - (radius + 16) * Math.sin(a)}
                      fill={isSel ? "#7dd3fc" : "#64748b"}
                      fontSize="9"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      className="font-mono"
                    >
                      ω{superscript(i)}
                    </text>
                  )}
                </g>
              );
            })}
          {!showDots && (
            <text x={cx} y={cy} fill="#64748b" textAnchor="middle" fontSize="12">
              n = {n} (too many points to draw individually)
            </text>
          )}
          <text x={cx} y={18} fill="#94a3b8" textAnchor="middle" fontSize="12">
            H = ⟨ω⟩, |H| = n = {n} = 2^{ex.layout.domain.k}
          </text>
        </svg>
        <div className="mt-2 space-y-1 text-xs text-slate-400">
          <div>
            <span className="mr-1 inline-block h-2 w-2 rounded-full bg-green-400" /> row 0 (ω⁰ = 1)
          </div>
          <div>
            <span className="mr-1 inline-block h-2 w-2 rounded-full bg-slate-600" /> usable rows 0–
            {usable - 1}
          </div>
          <div>
            <span className="mr-1 inline-block h-2 w-2 rounded-full bg-red-900" /> blinding rows{" "}
            {usable}–{n - 1} (t = {ex.layout.domain.blinding_factors} blinding factors + 1)
          </div>
          <div className="pt-1 text-slate-500">
            A rotation by ρ in a gate query means "look at the cell ρ steps around the circle":
            column(ω^ρ · x).
          </div>
        </div>
      </div>

      <div className="min-w-0 flex-1 space-y-3">
        <div className="text-sm text-slate-300">
          A column of the table is a function H → F; interpolating it gives the column polynomial
          the prover commits to. Pick one to see its values over the domain:
        </div>
        <select
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm text-slate-200"
          value={selected?.id ?? ""}
          onChange={(e) => setSeriesId(e.target.value)}
        >
          {seriesOptions.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
        {selected && (
          <div className="rounded border border-slate-800 bg-slate-900/60 p-2">
            <PolyPlot series={selected.series} height={200} />
          </div>
        )}
        <div className="text-xs text-slate-500">
          Click a bar (or a circle point) to select that row — the selection is shared with the
          table view. Prover polynomials (permutation z, LogUp m/h/Z, quotient limbs) come from
          trace.json and are the actual values committed during proof construction.
        </div>
        {ex.layout.domain && (
          <div className="rounded border border-slate-800 bg-slate-900/60 p-3 font-mono text-xs text-slate-400">
            <div>k = {ex.layout.domain.k}, n = {n}</div>
            <div>extended_k = {ex.layout.domain.extended_k} (for the quotient computation)</div>
            <div className="break-all">ω = {ex.layout.domain.omega}</div>
            <div>blinding_factors = {ex.layout.domain.blinding_factors}</div>
            <div>usable_rows = {usable} (= n − blinding_factors − 1)</div>
          </div>
        )}
      </div>
    </div>
  );
}

const SUP = "⁰¹²³⁴⁵⁶⁷⁸⁹";
function superscript(i: number): string {
  return String(i)
    .split("")
    .map((d) => SUP[parseInt(d, 10)])
    .join("");
}
