/**
 * Virtualised canvas renderer for the constraint table. An outer scroll
 * container holds a full-size spacer; the canvas is sticky and repaints the
 * visible window on scroll. Fixed row height makes hit-testing trivial.
 */

import { useCallback, useEffect, useRef } from "react";
import { LoadedExample } from "../../data/loader";
import { fmtValue, useStore } from "../../store";
import { Coverage, COV_COPY } from "../../analysis/coverage";
import {
  ColumnSpec,
  GridGeometry,
  GROUP_COLORS,
  GUTTER_W,
  HEADER_H,
  REGION_BAND_W,
  REGION_COLORS,
  ROW_H,
} from "./tableLayout";

interface Props {
  ex: LoadedExample;
  geometry: GridGeometry;
  scrollRef: React.RefObject<HTMLDivElement | null>;
  /** When set, advice cells are tinted by constraint coverage. */
  coverage?: Coverage | null;
}

export default function GridCanvas({ ex, geometry, scrollRef, coverage }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const selectedRow = useStore((s) => s.selectedRow);
  const hoverCells = useStore((s) => s.hoverCells);
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);
  const reconstructDiff = useStore((s) => s.reconstructDiff);
  const setSelectedRow = useStore((s) => s.setSelectedRow);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const scroller = scrollRef.current;
    if (!canvas || !scroller) return;

    const dpr = window.devicePixelRatio || 1;
    const cw = scroller.clientWidth;
    const ch = scroller.clientHeight;
    if (canvas.width !== cw * dpr || canvas.height !== ch * dpr) {
      canvas.width = cw * dpr;
      canvas.height = ch * dpr;
      canvas.style.width = `${cw}px`;
      canvas.style.height = `${ch}px`;
    }
    const ctx = canvas.getContext("2d")!;
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, cw, ch);
    ctx.font = "11px ui-monospace, monospace";
    ctx.textBaseline = "middle";

    const sx = scroller.scrollLeft;
    const sy = scroller.scrollTop;
    const n = ex.n;
    const usable = ex.layout.domain.usable_rows;
    const firstRow = Math.max(0, Math.floor(sy / ROW_H));
    const lastRow = Math.min(n - 1, Math.ceil((sy + ch - HEADER_H) / ROW_H));
    const cols = geometry.columns.filter((c) => c.x + c.width > sx && c.x < sx + cw);

    // --- rows background + cells
    for (let row = firstRow; row <= lastRow; row++) {
      const yTop = HEADER_H + row * ROW_H - sy;
      const blinding = row >= usable;
      // zebra + blinding tint
      ctx.fillStyle = blinding ? "#1e1b2e" : row % 2 ? "#0f172a" : "#111c33";
      ctx.fillRect(0, yTop, cw, ROW_H);
      if (row === usable) {
        ctx.fillStyle = "#f87171";
        ctx.fillRect(0, yTop - 1, cw, 2);
      }
      if (selectedRow === row) {
        ctx.fillStyle = "#0ea5e922";
        ctx.fillRect(0, yTop, cw, ROW_H);
      }

      // cells
      const y = yTop + ROW_H / 2;
      for (const col of cols) {
        const x = col.x - sx;
        const groupColor = GROUP_COLORS[col.group];
        ctx.fillStyle = groupColor.bg;
        ctx.fillRect(x, yTop, col.width - 1, ROW_H);

        if (col.group === "selector") {
          const on = ex.cell("fixed", col.index, row) === 1n;
          if (blinding && col.kind === "fixed") {
            // selectors are 0 on blinding rows; draw nothing
          }
          ctx.fillStyle = on ? groupColor.text : "#33415577";
          ctx.beginPath();
          ctx.arc(x + col.width / 2, y, on ? 5 : 2.5, 0, Math.PI * 2);
          ctx.fill();
          continue;
        }

        if (col.kind === "advice" && blinding) {
          ctx.fillStyle = "#64748b";
          ctx.fillText("⋆ blind", x + 5, y);
          continue;
        }
        const assigned = ex.cellAssigned(col.kind as "fixed" | "advice" | "instance", col.index, row);
        if (!assigned) {
          ctx.fillStyle = "#334155";
          ctx.fillText("·", x + 5, y);
          continue;
        }
        // Coverage overlay: assigned advice cells not touched by any
        // constraint are red; copy-only cells (equality but no computation
        // pins them) are amber.
        if (coverage && col.kind === "advice" && !blinding) {
          const f = coverage.flags[col.index][row];
          if (f === 0) {
            ctx.fillStyle = "#7f1d1dcc";
            ctx.fillRect(x, yTop, col.width - 1, ROW_H);
          } else if (f === COV_COPY) {
            ctx.fillStyle = "#78350f66";
            ctx.fillRect(x, yTop, col.width - 1, ROW_H);
          }
        }
        // Reconstruction diff overlay: source (blue) / match (green) /
        // differ (red) / unreached (dim). Takes precedence over plain
        // override tint so the diff is unambiguous.
        const diff =
          reconstructDiff && col.kind === "advice"
            ? reconstructDiff.get(`${col.index}/${row}`)
            : undefined;
        if (diff !== undefined) {
          const bg =
            diff === "source"
              ? "#075985aa"
              : diff === "match"
                ? "#14532daa"
                : diff === "differ"
                  ? "#7f1d1dcc"
                  : "#1e293b";
          const fg =
            diff === "source"
              ? "#bae6fd"
              : diff === "match"
                ? "#86efac"
                : diff === "differ"
                  ? "#fca5a5"
                  : "#475569";
          ctx.fillStyle = bg;
          ctx.fillRect(x, yTop, col.width - 1, ROW_H);
          ctx.fillStyle = fg;
          const v = overrides.get(`${col.index}/${row}`);
          ctx.fillText(v !== undefined ? fmtValue(v) : "·", x + 5, y, col.width - 10);
          continue;
        }

        // Workshop overrides: perturbed advice cells on violet, moved public
        // inputs (instance overrides) on sky.
        const override =
          col.kind === "advice"
            ? overrides.get(`${col.index}/${row}`)
            : col.kind === "instance"
              ? instanceOverrides.get(`${col.index}/${row}`)
              : undefined;
        if (override !== undefined) {
          ctx.fillStyle = col.kind === "instance" ? "#075985cc" : "#86198f99";
          ctx.fillRect(x, yTop, col.width - 1, ROW_H);
          ctx.fillStyle = col.kind === "instance" ? "#bae6fd" : "#f5d0fe";
          ctx.fillText(fmtValue(override), x + 5, y, col.width - 10);
          continue;
        }
        const v = ex.cell(col.kind as "fixed" | "advice" | "instance", col.index, row);
        ctx.fillStyle = groupColor.text;
        ctx.fillText(fmtValue(v), x + 5, y, col.width - 10);
      }
    }

    // --- gutter overlay (fixed to the left, above scrolled cells)
    ctx.fillStyle = "#0b1120";
    ctx.fillRect(0, HEADER_H, GUTTER_W + REGION_BAND_W, ch - HEADER_H);
    for (let row = firstRow; row <= lastRow; row++) {
      const yTop = HEADER_H + row * ROW_H - sy;
      if (selectedRow === row) {
        ctx.fillStyle = "#0ea5e922";
        ctx.fillRect(0, yTop, GUTTER_W + REGION_BAND_W, ROW_H);
      }
      ctx.fillStyle = selectedRow === row ? "#7dd3fc" : "#64748b";
      ctx.fillText(String(row), 6, yTop + ROW_H / 2);
      const regions = ex.regionsAt(row);
      regions.forEach((r, i) => {
        ctx.fillStyle = REGION_COLORS[r.index % REGION_COLORS.length];
        const w = Math.max(3, REGION_BAND_W / Math.max(1, regions.length));
        ctx.fillRect(GUTTER_W + i * w, yTop, w - 1, ROW_H);
      });
    }

    // --- hover highlights
    for (const cell of hoverCells) {
      const col = geometry.columns.find((c) => c.kind === cell.kind && c.index === cell.column);
      if (!col) continue;
      const yTop = HEADER_H + cell.row * ROW_H - sy;
      ctx.strokeStyle = "#c4b5fd";
      ctx.lineWidth = 2;
      ctx.strokeRect(col.x - sx + 0.5, yTop + 0.5, col.width - 2, ROW_H - 1);
    }

    // --- header (drawn last, fixed position)
    ctx.fillStyle = "#0b1120";
    ctx.fillRect(0, 0, cw, HEADER_H);
    ctx.strokeStyle = "#1e293b";
    ctx.beginPath();
    ctx.moveTo(0, HEADER_H - 0.5);
    ctx.lineTo(cw, HEADER_H - 0.5);
    ctx.stroke();

    // group spans
    const groups: { group: ColumnSpec["group"]; x0: number; x1: number }[] = [];
    for (const col of geometry.columns) {
      const last = groups[groups.length - 1];
      if (last && last.group === col.group) last.x1 = col.x + col.width;
      else groups.push({ group: col.group, x0: col.x, x1: col.x + col.width });
    }
    ctx.font = "bold 11px ui-sans-serif, sans-serif";
    for (const g of groups) {
      const color = GROUP_COLORS[g.group];
      ctx.fillStyle = color.header;
      ctx.fillRect(g.x0 - sx, 4, g.x1 - g.x0 - 2, 4);
      ctx.fillText(g.group, g.x0 - sx + 2, 16);
    }
    ctx.font = "11px ui-monospace, monospace";
    for (const col of cols) {
      ctx.fillStyle = GROUP_COLORS[col.group].text;
      ctx.save();
      if (col.group === "selector") {
        ctx.translate(col.x - sx + col.width / 2 + 4, HEADER_H - 6);
        ctx.rotate(-Math.PI / 4);
        ctx.fillText(col.label, 0, 0);
      } else {
        ctx.fillText(col.label, col.x - sx + 4, HEADER_H - 14, col.width - 8);
      }
      ctx.restore();
    }
    ctx.fillStyle = "#64748b";
    ctx.fillText("row", 6, HEADER_H - 14);

    ctx.restore();
  }, [
    ex,
    geometry,
    hoverCells,
    selectedRow,
    scrollRef,
    coverage,
    overrides,
    instanceOverrides,
    reconstructDiff,
  ]);

  useEffect(() => {
    const scroller = scrollRef.current;
    if (!scroller) return;
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(draw);
    };
    scroller.addEventListener("scroll", onScroll);
    const ro = new ResizeObserver(onScroll);
    ro.observe(scroller);
    draw();
    return () => {
      scroller.removeEventListener("scroll", onScroll);
      ro.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [draw, scrollRef]);

  const onClick = (e: React.MouseEvent) => {
    const scroller = scrollRef.current!;
    const rect = canvasRef.current!.getBoundingClientRect();
    const y = e.clientY - rect.top + scroller.scrollTop;
    if (y < HEADER_H) return;
    const row = Math.floor((y - HEADER_H) / ROW_H);
    if (row >= 0 && row < ex.n) setSelectedRow(row);
  };

  return (
    <div ref={scrollRef} className="relative h-full w-full overflow-auto">
      <div
        style={{ width: geometry.totalWidth, height: geometry.totalHeight }}
        className="pointer-events-none absolute"
      />
      <canvas
        ref={canvasRef}
        onClick={onClick}
        className="sticky left-0 top-0 block cursor-crosshair"
      />
    </div>
  );
}
