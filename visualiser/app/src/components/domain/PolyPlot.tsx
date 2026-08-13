/**
 * Bar plot of a polynomial's values over the domain rows. Field elements
 * have no natural magnitude, so we plot bit-length (log2), which makes
 * structure visible: zeros, small integers, and "random-looking" full-width
 * field elements are immediately distinguishable.
 */

import { useEffect, useRef } from "react";
import { useStore } from "../../store";

export interface Series {
  label: string;
  n: number;
  get: (row: number) => bigint;
}

export default function PolyPlot({ series, height = 120 }: { series: Series; height?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const selectedRow = useStore((s) => s.selectedRow);
  const setSelectedRow = useStore((s) => s.setSelectedRow);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const parent = canvas.parentElement!;
    const dpr = window.devicePixelRatio || 1;
    const w = parent.clientWidth;
    canvas.width = w * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${height}px`;
    const ctx = canvas.getContext("2d")!;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, height);

    const n = series.n;
    const barW = w / n;
    const maxBits = 255;
    for (let i = 0; i < n; i++) {
      const v = series.get(i);
      const bits = v === 0n ? 0 : v.toString(2).length;
      const h = (bits / maxBits) * (height - 14);
      ctx.fillStyle = i === selectedRow ? "#7dd3fc" : bits > 128 ? "#818cf8" : "#34d399";
      ctx.fillRect(i * barW, height - h, Math.max(1, barW - 0.5), h);
    }
    ctx.fillStyle = "#64748b";
    ctx.font = "10px ui-monospace, monospace";
    ctx.fillText(`${series.label} — bar height = bit length of the value at row i`, 4, 10);
  }, [series, height, selectedRow]);

  const onClick = (e: React.MouseEvent) => {
    const rect = ref.current!.getBoundingClientRect();
    const row = Math.floor(((e.clientX - rect.left) / rect.width) * series.n);
    setSelectedRow(Math.max(0, Math.min(series.n - 1, row)));
  };

  return (
    <div className="w-full">
      <canvas ref={ref} onClick={onClick} className="block w-full cursor-crosshair" />
    </div>
  );
}
