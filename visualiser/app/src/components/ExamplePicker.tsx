import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { loadManifest } from "../data/loader";
import type { Manifest } from "../data/types";

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

export default function ExamplePicker() {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadManifest().then(setManifest, (e) => setError(String(e)));
  }, []);

  return (
    <div className="mx-auto max-w-4xl p-8">
      <h1 className="mb-1 text-2xl font-bold text-sky-300">midnight-zk visualiser</h1>
      <p className="mb-6 text-sm text-slate-400">
        Explore the PLONK constraint table, the evaluation domain, proof construction and the
        verifier protocol of the midnight-zk example circuits.
      </p>
      {error && (
        <div className="rounded border border-red-700 bg-red-950 p-4 text-red-300">
          Could not load <code>artifacts/manifest.json</code>: {error}
          <p className="mt-2 text-sm text-red-400">
            Generate artifacts first:{" "}
            <code>cargo run --release --example export_visualiser -- --check</code>
          </p>
        </div>
      )}
      {!manifest && !error && <div className="text-slate-500">loading…</div>}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {manifest?.examples.map((ex) => (
          <Link
            key={ex.id}
            to={`/${ex.id}/table`}
            className="rounded-lg border border-slate-700 bg-slate-800/60 p-4 transition hover:border-sky-500 hover:bg-slate-800"
          >
            <div className="font-mono text-lg text-sky-200">{ex.id}</div>
            <div className="mt-2 text-sm text-slate-400">
              k = {ex.k} · n = {ex.n.toLocaleString()} rows
            </div>
            <div className="text-xs text-slate-500">
              {ex.transcript_hash} · {fmtBytes(ex.binary_bytes)} of column data
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
