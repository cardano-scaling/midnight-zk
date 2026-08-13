import { createContext, useContext, useEffect, useState } from "react";
import { Link, NavLink, Outlet, useParams } from "react-router-dom";
import { LoadedExample, loadExample } from "../data/loader";

const ExampleContext = createContext<LoadedExample | null>(null);

export function useExample(): LoadedExample {
  const ex = useContext(ExampleContext);
  if (!ex) throw new Error("example not loaded");
  return ex;
}

const VIEWS = [
  { path: "table", label: "Table" },
  { path: "domain", label: "Domain" },
  { path: "prover", label: "Prover" },
  { path: "verifier", label: "Verifier" },
];

export default function Shell() {
  const { example } = useParams();
  const [loaded, setLoaded] = useState<LoadedExample | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoaded(null);
    setError(null);
    let cancelled = false;
    loadExample(example!).then(
      (ex) => !cancelled && setLoaded(ex),
      (e) => !cancelled && setError(String(e)),
    );
    return () => {
      cancelled = true;
    };
  }, [example]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-6 border-b border-slate-700 bg-slate-900 px-4 py-2">
        <Link to="/" className="text-sm font-bold text-sky-300 hover:text-sky-200">
          midnight-zk
        </Link>
        <span className="font-mono text-sm text-slate-300">{example}</span>
        {loaded && (
          <span className="text-xs text-slate-500">
            k={loaded.layout.domain.k} · {loaded.n} rows · {loaded.layout.regions.length} regions
          </span>
        )}
        <nav className="ml-auto flex gap-1">
          {VIEWS.map((v) => (
            <NavLink
              key={v.path}
              to={v.path}
              className={({ isActive }) =>
                `rounded px-3 py-1 text-sm ${
                  isActive
                    ? "bg-sky-700 text-white"
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`
              }
            >
              {v.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="min-h-0 flex-1">
        {error && <div className="p-8 text-red-400">{error}</div>}
        {!loaded && !error && <div className="p-8 text-slate-500">loading artifacts…</div>}
        {loaded && (
          <ExampleContext.Provider value={loaded}>
            <Outlet />
          </ExampleContext.Provider>
        )}
      </main>
    </div>
  );
}
