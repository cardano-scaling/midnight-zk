/**
 * The perturbation workshop panel: the kept overrides (advice + public
 * inputs), every constraint they currently violate, and per-violation
 * solvers ("what value of cell X repairs this?"). Copies pinning a cell to a
 * public input can be repaired by MOVING that public input — constructing a
 * proof for a new statement. Driving the violation list to empty constructs a
 * second satisfying witness: for the same instance it is a demonstrated
 * multi-cell under-constraint; with a moved public input it is a valid proof
 * of a different statement (e.g. poseidon(x',y,z)=b'), which is exactly how
 * you confirm the solver works.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useExample } from "../Shell";
import { fmtValue, fmtValueFull, useStore } from "../../store";
import {
  checkAllRows,
  effectiveCell,
  evaluateWorkshop,
  ForwardSolver,
  Overrides,
  solveCheck,
  SolveResult,
  WorkshopCheck,
} from "../../analysis/workshop";
import { memberLabel } from "../../analysis/perturb";
import { LoadedExample } from "../../data/loader";

interface AutoSolveState {
  running: boolean;
  steps: number;
  violations: number;
  solved: number;
  movedPI: number;
  done: boolean;
  stuckReason?: string;
}

/**
 * Drives a `ForwardSolver` incrementally on animation frames, writing its
 * overrides to the store each tick so the table fills in live, and staying
 * responsive (stoppable). Respects soundness mode (public inputs pinned).
 */
function useAutoSolve(ex: LoadedExample) {
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);
  const soundnessMode = useStore((s) => s.soundnessMode);
  const applyOverrides = useStore((s) => s.applyOverrides);
  const [state, setState] = useState<AutoSolveState | null>(null);
  const stopRef = useRef(false);
  const solverRef = useRef<ForwardSolver | null>(null);

  // Cancel on unmount.
  useEffect(() => () => void (stopRef.current = true), []);

  const start = () => {
    // Seed = current advice overrides (frozen); solve forward from there.
    const seed: Overrides = new Map(overrides);
    const solver = new ForwardSolver(ex, seed, { allowInstanceMoves: !soundnessMode });
    solverRef.current = solver;
    stopRef.current = false;
    setState({ running: true, steps: 0, violations: solver.violations, solved: 0, movedPI: 0, done: false });

    let steps = 0;
    const tick = () => {
      if (stopRef.current) {
        commit(solver);
        setState((s) => (s ? { ...s, running: false } : s));
        return;
      }
      // A few steps per frame to keep it moving without locking up.
      for (let i = 0; i < 3 && !solver.done; i++) {
        if (solver.step()) steps++;
      }
      commit(solver);
      setState({
        running: !solver.done,
        steps,
        violations: solver.violations,
        solved: solver.solved.size,
        movedPI: solver.changedInstances.size,
        done: solver.done,
        stuckReason: solver.stuckReason,
      });
      if (!solver.done) requestAnimationFrame(tick);
    };
    const commit = (s: ForwardSolver) =>
      applyOverrides(new Map(s.overrides), new Map(s.instanceOverrides));
    requestAnimationFrame(tick);
  };

  const stop = () => {
    stopRef.current = true;
  };

  // Reset the panel state when the user clears/changes overrides externally.
  useEffect(() => {
    if (!state?.running && instanceOverrides.size === 0 && overrides.size === 0) setState(null);
  }, [overrides, instanceOverrides, state?.running]);

  return { state, start, stop };
}

export default function PerturbWorkshop() {
  const ex = useExample();
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);
  const removeOverride = useStore((s) => s.removeOverride);
  const clearOverrides = useStore((s) => s.clearOverrides);
  const setSelectedRow = useStore((s) => s.setSelectedRow);
  const soundnessMode = useStore((s) => s.soundnessMode);
  const setSoundnessMode = useStore((s) => s.setSoundnessMode);

  const auto = useAutoSolve(ex);

  const state = useMemo(
    () => evaluateWorkshop(ex, overrides, instanceOverrides),
    [ex, overrides, instanceOverrides],
  );
  // The triumphant banner must reflect the WHOLE circuit, not just the checks
  // the overrides happen to touch — confirm with a full MockProver-style pass.
  const fullyValid = useMemo(
    () =>
      state.failing.length === 0 && overrides.size > 0
        ? checkAllRows(ex, overrides, instanceOverrides).violations === 0
        : false,
    [ex, overrides, instanceOverrides, state.failing.length],
  );

  if (overrides.size === 0 && instanceOverrides.size === 0) return null;
  const statementChanged = instanceOverrides.size > 0;

  return (
    <div className="border-b border-slate-700 bg-slate-950/60 p-4 text-xs">
      <div className="mb-1 flex items-center gap-3">
        <span className="text-xs font-semibold uppercase tracking-wide text-fuchsia-400">
          Perturbation workshop
        </span>
        <label
          className="ml-auto flex cursor-pointer items-center gap-1.5 text-[11px] text-slate-300"
          title="Pin public inputs. Then closing the workshop by perturbing a PRIVATE input while the public inputs stay fixed would require a hash collision — so success means the circuit is under-constrained. Turn off to move public inputs and build a new (true) statement instead."
        >
          <input
            type="checkbox"
            checked={soundnessMode}
            onChange={(e) => setSoundnessMode(e.target.checked)}
          />
          soundness mode (pin public inputs)
        </label>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-1">
        {[...overrides.entries()].map(([key, value]) => {
          const [c, r] = key.split("/");
          return (
            <span
              key={key}
              className="flex items-center gap-1 rounded border border-fuchsia-800 bg-fuchsia-950/60 px-1.5 py-0.5 font-mono text-fuchsia-200"
              title={fmtValueFull(value)}
            >
              <button className="hover:text-sky-300" onClick={() => setSelectedRow(Number(r))}>
                a{c}[{r}]
              </button>
              = {fmtValue(value)}
              <button
                className="ml-0.5 text-fuchsia-400 hover:text-red-400"
                title="drop this perturbation"
                onClick={() => removeOverride(key)}
              >
                ×
              </button>
            </span>
          );
        })}
        {[...instanceOverrides.entries()].map(([key, value]) => {
          const [c, r] = key.split("/");
          return (
            <span
              key={`i${key}`}
              className="flex items-center gap-1 rounded border border-sky-700 bg-sky-950/60 px-1.5 py-0.5 font-mono text-sky-200"
              title={`public input — ${fmtValueFull(value)}`}
            >
              i{c}[{r}] = {fmtValue(value)}
              <span className="text-[10px] text-sky-400">(public input)</span>
            </span>
          );
        })}
        <button
          className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300 hover:bg-slate-700"
          onClick={clearOverrides}
        >
          clear all
        </button>
      </div>

      {/* Auto-solver: propagate the kept perturbations forward automatically. */}
      {overrides.size > 0 && !fullyValid && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded border border-slate-800 bg-slate-900/50 px-2 py-1">
          {auto.state?.running ? (
            <button
              className="rounded bg-red-800 px-2 py-0.5 text-red-100 hover:bg-red-700"
              onClick={auto.stop}
            >
              ■ stop
            </button>
          ) : (
            <button
              className="rounded bg-emerald-800 px-2 py-0.5 text-emerald-100 hover:bg-emerald-700"
              title="Automatically solve forward from your kept perturbations, filling the table live. Respects soundness mode. May stall on joint native-gadget / trash rows (single-cell solver)."
              onClick={auto.start}
            >
              ▶ auto-solve forward
            </button>
          )}
          {auto.state && (
            <span className="text-[11px] text-slate-400">
              {auto.state.solved} cells solved · {auto.state.violations} violations left
              {auto.state.movedPI > 0 && ` · ${auto.state.movedPI} public input(s) moved`}
              {auto.state.running && " · running…"}
              {auto.state.done && !auto.state.running && auto.state.violations === 0 && " · ✓ closed"}
              {auto.state.done && auto.state.stuckReason && (
                <span className="text-amber-400"> · stalled: {auto.state.stuckReason}</span>
              )}
            </span>
          )}
        </div>
      )}

      {fullyValid ? (
        <div
          className={`rounded border px-2 py-1.5 font-semibold ${
            statementChanged
              ? "border-emerald-600 bg-emerald-950/70 text-emerald-300"
              : "border-red-700 bg-red-950/70 text-red-300"
          }`}
        >
          {statementChanged ? (
            <>
              ✓ VALID NEW STATEMENT — the whole circuit is satisfied with a changed witness AND a
              changed public input. This is a proof of a <em>different</em> statement (e.g. a fresh
              hash of a new input), not a break: the public output moved with the input.
            </>
          ) : (
            <>
              ⚠ UNDER-CONSTRAINED — all constraints pass with the SAME public inputs but a changed
              private input. For a sound circuit this would require a hash collision (infeasible),
              so finding it means the circuit does not actually bind this input to the output. You
              constructed a second witness for the same statement.
            </>
          )}
        </div>
      ) : state.failing.length === 0 ? (
        <div className="rounded border border-amber-700 bg-amber-950/50 px-2 py-1 text-amber-300">
          The touched checks all pass, but the full circuit is not yet satisfied — perturb/solve
          further to reach a complete witness.
        </div>
      ) : (
        <div className="space-y-1.5">
          <div className="text-slate-400">
            {state.failing.length} of {state.checks.length} affected checks failing — solve them
            one by one (forward through the circuit), or hit a wall where no value works (that
            constraint pins your changes):
          </div>
          {state.failing.map((check, i) => (
            <FailingCheck key={i} ex={ex} check={check} />
          ))}
        </div>
      )}
      {state.pinnedNotes.length > 0 && !fullyValid && (
        <div className="mt-1.5 text-amber-400">
          {state.pinnedNotes.map((note, i) => (
            <div key={i}>⚓ {note}.</div>
          ))}
        </div>
      )}
    </div>
  );
}

function FailingCheck({ ex, check }: { ex: LoadedExample; check: WorkshopCheck }) {
  const overrides = useStore((s) => s.overrides);
  const instanceOverrides = useStore((s) => s.instanceOverrides);
  const setOverride = useStore((s) => s.setOverride);
  const setInstanceOverride = useStore((s) => s.setInstanceOverride);
  const soundnessMode = useStore((s) => s.soundnessMode);
  const [solveFor, setSolveFor] = useState<string>("");
  const [solution, setSolution] = useState<SolveResult | null>(null);

  // A copy to a public input (or fixed constant) is repaired specially.
  if (check.ref.type === "copy" && check.ref.member.kind !== "advice") {
    const m = check.ref.member;
    const [oc, or] = check.ref.overriddenKey.split("/").map(Number);
    const adviceVal = effectiveCell(ex, overrides, instanceOverrides)("advice", oc, or);
    const pinned = m.kind === "fixed" || soundnessMode;
    return (
      <div className="rounded border border-red-900/70 bg-red-950/30 px-2 py-1">
        <div className="flex items-center gap-2">
          <span className="text-red-400">✗</span>
          <span className="text-slate-300">{check.label}</span>
          <span className="ml-auto font-mono text-slate-500">{check.detail}</span>
        </div>
        <div className="mt-1">
          {!pinned ? (
            <button
              className="rounded bg-sky-800 px-1.5 py-0.5 text-sky-100 hover:bg-sky-700"
              title="Move the public input to match the computed cell — this changes the STATEMENT being proved."
              onClick={() => setInstanceOverride(m.index, m.row, adviceVal)}
            >
              set public input {memberLabel(m)} = {fmtValue(adviceVal)} (new statement)
            </button>
          ) : m.kind === "instance" ? (
            <span className="text-amber-400">
              ⚓ pinned public input {memberLabel(m)} — repairing this without moving it would need
              the computed cell to equal the fixed output, i.e. a hash collision. If you CAN close
              the workshop while this stays pinned, the circuit is under-constrained. (Turn off
              soundness mode to move it and build a new statement instead.)
            </span>
          ) : (
            <span className="text-amber-400">
              ⚓ pinned to a fixed constant {memberLabel(m)} = {fmtValue(ex.cell("fixed", m.index, m.row))} —
              this cell cannot change; revert your perturbation instead.
            </span>
          )}
        </div>
      </div>
    );
  }

  const candidates = check.cells;
  return (
    <div className="rounded border border-red-900/70 bg-red-950/30 px-2 py-1">
      <div className="flex items-center gap-2">
        <span className="text-red-400">✗</span>
        <span className="text-slate-300">{check.label}</span>
        <span className="ml-auto font-mono text-slate-500">{check.detail}</span>
      </div>
      {candidates.length > 0 && (
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          <span className="text-slate-500">solve for</span>
          <select
            className="rounded border border-slate-700 bg-slate-800 px-1 py-0.5 text-green-300"
            value={solveFor}
            onChange={(e) => {
              setSolveFor(e.target.value);
              setSolution(null);
            }}
          >
            <option value="">cell…</option>
            {candidates.map((cell) => (
              <option key={`${cell.column}/${cell.row}`} value={`${cell.column}/${cell.row}`}>
                a{cell.column}[{cell.row}]
                {overrides.has(`${cell.column}/${cell.row}`) ? " (perturbed)" : ""}
              </option>
            ))}
          </select>
          <button
            className="rounded bg-sky-800 px-1.5 py-0.5 text-sky-100 hover:bg-sky-700 disabled:opacity-40"
            disabled={solveFor === ""}
            onClick={() => {
              const [c, r] = solveFor.split("/").map(Number);
              setSolution(solveCheck(ex, overrides, check, { column: c, row: r }, instanceOverrides));
            }}
          >
            solve
          </button>
          {solution && (
            <span className="flex flex-wrap items-center gap-1">
              {solution.roots === null || solution.roots.length === 0 ? (
                <span className="text-amber-400">{solution.note ?? "no solution in Fr"}</span>
              ) : (
                <>
                  <span className="text-slate-500">
                    root{solution.roots.length === 1 ? "" : "s"}:
                  </span>
                  {solution.roots.map((root, i) => (
                    <button
                      key={i}
                      className="rounded border border-green-800 bg-green-950/60 px-1.5 py-0.5 font-mono text-green-300 hover:bg-green-900"
                      title={`set the cell to ${fmtValueFull(root)} (kept as a perturbation)`}
                      onClick={() => {
                        const [c, r] = solveFor.split("/").map(Number);
                        setOverride(c, r, root);
                        setSolution(null);
                      }}
                    >
                      {fmtValue(root)} ✎
                    </button>
                  ))}
                  {solution.note && <span className="text-slate-500">({solution.note})</span>}
                </>
              )}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
