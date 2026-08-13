/**
 * Step-by-step proof construction: the transcript events (recomputed live in
 * TS by walking vk + proof — not trusted from the Rust side) grouped into
 * protocol steps, joined with the prover's internal polynomial values from
 * trace.json.
 */

import { useMemo, useState } from "react";
import { useExample } from "../Shell";
import { useVerify } from "../../hooks/useVerify";
import type { SerializableTranscriptEvent } from "../../verifier/steplog";
import PolyPlot from "../domain/PolyPlot";

interface StepDef {
  id: string;
  title: string;
  description: string;
  /** trace.json step id whose polynomials belong to this step. */
  traceStep?: string;
  /** Event-label prefixes that belong to this step. */
  match: (e: SerializableTranscriptEvent) => boolean;
}

const STEPS: StepDef[] = [
  {
    id: "init",
    title: "0 · Bind the statement",
    description:
      "The transcript absorbs the verifying-key digest, the committed-instance commitment and the public inputs. Everything that follows is bound to this exact statement.",
    match: (e) =>
      e.label.startsWith("vk.") || e.label.startsWith("committed_instance") || e.label.startsWith("instance"),
  },
  {
    id: "advice",
    title: "1 · Commit to the witness (advice columns)",
    description:
      "One KZG commitment per advice column. The committed polynomials interpolate the column values you can see in the table view (plus blinding rows).",
    traceStep: "advice_commit",
    match: (e) => e.label.startsWith("cm(advice"),
  },
  {
    id: "theta",
    title: "2 · Challenge θ",
    description: "θ compresses multi-column lookup tuples into single field elements.",
    match: (e) => e.kind === "squeeze" && e.label === "theta",
  },
  {
    id: "logup_m",
    title: "3 · Commit LogUp multiplicities m(X)",
    description:
      "For each lookup argument, m(row) counts how many times the table entry at this row is looked up across all input rows.",
    traceStep: "logup_multiplicities",
    match: (e) => e.label.startsWith("cm(m_"),
  },
  {
    id: "beta_gamma",
    title: "4 · Challenges β, γ",
    description: "β randomises the LogUp denominators; β and γ randomise the permutation argument.",
    match: (e) => e.kind === "squeeze" && (e.label === "beta" || e.label === "gamma"),
  },
  {
    id: "perm_z",
    title: "5 · Commit permutation grand products z(X)",
    description:
      "The running products proving that cells connected by copy constraints hold equal values. Split into chunks of (degree−2) columns.",
    traceStep: "permutation_z",
    match: (e) => e.label.startsWith("cm(z_perm"),
  },
  {
    id: "logup_hz",
    title: "6 · Commit LogUp helpers h(X) and accumulators Z(X)",
    description:
      "h_j(X) sums the inverses 1/(f + β) of a chunk of lookup inputs; Z(X) accumulates Σ h − m/(t + β), which must telescope to zero over the active rows.",
    traceStep: "logup_helpers_aggregators",
    match: (e) => e.label.startsWith("cm(h_") || e.label.startsWith("cm(Z_"),
  },
  {
    id: "tau",
    title: "7 · Challenge τ",
    description: "τ batches the trash-argument constraints.",
    match: (e) => e.kind === "squeeze" && e.label === "tau",
  },
  {
    id: "trash",
    title: "8 · Commit trash polynomials",
    description:
      "Trash arguments absorb constraint values on rows where an additive selector is off — the committed polynomial is free there.",
    traceStep: "trash",
    match: (e) => e.label.startsWith("cm(trash"),
  },
  {
    id: "y",
    title: "9 · Challenge y",
    description:
      "y batches ALL identities (gates, permutation, LogUp, trash) into one polynomial: Σ y^ρ(j)·id_j. The fold order is normative: the FIRST identity gets the HIGHEST power.",
    match: (e) => e.kind === "squeeze" && e.label === "y",
  },
  {
    id: "quotient",
    title: "10 · Commit the quotient h(X)",
    description:
      "The batched identity polynomial is divided by the vanishing polynomial Z_H(X) = Xⁿ − 1; the quotient is split into (degree−1) limbs, each committed separately.",
    traceStep: "quotient",
    match: (e) => e.label.startsWith("cm(quotient"),
  },
  {
    id: "x",
    title: "11 · Challenge x",
    description: "The evaluation point. All identities are now checked at this single random point.",
    match: (e) => e.kind === "squeeze" && e.label === "x",
  },
  {
    id: "evals",
    title: "12 · Send evaluations",
    description:
      "The prover sends the evaluations of the committed polynomials at x (and ωx, ω^-(t+1)x where needed). Simple-selector fixed columns send nothing — the verifier substitutes 1.",
    match: (e) => e.label.startsWith("ev("),
  },
  {
    id: "shplonk",
    title: "13 · SHPLONK multi-open",
    description:
      "All openings are batched by rotation set with challenges x1..x4 into commitments F and W, verified with a single pairing equation.",
    match: (e) =>
      (e.kind === "squeeze" && ["x1", "x2", "x3", "x4"].includes(e.label)) ||
      e.label === "cm(F)" ||
      e.label === "cm(W)",
  },
];

export default function ProverView() {
  const ex = useExample();
  const log = useVerify(ex);
  const [open, setOpen] = useState<string>("init");

  const eventsByStep = useMemo(() => {
    const map = new Map<string, SerializableTranscriptEvent[]>();
    if (!log) return map;
    for (const e of log.transcript) {
      const step = STEPS.find((s) => s.match(e));
      if (!step) continue;
      if (!map.has(step.id)) map.set(step.id, []);
      map.get(step.id)!.push(e);
    }
    return map;
  }, [log]);

  if (!log) return <div className="p-8 text-slate-500">running the transcript…</div>;

  // The Rust prover recorded these challenges in trace.json; compare against
  // our recomputed (digest-reduced) challenges by name.
  const traceAnchors: Record<string, string | undefined> = {
    theta: ex.trace.challenges.theta,
    beta: ex.trace.challenges.beta,
    gamma: ex.trace.challenges.gamma,
    tau: ex.trace.challenges.trash,
    y: ex.trace.challenges.y,
  };
  const anchors: Record<string, "match" | "mismatch" | undefined> = {};
  for (const c of log.challenges) {
    const expected = traceAnchors[c.name];
    if (expected !== undefined) anchors[c.name] = expected === c.hex ? "match" : "mismatch";
  }

  return (
    <div className="mx-auto max-w-5xl space-y-2 overflow-y-auto p-6">
      <p className="pb-2 text-sm text-slate-400">
        The proof is a byte stream in exactly this order. Challenges are recomputed here, live, with
        blake2b-256 over the same bytes — where the Rust prover recorded a challenge in trace.json,
        the match is shown with ✓.
      </p>
      {STEPS.map((step) => {
        const events = eventsByStep.get(step.id) ?? [];
        const tracePolys = step.traceStep
          ? (ex.trace.steps.find((s) => s.id === step.traceStep)?.polys ?? [])
          : [];
        const isOpen = open === step.id;
        return (
          <div key={step.id} className="rounded border border-slate-800 bg-slate-900/50">
            <button
              className="flex w-full items-center gap-3 px-4 py-2 text-left"
              onClick={() => setOpen(isOpen ? "" : step.id)}
            >
              <span className="text-sm font-semibold text-sky-300">{step.title}</span>
              <span className="ml-auto text-xs text-slate-500">
                {events.length > 0 && `${events.length} transcript event${events.length > 1 ? "s" : ""}`}
              </span>
              <span className="text-slate-500">{isOpen ? "▾" : "▸"}</span>
            </button>
            {isOpen && (
              <div className="space-y-3 border-t border-slate-800 px-4 py-3">
                <p className="text-sm text-slate-400">{step.description}</p>
                <TranscriptTape events={events} anchors={anchors} />
                {tracePolys.map(
                  (p) =>
                    p.file &&
                    ex.tracePolys.has(p.id) && (
                      <div key={p.id} className="rounded border border-slate-800 bg-slate-950/60 p-2">
                        <PolyPlot
                          series={{
                            label: p.id,
                            n: ex.n,
                            get: (r) => ex.tracePolys.get(p.id)!.get(r).value,
                          }}
                          height={90}
                        />
                      </div>
                    ),
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function TranscriptTape({
  events,
  anchors,
}: {
  events: SerializableTranscriptEvent[];
  anchors: Record<string, "match" | "mismatch" | undefined>;
}) {
  if (events.length === 0) return null;
  const shown = events.length > 40 ? events.slice(0, 40) : events;
  return (
    <div className="flex flex-wrap items-center gap-1 font-mono text-[11px]">
      {shown.map((e, i) =>
        e.kind === "absorb" ? (
          <span
            key={i}
            title={e.hex}
            className={`rounded border px-1 py-0.5 ${
              e.proofSpan
                ? "border-emerald-800 bg-emerald-950/60 text-emerald-300"
                : "border-slate-700 bg-slate-800/80 text-slate-300"
            }`}
          >
            {e.proofSpan ? "⤓" : "+"} {e.label}
            <span className="opacity-60"> {e.hex.slice(0, 8)}…</span>
          </span>
        ) : (
          <span
            key={i}
            title={e.hex}
            className="rounded border border-fuchsia-700 bg-fuchsia-950/70 px-1 py-0.5 text-fuchsia-300"
          >
            ⇒ blake2b ⇒ {e.label} = {e.hex.slice(0, 12)}…
            {anchors[e.label] === "match" && (
              <span className="ml-1 text-green-400">✓ matches trace.json</span>
            )}
            {anchors[e.label] === "mismatch" && (
              <span className="ml-1 text-red-400">✗ trace.json mismatch</span>
            )}
          </span>
        ),
      )}
      {events.length > shown.length && (
        <span className="text-slate-500">… {events.length - shown.length} more</span>
      )}
    </div>
  );
}
