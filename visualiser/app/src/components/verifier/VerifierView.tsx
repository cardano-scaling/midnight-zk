/**
 * The verifier protocol, rendered from the instrumented StepLog of the TS
 * verifier: challenges, domain quantities, evaluation vectors, the partially
 * evaluated identities and their y-fold, the SHPLONK rotation sets, the flat
 * MSM, and the final pairing.
 */

import { ReactNode, useMemo, useState } from "react";
import katex from "katex";
import { useExample } from "../Shell";
import { useVerify } from "../../hooks/useVerify";
import { fromLEHex, mod, toLEHex } from "../../verifier/field";
import { verify } from "../../verifier/verify";
import { fmtValue, fmtValueFull } from "../../store";
import type { LoadedExample } from "../../data/loader";
import type { StepLog } from "../../verifier/steplog";

function Tex({ src, block = false }: { src: string; block?: boolean }) {
  const html = useMemo(
    () => katex.renderToString(src, { displayMode: block, throwOnError: false }),
    [src, block],
  );
  return <span dangerouslySetInnerHTML={{ __html: html }} />;
}

function Hex({ hex, label }: { hex: string; label?: string }) {
  const v = fromLEHex(hex);
  return (
    <span className="font-mono text-xs text-slate-300" title={fmtValueFull(v)}>
      {label && <span className="text-slate-500">{label} = </span>}
      {fmtValue(v)}
    </span>
  );
}

function Section({
  title,
  subtitle,
  children,
  defaultOpen = false,
}: {
  title: string;
  subtitle?: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded border border-slate-800 bg-slate-900/50">
      <button
        className="flex w-full items-center gap-3 px-4 py-2 text-left"
        onClick={() => setOpen(!open)}
      >
        <span className="text-sm font-semibold text-sky-300">{title}</span>
        {subtitle && <span className="text-xs text-slate-500">{subtitle}</span>}
        <span className="ml-auto text-slate-500">{open ? "▾" : "▸"}</span>
      </button>
      {open && <div className="border-t border-slate-800 px-4 py-3">{children}</div>}
    </div>
  );
}

/**
 * Soundness lab: edit a public input (a different, false statement) or tamper
 * with the proof, re-run the TS verifier, and watch it REJECT. A proof is
 * bound by the Fiat–Shamir transcript to its exact statement, so it cannot be
 * re-used to "prove" anything else — this is the soundness direction, the
 * counterpart to the acceptance of honest proofs.
 */
function SoundnessLab({ ex, honest }: { ex: LoadedExample; honest: StepLog }) {
  const bundle = ex.vk;
  const original = bundle.instances ?? [];
  const [pi, setPi] = useState<string[][]>(() => original.map((c) => c.map((v) => beDec(v))));
  const [flipByte, setFlipByte] = useState(false);
  const [result, setResult] = useState<StepLog | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const tampered =
    JSON.stringify(pi) !== JSON.stringify(original.map((c) => c.map((v) => beDec(v)))) || flipByte;

  const run = () => {
    setParseError(null);
    let instancesHex: string[][];
    try {
      instancesHex = pi.map((col) => col.map((s) => toLEHex(parseScalar(s))));
    } catch (e) {
      setParseError(String(e));
      return;
    }
    let proof = bundle.proof!;
    if (flipByte) {
      // Flip a byte in the middle of the proof.
      const at = proof.length - (proof.length % 2) - 40;
      proof = proof.slice(0, at) + (proof[at] === "0" ? "1" : "0") + proof.slice(at + 1);
    }
    setResult(verify(bundle, instancesHex, proof));
  };

  return (
    <Section
      title="Soundness lab — try to prove a false statement"
      subtitle="edit a public input or tamper the proof, then re-verify"
      defaultOpen
    >
      <p className="mb-2 text-xs text-slate-400">
        The honest proof above verifies. Change the statement (a public input) or corrupt the
        proof and re-run: the verifier must reject. Public inputs are absorbed into the transcript,
        so any change diverges every Fiat–Shamir challenge from the values the prover committed to,
        and the final pairing fails. You cannot re-use a proof of one statement to prove another.
      </p>
      <div className="space-y-2">
        {pi.map((col, ci) =>
          col.length === 0 ? null : (
            <div key={ci} className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-500">
                public input column {ci} ({col.length} scalar{col.length === 1 ? "" : "s"}):
              </span>
              {col.map((val, vi) => (
                <input
                  key={vi}
                  value={val}
                  onChange={(e) => {
                    const next = pi.map((c) => [...c]);
                    next[ci][vi] = e.target.value;
                    setPi(next);
                    setResult(null);
                  }}
                  className={`w-40 rounded border bg-slate-800 px-1.5 py-0.5 font-mono text-xs outline-none ${
                    val !== beDec(original[ci][vi])
                      ? "border-amber-600 text-amber-300"
                      : "border-slate-700 text-slate-200"
                  }`}
                />
              ))}
            </div>
          ),
        )}
        {pi.every((c) => c.length === 0) && (
          <div className="text-xs text-slate-500">
            This circuit exposes no raw public-input scalars (committed-instance only); use the
            proof-tamper toggle.
          </div>
        )}
        <label className="flex w-fit cursor-pointer items-center gap-1.5 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={flipByte}
            onChange={(e) => {
              setFlipByte(e.target.checked);
              setResult(null);
            }}
          />
          also flip a byte of the proof
        </label>
        <div className="flex items-center gap-2">
          <button
            className="rounded bg-sky-800 px-2 py-0.5 text-sm text-sky-100 hover:bg-sky-700"
            onClick={run}
          >
            re-verify {tampered ? "(tampered)" : "(unchanged)"}
          </button>
          <button
            className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-700"
            onClick={() => {
              setPi(original.map((c) => c.map((v) => beDec(v))));
              setFlipByte(false);
              setResult(null);
            }}
          >
            reset
          </button>
        </div>
        {parseError && <div className="text-xs text-red-400">{parseError}</div>}
        {result && (
          <div
            className={`rounded border px-3 py-1.5 text-sm font-semibold ${
              result.ok
                ? "border-green-700 bg-green-950/60 text-green-300"
                : "border-red-700 bg-red-950/60 text-red-300"
            }`}
          >
            {result.ok ? (
              tampered ? (
                <>✓ accepted — but you changed nothing that the transcript binds (no effective tampering).</>
              ) : (
                <>✓ accepted (the honest statement).</>
              )
            ) : (
              <>
                ✗ REJECTED — {result.error ?? "verification failed"}.{" "}
                {tampered
                  ? "The proof does not carry over to this statement: soundness holds."
                  : ""}
                {result.challenges.length > 0 && honest.challenges.length > 0 && (
                  <div className="mt-1 text-xs font-normal text-slate-400">
                    First diverged challenge:{" "}
                    {firstDivergence(honest, result) ?? "—"} (every downstream value differs from
                    the prover's, so the openings no longer match).
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </Section>
  );
}

/** Big-endian decimal string of an LE-hex scalar (friendlier to read/edit). */
function beDec(leHex: string): string {
  return fromLEHex(leHex).toString();
}

function parseScalar(s: string): bigint {
  const t = s.trim();
  if (t === "") throw new Error("empty scalar");
  const v = t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t);
  return mod(v);
}

function firstDivergence(a: StepLog, b: StepLog): string | null {
  for (let i = 0; i < Math.min(a.challenges.length, b.challenges.length); i++) {
    if (a.challenges[i].hex !== b.challenges[i].hex) return a.challenges[i].name;
  }
  return a.challenges.length !== b.challenges.length ? "(count differs)" : null;
}

export default function VerifierView() {
  const ex = useExample();
  const log = useVerify(ex);

  if (!log) return <div className="p-8 text-slate-500">verifying…</div>;

  const M = log.identities.length;

  return (
    <div className="mx-auto max-w-6xl space-y-2 overflow-y-auto p-6">
      <div
        className={`rounded border p-4 text-lg font-semibold ${
          log.ok
            ? "border-green-700 bg-green-950/60 text-green-300"
            : "border-red-700 bg-red-950/60 text-red-300"
        }`}
      >
        {log.ok ? "✓ Proof accepted" : `✗ Proof rejected: ${log.error}`}
        <div className="mt-1 text-xs font-normal text-slate-400">
          {log.proofLength} proof bytes · verified in TypeScript against the vk — every value below
          was computed live in your browser.
        </div>
      </div>

      <SoundnessLab ex={ex} honest={log} />

      <Section title="Challenges" subtitle="Fiat–Shamir via blake2b-256 digest-reset" defaultOpen>
        <div className="flex flex-wrap gap-2">
          {log.challenges.map((c) => (
            <span key={c.name} className="rounded border border-fuchsia-800 bg-fuchsia-950/50 px-2 py-1">
              <Hex label={c.name} hex={c.hex} />
            </span>
          ))}
        </div>
      </Section>

      {log.domain && (
        <Section title="Domain quantities at x">
          <div className="grid grid-cols-2 gap-x-8 gap-y-1 md:grid-cols-3">
            <Hex label="xⁿ" hex={log.domain.xnHex} />
            <Hex label="Z_H(x) = xⁿ−1" hex={log.domain.vanishingHex} />
            <Hex label="L₀(x)" hex={log.domain.l0Hex} />
            <Hex label="L_last(x)" hex={log.domain.lLastHex} />
            <Hex label="L_blind(x)" hex={log.domain.lBlindHex} />
            <Hex label="active(x)" hex={log.domain.activeHex} />
          </div>
          <p className="mt-2 text-xs text-slate-500">
            <Tex src="L_i(x) = \frac{\omega^i (x^n - 1)}{n\,(x - \omega^i)}" />
            {"  ·  "}active = 1 − L_last − L_blind restricts identities to usable rows.
          </p>
        </Section>
      )}

      <Section
        title="Evaluations"
        subtitle={`${log.adviceEvals.length + log.fixedEvals.length + log.instanceEvals.length + log.permutationEvals.length + log.lookupEvals.length + log.trashEvals.length} values`}
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {(
            [
              ["advice @ x", log.adviceEvals],
              ["fixed @ x (simple selectors → 1)", log.fixedEvals],
              ["instance", log.instanceEvals],
              ["permutation (σᵢ, z @ x/ωx/ω⁻⁽ᵗ⁺¹⁾x)", log.permutationEvals],
              ["logup (m, h, Z @ x/ωx)", log.lookupEvals],
              ["trash @ x", log.trashEvals],
            ] as const
          ).map(
            ([title, evals]) =>
              evals.length > 0 && (
                <div key={title} className="rounded border border-slate-800 p-2">
                  <div className="mb-1 text-xs font-semibold text-slate-400">{title}</div>
                  <div className="max-h-48 space-y-0.5 overflow-y-auto">
                    {evals.map((e, i) => (
                      <div key={i} className="flex justify-between gap-2 text-xs">
                        <span className="text-slate-500">
                          {e.label}
                          {e.computed && <span className="ml-1 text-sky-600">(computed)</span>}
                        </span>
                        <Hex hex={e.hex} />
                      </div>
                    ))}
                  </div>
                </div>
              ),
          )}
        </div>
      </Section>

      <Section
        title="Identities at x"
        subtitle={`${M} identities: gates, permutation, LogUp, trash — each with its simple selector κ factored out`}
        defaultOpen
      >
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="py-1 pr-2">j</th>
              <th className="pr-2">identity</th>
              <th className="pr-2">κ (selector col)</th>
              <th className="pr-2">y-power ρ(j)=M−1−j</th>
              <th>e_j = value at x</th>
            </tr>
          </thead>
          <tbody>
            {log.identities.map((id) => (
              <tr key={id.index} className="border-t border-slate-800/60">
                <td className="py-1 pr-2 text-slate-500">{id.index}</td>
                <td className="pr-2 text-slate-300">{id.label}</td>
                <td className="pr-2 font-mono text-pink-300">{id.kappa ?? "⊥"}</td>
                <td className="pr-2 font-mono text-slate-400">y^{M - 1 - id.index}</td>
                <td>
                  <Hex hex={id.valueHex} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      {log.fold && (
        <Section title="Linearisation (the fold)" defaultOpen>
          <p className="mb-2 text-xs text-slate-400">
            Identities are folded with <Tex src="\textstyle\sum_j y^{\rho(j)} e_j" />, grouping the
            coefficients by their selector column κ. The commitment-level identity is
          </p>
          <div className="mb-2 text-slate-300">
            <Tex
              block
              src="[L] \;=\; \sum_{\kappa} c_\kappa\,[\mathrm{fixed}_\kappa] \;-\; (x^n - 1)\sum_{j} \sigma^j\,[q_j], \qquad \mathrm{ev}(L) = -c_\bot"
            />
          </div>
          <div className="grid grid-cols-2 gap-1 md:grid-cols-3">
            {Object.entries(log.fold.cKappa).map(([kappa, hex]) => (
              <Hex key={kappa} label={`c_κ (fixed ${kappa})`} hex={hex} />
            ))}
            <Hex label="c_⊥" hex={log.fold.cBotHex} />
            <Hex label="ev(L) = −c_⊥" hex={log.fold.linEvalHex} />
          </div>
        </Section>
      )}

      <Section
        title="SHPLONK rotation sets"
        subtitle={`${log.rotationSets.length} sets, challenges x1..x4`}
      >
        <p className="mb-2 text-xs text-slate-400">
          Commitments are grouped by the set of rotations they are opened at. Per set, the claimed
          values interpolate a polynomial r_t; the proof supplies r_t(x3) and everything is batched
          into F and the witness W.
        </p>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="py-1 pr-2">t</th>
              <th className="pr-2">rotations (as ω^ρ·x)</th>
              <th className="pr-2">commitments (x1-power order)</th>
              <th className="pr-2">r_t(x3) computed</th>
              <th>q_t(x3) from proof</th>
            </tr>
          </thead>
          <tbody>
            {log.rotationSets.map((s) => (
              <tr key={s.index} className="border-t border-slate-800/60 align-top">
                <td className="py-1 pr-2 text-slate-500">{s.index}</td>
                <td className="pr-2 font-mono text-slate-300">{`{${s.rotations.join(", ")}}`}</td>
                <td className="pr-2 max-w-md font-mono text-[10px] text-slate-400">
                  {s.slots.join(", ")}
                </td>
                <td className="pr-2">
                  <Hex hex={s.rtHex} />
                </td>
                <td>
                  <Hex hex={s.qevHex} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-2 flex gap-6">
          {log.fEvalHex && <Hex label="f_eval" hex={log.fEvalHex} />}
          {log.vHex && <Hex label="v (aggregated opening value)" hex={log.vHex} />}
        </div>
      </Section>

      <Section title="Final MSM" subtitle={`${log.msm.length} terms — one multi-scalar multiplication`}>
        <p className="mb-2 text-xs text-slate-400">
          The linearisation commitment is never materialised: it dissolves into its fixed-column and
          quotient constituents, giving one flat MSM
          <Tex src="\;R = \sum_i s_i \cdot P_i" />.
        </p>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="py-1 pr-2">#</th>
              <th className="pr-2">point</th>
              <th className="pr-2">scalar</th>
              <th>commitment (compressed)</th>
            </tr>
          </thead>
          <tbody>
            {log.msm.map((m, i) => (
              <tr key={i} className="border-t border-slate-800/60">
                <td className="py-1 pr-2 text-slate-500">{i}</td>
                <td className="pr-2 font-mono text-sky-300">{m.label}</td>
                <td className="pr-2">
                  <Hex hex={m.scalarHex} />
                </td>
                <td className="font-mono text-[10px] text-slate-500">
                  {m.pointHex.slice(0, 20)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="Pairing check" defaultOpen>
        <div className="mb-2 text-slate-300">
          <Tex block src="e(W,\ [s]_2) \;\stackrel{?}{=}\; e(R,\ [1]_2)" />
        </div>
        <p className="mb-2 text-xs text-slate-400">
          W is the SHPLONK witness commitment from the proof; R is the MSM above (which already
          includes x3·W and −v·[1]₁). [s]₂ comes from the SRS (the trusted setup secret in G2).
        </p>
        <div
          className={`inline-block rounded px-3 py-1 font-mono text-sm ${
            log.pairingOk ? "bg-green-900/60 text-green-300" : "bg-red-900/60 text-red-300"
          }`}
        >
          pairing check: {log.pairingOk ? "PASSED" : "FAILED"}
        </div>
      </Section>
    </div>
  );
}
