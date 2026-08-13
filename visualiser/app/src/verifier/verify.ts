/**
 * TypeScript re-implementation of the midnight-zk (main protocol) verifier,
 * following the normative spec in latex-midnight-zk `docs/main/main.tex` and
 * mirroring the reference implementation in
 * `aiken-midnight-zk/scripts/specialize.py` (which is validated against the
 * same test vectors).
 *
 * Every intermediate value is recorded into a `StepLog` for visualisation.
 *
 * Restrictions (asserted): protocol "main", Blake2b256 transcript, default
 * feature set (`committed-instances` only — no `single-h-commitment`, no
 * `truncated-challenges`).
 */

import {
  Fr,
  add,
  sub,
  mul,
  neg,
  inv,
  pow,
  mod,
  omega as omegaOf,
  DELTA,
  fromLEHex,
  toLEHex,
  hexToBytes,
  bytesToHex,
  leBytesToBigint,
} from "./field";
import { Blake2b256Transcript } from "./transcript";
import { evaluate, findSimpleSelector, horner, QueryBinding, Expr } from "./expr";
import { G1, g1FromHex, G1Point, g2FromHex, msm, pairingCheck } from "./curve";
import { StepLog, emptyStepLog, IdentityRecord, MsmTermRecord } from "./steplog";
import type { VkBundle } from "./vk";

/** A commitment slot: identifies one committed polynomial. */
type Slot =
  | ["advice", number]
  | ["cinst", number]
  | ["zperm", number]
  | ["m", number]
  | ["h", number, number]
  | ["Z", number]
  | ["trash", number]
  | ["fixed", number]
  | ["sperm", number]
  | ["q", number]
  | ["lin"];

const slotKey = (s: Slot) => s.join("/");

const G1_IDENTITY_HEX = "c0" + "00".repeat(47);

export interface VerifyOptions {
  /** Skip the final pairing (for fast unit tests of the scalar side). */
  skipPairing?: boolean;
}

export function verify(
  bundle: VkBundle,
  instances: string[][],
  proofHex: string,
  options: VerifyOptions = {},
): StepLog {
  const log = emptyStepLog(proofHex.length / 2);
  try {
    verifyInner(bundle, instances, proofHex, log, options);
    log.ok = true;
  } catch (e) {
    log.ok = false;
    log.error = e instanceof Error ? e.message : String(e);
  }
  return log;
}

function verifyInner(
  bundle: VkBundle,
  instancesHex: string[][],
  proofHex: string,
  log: StepLog,
  options: VerifyOptions,
): void {
  // ------------------------------------------------------------- sanity
  if (bundle.meta.protocol !== "main") throw new Error("only the 'main' protocol is supported");
  if (bundle.meta.transcript_hash !== "Blake2b256") {
    throw new Error(`unsupported transcript hash ${bundle.meta.transcript_hash}`);
  }
  const features = bundle.meta.features.split(",").filter(Boolean);
  for (const f of features) {
    if (f !== "committed-instances") throw new Error(`unsupported feature: ${f}`);
  }

  const vk = bundle.vk;
  const cs = vk.cs;
  const n = vk.n;
  const k = vk.k;
  const t = cs.blinding_factors;
  const degree = cs.degree;
  const d = degree - 1; // number of quotient limbs
  const chunkLen = degree - 2;
  const permCols = cs.permutation_columns;
  const C = permCols.length === 0 ? 0 : Math.ceil(permCols.length / chunkLen);
  const nbCi = bundle.nb_committed_instances;
  const simple = new Set(cs.simple_selector_columns);
  const omega = omegaOf(k);

  const instances_: Fr[][] = instancesHex.map((col) => col.map(fromLEHex));
  if (nbCi + instances_.length !== cs.num_instance_columns) {
    throw new Error(
      `expected ${cs.num_instance_columns - nbCi} instance columns, got ${instances_.length}`,
    );
  }

  const tr = new Blake2b256Transcript(hexToBytes(proofHex));
  const challenge = (name: (typeof log.challenges)[number]["name"]): Fr => {
    const c = tr.squeezeChallenge(name);
    log.challenges.push({ name, hex: toLEHex(c) });
    return c;
  };

  // Point reads: keep the hex so MSM terms can name their sources.
  const pointHexOf = new Map<string, string>();
  const readPoint = (slot: Slot, label: string) => {
    const bytes = tr.readPoint(label);
    pointHexOf.set(slotKey(slot), bytesToHex(bytes));
  };

  // ------------------------------------------------------ steps 0 and 0'
  tr.absorbScalar("vk.transcript_repr", fromLEHex(vk.transcript_repr));
  for (const ci of bundle.committed_instances) {
    tr.absorb("committed_instance", hexToBytes(ci));
  }
  for (const column of instances_) {
    tr.absorbScalar("instance.len", BigInt(column.length));
    for (const v of column) tr.absorbScalar("instance", v);
  }

  // ------------------------------------------- steps 1-9: commitments
  for (let i = 0; i < cs.num_advice_columns; i++) readPoint(["advice", i], `cm(advice_${i})`);
  const theta = challenge("theta");

  for (let l = 0; l < cs.lookups.length; l++) readPoint(["m", l], `cm(m_${l})`);
  const beta = challenge("beta");
  const gamma = challenge("gamma");

  for (let c = 0; c < C; c++) readPoint(["zperm", c], `cm(z_perm_${c})`);
  for (let l = 0; l < cs.lookups.length; l++) {
    for (let j = 0; j < cs.lookups[l].num_chunks; j++) {
      readPoint(["h", l, j], `cm(h_${l},${j})`);
    }
    readPoint(["Z", l], `cm(Z_${l})`);
  }
  const tau = challenge("tau");

  for (let g = 0; g < cs.trash.length; g++) readPoint(["trash", g], `cm(trash_${g})`);
  const y = challenge("y");

  for (let i = 0; i < d; i++) readPoint(["q", i], `cm(quotient_${i})`);
  const x = challenge("x");

  // ------------------------------------------------- domain quantities
  const xn1 = pow(x, BigInt(n - 1)); // splitting factor sigma = x^(n-1)
  const xn = mul(xn1, x);
  const vanish = sub(xn, 1n);

  const lag = (i: number): Fr => {
    const wi = pow(omega, BigInt(i));
    return mul(wi, mul(vanish, inv(mul(BigInt(n), sub(x, wi)))));
  };
  const L0 = lag(0);
  const Llast = lag(n - t - 1);
  let Lblind = 0n;
  for (let i = n - t; i < n; i++) Lblind = add(Lblind, lag(i));
  const active = sub(1n, add(Llast, Lblind));

  log.domain = {
    k,
    n,
    omegaHex: toLEHex(omega),
    blindingFactors: t,
    usableRows: n - (t + 1),
    xnHex: toLEHex(xn),
    vanishingHex: toLEHex(vanish),
    l0Hex: toLEHex(L0),
    lLastHex: toLEHex(Llast),
    lBlindHex: toLEHex(Lblind),
    activeHex: toLEHex(active),
  };

  // ---------------------------------------- evaluation vectors (step 12)
  // Read order: committed-instance evals, advice evals, fixed evals (simple
  // selectors -> placeholder 1), sigma evals, permutation-z evals per chunk
  // (z, z@wx, z_last@w^-(t+1)x except for the final chunk), per lookup
  // (m, helpers, Z, Z@wx), trash.
  const iq = cs.instance_queries;
  const instanceEvals: Fr[] = new Array(iq.length);
  for (let idx = 0; idx < iq.length; idx++) {
    const [col] = iq[idx];
    if (col < nbCi) {
      const span: [number, number] = [tr.position, 32];
      instanceEvals[idx] = tr.readScalar(`ev(committed_instance q${idx})`);
      log.instanceEvals.push({
        label: `committed instance, query ${idx}`,
        hex: toLEHex(instanceEvals[idx]),
        proofSpan: span,
      });
    }
  }
  const adviceEvals: Fr[] = [];
  for (let i = 0; i < cs.advice_queries.length; i++) {
    const [col, rot] = cs.advice_queries[i];
    const span: [number, number] = [tr.position, 32];
    adviceEvals.push(tr.readScalar(`ev(advice q${i})`));
    log.adviceEvals.push({
      label: `advice col ${col} @ rot ${rot}`,
      hex: toLEHex(adviceEvals[i]),
      proofSpan: span,
    });
  }
  const fixedEvals: Fr[] = [];
  for (let i = 0; i < cs.fixed_queries.length; i++) {
    const [col, rot] = cs.fixed_queries[i];
    if (simple.has(col)) {
      fixedEvals.push(1n); // placeholder-1 rule
      log.fixedEvals.push({ label: `fixed col ${col} (simple selector) @ rot ${rot}`, hex: toLEHex(1n), computed: true });
    } else {
      const span: [number, number] = [tr.position, 32];
      fixedEvals.push(tr.readScalar(`ev(fixed q${i})`));
      log.fixedEvals.push({
        label: `fixed col ${col} @ rot ${rot}`,
        hex: toLEHex(fixedEvals[i]),
        proofSpan: span,
      });
    }
  }
  const sigmaEvals: Fr[] = [];
  for (let i = 0; i < permCols.length; i++) {
    const span: [number, number] = [tr.position, 32];
    sigmaEvals.push(tr.readScalar(`ev(sigma_${i})`));
    log.permutationEvals.push({
      label: `sigma_${i}`,
      hex: toLEHex(sigmaEvals[i]),
      proofSpan: span,
    });
  }
  const zp: Fr[] = [];
  const zpn: Fr[] = [];
  const zpl: (Fr | null)[] = [];
  for (let c = 0; c < C; c++) {
    zp.push(tr.readScalar(`ev(z_perm_${c} @ x)`));
    log.permutationEvals.push({ label: `z_${c} @ x`, hex: toLEHex(zp[c]) });
    zpn.push(tr.readScalar(`ev(z_perm_${c} @ wx)`));
    log.permutationEvals.push({ label: `z_${c} @ ωx`, hex: toLEHex(zpn[c]) });
    if (c < C - 1) {
      zpl.push(tr.readScalar(`ev(z_perm_${c} @ w^-(t+1)x)`));
      log.permutationEvals.push({ label: `z_${c} @ ω^-(t+1)x`, hex: toLEHex(zpl[c]!) });
    } else {
      zpl.push(null);
    }
  }
  const lookupEvals: { m: Fr; hs: Fr[]; z: Fr; zn: Fr }[] = [];
  for (let l = 0; l < cs.lookups.length; l++) {
    const m = tr.readScalar(`ev(m_${l})`);
    const hs: Fr[] = [];
    for (let j = 0; j < cs.lookups[l].num_chunks; j++) hs.push(tr.readScalar(`ev(h_${l},${j})`));
    const z = tr.readScalar(`ev(Z_${l} @ x)`);
    const zn = tr.readScalar(`ev(Z_${l} @ wx)`);
    lookupEvals.push({ m, hs, z, zn });
    log.lookupEvals.push({ label: `m_${l}`, hex: toLEHex(m) });
    hs.forEach((h, j) => log.lookupEvals.push({ label: `h_${l},${j}`, hex: toLEHex(h) }));
    log.lookupEvals.push({ label: `Z_${l} @ x`, hex: toLEHex(z) });
    log.lookupEvals.push({ label: `Z_${l} @ ωx`, hex: toLEHex(zn) });
  }
  const trashEvals: Fr[] = [];
  for (let g = 0; g < cs.trash.length; g++) {
    trashEvals.push(tr.readScalar(`ev(trash_${g})`));
    log.trashEvals.push({ label: `trash_${g}`, hex: toLEHex(trashEvals[g]) });
  }

  // Non-committed instance evaluations via the Lagrange window:
  // L_j(w^rot x) = w^j (x^n - 1) / (n (w^rot x - w^j)).
  for (let idx = 0; idx < iq.length; idx++) {
    const [col, rot] = iq[idx];
    if (col >= nbCi) {
      const column = instances_[col - nbCi];
      const pt = mul(pow(omega, BigInt(((rot % n) + n) % n)), x);
      let acc = 0n;
      for (let j = 0; j < column.length; j++) {
        const wj = pow(omega, BigInt(j));
        const lj = mul(wj, mul(vanish, inv(mul(BigInt(n), sub(pt, wj)))));
        acc = add(acc, mul(column[j], lj));
      }
      instanceEvals[idx] = acc;
      log.instanceEvals.push({
        label: `instance col ${col} @ rot ${rot} (computed)`,
        hex: toLEHex(acc),
        computed: true,
      });
    }
  }

  const binding: QueryBinding = {
    kind: "query",
    fixed: fixedEvals,
    advice: adviceEvals,
    instance: instanceEvals,
  };
  const ev = (e: Expr) => evaluate(e, binding);

  // -------------------------------------------- identities (normative order)
  const ids: { kappa: number | null; value: Fr; label: string }[] = [];

  for (const gate of cs.gates) {
    gate.constraints.forEach((cst, ci) => {
      ids.push({
        kappa: findSimpleSelector(cst, simple),
        value: ev(cst),
        label: `gate "${gate.name}" #${ci}`,
      });
    });
  }

  // Permutation identities.
  const colEval = (colRef: { kind: string; index: number }): Fr => {
    const find = (queries: [number, number][], vals: Fr[]) => {
      const qi = queries.findIndex(([c, r]) => c === colRef.index && r === 0);
      if (qi < 0) throw new Error(`no rotation-0 query for permutation column ${colRef.kind} ${colRef.index}`);
      return vals[qi];
    };
    if (colRef.kind === "fixed") return find(cs.fixed_queries as [number, number][], fixedEvals);
    if (colRef.kind === "advice") return find(cs.advice_queries as [number, number][], adviceEvals);
    return find(cs.instance_queries as [number, number][], instanceEvals);
  };
  if (C > 0) {
    ids.push({ kappa: null, value: mul(L0, sub(1n, zp[0])), label: "perm: L0(1 - z_0)" });
    ids.push({
      kappa: null,
      value: mul(Llast, sub(mul(zp[C - 1], zp[C - 1]), zp[C - 1])),
      label: "perm: L_last(z_last^2 - z_last)",
    });
    for (let c = 1; c < C; c++) {
      ids.push({
        kappa: null,
        value: mul(L0, sub(zp[c], zpl[c - 1]!)),
        label: `perm: chunk stitch L0(z_${c} - z_${c - 1}@w^-(t+1)x)`,
      });
    }
    for (let c = 0; c < C; c++) {
      const cols = permCols.slice(c * chunkLen, (c + 1) * chunkLen);
      let lhs = zpn[c];
      let rhs = zp[c];
      cols.forEach((colRef, u) => {
        const e_u = colEval(colRef);
        const s_u = sigmaEvals[c * chunkLen + u];
        lhs = mul(lhs, add(e_u, add(mul(beta, s_u), gamma)));
        const dp = pow(DELTA, BigInt(c * chunkLen + u));
        rhs = mul(rhs, add(e_u, add(mul(mul(dp, beta), x), gamma)));
      });
      ids.push({ kappa: null, value: mul(active, sub(lhs, rhs)), label: `perm: product chunk ${c}` });
    }
  }

  // LogUp identities.
  cs.lookups.forEach((lk, l) => {
    const { m, hs, z, zn } = lookupEvals[l];
    const tbl = horner(lk.table_expressions.map(ev), theta);
    const qSel = ev(lk.selector);
    ids.push({ kappa: null, value: mul(add(L0, Llast), z), label: `logup ${l}: boundary (L0+L_last)Z` });
    lk.input_expression_chunks.forEach((chunk, j) => {
      const fb = chunk.map((pl) => add(horner(pl.map(ev), theta), beta));
      let prodAll = 1n;
      for (const f of fb) prodAll = mul(prodAll, f);
      let sumTerms = 0n;
      for (let a = 0; a < fb.length; a++) {
        let p = 1n;
        for (let b = 0; b < fb.length; b++) if (b !== a) p = mul(p, fb[b]);
        sumTerms = add(sumTerms, p);
      }
      ids.push({
        kappa: null,
        value: sub(mul(hs[j], prodAll), sumTerms),
        label: `logup ${l}: helper chunk ${j}`,
      });
    });
    let hTotal = 0n;
    for (const h of hs) hTotal = add(hTotal, h);
    const accId = mul(sub(sub(zn, z), mul(qSel, hTotal)), add(tbl, beta));
    ids.push({ kappa: null, value: mul(active, add(accId, m)), label: `logup ${l}: accumulator` });
  });

  // Trash identities.
  cs.trash.forEach((tg, g) => {
    const Tr = horner(tg.constraints.map(ev), tau);
    const qg = ev(tg.selector);
    ids.push({
      kappa: null,
      value: sub(Tr, mul(sub(1n, qg), trashEvals[g])),
      label: `trash ${g}`,
    });
  });

  log.identities = ids.map(
    (id, i): IdentityRecord => ({
      index: i,
      label: id.label,
      kappa: id.kappa,
      valueHex: toLEHex(id.value),
    }),
  );

  // ------------------------- fold (def rho: reversed walk, ascending powers)
  const cKappa = new Map<number, Fr>();
  let cBot = 0n;
  let pw = 1n;
  for (let j = ids.length - 1; j >= 0; j--) {
    const term = mul(pw, ids[j].value);
    if (ids[j].kappa === null) {
      cBot = add(cBot, term);
    } else {
      const kap = ids[j].kappa!;
      cKappa.set(kap, add(cKappa.get(kap) ?? 0n, term));
    }
    pw = mul(pw, y);
  }
  const linEval = neg(cBot);
  log.fold = {
    cKappa: Object.fromEntries([...cKappa.entries()].map(([kp, v]) => [kp, toLEHex(v)])),
    cBotHex: toLEHex(cBot),
    linEvalHex: toLEHex(linEval),
  };

  // ------------------------------- opening queries and rotation sets (step 5)
  // (rho mod n, slot, value)
  const queries: [number, Slot, Fr][] = [];
  const rotMod = (r: number) => ((r % n) + n) % n;
  cs.advice_queries.forEach(([col, rot], idx) => {
    queries.push([rotMod(rot), ["advice", col], adviceEvals[idx]]);
  });
  iq.forEach(([col, rot], idx) => {
    if (col < nbCi) queries.push([rotMod(rot), ["cinst", col], instanceEvals[idx]]);
  });
  for (let c = 0; c < C; c++) {
    queries.push([0, ["zperm", c], zp[c]]);
    queries.push([1, ["zperm", c], zpn[c]]);
  }
  for (let c = C - 2; c >= 0; c--) {
    queries.push([rotMod(-(t + 1)), ["zperm", c], zpl[c]!]);
  }
  cs.lookups.forEach((lk, l) => {
    queries.push([0, ["m", l], lookupEvals[l].m]);
    for (let j = 0; j < lk.num_chunks; j++) queries.push([0, ["h", l, j], lookupEvals[l].hs[j]]);
    queries.push([0, ["Z", l], lookupEvals[l].z]);
    queries.push([1, ["Z", l], lookupEvals[l].zn]);
  });
  cs.trash.forEach((_, g) => queries.push([0, ["trash", g], trashEvals[g]]));
  cs.fixed_queries.forEach(([col, rot], idx) => {
    if (!simple.has(col)) queries.push([rotMod(rot), ["fixed", col], fixedEvals[idx]]);
  });
  permCols.forEach((_, i) => queries.push([0, ["sperm", i], sigmaEvals[i]]));
  queries.push([0, ["lin"], linEval]);

  // Group by slot in first-appearance order, then rotation sets by point-set,
  // sorted by (cardinality, first slot index).
  const slots: { slot: Slot; points: [number, Fr][] }[] = [];
  const slotIndex = new Map<string, number>();
  for (const [rho, slot, val] of queries) {
    const key = slotKey(slot);
    if (!slotIndex.has(key)) {
      slotIndex.set(key, slots.length);
      slots.push({ slot, points: [] });
    }
    const entry = slots[slotIndex.get(key)!];
    if (entry.points.some(([r]) => r === rho)) throw new Error(`duplicate rotation ${rho} for slot ${key}`);
    entry.points.push([rho, val]);
  }
  const sets: { rhos: number[]; slotIndices: number[] }[] = [];
  slots.forEach((s, i) => {
    const rhos = [...s.points.map(([r]) => r)].sort((a, b) => a - b);
    const found = sets.find(
      (st) => st.rhos.length === rhos.length && st.rhos.every((r, j) => r === rhos[j]),
    );
    if (found) found.slotIndices.push(i);
    else sets.push({ rhos, slotIndices: [i] });
  });
  sets.sort((a, b) => a.rhos.length - b.rhos.length || a.slotIndices[0] - b.slotIndices[0]);
  const T = sets.length;

  // -------------------------------------- SHPLONK transcript (x1..x4, F, W)
  const x1 = challenge("x1");
  const x2 = challenge("x2");
  const fBytes = tr.readPoint("cm(F)");
  const fHex = bytesToHex(fBytes);
  const x3 = challenge("x3");
  const qev: Fr[] = [];
  for (let ti = 0; ti < T; ti++) qev.push(tr.readScalar(`ev(r_${ti} @ x3)`));
  const x4 = challenge("x4");
  const wBytes = tr.readPoint("cm(W)");
  const wHex = bytesToHex(wBytes);
  tr.assertEmpty();

  // Per-set interpolations r_t at x3, and f_ev.
  const rotPt = new Map<number, Fr>();
  for (const st of sets) for (const r of st.rhos) rotPt.set(r, mul(pow(omega, BigInt(r)), x));

  let fEval = 0n;
  let x2p = 1n;
  sets.forEach((st, ti) => {
    const pts = st.rhos;
    // Barycentric weights at x3: prod_{k!=j}(x3 - z_k) / prod_{k!=j}(z_j - z_k).
    const weights = new Map<number, Fr>();
    for (const zj of pts) {
      let num = 1n;
      let den = 1n;
      for (const zk of pts) {
        if (zk !== zj) {
          num = mul(num, sub(x3, rotPt.get(zk)!));
          den = mul(den, sub(rotPt.get(zj)!, rotPt.get(zk)!));
        }
      }
      weights.set(zj, mul(num, inv(den)));
    }
    let rt = 0n;
    let x1p = 1n;
    for (const si of st.slotIndices) {
      let ri = 0n;
      for (const [rho, val] of slots[si].points) {
        ri = add(ri, mul(val, weights.get(rho)!));
      }
      rt = add(rt, mul(x1p, ri));
      x1p = mul(x1p, x1);
    }
    let sden = 1n;
    for (const zj of pts) sden = mul(sden, sub(x3, rotPt.get(zj)!));
    fEval = add(fEval, mul(x2p, mul(sub(qev[ti], rt), inv(sden))));
    x2p = mul(x2p, x2);

    log.rotationSets.push({
      index: ti,
      rotations: pts,
      slots: st.slotIndices.map((si) => slotKey(slots[si].slot)),
      rtHex: toLEHex(rt),
      qevHex: toLEHex(qev[ti]),
    });
  });
  log.fEvalHex = toLEHex(fEval);

  let v = 0n;
  let x4p = 1n;
  const setCoefs: Fr[] = [];
  for (let ti = 0; ti < T; ti++) {
    setCoefs.push(x4p);
    v = add(v, mul(x4p, qev[ti]));
    x4p = mul(x4p, x4);
  }
  const x4T = x4p;
  v = add(v, mul(x4T, fEval));
  log.vHex = toLEHex(v);

  // ----------------------------------------------- flat MSM (spec T6)
  // Merge scalars per distinct point; vk points are keyed by their bytes so
  // byte-equal commitments share one term.
  const msmOrder: string[] = [];
  const msmScalar = new Map<string, Fr>();
  const msmPointHex = new Map<string, string>();
  const msmLabel = new Map<string, string>();

  const pointKeyAndHex = (slot: Slot): [string, string] => {
    if (slot[0] === "fixed") return ["vk/" + vk.fixed_commitments[slot[1]], vk.fixed_commitments[slot[1]]];
    if (slot[0] === "sperm") {
      return ["vk/" + vk.permutation_commitments[slot[1]], vk.permutation_commitments[slot[1]]];
    }
    if (slot[0] === "cinst") {
      return ["vk/" + bundle.committed_instances[slot[1]], bundle.committed_instances[slot[1]]];
    }
    const key = slotKey(slot);
    const hex = pointHexOf.get(key);
    if (!hex) throw new Error(`no proof point recorded for slot ${key}`);
    return [key, hex];
  };

  const addTerm = (scalar: Fr, slot: Slot) => {
    const [key, hex] = pointKeyAndHex(slot);
    if (hex === G1_IDENTITY_HEX) return; // identity contributes nothing
    if (msmScalar.has(key)) {
      msmScalar.set(key, add(msmScalar.get(key)!, scalar));
      msmLabel.set(key, msmLabel.get(key) + " + " + slotKey(slot));
    } else {
      msmOrder.push(key);
      msmScalar.set(key, scalar);
      msmPointHex.set(key, hex);
      msmLabel.set(key, slotKey(slot));
    }
  };

  sets.forEach((st, ti) => {
    let x1p = 1n;
    for (const si of st.slotIndices) {
      const slot = slots[si].slot;
      const coef = mul(setCoefs[ti], x1p);
      x1p = mul(x1p, x1);
      if (slot[0] === "lin") {
        // The linearisation commitment dissolves into its constituents:
        // sum_kappa c_kappa [fixed_kappa] - (x^n - 1) sum_j sigma^j [q_j].
        for (const [kap, ck] of cKappa.entries()) {
          addTerm(mul(coef, ck), ["fixed", kap]);
        }
        const nvan = neg(vanish);
        let sigP = 1n;
        for (let j = 0; j < d; j++) {
          addTerm(mul(coef, mul(nvan, sigP)), ["q", j]);
          sigP = mul(sigP, xn1);
        }
      } else {
        addTerm(coef, slot);
      }
    }
  });

  // + x4^T [F] - v [1]_1 + x3 [W]
  const G1_GEN_HEX =
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
  const terms: MsmTermRecord[] = msmOrder.map((key) => ({
    label: msmLabel.get(key)!,
    scalarHex: toLEHex(msmScalar.get(key)!),
    pointHex: msmPointHex.get(key)!,
  }));
  terms.push({ label: "F", scalarHex: toLEHex(x4T), pointHex: fHex });
  terms.push({ label: "-v * [1]_1", scalarHex: toLEHex(neg(v)), pointHex: G1_GEN_HEX });
  terms.push({ label: "x3 * W", scalarHex: toLEHex(x3), pointHex: wHex });
  log.msm = terms;

  log.transcript = tr.events.map((e) => ({
    kind: e.kind,
    label: e.label,
    hex: bytesToHex(e.bytes),
    proofSpan: e.proofSpan,
  }));

  if (options.skipPairing) {
    log.pairingOk = undefined;
    return;
  }

  // ------------------------------------------------------- final pairing
  // e(W, [s]_2) == e(R, [1]_2)  <=>  e(-W, [s]_2) * e(R, [1]_2) == 1.
  const points: G1[] = terms.map((t2) => g1FromHex(t2.pointHex));
  const scalars: Fr[] = terms.map((t2) => fromLEHex(t2.scalarHex));
  const R = msm(points, scalars);
  const W = g1FromHex(wHex);
  const sG2 = g2FromHex(bundle.srs.s_g2);
  const g2 = g2FromHex(bundle.srs.g2);
  const ok = pairingCheck([
    { g1: W.negate(), g2: sG2 },
    { g1: R, g2: g2 },
  ]);
  log.pairingOk = ok;
  if (!ok) throw new Error("final pairing check failed");
}

/** Convenience: verify a self-contained bundle that carries its own proof. */
export function verifyBundle(bundle: VkBundle, options: VerifyOptions = {}): StepLog {
  if (!bundle.proof || !bundle.instances) {
    throw new Error("bundle has no proof/instances");
  }
  return verify(bundle, bundle.instances, bundle.proof, options);
}

// Re-exported internals used by tests.
export const _internal = { leBytesToBigint, mod, G1Point };
