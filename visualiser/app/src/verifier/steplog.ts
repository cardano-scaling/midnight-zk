/**
 * The instrumented record of one verification run. The verifier appends to
 * this as it goes; the VerifierView renders it. Everything is
 * structured-clone-safe (hex strings, numbers, plain objects) so it crosses
 * the worker boundary intact.
 */

import type { TranscriptEvent } from "./transcript";

export interface ChallengeRecord {
  name: "theta" | "beta" | "gamma" | "tau" | "y" | "x" | "x1" | "x2" | "x3" | "x4";
  hex: string;
}

export interface EvalRecord {
  /** e.g. "advice q3 (col 2, rot 0)", "perm z_0 @ wx" */
  label: string;
  hex: string;
  /** Byte span in the proof, if read from it (vs computed). */
  proofSpan?: [number, number];
  computed?: boolean;
}

export interface IdentityRecord {
  index: number;
  /** e.g. "gate poseidon/constraint 2", "permutation boundary", "logup 0 helper 1" */
  label: string;
  /** Fixed column of the factored-out simple selector, or null. */
  kappa: number | null;
  /** e_j: the partially evaluated identity value at x. */
  valueHex: string;
}

export interface FoldRecord {
  /** y^rho(j) coefficients grouped per kappa: fixed column -> c_kappa hex. */
  cKappa: Record<number, string>;
  cBotHex: string;
  linEvalHex: string;
}

export interface RotationSetRecord {
  index: number;
  /** Rotations (mod n) in this set. */
  rotations: number[];
  /** Slot labels of the commitments opened at this set, in x1-power order. */
  slots: string[];
  /** r_t evaluated at x3. */
  rtHex: string;
  /** The per-set opening value read from the proof (q_t(x4-combined)). */
  qevHex: string;
}

export interface MsmTermRecord {
  label: string;
  scalarHex: string;
  pointHex: string;
}

export interface StepLogDomain {
  k: number;
  n: number;
  omegaHex: string;
  blindingFactors: number;
  usableRows: number;
  xnHex: string;
  vanishingHex: string;
  l0Hex: string;
  lLastHex: string;
  lBlindHex: string;
  activeHex: string;
}

export interface StepLog {
  ok: boolean;
  error?: string;
  proofLength: number;
  transcript: SerializableTranscriptEvent[];
  challenges: ChallengeRecord[];
  domain?: StepLogDomain;
  instanceEvals: EvalRecord[];
  adviceEvals: EvalRecord[];
  fixedEvals: EvalRecord[];
  permutationEvals: EvalRecord[];
  lookupEvals: EvalRecord[];
  trashEvals: EvalRecord[];
  identities: IdentityRecord[];
  fold?: FoldRecord;
  rotationSets: RotationSetRecord[];
  fEvalHex?: string;
  vHex?: string;
  msm: MsmTermRecord[];
  pairingOk?: boolean;
}

export interface SerializableTranscriptEvent {
  kind: TranscriptEvent["kind"];
  label: string;
  hex: string;
  proofSpan?: [number, number];
}

export function emptyStepLog(proofLength: number): StepLog {
  return {
    ok: false,
    proofLength,
    transcript: [],
    challenges: [],
    instanceEvals: [],
    adviceEvals: [],
    fixedEvals: [],
    permutationEvals: [],
    lookupEvals: [],
    trashEvals: [],
    identities: [],
    rotationSets: [],
    msm: [],
  };
}
