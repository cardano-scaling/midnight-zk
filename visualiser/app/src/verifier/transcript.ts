/**
 * TypeScript re-implementation of midnight-proofs'
 * `CircuitTranscript<Blake2b256>` (see `proofs/src/transcript/`):
 *
 * - hash state = byte buffer; absorb appends raw bytes;
 * - squeeze = blake2b-256(buffer); buffer := digest;
 * - challenge = little-endian integer of the 32-byte digest, reduced mod r
 *   (`Fq::from_uniform_bytes` with zero padding to 64 bytes);
 * - scalars absorb as 32-byte LE (`to_repr`), G1 points as 48-byte
 *   compressed.
 *
 * Reading (`read`) pulls bytes from the proof stream AND absorbs them;
 * `common` absorbs without consuming proof bytes.
 */

import { blake2b } from "@noble/hashes/blake2.js";
import { Fr, mod, leBytesToBigint, bigintToLEBytes } from "./field";

/** A record of one transcript event, for visualisation. */
export interface TranscriptEvent {
  kind: "absorb" | "squeeze";
  /** What was absorbed / squeezed (e.g. "vk.transcript_repr", "theta"). */
  label: string;
  /** Bytes absorbed (absorb) or digest produced (squeeze). */
  bytes: Uint8Array;
  /** For reads from the proof: [offset, length) into the proof stream. */
  proofSpan?: [number, number];
}

export class Blake2b256Transcript {
  /** Accumulating hash state (digest-reset semantics). */
  private state: Uint8Array = new Uint8Array(0);
  /** Proof byte stream and read cursor. */
  private proof: Uint8Array;
  private cursor = 0;
  /** Event log for visualisation; cheap to keep, always on. */
  readonly events: TranscriptEvent[] = [];

  constructor(proof: Uint8Array = new Uint8Array(0)) {
    this.proof = proof;
  }

  get position(): number {
    return this.cursor;
  }

  get remaining(): number {
    return this.proof.length - this.cursor;
  }

  assertEmpty(): void {
    if (this.cursor !== this.proof.length) {
      throw new Error(
        `transcript has ${this.proof.length - this.cursor} unexpected trailing bytes`,
      );
    }
  }

  /** Absorb bytes without consuming the proof stream (Rust `common`). */
  absorb(label: string, bytes: Uint8Array): void {
    const next = new Uint8Array(this.state.length + bytes.length);
    next.set(this.state);
    next.set(bytes, this.state.length);
    this.state = next;
    this.events.push({ kind: "absorb", label, bytes });
  }

  /** Absorb a scalar (32-byte LE). */
  absorbScalar(label: string, v: Fr): void {
    this.absorb(label, bigintToLEBytes(v, 32));
  }

  /** Read `len` bytes from the proof and absorb them (Rust `read`). */
  read(label: string, len: number): Uint8Array {
    if (this.cursor + len > this.proof.length) {
      throw new Error(`proof stream exhausted reading ${label}`);
    }
    const span: [number, number] = [this.cursor, len];
    const bytes = this.proof.slice(this.cursor, this.cursor + len);
    this.cursor += len;
    const next = new Uint8Array(this.state.length + bytes.length);
    next.set(this.state);
    next.set(bytes, this.state.length);
    this.state = next;
    this.events.push({ kind: "absorb", label, bytes, proofSpan: span });
    return bytes;
  }

  /** Read a scalar (32-byte LE, must be canonical). */
  readScalar(label: string): Fr {
    const bytes = this.read(label, 32);
    const v = leBytesToBigint(bytes);
    if (v >= 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n) {
      throw new Error(`non-canonical scalar in proof at ${label}`);
    }
    return v;
  }

  /** Read a compressed G1 point (48 bytes). Subgroup checks happen upstream. */
  readPoint(label: string): Uint8Array {
    return this.read(label, 48);
  }

  /** Squeeze a challenge: digest-reset blake2b-256, then LE mod r. */
  squeezeChallenge(label: string): Fr {
    const digest = blake2b(this.state, { dkLen: 32 });
    this.state = digest;
    this.events.push({ kind: "squeeze", label, bytes: digest });
    return mod(leBytesToBigint(digest));
  }
}
