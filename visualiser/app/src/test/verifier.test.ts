/**
 * Full TS-verifier validation against the latex-midnight-zk test vectors
 * (generated from the Rust prover with the Blake2b256 transcript, all
 * `expected: true`), plus mutation tests proving the checks bite.
 */

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseVkBundle } from "../verifier/vk";
import { verify, verifyBundle } from "../verifier/verify";
import { add, fromLEHex, toLEHex } from "../verifier/field";

const VECTORS = join(__dirname, "vectors");
const files = readdirSync(VECTORS).filter((f) => f.endsWith(".json"));

function loadBundle(file: string) {
  return parseVkBundle(JSON.parse(readFileSync(join(VECTORS, file), "utf8")));
}

describe("TS verifier vs latex-midnight-zk test vectors", () => {
  for (const file of files) {
    it(`${file} verifies`, () => {
      const bundle = loadBundle(file);
      const log = verifyBundle(bundle);
      expect(log.error).toBeUndefined();
      expect(log.ok).toBe(bundle.expected);
      expect(log.pairingOk).toBe(true);
    });
  }
});

describe("our generated artifacts verify too", () => {
  // Artifacts are generated (not committed); skip when absent.
  const artifactsDir = join(__dirname, "../../public/artifacts");
  let examples: string[] = [];
  try {
    examples = readdirSync(artifactsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    it.skip("no generated artifacts present", () => {});
  }
  for (const example of examples) {
    it(`public/artifacts/${example}/vk.json`, () => {
      const bundle = parseVkBundle(
        JSON.parse(readFileSync(join(artifactsDir, example, "vk.json"), "utf8")),
      );
      const log = verifyBundle(bundle);
      expect(log.error).toBeUndefined();
      expect(log.ok).toBe(true);
    });
  }
});

describe("mutation tests (poseidon vector)", () => {
  const bundle = loadBundle("poseidon.json");

  it("rejects a flipped proof byte", () => {
    // Flip a byte inside the first advice commitment.
    const proof = bundle.proof!;
    const mutated = proof.slice(0, 10) + (proof[10] === "0" ? "1" : "0") + proof.slice(11);
    const log = verify(bundle, bundle.instances!, mutated);
    expect(log.ok).toBe(false);
  });

  it("rejects a flipped evaluation scalar near the end of the proof", () => {
    const proof = bundle.proof!;
    // 100 bytes from the end lands in the SHPLONK region (qev / W).
    const at = proof.length - 200;
    const mutated = proof.slice(0, at) + (proof[at] === "0" ? "1" : "0") + proof.slice(at + 1);
    const log = verify(bundle, bundle.instances!, mutated);
    expect(log.ok).toBe(false);
  });

  it("rejects a wrong public input", () => {
    const instances = bundle.instances!.map((col) => [...col]);
    // poseidon has one public input in the last column.
    const col = instances[instances.length - 1];
    col[0] = col[0].startsWith("00") ? "01" + col[0].slice(2) : "00" + col[0].slice(2);
    const log = verify(bundle, instances, bundle.proof!);
    expect(log.ok).toBe(false);
  });

  it("rejects a truncated proof", () => {
    const log = verify(bundle, bundle.instances!, bundle.proof!.slice(0, -96));
    expect(log.ok).toBe(false);
    expect(log.error).toMatch(/exhausted|trailing/);
  });
});

/**
 * Soundness: a proof is bound by the Fiat–Shamir transcript to its EXACT
 * statement. Checking it against a perturbed public input (a different, false
 * statement) must be rejected — you cannot re-use a proof of A to "prove" B.
 * The public inputs are absorbed into the transcript, so tampering with one
 * diverges every challenge from the values the prover committed to, and the
 * final pairing fails.
 */
describe("cannot verify a false statement (public-input soundness)", () => {
  // A representative spread of circuits (skip the 700 KB hd-prover vectors to
  // keep the run snappy — the mechanism is identical).
  const soundnessFiles = files.filter((f) => !f.startsWith("hd-prover"));

  for (const file of soundnessFiles) {
    const bundle = loadBundle(file);
    // The last non-empty instance column carries public inputs.
    const colIdx = (bundle.instances ?? []).map((c) => c.length).lastIndexOf(
      Math.max(...(bundle.instances ?? [[]]).map((c) => c.length)),
    );
    const hasPI = (bundle.instances?.[colIdx]?.length ?? 0) > 0;

    it.skipIf(!hasPI)(`${file}: perturbing a public input is rejected`, () => {
      const instances = bundle.instances!.map((c) => [...c]);
      // Bump the first public scalar by 1 (stays canonical).
      instances[colIdx][0] = toLEHex(add(fromLEHex(instances[colIdx][0]), 1n));
      const log = verify(bundle, instances, bundle.proof!);
      expect(log.ok).toBe(false);
      // It fails algebraically (diverged transcript → pairing), not by parse.
      expect(log.pairingOk === false || /pairing|exhausted|trailing/.test(log.error ?? "")).toBe(
        true,
      );
    });
  }

  it("the honest statement still verifies (baseline, poseidon)", () => {
    const bundle = loadBundle("poseidon.json");
    expect(verifyBundle(bundle).ok).toBe(true);
  });
});
