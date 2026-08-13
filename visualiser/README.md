# midnight-zk visualiser

An interactive web app for learning how the midnight-zk proof system (main
protocol: PLONK with simple + additive selectors, LogUp lookups, permutation
and trash arguments, KZG/SHPLONK over BLS12-381, Blake2b256 digest-reset
transcript) actually works, using the example circuits of `zk_stdlib`.

Four views per example:

| View | What it teaches |
|---|---|
| **Table** | The constraint table: instance/advice/fixed/selector columns with real cell values, region spans, the usable/blinding row boundary. Click a row to see which gates are active there, each constraint with the actual values substituted (hover a term to highlight its cell, including rotations), lookups resolved to their table row, and copy-constraint links. Under-constraint aids, in increasing power (see below). |

### Under-constraint tooling (Table view)

- **Coverage overlay** (toolbar toggle) — tints every assigned advice cell by what enforces it: red = touched by no gate/lookup/copy/trash at all, amber = pinned only by a copy (equality, not a computation). `analysis/coverage.ts`.
- **Determinism map** (toolbar button) — for every assigned advice cell, holds the rest of the witness honest and asks whether that cell's value is uniquely forced. Green = determined (a from-inputs reconstruction would reproduce its exact bytes); red = free (under-constraint). "274 determined ✓" on poseidon means the whole witness is rigid. This is the robust answer to "would the witness reconstruct byte-for-byte?": a true global refill "from inputs" is ill-posed (a circuit doesn't label which cells are the prover's free inputs, and you can't recover them from the output without inverting the hash), so the per-cell test is used instead — it needs no input guess and can't be fooled by a solver stall. Caveat: it cannot see correlated multi-cell freedom (two cells free together but each pinned given the other); that needs formal tools. `analysis/reconstruct.ts`.
- **Freedom test** (row inspector) — perturb a chosen cell to a chosen or random value and re-run every constraint touching it; if nothing breaks, that value is a second valid witness, i.e. the cell is provably free. "Follow copies" perturbs the whole copy-equivalence class together, so copy checks hold by construction and only genuine computation can object. `analysis/perturb.ts`.
- **Perturbation workshop** (row inspector, "keep — add to workshop") — kept perturbations become persistent overrides: the grid and all values switch to the perturbed witness, and the workshop panel lists every constraint they now violate. Each failing gate/trash/lookup can be **solved**: restricting it to one unknown cell makes it a univariate polynomial over Fr, whose roots (the repairing values) are found by interpolation + `gcd(f, Xʳ−X)` factoring (`analysis/roots.ts`) — click a root to apply it. A copy pinning a cell to a **public input** offers "set public input = … (new statement)"; a copy to a **fixed constant** is a hard wall. Drive the violation list to empty and you have constructed a second satisfying witness — for the same instance (a demonstrated multi-cell under-constraint) or, with a moved public input, a valid proof of a *different* statement, e.g. `poseidon(x',y,z)=b'`. `analysis/workshop.ts`.

`forwardSolve` (workshop.ts) automates the perturb-and-repair loop: it propagates a perturbed input forward, solving each frontier constraint and moving the public input when the output copy demands it. It provably reconstructs the feed-forward portion and relocates the public output, but single-cell root-finding **stalls** on `ZkStdLib`-poseidon's native-gadget / trash rows, which couple several unknown cells per row and need a per-row *linear-system* solver (a natural next step). So full closure of these circuits is best driven interactively in the workshop; the automated solver is best-effort. This is a real structural property of the circuit family, not a solver bug — and it is itself instructive.

These are constructive counterexample searches, not soundness proofs. Proving a circuit is *not* under-constrained (determinism of the semantic signals) needs uniqueness reasoning — SMT/Gröbner (Picus, halo2-analyzer), deductive propagation (Ecne-style), or an ITP proof. The coverage + freedom + workshop tools find bugs; they do not certify their absence.
| **Domain** | The evaluation domain H = ⟨ω⟩ as a circle of roots of unity; row i ↔ ω^i; rotations as steps around the circle; any column or prover polynomial plotted over the domain. |
| **Prover** | Proof construction, step by step in transcript order: what is committed at each step (with the actual internal polynomial values: LogUp m/h/Z, permutation z, quotient limbs), which challenges are squeezed. All challenges are recomputed live with blake2b-256 and cross-checked against the Rust prover's trace. |
| **Verifier** | A complete TypeScript re-implementation of the verifier (per the spec in `latex-midnight-zk/docs/main/main.tex`), instrumented so every intermediate value is inspectable: challenges, evaluation vectors, the partially evaluated identities and their y-fold (linearisation), SHPLONK rotation sets, the flat MSM, and the final pairing — computed in your browser via @noble/curves. |

## Generating the artifacts

The app is a static viewer over pre-generated artifacts. From the repo root,
inside `nix develop`:

```bash
# one-time: fetch the filecoin SRS (~100 MB)
curl -L -o zk_stdlib/examples/assets/bls_filecoin_2p19 \
  https://midnight-s3-fileshare-dev-eu-west-1.s3.eu-west-1.amazonaws.com/bls_filecoin_2p19

cargo run --release --example export_visualiser -- --check
```

Flags: `--only <name>` / `--skip <name>` (repeatable), `--out <dir>`,
`--no-trace-polys` (omit the per-row prover polynomials), `--check`
(recommit every layout fixed column and assert equality with the vk's
fixed commitments — proves the layout/vk index mapping end to end).

Per example this writes `visualiser/app/public/artifacts/<name>/`:

- `vk.json` — the verifier bundle (`export_verifier_bundle`): meta, SRS G2
  elements, vk (incl. the full constraint system with gate/lookup/trash
  expression ASTs), public inputs, proof hex, `expected: true`.
- `layout.json` — domain parameters, column metadata, selectors as RLE row
  ranges, regions (name, row span, columns, enabled selectors, annotations),
  permutation columns. Emitted by `MockProver::run_with_k` at the vk's k.
- `columns/*.bin` — cell values, sparse `MZKC` binary (32-byte LE scalars +
  assigned bitmap); `columns/copies.bin` — non-identity permutation mapping.
- `trace.json` + `trace/*.bin` — the prover's internal polynomial values
  (dense MZKC), captured by `plonk::prover_trace::create_proof_with_dump`,
  plus the challenges as cross-check anchors.

The proof in `vk.json` and the polynomials in `trace/` come from the same
prover run (quotient blinding uses OsRng, so runs are not reproducible —
regenerate an example's directory atomically).

Everything uses the `Blake2b256` transcript (the on-chain profile), matching
the TS verifier; the stock example binaries keep using `blake2b_simd::State`.

## Running the app

```bash
cd visualiser/app
npm install
npm run dev        # dev server
npm test           # vitest: TS verifier vs 22 test vectors from latex-midnight-zk + mutation tests
npm run build      # static bundle in dist/ (artifacts included via public/)
```

`scripts/screenshot.mjs` smoke-tests the built app in headless chromium
(`npx vite preview` first).

## Code map

```
app/src/
  verifier/          pure TS, no DOM — the protocol itself
    field.ts         Fr arithmetic (BigInt mod r), ω/Δ derived from generator 7
    transcript.ts    Blake2b256 digest-reset transcript (mirrors proofs/src/transcript)
    curve.ts         @noble/curves wrappers: G1/G2 decompression, MSM, pairing
    expr.ts          expression-AST evaluator — one evaluator, two bindings:
                     query-index (verifier) and (column,rotation)@row (table)
    vk.ts            zod schema of vk.json
    verify.ts        the full verifier, ported step-for-step from the spec /
                     aiken-midnight-zk/scripts/specialize.py; records a StepLog
  data/              artifact loading: MZKC/MZKP parsers, lazy fetch, LoadedExample
  workers/           the verifier runs in a Web Worker (comlink)
  components/        table/ domain/ prover/ verifier/ views + ExprView
  test/              vectors/ = latex-midnight-zk test-vectors/main (all pass)
```

Rust side (this repo):

- `proofs/src/dev/mod.rs` — `MockProver::run_with_k` (explicit k; table
  filling depends on it) and public `Region` accessors.
- `proofs/src/plonk/prover_trace.rs` — `create_proof_with_dump`, a dev-only
  `create_proof` variant capturing internal polynomial values (mirrors
  `finalise_proof`; keep in sync).
- `zk_stdlib/examples/export_visualiser.rs` — the artifact generator
  (reuses the example Relations as modules, deterministic witnesses).

## Notes & limitations

- The `identity/` (JWT) examples are not wired into the generator yet.
- k=15–17 examples produce 60–250 MB of column data each; columns are
  fetched lazily per file, but the table worker precompute is not yet
  implemented, so the k=17 table view is functional but not snappy.
- The TS verifier asserts the default feature set (`committed-instances`,
  no `single-h-commitment`/`truncated-challenges`) and protocol `main`.
