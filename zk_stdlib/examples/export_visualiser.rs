//! Generates the static artifacts consumed by the visualiser frontend
//! (`visualiser/app`): for each example relation, a `vk.json` (verifier
//! bundle with proof), a `layout.json` (per-row circuit layout metadata),
//! binary column files with the cell values, and a `trace.json` with the
//! prover's internal polynomial values.
//!
//! Run from anywhere inside the workspace:
//!
//! ```text
//! cargo run --release --example export_visualiser -- [--out <dir>]
//!     [--only <name>]... [--skip <name>]... [--no-trace-polys] [--check]
//! ```
//!
//! Requires the filecoin SRS asset (see `utils::plonk_api::srs_for_test`).
//!
//! Binary formats (all integers little-endian, scalars 32-byte canonical LE):
//!
//! * `MZKC` (column values): magic `MZKC`, u8 version = 1, u8 encoding
//!   (0 = dense, 1 = sparse-bitmap), u16 reserved, u32 n, u32 count,
//!   `[sparse only]` ceil(n/8)-byte LSB-first bitmap of assigned rows,
//!   then `count` 32-byte scalars in ascending row order.
//! * `MZKP` (permutation copies): magic `MZKP`, u8 version = 1, u8+u16
//!   reserved, u32 count, then `count` 16-byte records
//!   `(u32 col, u32 row, u32 mapped_col, u32 mapped_row)` — only cells whose
//!   permutation mapping is not the identity. Column indices refer to the
//!   `permutation.columns` list of `layout.json`.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

// Reuse the example relations by including the sibling example files as
// modules (same hack as `exposing_types.rs`). Their `fn main`s become dead
// code here.
mod bitcoin_ecdsa_threshold;
mod bitcoin_signature;
mod cardano_signature;
mod ecc_ops;
mod ethereum_signature;
mod hybrid_mt;
mod membership;
mod native_gadget;
mod poseidon;
mod rsa_signature;
mod schnorr_sig;
mod sha_preimage;

use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ff::{Field, PrimeField};
use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
use midnight_proofs::{
    dev::{CellValue, InstanceValue, MockProver},
    plonk::{prover_trace, Any},
    poly::{
        commitment::PolynomialCommitmentScheme,
        kzg::{params::ParamsKZG, KZGCommitmentScheme},
        PolynomialLabel,
    },
    transcript::{Blake2b256, CircuitTranscript, Transcript},
};
use midnight_zk_stdlib::{
    export_verifier_bundle, setup_pk, setup_vk, utils::plonk_api::srs_for_test, verify,
    MidnightCircuit, MidnightPK, MidnightVK, Relation,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value as Json};

type F = midnight_curves::Fq;
type Bls12 = midnight_curves::Bls12;
type Scheme = KZGCommitmentScheme<Bls12>;
/// Transcript hash used for ALL visualiser artifacts, matching the TS
/// verifier re-implementation of the frontend.
type TH = Blake2b256;

/// zk_stdlib reserves instance column 0 for committed instances
/// (`NB_COMMITTED_INSTANCES`, private in the crate).
const NB_COMMITTED_INSTANCES: usize = 1;

// ---------------------------------------------------------------------------
// Encoding helpers (conventions of proofs/src/dev/json_dump.rs)
// ---------------------------------------------------------------------------

fn hex_scalar(f: &F) -> String {
    let repr = f.to_repr();
    let bytes: &[u8] = repr.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn kind_str(any: Any) -> &'static str {
    match any {
        Any::Advice => "advice",
        Any::Fixed => "fixed",
        Any::Instance => "instance",
    }
}

/// Run-length encodes a sorted, deduplicated list of row indices into
/// half-open `[start, end)` ranges.
fn rle_ranges(rows: &[usize]) -> Vec<[usize; 2]> {
    let mut ranges: Vec<[usize; 2]> = Vec::new();
    for &r in rows {
        match ranges.last_mut() {
            Some(last) if last[1] == r => last[1] = r + 1,
            _ => ranges.push([r, r + 1]),
        }
    }
    ranges
}

fn sorted_dedup(mut rows: Vec<usize>) -> Vec<usize> {
    rows.sort_unstable();
    rows.dedup();
    rows
}

// ---------------------------------------------------------------------------
// Binary writers
// ---------------------------------------------------------------------------

const ENC_DENSE: u8 = 0;
const ENC_SPARSE: u8 = 1;

fn mzkc_header(encoding: u8, n: usize, count: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(b"MZKC");
    buf.push(1); // version
    buf.push(encoding);
    buf.extend_from_slice(&[0u8; 2]); // reserved
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    buf
}

/// Writes a sparse column: only `Assigned` cells are stored, with a bitmap
/// marking which rows they are. `Unassigned` and `Poison` rows are omitted.
fn write_sparse_column(path: &Path, cells: &[CellValue<F>]) -> std::io::Result<()> {
    let n = cells.len();
    let assigned: Vec<(usize, F)> = cells
        .iter()
        .enumerate()
        .filter_map(|(row, c)| match c {
            CellValue::Assigned(v) => Some((row, *v)),
            _ => None,
        })
        .collect();

    let mut buf = mzkc_header(ENC_SPARSE, n, assigned.len());
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    for (row, _) in &assigned {
        bitmap[row / 8] |= 1 << (row % 8);
    }
    buf.extend_from_slice(&bitmap);
    for (_, v) in &assigned {
        buf.extend_from_slice(v.to_repr().as_ref());
    }
    fs::write(path, buf)
}

/// Writes a dense polynomial-values file (one scalar per row).
fn write_dense_column(path: &Path, values: &[F]) -> std::io::Result<()> {
    let mut buf = mzkc_header(ENC_DENSE, values.len(), values.len());
    for v in values {
        buf.extend_from_slice(v.to_repr().as_ref());
    }
    fs::write(path, buf)
}

/// Writes the non-identity permutation-mapping records.
fn write_copies(path: &Path, mapping: &[Vec<(usize, usize)>]) -> std::io::Result<usize> {
    let mut records: Vec<[u32; 4]> = Vec::new();
    for (col, rows) in mapping.iter().enumerate() {
        for (row, &(mc, mr)) in rows.iter().enumerate() {
            if (mc, mr) != (col, row) {
                records.push([col as u32, row as u32, mc as u32, mr as u32]);
            }
        }
    }
    let mut buf = Vec::with_capacity(12 + records.len() * 16);
    buf.extend_from_slice(b"MZKP");
    buf.push(1); // version
    buf.extend_from_slice(&[0u8; 3]); // reserved
    buf.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for rec in &records {
        for v in rec {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
    fs::write(path, buf)?;
    Ok(records.len())
}

// ---------------------------------------------------------------------------
// Layout dump
// ---------------------------------------------------------------------------

fn column_name(
    annotations: &HashMap<midnight_proofs::dev::metadata::Column, String>,
    kind: Any,
    index: usize,
) -> Option<String> {
    annotations
        .iter()
        .find(|(col, _)| col.column_type() == kind && col.index() == index)
        .map(|(_, name)| name.clone())
}

fn dump_layout(
    dir: &Path,
    name: &str,
    vk: &MidnightVK,
    prover: &MockProver<F>,
) -> std::io::Result<()> {
    let cols_dir = dir.join("columns");
    fs::create_dir_all(&cols_dir)?;

    let domain = vk.vk().get_domain();
    let cs = prover.cs(); // post selector->fixed conversion
    let n = 1usize << domain.k();
    let blinding_factors = cs.blinding_factors();

    let num_selectors = prover.selectors().len();
    let num_fixed_total = prover.fixed().len();
    let num_fixed_base = num_fixed_total - num_selectors;
    assert_eq!(
        num_fixed_total,
        cs.num_fixed_columns(),
        "converted cs fixed-column count must match MockProver fixed matrix"
    );

    let col_annotations = cs.general_column_annotations();

    // Advice columns -> sparse bins.
    let mut advice_meta = Vec::new();
    for (i, cells) in prover.advice().iter().enumerate() {
        let file = format!("columns/advice_{i}.bin");
        write_sparse_column(&dir.join(&file), cells)?;
        advice_meta.push(json!({
            "index": i,
            "name": column_name(col_annotations, Any::Advice, i),
            "file": file,
        }));
    }

    // Base fixed columns -> sparse bins (selector columns are RLE'd below).
    let mut fixed_meta = Vec::new();
    for (i, cells) in prover.fixed().iter().take(num_fixed_base).enumerate() {
        let file = format!("columns/fixed_{i}.bin");
        write_sparse_column(&dir.join(&file), cells)?;
        fixed_meta.push(json!({
            "index": i,
            "name": column_name(col_annotations, Any::Fixed, i),
            "file": file,
        }));
    }

    // Selectors: boolean per row, stored as ranges.
    let selectors_meta: Vec<Json> = prover
        .selectors()
        .iter()
        .enumerate()
        .map(|(s, rows)| {
            let enabled: Vec<usize> =
                rows.iter().enumerate().filter_map(|(r, &on)| on.then_some(r)).collect();
            let fixed_column = num_fixed_base + s;
            json!({
                "selector_index": s,
                "fixed_column": fixed_column,
                "simple": cs.has_simple_selector_col(fixed_column),
                "enabled_ranges": rle_ranges(&enabled),
            })
        })
        .collect();

    // Instance columns: small, inline.
    let instance_meta: Vec<Json> = prover
        .instance()
        .iter()
        .enumerate()
        .map(|(i, cells)| {
            let assigned: Vec<String> = cells
                .iter()
                .take_while(|c| matches!(c, InstanceValue::Assigned(_)))
                .map(|c| match c {
                    InstanceValue::Assigned(v) => hex_scalar(v),
                    InstanceValue::Padding => unreachable!(),
                })
                .collect();
            json!({
                "index": i,
                "committed": i < NB_COMMITTED_INSTANCES,
                "values": assigned,
            })
        })
        .collect();

    // Regions.
    let regions_meta: Vec<Json> = prover
        .regions()
        .iter()
        .enumerate()
        .map(|(idx, region)| {
            let mut columns: Vec<(Any, usize)> =
                region.columns().iter().map(|c| (*c.column_type(), c.index())).collect();
            columns.sort_by_key(|(kind, index)| (kind_str(*kind), *index));
            let columns: Vec<Json> = columns
                .into_iter()
                .map(|(kind, index)| json!({"kind": kind_str(kind), "index": index}))
                .collect();

            let mut enabled: Vec<Json> = region
                .enabled_selectors()
                .iter()
                .map(|(sel, rows)| {
                    json!({
                        "selector": sel.index(),
                        "rows": rle_ranges(&sorted_dedup(rows.clone())),
                    })
                })
                .collect();
            enabled.sort_by_key(|j| j["selector"].as_u64());

            let annotations: Vec<Json> = region
                .annotations()
                .iter()
                .map(|(col, label)| {
                    json!({
                        "kind": kind_str(col.column_type()),
                        "index": col.index(),
                        "label": label,
                    })
                })
                .collect();

            json!({
                "index": idx,
                "name": region.name(),
                "rows": region.rows().map(|(s, e)| json!([s, e])),
                "columns": columns,
                "enabled_selectors": enabled,
                "annotations": annotations,
            })
        })
        .collect();

    // Permutation: involved columns + non-identity copy mapping.
    let perm_columns: Vec<Json> = prover
        .permutation()
        .columns()
        .iter()
        .map(|c| json!({"kind": kind_str(*c.column_type()), "index": c.index()}))
        .collect();
    let mapping: Vec<Vec<(usize, usize)>> = prover
        .permutation()
        .mapping()
        .map(|col| {
            use rayon::iter::ParallelIterator;
            col.collect()
        })
        .collect();
    let num_copies = write_copies(&dir.join("columns/copies.bin"), &mapping)?;

    let layout = json!({
        "version": 1,
        "meta": {
            "name": name,
            "transcript_hash": "Blake2b256",
        },
        "domain": {
            "k": domain.k(),
            "n": n,
            "extended_k": domain.extended_k(),
            "omega": hex_scalar(&domain.get_omega()),
            "omega_inv": hex_scalar(&domain.get_omega_inv()),
            "blinding_factors": blinding_factors,
            "usable_rows": n - (blinding_factors + 1),
        },
        "columns": {
            "num_advice": prover.advice().len(),
            "num_fixed_total": num_fixed_total,
            "num_fixed_base": num_fixed_base,
            "num_selectors": num_selectors,
            "num_instance": prover.instance().len(),
            "advice": advice_meta,
            "fixed": fixed_meta,
            "selectors": selectors_meta,
            "instance": instance_meta,
        },
        "regions": regions_meta,
        "permutation": {
            "columns": perm_columns,
            "copies_file": "columns/copies.bin",
            "num_copies": num_copies,
        },
    });

    fs::write(dir.join("layout.json"), serde_json::to_vec_pretty(&layout)?)
}

// ---------------------------------------------------------------------------
// Prover trace dump
// ---------------------------------------------------------------------------

fn dump_trace(
    dir: &Path,
    name: &str,
    dump: &prover_trace::ProverPolyDump<F>,
    with_polys: bool,
) -> std::io::Result<()> {
    let trace_dir = dir.join("trace");
    if with_polys {
        fs::create_dir_all(&trace_dir)?;
    }

    // (step id, label, file stem, values) — steps mirror the transcript order
    // of the proof; sigma polynomials come from keygen, not the transcript.
    let mut steps: Vec<(&str, Vec<(String, &Vec<F>)>)> = Vec::new();

    steps.push((
        "advice_commit",
        dump.advice_values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("advice_{i}"), v))
            .collect(),
    ));
    steps.push((
        "logup_multiplicities",
        dump.lookups
            .iter()
            .map(|l| (format!("logup{}_m", l.argument_index), &l.multiplicities))
            .collect(),
    ));
    steps.push((
        "permutation_z",
        dump.permutation_z
            .iter()
            .enumerate()
            .map(|(c, v)| (format!("perm_z_{c}"), v))
            .collect(),
    ));
    steps.push((
        "logup_helpers_aggregators",
        dump.lookups
            .iter()
            .flat_map(|l| {
                l.helpers
                    .iter()
                    .enumerate()
                    .map(|(j, h)| (format!("logup{}_h{}", l.argument_index, j), h))
                    .chain(std::iter::once((
                        format!("logup{}_agg", l.argument_index),
                        &l.aggregator,
                    )))
                    .collect::<Vec<_>>()
            })
            .collect(),
    ));
    steps.push((
        "trash",
        dump.trash_values
            .iter()
            .enumerate()
            .map(|(g, v)| (format!("trash_{g}"), v))
            .collect(),
    ));
    steps.push((
        "quotient",
        dump.quotient_limbs
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("quotient_{i}"), v))
            .collect(),
    ));
    steps.push((
        "keygen_sigmas",
        dump.sigma_values
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("sigma_{i}"), v))
            .collect(),
    ));

    let mut steps_json = Vec::new();
    for (id, polys) in &steps {
        let mut polys_json = Vec::new();
        for (stem, values) in polys {
            let file = format!("trace/{stem}.bin");
            if with_polys {
                write_dense_column(&dir.join(&file), values)?;
            }
            polys_json.push(json!({
                "id": stem,
                "file": if with_polys { Json::from(file) } else { Json::Null },
            }));
        }
        steps_json.push(json!({"id": id, "polys": polys_json}));
    }

    let trace = json!({
        "version": 1,
        "meta": { "name": name, "transcript_hash": "Blake2b256" },
        "challenges": {
            "theta": hex_scalar(&dump.theta),
            "beta": hex_scalar(&dump.beta),
            "gamma": hex_scalar(&dump.gamma),
            "trash": hex_scalar(&dump.trash_challenge),
            "y": hex_scalar(&dump.y),
        },
        "steps": steps_json,
    });

    fs::write(dir.join("trace.json"), serde_json::to_vec_pretty(&trace)?)
}

// ---------------------------------------------------------------------------
// Self-check: recommit the layout's fixed columns against the vk
// ---------------------------------------------------------------------------

fn check_fixed_commitments(srs: &ParamsKZG<Bls12>, vk: &MidnightVK, prover: &MockProver<F>) {
    let domain = vk.vk().get_domain();
    for (i, cells) in prover.fixed().iter().enumerate() {
        let values: Vec<F> = cells
            .iter()
            .map(|c| match c {
                CellValue::Assigned(v) => *v,
                // Keygen batch-inverts unassigned rational cells to zero.
                CellValue::Unassigned => F::ZERO,
                CellValue::Poison(_) => panic!("poisoned fixed cell in column {i}"),
            })
            .collect();
        let poly = domain.lagrange_from_vec(values);
        let commitment = Scheme::commit(srs, &poly, PolynomialLabel::Fixed(i));
        let expected = &vk.vk().fixed_commitments()[i];
        assert_eq!(
            commitment.0.iter().map(|c| *c.as_point()).collect::<Vec<_>>(),
            expected.0.iter().map(|c| *c.as_point()).collect::<Vec<_>>(),
            "recommitted fixed column {i} does not match vk.fixed_commitments[{i}]",
        );
    }
    println!(
        "  check: all {} fixed-column commitments match the vk",
        prover.fixed().len()
    );
}

// ---------------------------------------------------------------------------
// Per-example driver
// ---------------------------------------------------------------------------

struct Cli {
    out: PathBuf,
    only: Vec<String>,
    skip: Vec<String>,
    trace_polys: bool,
    check: bool,
}

fn export_example<R: Relation<Error = midnight_proofs::plonk::Error>>(
    cli: &Cli,
    name: &str,
    k: u32,
    relation: &R,
    instance: R::Instance,
    witness: R::Witness,
) {
    use midnight_proofs::circuit::Value;

    println!("[{name}] k = {k}");
    let dir = cli.out.join(name);
    fs::create_dir_all(&dir).expect("create artifact dir");

    let srs = srs_for_test(relation, Some(k));
    let vk = setup_vk(&srs, relation);
    assert_eq!(
        vk.vk().cs().num_instance_columns(),
        1 + NB_COMMITTED_INSTANCES
    );
    let pk: MidnightPK<R> = setup_pk(relation, &vk);
    println!("  keys generated");

    let pi = R::format_instance(&instance).expect("format_instance");
    let com_inst = R::format_committed_instances(&witness);

    // Layout via MockProver at the vk's k.
    let circuit = MidnightCircuit::new(
        relation,
        Value::known(instance.clone()),
        Value::known(witness.clone()),
        Some(k),
    );
    let prover = MockProver::run_with_k(&circuit, k, vec![com_inst.clone(), pi.clone()])
        .expect("MockProver::run_with_k");
    prover.verify().expect("MockProver::verify: circuit not satisfied");
    println!("  layout captured ({} regions)", prover.regions().len());

    if cli.check {
        check_fixed_commitments(&srs, &vk, &prover);
    }
    dump_layout(&dir, name, &vk, &prover).expect("write layout");

    // Proof with internal-polynomial dump.
    let circuit = MidnightCircuit::new(
        relation,
        Value::known(instance.clone()),
        Value::known(witness),
        Some(k),
    );
    let mut transcript = CircuitTranscript::<TH>::init();
    let dump = prover_trace::create_proof_with_dump::<F, Scheme, _, MidnightCircuit<R>>(
        &srs,
        pk.pk(),
        &circuit,
        NB_COMMITTED_INSTANCES,
        &[&com_inst, &pi],
        &mut transcript,
        ChaCha8Rng::seed_from_u64(42),
    )
    .expect("create_proof_with_dump");
    let proof = transcript.finalize();
    println!("  proof generated ({} bytes)", proof.len());

    verify::<R, TH>(&srs.verifier_params(), &vk, &instance, None, &proof)
        .expect("proof does not verify");

    dump_trace(&dir, name, &dump, cli.trace_polys).expect("write trace");

    // vk.json (verifies the proof once more internally).
    export_verifier_bundle::<R, TH>(
        &srs.verifier_params(),
        &vk,
        &instance,
        None,
        Some(&proof),
        name,
        &dir.join("vk.json"),
    )
    .expect("export_verifier_bundle");
    println!("  artifacts written to {}", dir.display());
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn selected(cli: &Cli, name: &str) -> bool {
    if !cli.only.is_empty() {
        return cli.only.iter().any(|s| s == name);
    }
    !cli.skip.iter().any(|s| s == name)
}

fn run_poseidon(cli: &Cli) {
    let name = "poseidon";
    if !selected(cli, name) {
        return;
    }
    let relation = poseidon::PoseidonExample;
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [F; 3] = core::array::from_fn(|_| F::random(&mut rng));
    let instance = <PoseidonChip<F> as HashCPU<F, F>>::hash(&witness);
    export_example(cli, name, 6, &relation, instance, witness);
}

fn run_native_gadget(cli: &Cli) {
    let name = "native_gadget";
    if !selected(cli, name) {
        return;
    }
    let relation = native_gadget::NativeGadgetExample;
    let witness = (F::from(30), F::from(15));
    let instance = F::from(17); // 30 nand 15, bitwise over 5 bits
    export_example(cli, name, 11, &relation, instance, witness);
}

fn run_sha_preimage(cli: &Cli) {
    let name = "sha_preimage";
    if !selected(cli, name) {
        return;
    }
    use rand::Rng;
    use sha2::Digest;
    let relation = sha_preimage::ShaPreImageCircuit;
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness: [u8; 24] = core::array::from_fn(|_| rng.gen());
    let instance: [u8; 32] = sha2::Sha256::digest(witness).into();
    export_example(cli, name, 13, &relation, instance, witness);
}

fn run_ecc_ops(cli: &Cli) {
    let name = "ecc_ops";
    if !selected(cli, name) {
        return;
    }
    use group::Group;
    let relation = ecc_ops::EccExample;
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let witness = midnight_curves::Fr::random(&mut rng);
    let instance = midnight_curves::JubjubSubgroup::generator() * witness;
    export_example(cli, name, 11, &relation, instance, witness);
}

fn run_schnorr_sig(cli: &Cli) {
    let name = "schnorr_sig";
    if !selected(cli, name) {
        return;
    }
    let relation = schnorr_sig::SchnorrExample;
    let mut rng = ChaCha8Rng::seed_from_u64(0xf001ba11);
    let (schnorr_pk, sk) = schnorr_sig::keygen(&mut rng);
    let m = F::random(&mut rng);
    let sig = schnorr_sig::sign(m, &sk, &mut rng);
    let instance = (schnorr_pk, m);
    export_example(cli, name, 11, &relation, instance, sig);
}

fn run_membership(cli: &Cli) {
    let name = "membership";
    if !selected(cli, name) {
        return;
    }
    use midnight_circuits::{instructions::map::MapCPU, map::cpu::MapMt};
    let relation = membership::MembershipExample;
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let mut mt = MapMt::<F, PoseidonChip<F>>::new(&F::ZERO);
    for _ in 0..100 {
        mt.insert(&F::random(&mut rng), &F::from(0b1000_0000));
    }
    mt.insert(&F::ONE, &F::from(0b1010_1000));
    let proof_set = F::from(0b1000_1000);
    let mut sets_bytes = <F as PrimeField>::Repr::default();
    sets_bytes.as_mut()[0] = 0b1010_1000;
    let sets = F::from_repr(sets_bytes).unwrap();
    let witness = (F::ONE, sets, mt.clone());
    let instance = (mt.succinct_repr(), proof_set);
    export_example(cli, name, 13, &relation, instance, witness);
}

fn run_rsa_signature(cli: &Cli) {
    let name = "rsa_signature";
    if !selected(cli, name) {
        return;
    }
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{Num, One};
    use std::ops::Rem;
    let relation = rsa_signature::RSASignatureCircuit;
    // Same 512-bit primes as the example's main; exponent e = 3.
    let p = BigUint::from_str_radix("81e05798232330a8c7059621c812dc9d2bba37edbd0e79f101eef1db373c12724595480ae6a9dbbf158fa65d6910b8aea7b3be2eede9123ede8d84ec9e8ee907", 16).unwrap();
    let q = BigUint::from_str_radix("acd6fd3c0d70502e8ecefb20259fbf4783a614a0fb1a33701e3adc84947326a754f8a632e5f6cd718a681cde953024b3612bb0646f180b6fd063b1ef4e10d4a5", 16).unwrap();
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    let d = BigUint::from(3u64).modinv(&phi).unwrap();
    let public_key = &p * &q;
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let message = rng.gen_biguint(1024).rem(&public_key);
    let signature = message.modpow(&d, &public_key);
    let instance = (public_key, message);
    export_example(cli, name, 12, &relation, instance, signature);
}

fn run_hybrid_mt(cli: &Cli) {
    let name = "hybrid_mt";
    if !selected(cli, name) {
        return;
    }
    let relation = hybrid_mt::HybridMtExample;
    let witness = hybrid_mt::create_random_merkle_path();
    let instance = witness.compute_root();
    export_example(cli, name, 13, &relation, instance, witness);
}

fn run_ethereum_signature(cli: &Cli) {
    let name = "ethereum_signature";
    if !selected(cli, name) {
        return;
    }
    use midnight_circuits::CircuitField;
    use midnight_curves::k256::Fq as K256Scalar;
    let relation = ethereum_signature::EthereumSigExample;
    let msg_bytes: [u8; 32] = *b"this is really 32 byte long, huh";
    let pk_bytes: [[u8; 32]; 2] = [
        hex_literal::hex!("4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"),
        hex_literal::hex!("fe77b4dd0a4bfb95851f3b7355c781dd60f8418fc8a65d14907aff47c903a559"),
    ];
    let sig_bytes: [[u8; 32]; 2] = [
        hex_literal::hex!("3c0fb2cfab098941e41e180c5e83bd270f1d52811a517dbee235219f35935717"),
        hex_literal::hex!("1ce5858264bbdf0afe617da1dc8f3fa94a350e40442eb0363c3c95be9cd0d6d8"),
    ];
    let instance = (ethereum_signature::parse_eth_point(&pk_bytes), msg_bytes);
    let witness = (
        K256Scalar::from_bytes_be(&sig_bytes[0]).expect("Secp scalar 0"),
        K256Scalar::from_bytes_be(&sig_bytes[1]).expect("Secp scalar 1"),
    );
    export_example(cli, name, 15, &relation, instance, witness);
}

fn run_bitcoin_signature(cli: &Cli) {
    let name = "bitcoin_signature";
    if !selected(cli, name) {
        return;
    }
    use midnight_circuits::CircuitField;
    use midnight_curves::k256::{Fp as K256Base, Fq as K256Scalar};
    let relation = bitcoin_signature::BitcoinSigExample;
    let msg_bytes: [u8; 32] = [
        27, 214, 156, 7, 93, 215, 183, 140, 79, 32, 166, 152, 178, 42, 63, 185, 215, 70, 21, 37,
        195, 152, 39, 214, 170, 247, 161, 98, 139, 224, 162, 131,
    ];
    let pk_bytes: [u8; 32] = [
        179, 21, 213, 119, 148, 98, 81, 244, 98, 197, 69, 237, 108, 48, 37, 32, 206, 5, 247, 157,
        67, 110, 22, 104, 179, 49, 214, 89, 58, 147, 58, 98,
    ];
    let sig_bytes: [u8; 64] = [
        130, 202, 167, 37, 68, 100, 97, 250, 64, 31, 112, 100, 84, 155, 189, 94, 44, 183, 164, 69,
        191, 116, 182, 25, 49, 201, 43, 66, 204, 112, 124, 32, 49, 8, 60, 245, 140, 215, 44, 157,
        221, 20, 191, 69, 227, 251, 112, 89, 42, 136, 159, 147, 148, 126, 60, 47, 139, 187, 129,
        58, 59, 239, 164, 80,
    ];
    let instance = (bitcoin_signature::parse_bitcoin_point(&pk_bytes), msg_bytes);
    let witness = (
        K256Base::from_bytes_be(&sig_bytes[..32]).expect("Secp base"),
        K256Scalar::from_bytes_be(&sig_bytes[32..]).expect("Secp scalar"),
    );
    export_example(cli, name, 15, &relation, instance, witness);
}

fn run_bitcoin_ecdsa_threshold(cli: &Cli) {
    let name = "bitcoin_ecdsa_threshold";
    if !selected(cli, name) {
        return;
    }
    use midnight_circuits::testing_utils::ecdsa::{ECDSASig, Ecdsa};
    use midnight_curves::k256::{Fq as K256Scalar, K256};
    use rand::prelude::SliceRandom;
    // Matches the example's N = 5 total keys, T = 4 known signatures.
    const N: usize = 5;
    const T: usize = 4;
    let relation = bitcoin_ecdsa_threshold::BitcoinThresholdECDSA;
    let mut rng = ChaCha8Rng::seed_from_u64(0xba5eba11);
    let msg_hash = K256Scalar::random(&mut rng);
    let keys: [_; N] = core::array::from_fn(|_| Ecdsa::keygen(&mut rng));
    let pks = keys.map(|(pk, _)| pk);
    let mut indices: Vec<usize> = (0..N).collect();
    indices.shuffle(&mut rng);
    let mut idxs_of_known_sigs = indices[..T].to_vec();
    idxs_of_known_sigs.sort();
    let signatures: [(K256, ECDSASig); T] = idxs_of_known_sigs
        .into_iter()
        .map(|i| (keys[i].0, Ecdsa::sign(&keys[i].1, &msg_hash, &mut rng)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let instance = (msg_hash, pks);
    export_example(cli, name, 16, &relation, instance, signatures);
}

fn run_cardano_signature(cli: &Cli) {
    let name = "cardano_signature";
    if !selected(cli, name) {
        return;
    }
    let relation = cardano_signature::CardanoSigExample;
    let m: [u8; 86] =
        "Bajado ya de los árboles/las altas hierbas lo volvieron erecto/y miró las estrellas."
            .as_bytes()
            .try_into()
            .unwrap();
    let a_bytes: [u8; 32] = [
        32, 122, 6, 120, 146, 130, 30, 37, 215, 112, 241, 251, 160, 196, 124, 17, 255, 75, 129, 62,
        84, 22, 46, 206, 158, 184, 57, 224, 118, 35, 26, 182,
    ];
    let r_bytes: [u8; 32] = [
        2, 149, 17, 250, 35, 213, 26, 139, 202, 65, 23, 200, 170, 109, 4, 161, 27, 152, 221, 254,
        15, 224, 56, 90, 99, 14, 98, 181, 219, 194, 61, 148,
    ];
    let s_bytes: [u8; 32] = [
        177, 221, 190, 208, 136, 151, 72, 0, 180, 137, 141, 219, 245, 134, 42, 56, 131, 62, 179,
        20, 55, 27, 59, 125, 238, 4, 12, 14, 25, 231, 21, 12,
    ];
    let instance = (a_bytes, m);
    let witness = (r_bytes, s_bytes);
    export_example(cli, name, 17, &relation, instance, witness);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

fn write_manifest(out: &Path) -> std::io::Result<()> {
    let mut examples = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(out)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("vk.json").exists())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let dir = entry.path();
        let id = entry.file_name().to_string_lossy().into_owned();
        let vk: Json = serde_json::from_slice(&fs::read(dir.join("vk.json"))?)?;

        let mut files = serde_json::Map::new();
        for f in ["vk.json", "layout.json", "trace.json"] {
            if let Ok(meta) = fs::metadata(dir.join(f)) {
                files.insert(f.into(), json!({"size": meta.len()}));
            }
        }
        let mut bin_bytes = 0u64;
        for sub in ["columns", "trace"] {
            if let Ok(rd) = fs::read_dir(dir.join(sub)) {
                for f in rd.filter_map(|e| e.ok()) {
                    bin_bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }

        examples.push(json!({
            "id": id,
            "k": vk["vk"]["k"],
            "n": vk["vk"]["n"],
            "transcript_hash": vk["meta"]["transcript_hash"],
            "files": files,
            "binary_bytes": bin_bytes,
        }));
    }
    let manifest = json!({"version": 1, "examples": examples});
    fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
}

// ---------------------------------------------------------------------------

fn parse_cli() -> Cli {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Make the SRS path independent of the current working directory.
    if std::env::var("SRS_DIR").is_err() {
        std::env::set_var("SRS_DIR", manifest_dir.join("examples/assets"));
    }

    let mut cli = Cli {
        out: manifest_dir.parent().unwrap().join("visualiser/app/public/artifacts"),
        only: vec![],
        skip: vec![],
        trace_polys: true,
        check: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => cli.out = PathBuf::from(args.next().expect("--out <dir>")),
            "--only" => cli.only.push(args.next().expect("--only <name>")),
            "--skip" => cli.skip.push(args.next().expect("--skip <name>")),
            "--no-trace-polys" => cli.trace_polys = false,
            "--check" => cli.check = true,
            other => panic!("unknown argument: {other}"),
        }
    }
    cli
}

fn main() {
    let cli = parse_cli();
    fs::create_dir_all(&cli.out).expect("create output dir");

    run_poseidon(&cli);
    run_native_gadget(&cli);
    run_ecc_ops(&cli);
    run_schnorr_sig(&cli);
    run_rsa_signature(&cli);
    run_sha_preimage(&cli);
    run_membership(&cli);
    run_hybrid_mt(&cli);
    run_ethereum_signature(&cli);
    run_bitcoin_signature(&cli);
    run_bitcoin_ecdsa_threshold(&cli);
    run_cardano_signature(&cli);

    write_manifest(&cli.out).expect("write manifest");
    println!(
        "manifest written to {}",
        cli.out.join("manifest.json").display()
    );
    let _ = std::io::stdout().flush();
}
